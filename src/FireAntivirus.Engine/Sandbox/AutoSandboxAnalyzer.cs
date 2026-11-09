// 自动沙箱分析器（完整流程，C# 实现）：
//   触发：未签名 + 弱证据未达共识（YARA 社区规则命中 / 单弱票）→ 不再直接报毒，送沙盒行为验证（根除误报）
//   流程：环境就绪 → 清 Sandboxie 托盘 UI → Start.exe 沙盒静默运行 → 60 秒行为跟踪
//         （沙盒目录新文件 / 沙盒进程与命令行 / 沙盒进程网络连接 / 未签名执行）
//         → IOA 62 条规则评分（阈值 100）→ 恶意：终止沙盒进程 + 弹处置窗；安全：清白哈希入库后放行
//   防再触发（三重防线）：最近分析路径 TTL 10s + 全局冷却 4s
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Engine.Sandbox
{
    public static class AutoSandboxAnalyzer
    {
        /// <summary>自动沙箱验证总开关（设置页控制，默认开）。</summary>
        public static volatile bool Enabled;

        public const int AnalysisTimeoutSec = 60;
        public const int MassFileWriteThreshold = 30;

        /// <summary>沙箱行为确认恶意（宿主：弹处置窗 + 自动隔离）。</summary>
        public static event Action<ScanResult> ThreatConfirmed;
        /// <summary>沙箱验证安全（已自动加入清白库放行）。</summary>
        public static event Action<string> VerifiedBenign;

        private static readonly ConcurrentQueue<string> _queue = new ConcurrentQueue<string>();
        private static int _pending;
        private static int _workerRunning;

        // 全局冷却期 + 最近分析路径（防"分析→重跑→再分析"死循环）
        private static DateTime _lastEnd = DateTime.MinValue;
        private static readonly TimeSpan Cooldown = TimeSpan.FromSeconds(4);
        private static readonly ConcurrentDictionary<string, DateTime> _recentPaths =
            new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan RecentTtl = TimeSpan.FromSeconds(10);

        public static int PendingCount => Volatile.Read(ref _pending);

        // ---------------------------------------------------------------- 入队

        public static void EnqueueForVerification(string filePath, string reason)
        {
            if (!Enabled) return;
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return;
            if (InCooldown()) return;
            if (IsRecentlyAnalyzed(filePath)) return;

            Interlocked.Increment(ref _pending);
            _queue.Enqueue(filePath);
            Log($"已排队沙箱验证: {filePath}（{reason}）");
            EnsureWorker();
        }

        private static void EnsureWorker()
        {
            if (Interlocked.Exchange(ref _workerRunning, 1) == 1) return;
            _ = Task.Run(async () =>
            {
                try
                {
                    while (true)
                    {
                        if (Volatile.Read(ref _pending) <= 0 && _queue.IsEmpty) break;
                        if (!_queue.TryDequeue(out var file))
                        {
                            await Task.Delay(300);
                            continue;
                        }
                        Interlocked.Decrement(ref _pending);

                        try { await AnalyzeAsync(file); }
                        catch (Exception ex) { Log("沙箱分析异常: " + ex.Message); }
                        finally { _lastEnd = DateTime.Now; }
                    }
                }
                finally { Interlocked.Exchange(ref _workerRunning, 0); }
            });
        }

        // ---------------------------------------------------------------- 分析主流程

        private static async Task AnalyzeAsync(string filePath)
        {
            string root = SandboxProvisioner.SandboxRoot;
            try { Directory.CreateDirectory(root); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            bool envOk = await SandboxProvisioner.EnsureConfiguredAsync();
            if (!envOk)
            {
                Log("沙箱环境不可用，跳过验证（维持弱证据，不误报）: " + filePath);
                return;
            }
            SandboxProvisioner.KillTrayUi();

            // 反沙箱识别：强反沙箱样本进沙箱会"装死"，行为判定失真。
            // 对策：加固沙箱配置 + 把"反分析痕迹"本身计为一条 IOA 证据（T1497.001）。
            var evasion = SandboxEvasionGuard.Analyze(filePath);
            if (evasion.Level != SandboxEvasionLevel.None)
            {
                Log(evasion.Summary);
                if (evasion.Decision == SandboxRunDecision.HardenedSandbox)
                {
                    try { await Task.Run(() => SandboxEvasionGuard.ApplyHardening(out _)).ConfigureAwait(false); }
                    catch (Exception ex) { Log("沙箱加固配置异常: " + ex.Message); }
                }
            }

            var behaviors = new List<string>();
            var preFiles = SafeFiles(root);
            var seenPids = new HashSet<int>(SandboxProcessPids(root));
            var seenFiles = new HashSet<string>(preFiles, StringComparer.OrdinalIgnoreCase);

            // 未签名执行本身计一条证据（仅未签名文件进沙箱）
            if (IsUnsigned(filePath)) behaviors.Add("unsigned-execute");

            // 反沙箱痕迹作为行为证据（避免样本装死导致评分永远为 0）
            foreach (var evidence in SandboxEvasionGuard.ToBehaviorEvidence(evasion))
                behaviors.Add(evidence);

            if (!StartInSandbox(filePath))
            {
                Log("沙盒启动失败（Start.exe 多次返回失败）: " + filePath);
                return;  
            }
            Log($"沙盒内运行: {filePath}（行为跟踪 {AnalysisTimeoutSec}s）");

            var deadline = DateTime.UtcNow.AddSeconds(AnalysisTimeoutSec);
            while (DateTime.UtcNow < deadline)
            {
                // ① 沙盒目录新增文件（写文件/落地载荷/加密文件等）
                int newFiles = 0;
                foreach (var f in SafeFiles(root))
                {
                    if (seenFiles.Add(f))
                    {
                        newFiles++;
                        behaviors.Add("file:" + f);
                    }
                }
                if (newFiles >= MassFileWriteThreshold) behaviors.Add("mass-file-write");

                // ② 沙盒内进程与命令行（PowerShell/mshta/注入链等）
                foreach (var (pid, cmd, exe) in SandboxProcesses(root))
                {
                    if (seenPids.Add(pid))
                    {
                        if (!string.IsNullOrEmpty(exe)) behaviors.Add("exe:" + exe);
                        if (!string.IsNullOrWhiteSpace(cmd)) behaviors.Add("cmd:" + cmd);
                    }
                }

                // ③ 沙盒进程网络连接（C2/矿池/Tor 端口）
                foreach (var endpoint in SandboxNetworkEndpoints(seenPids))
                    behaviors.Add("net:" + endpoint);

                await Task.Delay(2000);
            }

            // IOA 评分
            var (score, hits) = IoaRules.Evaluate(behaviors);
            Log($"沙箱评分 {score}/{IoaRules.MaliciousThreshold} · 命中 {hits.Count} 条: " +
                string.Join("，", hits.Take(8).Select(h => $"{h.Name}(+{h.Score})")));

            if (score >= IoaRules.MaliciousThreshold)
            {
                KillSandboxProcesses(root);
                var result = new ScanResult
                {
                    FilePath = filePath,
                    IsInfected = true,
                    ThreatName = "Sandbox." + (hits.FirstOrDefault()?.Name ?? "MaliciousBehavior"),
                    ThreatType = "Behavior",
                    Severity = "High",
                    Confidence = 0.9,
                    DetectionMethod = "Sandbox-IOA",
                    DetectionTime = DateTime.Now,
                    AdditionalInfo = $"沙箱行为评分 {score}（阈值 {IoaRules.MaliciousThreshold}）；" +
                                     $"命中: {string.Join("；", hits.Take(6).Select(h => $"{h.Name}+{h.Score}"))}"
                };
                ThreatConfirmed?.Invoke(result);
                Log($"沙箱确认恶意: {filePath}（评分 {score}）");
            }
            else
            {
                _recentPaths[filePath] = DateTime.Now;
                try { WhitelistStore.RememberFile(filePath); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                VerifiedBenign?.Invoke(filePath);
                Log($"沙箱验证安全（评分 {score}），已入清白库放行: {filePath}");
            }
        }

        // ---------------------------------------------------------------- 沙盒操作

        private static bool StartInSandbox(string filePath)
        {
            string startExe = SandboxProvisioner.StartExe;
            if (string.IsNullOrEmpty(startExe) || !File.Exists(startExe)) return false;

            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = startExe,
                        Arguments = $"/box:{SandboxProvisioner.BoxName} /silent \"{filePath}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using var p = Process.Start(psi);
                    if (p == null) continue;
                    string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                    p.WaitForExit(20000);
                    if (p.HasExited && p.ExitCode == 0)
                    {
                        Log($"Start.exe 启动成功（尝试 #{attempt}）");
                        return true;
                    }
                    Log($"Start.exe 返回失败 exit={(p.HasExited ? p.ExitCode : -1)}（尝试 #{attempt}）{output.Trim()}");
                }
                catch (Exception ex)
                {
                    Log($"Start.exe 启动异常（尝试 #{attempt}）: {ex.Message}");
                }
                Thread.Sleep(1500);
            }
            return false;
        }

        private static List<string> SafeFiles(string root)
        {
            try
            {
                if (!Directory.Exists(root)) return new List<string>();
                return Directory.GetFiles(root, "*", SearchOption.AllDirectories).ToList();
            }
            catch { return new List<string>(); }
        }

        /// <summary>沙盒内进程（可执行路径位于沙盒目录下）。</summary>
        private static List<(int Pid, string Cmd, string Exe)> SandboxProcesses(string root)
        {
            var list = new List<(int, string, string)>();
            try
            {
                string rootLower = root.TrimEnd('\\').ToLowerInvariant();
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        string exe = null;
                        try { exe = p.MainModule?.FileName; } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                        if (string.IsNullOrEmpty(exe)) continue;
                        if (!exe.ToLowerInvariant().StartsWith(rootLower)) continue;
                        list.Add((p.Id, "", exe));
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            // 命令行补充（WMI，权限不足时跳过）
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT ProcessId, CommandLine, ExecutablePath FROM Win32_Process");
                foreach (System.Management.ManagementObject mo in searcher.Get())
                {
                    try
                    {
                        int pid = Convert.ToInt32(mo["ProcessId"]);
                        int idx = list.FindIndex(x => x.Item1 == pid);
                        if (idx < 0) continue;
                        string cmd = mo["CommandLine"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(cmd))
                            list[idx] = (pid, cmd, list[idx].Item3);
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return list;
        }

        private static HashSet<int> SandboxProcessPids(string root) =>
            new HashSet<int>(SandboxProcesses(root).Select(x => x.Item1));

        private static void KillSandboxProcesses(string root)
        {
            foreach (var (pid, _, _) in SandboxProcesses(root))
            {
                try
                {
                    using var p = Process.GetProcessById(pid);
                    p.Kill();
                    p.WaitForExit(2000);
                    Log($"已终止沙盒进程 PID={pid}");
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }
        }

        /// <summary>沙盒进程的 TCP 端点（netstat -ano 真实解析）。</summary>
        private static HashSet<string> SandboxNetworkEndpoints(HashSet<int> pids)
        {
            var endpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (pids.Count == 0) return endpoints;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-ano",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };
                using var p = Process.Start(psi);
                if (p == null) return endpoints;
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(5000);

                foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var t = line.Trim();
                    if (!t.StartsWith("TCP", StringComparison.OrdinalIgnoreCase)) continue;
                    var parts = t.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 5) continue;
                    if (!int.TryParse(parts[4], out int pid) || !pids.Contains(pid)) continue;
                    endpoints.Add(parts[2]); // 远端地址:端口
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return endpoints;
        }

        private static bool IsUnsigned(string filePath)
        {
            try
            {
                using var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
                return cert == null; // 有签名 → false
            }
            catch { return true; } // 无签名/签名损坏 → true
        }

        private static bool InCooldown() =>
            _lastEnd != DateTime.MinValue && (DateTime.Now - _lastEnd) < Cooldown;

        private static bool IsRecentlyAnalyzed(string filePath)
        {
            if (!_recentPaths.TryGetValue(filePath, out var t)) return false;
            if ((DateTime.Now - t) < RecentTtl) return true;
            _recentPaths.TryRemove(filePath, out _);
            return false;
        }

        private static void Log(string msg) =>
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[沙箱] " + msg);
    }
}