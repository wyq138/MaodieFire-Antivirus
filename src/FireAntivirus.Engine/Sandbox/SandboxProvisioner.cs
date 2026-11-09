// 沙箱环境供给器（环境准备流程，C# 版）：
//   组件查找优先级：①程序目录 Sandbox\Start.exe（随软件分发）→ ②程序同级 Sandboxie-Plus-*.exe 安装包（静默安装）
//                   → ③系统安装路径（Program Files\Sandboxie-Plus 等 4 个候选）
//   服务：SbieSvc（沙箱 RPC 服务，未运行则启动）；SbieDrv 驱动缺失则 sc create 注册
//   配置：SbieIni set AUTOSandBox <13 项>（会话内只配置一次）
//   关键实测结论：分析前必须结束 Sandboxie 托盘 UI（Sandboxie.exe/SandMan.exe/SbieCtrl.exe），
//   否则托盘进程持有沙箱 IPC 锁，Start.exe 启动的目标程序弹不出窗口、分析"监控中但程序没启动"。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace FireAntivirus.Engine.Sandbox
{
    public static class SandboxProvisioner
    {
        public const string BoxName = "AUTOSandBox";

        private static readonly object _lock = new object();
        private static bool _configured;
        private static bool _configureBusy;
        private static string _startExe;
        private static string _sbieIni;
        private static string _sbieDir;

        public static string StartExe
        {
            get { lock (_lock) return _startExe; }
        }

        public static string SandboxRoot => Path.Combine(
            Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\",
            "Sandbox", Environment.UserName, BoxName);

        /// <summary>定位 Sandboxie（随软件分发 / 安装包静默安装 / 系统安装路径）。</summary>
        public static bool TryLocate()
        {
            lock (_lock)
            {
                if (!string.IsNullOrEmpty(_startExe) && File.Exists(_startExe)) return true;

                string baseDir = AppContext.BaseDirectory;
                var candidates = new[]
                {
                    Path.Combine(baseDir, "Sandbox", "Start.exe"),   // 随软件分发
                    @"C:\Program Files\Sandboxie-Plus\Start.exe",
                    @"C:\Program Files\Sandboxie\Start.exe",
                    @"C:\Program Files (x86)\Sandboxie-Plus\Start.exe",
                    @"C:\Program Files (x86)\Sandboxie\Start.exe",
                };

                foreach (var c in candidates)
                {
                    if (!File.Exists(c)) continue;
                    _startExe = c;
                    _sbieDir = Path.GetDirectoryName(c);
                    _sbieIni = Path.Combine(_sbieDir, "SbieIni.exe");
                    Log("已定位 Sandboxie: " + c);
                    return true;
                }

                // 分发模式：程序同级目录带 Sandboxie 安装包 → 静默安装
                try
                {
                    var installer = Directory.GetFiles(baseDir, "Sandboxie*.exe")
                        .FirstOrDefault(f => !Path.GetFileName(f).Equals("Start.exe", StringComparison.OrdinalIgnoreCase));
                    if (installer != null)
                    {
                        Log("发现 Sandboxie 安装包，执行静默安装: " + installer);
                        try
                        {
                            using var p = Process.Start(new ProcessStartInfo(installer)
                            { Arguments = "/S", UseShellExecute = true });
                            p?.WaitForExit(180000);
                        }
                        catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

                        foreach (var c in candidates.Skip(1))
                        {
                            if (!File.Exists(c)) continue;
                            _startExe = c;
                            _sbieDir = Path.GetDirectoryName(c);
                            _sbieIni = Path.Combine(_sbieDir, "SbieIni.exe");
                            return true;
                        }
                    }
                }
                catch (Exception ex) { Log("Sandboxie 安装包处理失败: " + ex.Message); }

                Log("未找到 Sandboxie（程序目录 Sandbox\\Start.exe / 安装包 / 系统安装均缺失）");
                return false;
            }
        }

        /// <summary>确保沙箱环境就绪：服务 → 驱动 → 13 项配置（会话内一次）。</summary>
        public static async Task<bool> EnsureConfiguredAsync()
        {
            if (_configured) return true;
            if (_configureBusy) return false;
            _configureBusy = true;
            try
            {
                return await Task.Run(() =>
                {
                    if (!TryLocate()) return false;

                    // 1) SbieSvc 服务（驱动随安装程序注册；本机已装则仅启动）
                    EnsureServiceRunning("SbieSvc");

                    // 2) SbieDrv 驱动：服务不存在则用自带 .sys 注册（sc create SbieDrv type= kernel）
                    EnsureDriverService();

                    // 3) 13 项沙盒配置，并确保 MsiInstaller 恢复默认
                    ConfigureBox();

                    _configured = true;
                    Log($"沙箱环境就绪（Box={BoxName}）");
                    return true;
                });
            }
            finally
            {
                _configureBusy = false;
            }
        }

        private static void EnsureServiceRunning(string name)
        {
            try
            {
                var query = Run("sc.exe", "query " + name, 10000);
                if (query.Item1 == 0 && query.Item2.Contains("RUNNING")) return;
                var start = Run("sc.exe", "start " + name, 15000);
                Log($"启动服务 {name}: exit={start.Item1} {FirstLine(start.Item2)}");
            }
            catch (Exception ex) { Log($"服务 {name} 处理失败: {ex.Message}"); }
        }

        private static void EnsureDriverService()
        {
            try
            {
                var query = Run("sc.exe", "query SbieDrv", 10000);
                if (query.Item1 == 0) return; // 已注册

                string sys = string.IsNullOrEmpty(_sbieDir) ? null : Path.Combine(_sbieDir, "SbieDrv.sys");
                if (sys == null || !File.Exists(sys))
                {
                    var alt = @"C:\Program Files\Sandboxie-Plus\SbieDrv.sys";
                    if (File.Exists(alt)) sys = alt;
                }
                if (sys == null || !File.Exists(sys)) { Log("未找到 SbieDrv.sys，跳过驱动注册"); return; }

                var create = Run("sc.exe", $"create SbieDrv type= kernel start= system binPath= \"{sys}\"", 15000);
                if (create.Item1 == 0) Run("sc.exe", "start SbieDrv", 15000);
                Log($"SbieDrv 注册: exit={create.Item1} {FirstLine(create.Item2)}");
            }
            catch (Exception ex) { Log("SbieDrv 注册失败: " + ex.Message); }
        }

        private static void ConfigureBox()
        {
            if (string.IsNullOrEmpty(_sbieIni) || !File.Exists(_sbieIni))
            {
                Log("SbieIni.exe 缺失，无法配置沙盒（将使用默认沙盒配置）");
                return;
            }

            // 13 项基础沙盒配置
            var settings = new (string Key, string Value)[]
            {
                ("Enabled", "y"),
                ("AutoDelete", "n"),
                ("BlockNetworkFiles", "y"),
                ("ConfigLevel", "10"),
                ("BorderColor", "#00FFFF,ttl"),
                ("FileTrace", "wcd"),
                ("KeyTrace", "wcd"),
                ("PipeTrace", "w"),
                ("IpcTrace", "w"),
                ("NetFwTrace", "*"),
                ("DnsTrace", "*"),
                ("TraceBufferPages", "2560"),
                ("FakeAdminRights", "y"),
            };

            foreach (var (key, value) in settings)
                Run(_sbieIni, $"set {BoxName} {key} {value}", 8000);

            // 确保 MSI 分析后恢复默认安全级别
            Run(_sbieIni, $"unset {BoxName} MsiInstaller", 8000);

            Log("沙盒 AUTOSandBox 13 项配置已应用");
        }

        /// <summary>
        /// 追加 SbieIni 配置（反沙箱加固等）。与 13 项基础配置独立，可重复调用（幂等）。
        /// 同步阻塞，调用方应在后台线程执行。
        /// </summary>
        public static void ApplyExtraSettings(IEnumerable<(string Key, string Value)> settings)
        {
            if (settings == null) return;

            if (string.IsNullOrEmpty(_sbieIni) || !File.Exists(_sbieIni))
            {
                try { EnsureConfiguredAsync().GetAwaiter().GetResult(); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }
            if (string.IsNullOrEmpty(_sbieIni) || !File.Exists(_sbieIni))
            {
                Log("SbieIni.exe 不可用，附加配置未应用");
                return;
            }

            foreach (var (key, value) in settings)
                Run(_sbieIni, $"set {BoxName} {key} {value}", 8000);

            Log("沙箱附加加固配置已应用");
        }

        /// <summary>
        /// 结束 Sandboxie 托盘/管理 UI。实测：托盘进程持有沙箱 IPC 锁，导致
        /// Start.exe 启动的目标程序弹不出窗口、分析"监控中但程序没启动"。
        /// </summary>
        public static void KillTrayUi()
        {
            foreach (var name in new[] { "Sandboxie", "SandMan", "SbieCtrl" })
            {
                try
                {
                    foreach (var p in Process.GetProcessesByName(name))
                    {
                        try { p.Kill(); p.WaitForExit(2000); Log($"已结束 Sandboxie UI 进程: {name} (PID {p.Id})"); }
                        catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    }
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }
        }

        private static (int, string) Run(string file, string args, int timeoutMs)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = file,
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = Process.Start(psi);
                if (p == null) return (-1, "");
                string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit(timeoutMs);
                return (p.HasExited ? p.ExitCode : -1, output);
            }
            catch (Exception ex) { return (-1, ex.Message); }
        }

        private static string FirstLine(string s) =>
            string.IsNullOrEmpty(s) ? "" : s.Split('\n')[0].Trim();

        private static void Log(string msg) =>
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[沙箱] " + msg);
    }
}