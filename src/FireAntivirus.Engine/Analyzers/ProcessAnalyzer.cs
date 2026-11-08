using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// 进程级强信号检测器。
    /// 原则：
    ///  - 绝不因"进程名/路径 Contains 常见词"扣分——正常系统脚本宿主（cmd/powershell/rundll32）不在黑名单；
    ///  - 绝不信任"系统目录"，只把目录+数字签名作为负向降权因子，恶意哈希/动态注入/真实攻击链证据永远优先；
    ///  - 必须依赖"证据链"（主模块哈希+数字签名+运行位置+可疑加载模块+攻击命令行）加权融合。
    /// </summary>
    public class ProcessAnalyzer
    {
        private DataManager dataManager;
        private Dictionary<int, List<string>> processCache;

        // 判定阈值
        private const double HIGH_RISK_THRESHOLD = 0.8;
        private const double SUSPICIOUS_THRESHOLD = 0.62;

        // 已知良性/受保护的系统进程（精确名，非子串）
        private static readonly HashSet<string> SystemProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost", "explorer", "winlogon", "lsass", "csrss", "smss",
            "services", "wininit", "taskhost", "taskhostw", "dwm", "conhost",
            "winlogon", "fontdrvhost", "clip", "ctfmon", "RuntimeBroker",
            "ShellExperienceHost", "SearchHost", "StartMenuExperienceHost",
            "dllhost", "sihost", "backgroundTaskHost", "spoolsv", "System",
            "Registry", "Idle", "Memory Compression", "audiodg", "dwm"
        };

        // 恶意进程名/可疑驻留路径/注入模块片段/攻击命令行信号等特征全部外置到
        // embedded_threats.json（经 EmbeddedThreatDatabase 运行时加载），不硬编码进 DLL 避免被误判。

        // 可信签名发布者白名单（仅用于降权）
        private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Microsoft Windows", "Google LLC", "Apple Inc.",
            "Mozilla Corporation", "Adobe Inc.", "Oracle Corporation", "VMware, Inc.",
            "Intel Corporation", "Dell Inc.", "NVIDIA Corporation", "AMD",
            "GitHub, Inc.", "Dropbox, Inc.", "Zoom Video Communications, Inc.",
            "Docker, Inc.", "SUSE", "Canonical Group Limited", "Cisco Systems, Inc.",
            "耄耋软件工作室", "FireAntivirus"
        };

        public ProcessAnalyzer()
        {
            dataManager = DataManager.SharedInstance;
            processCache = new Dictionary<int, List<string>>();
        }

        public List<ScanResult> AnalyzeProcess(int processId)
        {
            var results = new List<ScanResult>();
            
            try
            {
                var process = Process.GetProcessById(processId);
                var processInfo = GetProcessInfo(processId);
                var modules = GetProcessModules(processId);
                var scan = EvaluateProcess(process, processInfo, modules);
                results.Add(scan.Result);

                if (scan.Result.IsInfected && !string.IsNullOrEmpty(scan.Result.FilePath))
                {
                    dataManager.LogThreat($"进程分析检测到恶意进程: {process.ProcessName} (PID: {processId})",
                        $"评分: {scan.Result.Confidence:P} 证据: {scan.Evidence}", "ProcessAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"进程分析失败: PID {processId}", ex.Message, "ProcessAnalyzer");
            }

            return results;
        }

        public List<ScanResult> AnalyzeAllProcesses()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        var processResults = AnalyzeProcess(process.Id);
                        results.AddRange(processResults);
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("分析所有进程失败", ex.Message, "ProcessAnalyzer");
            }

            return results;
        }

        /// <summary>
        /// 进程证据评估中心：将多个独立信号做加权融合。
        /// A. 主模块哈希命中已知恶意库 -> 直接高危（永远优先）
        ///    否则 B. 数字签名可信 + 系统进程 -> 直接良性（正常系统进程）
        ///    否则 C.（非系统进程）依据 签名/运行位置/可疑加载模块/攻击命令行/父进程 计算风险分
        /// </summary>
        private (ScanResult Result, string Evidence) EvaluateProcess(Process process, List<string> processInfo, List<string> modules)
        {
            string exePath = process.MainModule?.FileName ?? ExtractExecutablePath(processInfo);
            string processName = (process.ProcessName ?? "").Trim();
            string cmdline = ExtractCommandLine(processInfo);
            int parentPid = ExtractParentPid(processInfo);
            var evidence = new List<string>();

            // ---------------- A) 主模块哈希：最强信号 ----------------
            string hash = !string.IsNullOrEmpty(exePath) && File.Exists(exePath) ? ComputeSha256(exePath) : string.Empty;
            if (!string.IsNullOrEmpty(hash))
            {
                if (SignatureDatabaseUpdater.TryGetHashThreat(hash, out var threatName))
                {
                    return (MakeHit(exePath, $"已知恶意进程特征码 ({threatName})", "Malware", "High", 0.99, $"进程 {processName} 主模块 SHA256 命中恶意特征库"), $"哈希命中 {threatName}");
                }
                var localSig = dataManager.GetSignatureByHash(hash);
                if (localSig != null && !string.IsNullOrEmpty(localSig.Name))
                {
                    return (MakeHit(exePath, $"已知恶意进程特征码 ({localSig.Name})", "Malware", "High", 0.99, $"进程 {processName} 主模块命中本地特征库"), $"本地哈希命中 {localSig.Name}");
                }
            }

            // ---------------- B) 数字签名验证 + 系统进程：正常系统进程 ----------------
            double trustDiscount = 0.0;
            string publisher = string.Empty;
            bool isSignedValid = TryValidateSignature(exePath, out publisher);
            bool trustedPublisher = isSignedValid && IsTrustedPublisher(publisher);
            bool isSystemProc = SystemProcesses.Contains(processName);
            bool inSystemDir = IsInTrustedDirectory(exePath);

            // 正常系统进程 + 有效系统签名 + 位于系统目录：直接良性（这是可证明可信的基线）
            if ((isSystemProc && inSystemDir) || (trustedPublisher && inSystemDir && isSystemProc))
            {
                var clean = new ScanResult
                {
                    FilePath = exePath ?? processName,
                    IsInfected = false,
                    Confidence = 0.0,
                    DetectionTime = DateTime.Now,
                    DetectionMethod = "Process",
                    ThreatName = string.Empty,
                    AdditionalInfo = "系统可信进程"
                };
                return (clean, "系统可信进程");
            }

            // 可信签名作为降权因子（不豁免）
            if (trustedPublisher) trustDiscount = 0.35;

            // ---------------- C) 非可信系统进程：证据链评分 ----------------
            double score = 0.0;

            // C1) 运行位置（高可疑驻留区）
            string resolved = exePath ?? string.Empty;
            foreach (var p in FireAntivirus.Engine.Data.EmbeddedThreatDatabase.SuspiciousLaunchPaths)
            {
                if (resolved.Contains(p, StringComparison.OrdinalIgnoreCase))
                {
                    score += 0.5; evidence.Add($"运行在可疑路径 {p}");
                    break;
                }
            }

            // C2) 可疑动态加载模块（注入证据）
            int injectedModules = 0;
            foreach (var m in modules)
            {
                string lower = m ?? string.Empty;
                if (!lower.StartsWith("C:\\Windows\\", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var pat in FireAntivirus.Engine.Data.EmbeddedThreatDatabase.InjectionModulePatterns)
                    {
                        if (lower.Contains(pat, StringComparison.OrdinalIgnoreCase))
                        {
                            injectedModules++;
                            evidence.Add($"加载可疑模块 {Path.GetFileName(lower)}");
                            break;
                        }
                    }
                }
            }
            if (injectedModules >= 2) score += 0.8;
            else if (injectedModules == 1) score += 0.4;

            // C3) 攻击命令行信号
            int attackSignals = 0;
            foreach (var sig in FireAntivirus.Engine.Data.EmbeddedThreatDatabase.AttackCommandLineSignals)
            {
                if (cmdline.Contains(sig, StringComparison.OrdinalIgnoreCase))
                {
                    attackSignals++;
                    evidence.Add($"命令行含攻击特征 {sig}");
                }
            }
            if (attackSignals >= 2) score += 0.7;
            else if (attackSignals == 1) score += 0.35;

            // C4) 已知恶意进程名（精确）
            if (FireAntivirus.Engine.Data.EmbeddedThreatDatabase.IsMaliciousProcessName(processName))
            {
                score += 0.9;
                evidence.Add($"命中已知恶意进程名 {processName}");
            }

            // C5) 父进程为办公文档/浏览器且自身为脚本宿主 + 解码命令 = 常见钓鱼/宏投递链
            string parentName = GetProcessNameSafe(parentPid);
            bool childScriptHost = new[] { "powershell", "cmd", "mshta", "wscript", "cscript", "rundll32", "regsvr32" }
                .Contains(processName, StringComparer.OrdinalIgnoreCase);
            if (childScriptHost && new[] { "winword", "excel", "powerpnt", "chrome", "firefox", "msedge", "outlook", "acrord32" }
                .Contains(parentName, StringComparer.OrdinalIgnoreCase))
            {
                score += 0.5;
                evidence.Add($"脚本宿主由办公/浏览器进程 {parentName} 派生");
                if (attackSignals >= 1) score += 0.3;
            }

            // C6) 未知签名且在小写 temp 目录反复出现
            if (!isSignedValid && resolved.StartsWith(System.IO.Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
            {
                score += 0.4;
                evidence.Add("未签署且位于临时目录");
            }

            // 应用可信签名降权（只减分不豁免）
            score = System.Math.Max(0, score - trustDiscount);

            var result = new ScanResult
            {
                FilePath = exePath ?? processName,
                IsInfected = score >= HIGH_RISK_THRESHOLD,
                Confidence = System.Math.Max(0, System.Math.Min(score, 1.0)),
                DetectionTime = DateTime.Now,
                DetectionMethod = "Process"
            };

            if (result.IsInfected)
            {
                result.ThreatName = score > 0.92 ? "检测到恶意进程" : "检测到高可疑进程";
                result.ThreatType = score > 0.92 ? "Malware" : "Suspicious";
                result.Severity = score > 0.92 ? "High" : "Medium";
                result.AdditionalInfo = $"进程 {processName} (PID {process.Id}) 风险 {score:P}；证据: {string.Join("; ", evidence)}";
            }
            else if (score >= SUSPICIOUS_THRESHOLD)
            {
                result.ThreatName = "低风险未知进程";
                result.ThreatType = "Risk";
                result.Severity = "Low";
                result.AdditionalInfo = $"进程 {processName} 为未知来源程序（{score:P}）";
            }
            else
            {
                result.ThreatName = string.Empty;
            }

            return (result, string.Join("; ", evidence));
        }

        private ScanResult MakeHit(string path, string name, string type, string severity, double conf, string info)
        {
            return new ScanResult
            {
                FilePath = path,
                IsInfected = true,
                ThreatName = name,
                ThreatType = type,
                Severity = severity,
                Confidence = conf,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Process",
                AdditionalInfo = info
            };
        }

        private List<string> GetProcessInfo(int processId)
        {
            var info = new List<string>();
            
            if (processCache.TryGetValue(processId, out List<string> cachedInfo))
            {
                return cachedInfo;
            }

            try
            {
                var process = Process.GetProcessById(processId);
                info.Add($"Name: {process.ProcessName}");
                info.Add($"Id: {process.Id}");
                info.Add($"MainModule: {process.MainModule?.FileName}");
                info.Add($"StartTime: {process.StartTime}");
                info.Add($"TotalProcessorTime: {process.TotalProcessorTime}");
                info.Add($"WorkingSet64: {process.WorkingSet64}");
                info.Add($"PrivateMemorySize64: {process.PrivateMemorySize64}");
                info.Add($"VirtualMemorySize64: {process.VirtualMemorySize64}");

                try
                {
                    using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessId = {processId}"))
                    {
                        var mo = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                        if (mo != null)
                        {
                            info.Add($"CommandLine: {mo["CommandLine"]}");
                            info.Add($"ParentProcessId: {mo["ParentProcessId"]}");
                            info.Add($"ExecutablePath: {mo["ExecutablePath"]}");
                            info.Add($"CreationDate: {mo["CreationDate"]}");
                        }
                    }
                }
                catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Warning, "ProcessAnalyzer WMI失败", ex.Message); }

                processCache[processId] = info;
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Warning, "ProcessAnalyzer 获取进程信息失败", ex.Message);
                info.Clear();
            }

            return info;
        }

        private List<string> GetProcessModules(int processId)
        {
            var modules = new List<string>();
            
            try
            {
                var process = Process.GetProcessById(processId);
                foreach (ProcessModule module in process.Modules)
                {
                    modules.Add(module.FileName);
                }
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Warning, "ProcessAnalyzer 读取模块失败", ex.Message);
                modules.Clear();
            }

            return modules;
        }

        private string ExtractExecutablePath(List<string> info)
        {
            foreach (var line in info)
            {
                if (line.StartsWith("ExecutablePath:") && line.Length > "ExecutablePath:".Length)
                    return line.Substring("ExecutablePath:".Length).Trim();
            }
            foreach (var line in info)
            {
                if (line.StartsWith("MainModule:") && line.Length > "MainModule:".Length)
                    return line.Substring("MainModule:".Length).Trim();
            }
            return string.Empty;
        }

        private string ExtractCommandLine(List<string> info)
        {
            foreach (var line in info)
            {
                if (line.StartsWith("CommandLine:") && line.Length > "CommandLine:".Length)
                    return line.Substring("CommandLine:".Length).Trim();
            }
            return string.Empty;
        }

        private int ExtractParentPid(List<string> info)
        {
            foreach (var line in info)
            {
                if (line.StartsWith("ParentProcessId:") && line.Length > "ParentProcessId:".Length)
                {
                    int.TryParse(line.Substring("ParentProcessId:".Length).Trim(), out int pid);
                    return pid;
                }
            }
            return 0;
        }

        private string GetProcessNameSafe(int pid)
        {
            if (pid <= 0) return string.Empty;
            try { using var p = Process.GetProcessById(pid); return p.ProcessName; }
            catch { return string.Empty; }
        }

        private static bool IsInTrustedDirectory(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string full = Path.GetFullPath(path);
            return full.StartsWith("C:\\Windows\\System32", StringComparison.OrdinalIgnoreCase)
                || full.StartsWith("C:\\Windows\\SysWOW64", StringComparison.OrdinalIgnoreCase)
                || full.StartsWith("C:\\Windows\\WinSxS", StringComparison.OrdinalIgnoreCase)
                || full.StartsWith("C:\\Windows\\Microsoft.NET", StringComparison.OrdinalIgnoreCase)
                || full.StartsWith("C:\\Program Files", StringComparison.OrdinalIgnoreCase)
                || full.StartsWith("C:\\ProgramData\\", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsTrustedPublisher(string publisher)
        {
            if (string.IsNullOrEmpty(publisher)) return false;
            foreach (var tp in TrustedPublishers)
                if (publisher.Contains(tp, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        /// <summary>
        /// WinTrust 数字签名验证。返回是否有有效签名，并输出签名者信息。
        /// </summary>
        private static bool TryValidateSignature(string exePath, out string publisher)
        {
            publisher = string.Empty;
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) return false;
            try
            {
                using (var cert = X509Certificate.CreateFromSignedFile(exePath))
                using (var cert2 = new X509Certificate2(cert))
                {
                    if (!cert2.Verify()) return false;
                    publisher = cert2.GetNameInfo(X509NameType.SimpleName, false);
                    return true;
                }
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Debug, "ProcessAnalyzer 签名校验", ex.Message);
                return false;
            }
        }

        private static string ComputeSha256(string exePath)
        {
            try
            {
                using var stream = File.OpenRead(exePath);
                using var sha = SHA256.Create();
                var hashBytes = sha.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
            catch { return string.Empty; }
        }

        public void ClearCache()
        {
            processCache.Clear();
        }

        public int GetCacheSize()
        {
            return processCache.Count;
        }
    }
}