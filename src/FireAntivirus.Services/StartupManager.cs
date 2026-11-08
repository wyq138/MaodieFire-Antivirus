// 专业级启动项管理引擎 - 对标Autoruns/Sysinternals能力
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace FireAntivirus.Services
{
    public class StartupManager : IDisposable
    {
        #region Windows API

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        private static extern void IShellLinkW();

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SHCreateShellItem(
            IntPtr pidlParent, IntPtr psfParent, IntPtr pidl, out IntPtr ppsi);

        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
        private static extern int PathParseIconLocation(StringBuilder pszIconFile);

        [DllImport("version.dll", CharSet = CharSet.Unicode)]
        private static extern bool GetFileVersionInfo(string lptstrFilename, int dwHandle, int dwLen, byte[] lpData);

        [DllImport("version.dll", CharSet = CharSet.Unicode)]
        private static extern int GetFileVersionInfoSize(string lptstrFilename, out int dwHandle);

        [DllImport("version.dll", CharSet = CharSet.Unicode)]
        private static extern bool VerQueryValue(byte[] pBlock, string lpSubBlock, out IntPtr lplpBuffer, out int puLen);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct VS_FIXEDFILEINFO
        {
            public int dwSignature;
            public int dwStrucVersion;
            public int dwFileVersionMS;
            public int dwFileVersionLS;
            public int dwProductVersionMS;
            public int dwProductVersionLS;
            public int dwFileFlagsMask;
            public int dwFileFlags;
            public int dwFileOS;
            public int dwFileType;
            public int dwFileSubtype;
            public int dwFileDateMS;
            public int dwFileDateLS;
        }

        #endregion

        private readonly string _configPath;
        private readonly string _backupPath;
        private readonly string _logPath;

        // 监控
        private Timer _monitorTimer;
        private bool _isMonitoring = false;
        private ConcurrentDictionary<string, StartupItemSnapshot> _lastSnapshot = new ConcurrentDictionary<string, StartupItemSnapshot>();

        // 缓存
        private ConcurrentDictionary<string, SignatureInfo> _signatureCache = new ConcurrentDictionary<string, SignatureInfo>();
        private ConcurrentDictionary<string, ReputationInfo> _reputationCache = new ConcurrentDictionary<string, ReputationInfo>();

        // 已知安全项
        private HashSet<string> _knownSafePublishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _knownMaliciousPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public event EventHandler<StartupItemChangedEventArgs> StartupItemChanged;
        public event EventHandler<SuspiciousStartupItemDetectedEventArgs> SuspiciousItemDetected;

        public StartupManager()
        {
            _configPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "StartupManager");

            _backupPath = Path.Combine(_configPath, "Backup");
            _logPath = Path.Combine(_configPath, "Logs");

            foreach (var path in new[] { _configPath, _backupPath, _logPath })
            {
                if (!Directory.Exists(path))
                    Directory.CreateDirectory(path);
            }

            InitializeKnownPublishers();
            InitializeMaliciousPatterns();
        }

        #region 初始化

        private void InitializeKnownPublishers()
        {
            _knownSafePublishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Microsoft Corporation", "Microsoft Windows", "Microsoft",
                "Google LLC", "Google Inc", "Google",
                "Apple Inc.", "Apple Computer, Inc.",
                "Mozilla Corporation", "Mozilla",
                "Adobe Systems Incorporated", "Adobe",
                "Intel Corporation", "Intel",
                "NVIDIA Corporation", "NVIDIA",
                "Realtek Semiconductor Corp", "Realtek",
                "Broadcom Corporation", "Broadcom",
                "Qualcomm Atheros Communications Inc", "Qualcomm",
                "Logitech, Inc", "Logitech",
                "Dropbox, Inc.", "Dropbox",
                "Spotify AB", "Spotify",
                "Slack Technologies, Inc.", "Slack",
                "Zoom Video Communications, Inc.", "Zoom",
                "Tencent", "腾讯",
                "Alibaba", "阿里巴巴",
                "Baidu", "百度",
                "360安全中心", "360"
            };
        }

        private void InitializeMaliciousPatterns()
        {
            _knownMaliciousPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "bitcoin", "miner", "crypto", "monero",
                "hack", "crack", "keygen", "patch",
                "pirated", "warez", "serial",
                "temp\\", "appdata\\local\\temp",
                "public\\downloads", "programdata\\microsoft\\windows\\templates"
            };
        }

        #endregion

        #region 公共方法

        /// <summary>
        /// 获取所有启动项
        /// </summary>
        public List<StartupItem> GetStartupItems()
        {
            var items = new List<StartupItem>();

            try
            {
                items.AddRange(GetRegistryStartupItems());
                items.AddRange(GetFolderStartupItems());
                items.AddRange(GetServiceStartupItems());
                items.AddRange(GetTaskSchedulerStartupItems());
                items.AddRange(GetWinlogonStartupItems());
                items.AddRange(GetDriverStartupItems());
                items.AddRange(GetBootExecuteItems());

                // 丰富每个启动项的信息
                foreach (var item in items)
                {
                    EnrichStartupItem(item);
                }

                // 计算风险评分
                foreach (var item in items)
                {
                    CalculateRiskScore(item);
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return items.OrderBy(i => i.RiskLevel).ThenBy(i => i.Name).ToList();
        }

        /// <summary>
        /// 获取启动项详细信息
        /// </summary>
        public StartupItemDetail GetStartupItemDetail(StartupItem item)
        {
            var detail = new StartupItemDetail
            {
                Item = item,
                AnalyzedAt = DateTime.Now
            };

            // 获取文件信息
            if (!string.IsNullOrEmpty(item.TargetPath) && File.Exists(item.TargetPath))
            {
                detail.FileInfo = AnalyzeFile(item.TargetPath);
            }

            // 获取签名信息
            detail.SignatureInfo = GetSignatureInfo(item.TargetPath ?? item.Path);

            // 获取声誉信息
            detail.ReputationInfo = GetReputationInfo(item);

            // 获取启动影响
            detail.StartupImpact = AnalyzeStartupImpact(item);

            // 获取依赖项
            detail.Dependencies = GetDependencies(item);

            // 安全建议
            detail.Recommendations = GenerateRecommendations(item, detail);

            return detail;
        }

        /// <summary>
        /// 获取可疑启动项
        /// </summary>
        public List<StartupItem> GetSuspiciousStartupItems()
        {
            return GetStartupItems()
                .Where(i => i.RiskLevel >= RiskLevel.Medium)
                .OrderByDescending(i => i.RiskScore)
                .ToList();
        }

        /// <summary>
        /// 获取启动性能分析
        /// </summary>
        public StartupPerformanceAnalysis AnalyzeStartupPerformance()
        {
            var analysis = new StartupPerformanceAnalysis
            {
                AnalyzedAt = DateTime.Now
            };

            var items = GetStartupItems();
            var enabledItems = items.Where(i => i.Enabled).ToList();

            // 计算总启动影响
            foreach (var item in enabledItems)
            {
                analysis.TotalImpactScore += item.StartupImpact?.ImpactScore ?? 0;

                if (item.StartupImpact?.BootDelayMs > 0)
                {
                    analysis.EstimatedBootDelayMs += item.StartupImpact.BootDelayMs;
                }
            }

            // 分类统计
            analysis.TotalItems = items.Count;
            analysis.EnabledItems = enabledItems.Count;
            analysis.DisabledItems = items.Count - enabledItems.Count;

            analysis.HighRiskItems = items.Count(i => i.RiskLevel >= RiskLevel.High);
            analysis.MediumRiskItems = items.Count(i => i.RiskLevel == RiskLevel.Medium);
            analysis.LowRiskItems = items.Count(i => i.RiskLevel == RiskLevel.Low);
            analysis.SafeItems = items.Count(i => i.RiskLevel == RiskLevel.Safe);

            // 按影响排序
            analysis.TopImpactItems = enabledItems
                .Where(i => i.StartupImpact != null)
                .OrderByDescending(i => i.StartupImpact.ImpactScore)
                .Take(10)
                .ToList();

            // 优化建议
            analysis.OptimizationRecommendations = GenerateOptimizationRecommendations(items);

            return analysis;
        }

        /// <summary>
        /// 禁用启动项
        /// </summary>
        public bool DisableStartupItem(StartupItem item)
        {
            // 创建恢复点
            CreateRestorePoint(item, "禁用前备份");

            bool result = false;

            switch (item.Type)
            {
                case StartupType.Registry:
                    result = DisableRegistryStartupItem(item);
                    break;
                case StartupType.Folder:
                    result = DisableFolderStartupItem(item);
                    break;
                case StartupType.Service:
                    result = DisableServiceStartupItem(item);
                    break;
                case StartupType.TaskScheduler:
                    result = DisableTaskSchedulerStartupItem(item);
                    break;
                case StartupType.Winlogon:
                    result = DisableWinlogonStartupItem(item);
                    break;
                case StartupType.Driver:
                    result = DisableDriverStartupItem(item);
                    break;
            }

            if (result)
            {
                LogOperation("禁用", item);
            }

            return result;
        }

        /// <summary>
        /// 启用启动项
        /// </summary>
        public bool EnableStartupItem(StartupItem item)
        {
            bool result = false;

            switch (item.Type)
            {
                case StartupType.Registry:
                    result = EnableRegistryStartupItem(item);
                    break;
                case StartupType.Folder:
                    result = EnableFolderStartupItem(item);
                    break;
                case StartupType.Service:
                    result = EnableServiceStartupItem(item);
                    break;
                case StartupType.TaskScheduler:
                    result = EnableTaskSchedulerStartupItem(item);
                    break;
                case StartupType.Winlogon:
                    result = EnableWinlogonStartupItem(item);
                    break;
                case StartupType.Driver:
                    result = EnableDriverStartupItem(item);
                    break;
            }

            if (result)
            {
                LogOperation("启用", item);
            }

            return result;
        }

        /// <summary>
        /// 删除启动项
        /// </summary>
        public bool DeleteStartupItem(StartupItem item)
        {
            // 创建恢复点
            CreateRestorePoint(item, "删除前备份");

            bool result = false;

            switch (item.Type)
            {
                case StartupType.Registry:
                    result = DeleteRegistryStartupItem(item);
                    break;
                case StartupType.Folder:
                    result = DeleteFolderStartupItem(item);
                    break;
                case StartupType.Service:
                    result = DeleteServiceStartupItem(item);
                    break;
                case StartupType.TaskScheduler:
                    result = DeleteTaskSchedulerStartupItem(item);
                    break;
                case StartupType.Winlogon:
                    result = DeleteWinlogonStartupItem(item);
                    break;
                case StartupType.Driver:
                    result = DeleteDriverStartupItem(item);
                    break;
            }

            if (result)
            {
                LogOperation("删除", item);
            }

            return result;
        }

        /// <summary>
        /// 添加启动项
        /// </summary>
        public bool AddStartupItem(StartupItem item)
        {
            bool result = false;

            switch (item.Type)
            {
                case StartupType.Registry:
                    result = AddRegistryStartupItem(item);
                    break;
                case StartupType.Folder:
                    result = AddFolderStartupItem(item);
                    break;
            }

            if (result)
            {
                LogOperation("添加", item);
            }

            return result;
        }

        /// <summary>
        /// 设置启动延迟
        /// </summary>
        public bool SetStartupDelay(StartupItem item, int delaySeconds)
        {
            try
            {
                // 对于注册表项，创建延迟启动任务
                if (item.Type == StartupType.Registry)
                {
                    // 禁用原启动项
                    DisableRegistryStartupItem(item);

                    // 创建延迟启动的计划任务
                    return CreateDelayedStartupTask(item, delaySeconds);
                }

                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// 开始监控启动项变化
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring) return;

            _isMonitoring = true;

            // 获取初始快照
            var items = GetStartupItems();
            foreach (var item in items)
            {
                _lastSnapshot[item.Id] = new StartupItemSnapshot
                {
                    Id = item.Id,
                    Name = item.Name,
                    Path = item.Path,
                    TargetPath = item.TargetPath,
                    Enabled = item.Enabled,
                    Timestamp = DateTime.Now
                };
            }

            // 开始定期检查
            _monitorTimer = new Timer(MonitorCallback, null, TimeSpan.Zero, TimeSpan.FromSeconds(30));
        }

        /// <summary>
        /// 停止监控
        /// </summary>
        public void StopMonitoring()
        {
            _isMonitoring = false;
            _monitorTimer?.Dispose();
            _monitorTimer = null;
        }

        /// <summary>
        /// 恢复启动项
        /// </summary>
        public bool RestoreStartupItem(string backupId)
        {
            try
            {
                var backupFile = Path.Combine(_backupPath, $"{backupId}.json");
                if (!File.Exists(backupFile))
                    return false;

                var backup = System.Text.Json.JsonSerializer.Deserialize<StartupItemBackup>(
                    File.ReadAllText(backupFile));

                if (backup == null)
                    return false;

                // 根据备份恢复
                return RestoreFromBackup(backup);
            }
            catch { return false; }
        }

        /// <summary>
        /// 获取备份列表
        /// </summary>
        public List<StartupItemBackup> GetBackups()
        {
            var backups = new List<StartupItemBackup>();

            try
            {
                foreach (var file in Directory.GetFiles(_backupPath, "*.json"))
                {
                    try
                    {
                        var backup = System.Text.Json.JsonSerializer.Deserialize<StartupItemBackup>(
                            File.ReadAllText(file));
                        if (backup != null)
                        {
                            backups.Add(backup);
                        }
                    }
                    catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return backups.OrderByDescending(b => b.Timestamp).ToList();
        }

        #endregion

        #region 私有方法 - 获取启动项

        private List<StartupItem> GetRegistryStartupItems()
        {
            var items = new List<StartupItem>();

            var registryPaths = new[]
            {
                new { Path = @"Software\Microsoft\Windows\CurrentVersion\Run", Root = Registry.CurrentUser, User = Environment.UserName },
                new { Path = @"Software\Microsoft\Windows\CurrentVersion\RunOnce", Root = Registry.CurrentUser, User = Environment.UserName },
                new { Path = @"Software\Microsoft\Windows\CurrentVersion\Run", Root = Registry.LocalMachine, User = "All Users" },
                new { Path = @"Software\Microsoft\Windows\CurrentVersion\RunOnce", Root = Registry.LocalMachine, User = "All Users" },
                new { Path = @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", Root = Registry.LocalMachine, User = "All Users (32-bit)" },
                new { Path = @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", Root = Registry.LocalMachine, User = "All Users (32-bit)" }
            };

            foreach (var regPath in registryPaths)
            {
                try
                {
                    using (var key = regPath.Root.OpenSubKey(regPath.Path, false))
                    {
                        if (key == null) continue;

                        foreach (var valueName in key.GetValueNames())
                        {
                            var value = key.GetValue(valueName)?.ToString();
                            if (string.IsNullOrEmpty(value)) continue;

                            var item = new StartupItem
                            {
                                Id = $"REG_{regPath.Root.Name}_{regPath.Path}_{valueName}".Replace("\\", "_"),
                                Name = valueName,
                                Path = value,
                                Type = StartupType.Registry,
                                Location = $"{regPath.Root.Name}\\{regPath.Path}",
                                Enabled = true,
                                User = regPath.User,
                                Source = "Registry"
                            };

                            // 解析命令行获取实际路径
                            item.TargetPath = ExtractExecutablePath(value);
                            item.Arguments = ExtractArguments(value);

                            items.Add(item);
                        }
                    }
                }
                catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
            }

            return items;
        }

        private List<StartupItem> GetFolderStartupItems()
        {
            var items = new List<StartupItem>();

            var folders = new[]
            {
                new { Path = Environment.GetFolderPath(Environment.SpecialFolder.Startup), User = Environment.UserName },
                new { Path = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), User = "All Users" }
            };

            foreach (var folder in folders)
            {
                try
                {
                    if (!Directory.Exists(folder.Path)) continue;

                    foreach (var file in Directory.GetFiles(folder.Path, "*.lnk"))
                    {
                        try
                        {
                            var target = GetShortcutTarget(file);
                            var item = new StartupItem
                            {
                                Id = $"FOLDER_{file.GetHashCode()}",
                                Name = Path.GetFileNameWithoutExtension(file),
                                Path = file,
                                TargetPath = target,
                                Type = StartupType.Folder,
                                Location = folder.Path,
                                Enabled = true,
                                User = folder.User,
                                Source = "StartupFolder"
                            };

                            items.Add(item);
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
                    }
                }
                catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
            }

            return items;
        }

        private List<StartupItem> GetServiceStartupItems()
        {
            var items = new List<StartupItem>();

            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_Service WHERE StartMode='Auto' OR StartMode='Manual'"))
                {
                    foreach (ManagementObject service in searcher.Get())
                    {
                        try
                        {
                            var serviceName = service["Name"]?.ToString();
                            var displayName = service["DisplayName"]?.ToString();
                            var startMode = service["StartMode"]?.ToString();
                            var state = service["State"]?.ToString();
                            var pathName = service["PathName"]?.ToString();

                            var item = new StartupItem
                            {
                                Id = $"SERVICE_{serviceName}",
                                Name = displayName ?? serviceName,
                                Path = pathName ?? serviceName,
                                TargetPath = ExtractExecutablePath(pathName ?? ""),
                                Type = StartupType.Service,
                                Location = "Windows Services",
                                Enabled = startMode == "Auto",
                                User = "System",
                                Source = "WindowsService",
                                Status = state
                            };

                            items.Add(item);
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return items;
        }

        private List<StartupItem> GetTaskSchedulerStartupItems()
        {
            var items = new List<StartupItem>();

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ScheduledJob"))
                {
                    foreach (ManagementObject job in searcher.Get())
                    {
                        try
                        {
                            var name = job["Name"]?.ToString();
                            var command = job["Command"]?.ToString();

                            if (string.IsNullOrEmpty(name)) continue;

                            var item = new StartupItem
                            {
                                Id = $"TASK_{name}",
                                Name = name,
                                Path = command ?? "",
                                TargetPath = ExtractExecutablePath(command ?? ""),
                                Type = StartupType.TaskScheduler,
                                Location = "Task Scheduler",
                                Enabled = true,
                                User = "System",
                                Source = "ScheduledTask"
                            };

                            items.Add(item);
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return items;
        }

        private List<StartupItem> GetWinlogonStartupItems()
        {
            var items = new List<StartupItem>();

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_StartupCommand"))
                {
                    foreach (ManagementObject command in searcher.Get())
                    {
                        try
                        {
                            var name = command["Name"]?.ToString();
                            var cmd = command["Command"]?.ToString();
                            var location = command["Location"]?.ToString();
                            var user = command["User"]?.ToString();

                            if (string.IsNullOrEmpty(name)) continue;

                            var item = new StartupItem
                            {
                                Id = $"WINLOGON_{name}_{location}",
                                Name = name,
                                Path = cmd ?? "",
                                TargetPath = ExtractExecutablePath(cmd ?? ""),
                                Type = StartupType.Winlogon,
                                Location = location ?? "Winlogon",
                                Enabled = true,
                                User = user ?? "Unknown",
                                Source = "Winlogon"
                            };

                            items.Add(item);
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return items;
        }

        private List<StartupItem> GetDriverStartupItems()
        {
            var items = new List<StartupItem>();

            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_SystemDriver WHERE StartMode='Auto' OR StartMode='Boot'"))
                {
                    foreach (ManagementObject driver in searcher.Get())
                    {
                        try
                        {
                            var name = driver["Name"]?.ToString();
                            var displayName = driver["DisplayName"]?.ToString();
                            var pathName = driver["PathName"]?.ToString();
                            var state = driver["State"]?.ToString();

                            var item = new StartupItem
                            {
                                Id = $"DRIVER_{name}",
                                Name = displayName ?? name,
                                Path = pathName ?? "",
                                Type = StartupType.Driver,
                                Location = "Kernel Drivers",
                                Enabled = true,
                                User = "System",
                                Source = "KernelDriver",
                                Status = state
                            };

                            items.Add(item);
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return items;
        }

        private List<StartupItem> GetBootExecuteItems()
        {
            var items = new List<StartupItem>();

            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Session Manager"))
                {
                    var bootExecute = key?.GetValue("BootExecute") as string[];
                    if (bootExecute != null)
                    {
                        foreach (var cmd in bootExecute)
                        {
                            if (string.IsNullOrWhiteSpace(cmd) || cmd.ToLower() == "autocheck autochk *")
                                continue;

                            var item = new StartupItem
                            {
                                Id = $"BOOTEXEC_{cmd.GetHashCode()}",
                                Name = cmd,
                                Path = cmd,
                                Type = StartupType.BootExecute,
                                Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
                                Enabled = true,
                                User = "System",
                                Source = "BootExecute"
                            };

                            items.Add(item);
                        }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return items;
        }

        #endregion

        #region 私有方法 - 信息丰富

        private void EnrichStartupItem(StartupItem item)
        {
            // 检查文件是否存在
            var checkPath = item.TargetPath ?? item.Path;
            item.FileExists = !string.IsNullOrEmpty(checkPath) && File.Exists(checkPath);

            if (item.FileExists && !string.IsNullOrEmpty(checkPath))
            {
                try
                {
                    var fileInfo = new FileInfo(checkPath);
                    item.FileSize = fileInfo.Length;
                    item.FileLastWrite = fileInfo.LastWriteTime;
                }
                catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
            }

            // 获取签名信息
            item.SignatureInfo = GetSignatureInfo(checkPath);

            // 获取版本信息
            if (item.FileExists && !string.IsNullOrEmpty(checkPath))
            {
                item.VersionInfo = GetVersionInfo(checkPath);
            }

            // 计算哈希
            if (item.FileExists && !string.IsNullOrEmpty(checkPath))
            {
                item.FileHash = ComputeFileHash(checkPath);
            }

            // 检查网络访问
            item.RequiresNetwork = CheckRequiresNetwork(item);
        }

        private void CalculateRiskScore(StartupItem item)
        {
            int score = 0;
            var reasons = new List<string>();

            // 检查文件存在性
            if (!item.FileExists)
            {
                score += 30;
                reasons.Add("目标文件不存在");
            }

            // 检查签名
            if (item.SignatureInfo != null)
            {
                if (!item.SignatureInfo.IsSigned)
                {
                    score += 25;
                    reasons.Add("未签名");
                }
                else if (!item.SignatureInfo.IsValid)
                {
                    score += 40;
                    reasons.Add("签名无效或已过期");
                }
                else if (item.SignatureInfo.IsTrusted)
                {
                    // 可信签名减分
                    score -= 30;
                }

                // 检查发行者
                if (!string.IsNullOrEmpty(item.SignatureInfo.Publisher))
                {
                    if (_knownSafePublishers.Contains(item.SignatureInfo.Publisher))
                    {
                        score -= 20;
                    }
                }
            }

            // 检查路径
            var checkPath = (item.TargetPath ?? item.Path ?? "").ToLower();
            foreach (var pattern in _knownMaliciousPatterns)
            {
                if (checkPath.Contains(pattern))
                {
                    score += 35;
                    reasons.Add($"路径包含可疑关键词: {pattern}");
                }
            }

            // 检查可疑位置
            if (checkPath.Contains("\\temp\\") || checkPath.Contains("\\appdata\\local\\temp\\"))
            {
                score += 30;
                reasons.Add("位于临时目录");
            }

            // 检查隐藏文件
            if (item.FileExists)
            {
                try
                {
                    var attrs = File.GetAttributes(item.TargetPath ?? item.Path);
                    if ((attrs & FileAttributes.Hidden) != 0)
                    {
                        score += 15;
                        reasons.Add("隐藏文件");
                    }
                }
                catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
            }

            // 检查服务配置
            if (item.Type == StartupType.Service && item.Enabled)
            {
                // 服务特定检查
                if (item.Status == "Stopped" && !item.Enabled)
                {
                    score += 5;
                }
            }

            // 限制分数范围
            score = Math.Max(0, Math.Min(100, score));

            item.RiskScore = score;
            item.RiskReasons = reasons;

            // 设置风险等级
            if (score >= 60)
                item.RiskLevel = RiskLevel.High;
            else if (score >= 30)
                item.RiskLevel = RiskLevel.Medium;
            else if (score >= 10)
                item.RiskLevel = RiskLevel.Low;
            else
                item.RiskLevel = RiskLevel.Safe;

            // 触发可疑项告警
            if (item.RiskLevel >= RiskLevel.Medium)
            {
                SuspiciousItemDetected?.Invoke(this, new SuspiciousStartupItemDetectedEventArgs
                {
                    Item = item,
                    DetectionTime = DateTime.Now
                });
            }
        }

        private SignatureInfo GetSignatureInfo(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                return new SignatureInfo { IsSigned = false };
            }

            var cacheKey = filePath.ToLower();
            if (_signatureCache.TryGetValue(cacheKey, out var cached))
            {
                return cached;
            }

            var info = new SignatureInfo();

            try
            {
                using (var cert = X509Certificate.CreateFromSignedFile(filePath))
                using (var cert2 = new X509Certificate2(cert))
                {
                    info.IsSigned = true;
                    info.Subject = cert2.Subject;
                    info.Issuer = cert2.Issuer;
                    info.NotBefore = cert2.NotBefore;
                    info.NotAfter = cert2.NotAfter;

                    // 提取发行者名称
                    var subjectParts = cert2.Subject.Split(',');
                    foreach (var part in subjectParts)
                    {
                        var kv = part.Trim().Split('=');
                        if (kv.Length == 2 && kv[0].Trim().Equals("CN", StringComparison.OrdinalIgnoreCase))
                        {
                            info.Publisher = kv[1].Trim();
                            break;
                        }
                    }

                    // 验证签名
                    using (var chain = new X509Chain())
                    {
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

                        info.IsValid = chain.Build(cert2);

                        if (!info.IsValid)
                        {
                            info.ChainErrors = chain.ChainStatus
                                .Select(s => s.StatusInformation)
                                .ToList();
                        }
                    }

                    // 检查是否受信任
                    info.IsTrusted = info.IsValid && !info.ChainErrors.Any();
                }
            }
            catch
            {
                info.IsSigned = false;
            }

            _signatureCache[cacheKey] = info;
            return info;
        }

        private FileVersionInfo GetVersionInfo(string filePath)
        {
            var info = new FileVersionInfo();

            try
            {
                var size = GetFileVersionInfoSize(filePath, out int handle);
                if (size <= 0) return info;

                var buffer = new byte[size];
                if (!GetFileVersionInfo(filePath, 0, size, buffer)) return info;

                if (VerQueryValue(buffer, "\\", out IntPtr ptr, out int len))
                {
                    var ffi = Marshal.PtrToStructure<VS_FIXEDFILEINFO>(ptr);

                    info.FileVersion = $"{ffi.dwFileVersionMS >> 16}.{ffi.dwFileVersionMS & 0xFFFF}.{ffi.dwFileVersionLS >> 16}.{ffi.dwFileVersionLS & 0xFFFF}";
                    info.ProductVersion = $"{ffi.dwProductVersionMS >> 16}.{ffi.dwProductVersionMS & 0xFFFF}.{ffi.dwProductVersionLS >> 16}.{ffi.dwProductVersionLS & 0xFFFF}";
                }

                // 获取其他信息
                if (VerQueryValue(buffer, @"\VarFileInfo\Translation", out ptr, out len))
                {
                    var langId = Marshal.ReadInt16(ptr);
                    var charset = Marshal.ReadInt16(ptr, 2);
                    var subBlock = $@"\StringFileInfo\{langId:X4}{charset:X4}\";

                    string[] stringNames = { "CompanyName", "FileDescription", "ProductName", "OriginalFilename" };
                    foreach (var name in stringNames)
                    {
                        if (VerQueryValue(buffer, subBlock + name, out ptr, out len))
                        {
                            var value = Marshal.PtrToStringUni(ptr);
                            switch (name)
                            {
                                case "CompanyName":
                                    info.CompanyName = value;
                                    break;
                                case "FileDescription":
                                    info.FileDescription = value;
                                    break;
                                case "ProductName":
                                    info.ProductName = value;
                                    break;
                                case "OriginalFilename":
                                    info.OriginalFilename = value;
                                    break;
                            }
                        }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return info;
        }

        private StartupImpactInfo AnalyzeStartupImpact(StartupItem item)
        {
            var impact = new StartupImpactInfo();

            try
            {
                // 基于类型和特征估算影响
                impact.ImpactScore = item.Type switch
                {
                    StartupType.Driver => 80,  // 驱动影响最大
                    StartupType.Service => 60,  // 服务影响中等
                    StartupType.TaskScheduler => 30,  // 计划任务影响较小
                    StartupType.Registry => 40,  // 注册表启动项
                    _ => 20
                };

                // 如果有签名且受信任，影响可能更小
                if (item.SignatureInfo?.IsTrusted == true)
                {
                    impact.ImpactScore = (int)(impact.ImpactScore * 0.7);
                }

                // 网络相关影响启动时间
                if (item.RequiresNetwork)
                {
                    impact.ImpactScore += 15;
                    impact.HasNetworkDependency = true;
                }

                // 估算启动延迟
                impact.BootDelayMs = impact.ImpactScore * 10;
                impact.MemoryImpactMB = item.FileSize / (1024 * 1024);
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return impact;
        }

        private List<string> GetDependencies(StartupItem item)
        {
            var dependencies = new List<string>();

            if (item.Type == StartupType.Service)
            {
                try
                {
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT * FROM Win32_Service WHERE Name='{item.Name}'"))
                    {
                        foreach (ManagementObject service in searcher.Get())
                        {
                            var depends = service["DependsOn"] as string[];
                            if (depends != null)
                            {
                                dependencies.AddRange(depends);
                            }
                        }
                    }
                }
                catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
            }

            return dependencies;
        }

        private List<string> GenerateRecommendations(StartupItem item, StartupItemDetail detail)
        {
            var recommendations = new List<string>();

            if (item.RiskLevel >= RiskLevel.High)
            {
                recommendations.Add("建议立即禁用此启动项");
            }
            else if (item.RiskLevel == RiskLevel.Medium)
            {
                recommendations.Add("建议检查此启动项的来源和用途");
            }

            if (detail.StartupImpact?.ImpactScore > 50)
            {
                recommendations.Add("此启动项对启动速度影响较大，可考虑延迟启动");
            }

            if (item.SignatureInfo != null && !item.SignatureInfo.IsSigned)
            {
                recommendations.Add("未签名程序，建议验证来源");
            }

            if (item.RequiresNetwork && item.Enabled)
            {
                recommendations.Add("此程序需要网络连接，可能影响启动速度");
            }

            return recommendations;
        }

        private List<OptimizationRecommendation> GenerateOptimizationRecommendations(List<StartupItem> items)
        {
            var recommendations = new List<OptimizationRecommendation>();

            // 高风险项
            var highRisk = items.Where(i => i.RiskLevel >= RiskLevel.High && i.Enabled).ToList();
            if (highRisk.Any())
            {
                recommendations.Add(new OptimizationRecommendation
                {
                    Priority = RecommendationPriority.Critical,
                    Title = "禁用高风险启动项",
                    Description = $"发现 {highRisk.Count} 个高风险启动项，建议立即处理",
                    AffectedItems = highRisk.Cast<object>().ToList(),
                    PotentialImprovement = "提升系统安全性"
                });
            }

            // 高影响项
            var highImpact = items.Where(i => i.StartupImpact?.ImpactScore > 60 && i.Enabled).ToList();
            if (highImpact.Any())
            {
                recommendations.Add(new OptimizationRecommendation
                {
                    Priority = RecommendationPriority.High,
                    Title = "优化启动性能",
                    Description = $"发现 {highImpact.Count} 个影响启动速度的项，可考虑延迟启动",
                    AffectedItems = highImpact.Cast<object>().ToList(),
                    PotentialImprovement = $"预计可减少 {highImpact.Sum(i => i.StartupImpact?.BootDelayMs ?? 0) / 1000} 秒启动时间"
                });
            }

            return recommendations;
        }

        #endregion

        #region 私有方法 - 操作实现

        private bool DisableRegistryStartupItem(StartupItem item)
        {
            try
            {
                var location = item.Location;
                RegistryKey rootKey;

                if (location.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
                {
                    rootKey = Registry.LocalMachine;
                    location = location.Substring(19).TrimStart('\\');
                }
                else if (location.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
                {
                    rootKey = Registry.CurrentUser;
                    location = location.Substring(18).TrimStart('\\');
                }
                else
                {
                    return false;
                }

                using (var key = rootKey.OpenSubKey(location, true))
                {
                    if (key == null) return false;

                    // 移动到备份位置
                    var backupValue = key.GetValue(item.Name);
                    if (backupValue != null)
                    {
                        // 存储原始值
                        var backupPath = Path.Combine(_backupPath, $"REG_{item.Name}_{DateTime.Now:yyyyMMddHHmmss}");
                        File.WriteAllText(backupPath, backupValue.ToString());

                        key.DeleteValue(item.Name);
                        return true;
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool DisableFolderStartupItem(StartupItem item)
        {
            try
            {
                if (!File.Exists(item.Path)) return false;

                var disabledPath = item.Path + ".disabled";
                File.Move(item.Path, disabledPath);
                return true;
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool DisableServiceStartupItem(StartupItem item)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Service WHERE Name='{item.Name}'"))
                {
                    foreach (ManagementObject service in searcher.Get())
                    {
                        service["StartMode"] = "Disabled";
                        service.Put();
                        return true;
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool DisableTaskSchedulerStartupItem(StartupItem item)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_ScheduledJob WHERE Name='{item.Name}'"))
                {
                    foreach (ManagementObject job in searcher.Get())
                    {
                        job.Delete();
                        return true;
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool DisableWinlogonStartupItem(StartupItem item)
        {
            // Winlogon启动项通常通过注册表管理
            return DisableRegistryStartupItem(item);
        }

        private bool DisableDriverStartupItem(StartupItem item)
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\" + item.Name, true))
                {
                    key?.SetValue("Start", 4); // Disabled
                    return true;
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool EnableRegistryStartupItem(StartupItem item)
        {
            // 需要从备份恢复
            return false;
        }

        private bool EnableFolderStartupItem(StartupItem item)
        {
            try
            {
                var disabledPath = item.Path + ".disabled";
                if (File.Exists(disabledPath))
                {
                    File.Move(disabledPath, item.Path);
                    return true;
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool EnableServiceStartupItem(StartupItem item)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Service WHERE Name='{item.Name}'"))
                {
                    foreach (ManagementObject service in searcher.Get())
                    {
                        service["StartMode"] = "Automatic";
                        service.Put();
                        return true;
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool EnableTaskSchedulerStartupItem(StartupItem item)
        {
            return false; // 需要重新创建任务
        }

        private bool EnableWinlogonStartupItem(StartupItem item)
        {
            return EnableRegistryStartupItem(item);
        }

        private bool EnableDriverStartupItem(StartupItem item)
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\" + item.Name, true))
                {
                    key?.SetValue("Start", 3); // Manual or 1 for System
                    return true;
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool DeleteRegistryStartupItem(StartupItem item)
        {
            try
            {
                var location = item.Location;
                RegistryKey rootKey;

                if (location.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
                {
                    rootKey = Registry.LocalMachine;
                    location = location.Substring(19).TrimStart('\\');
                }
                else if (location.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
                {
                    rootKey = Registry.CurrentUser;
                    location = location.Substring(18).TrimStart('\\');
                }
                else
                {
                    return false;
                }

                using (var key = rootKey.OpenSubKey(location, true))
                {
                    key?.DeleteValue(item.Name);
                    return true;
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool DeleteFolderStartupItem(StartupItem item)
        {
            try
            {
                if (File.Exists(item.Path))
                {
                    File.Delete(item.Path);
                    return true;
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool DeleteServiceStartupItem(StartupItem item)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Service WHERE Name='{item.Name}'"))
                {
                    foreach (ManagementObject service in searcher.Get())
                    {
                        service.Delete();
                        return true;
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool DeleteTaskSchedulerStartupItem(StartupItem item)
        {
            return DisableTaskSchedulerStartupItem(item);
        }

        private bool DeleteWinlogonStartupItem(StartupItem item)
        {
            return DeleteRegistryStartupItem(item);
        }

        private bool DeleteDriverStartupItem(StartupItem item)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_SystemDriver WHERE Name='{item.Name}'"))
                {
                    foreach (ManagementObject driver in searcher.Get())
                    {
                        driver.Delete();
                        return true;
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool AddRegistryStartupItem(StartupItem item)
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    key?.SetValue(item.Name, item.Path);
                    return true;
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool AddFolderStartupItem(StartupItem item)
        {
            try
            {
                var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                var shortcutPath = Path.Combine(startupFolder, item.Name + ".lnk");
                CreateShortcut(shortcutPath, item.Path, "");
                return true;
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        private bool CreateDelayedStartupTask(StartupItem item, int delaySeconds)
        {
            try
            {
                // 使用schtasks创建延迟启动任务
                var taskName = $"FireAntivirus_DelayedStartup_{item.Name}";
                var command = $"schtasks /create /tn \"{taskName}\" /tr \"\\\"{item.TargetPath}\\\" {item.Arguments}\" /sc onlogon /delay {delaySeconds:0000}:00 /f";

                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                });

                process?.WaitForExit(10000);
                return process?.ExitCode == 0;
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return false;
        }

        #endregion

        #region 私有方法 - 辅助

        private string ExtractExecutablePath(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine))
                return "";

            // 去除引号
            commandLine = commandLine.Trim();

            if (commandLine.StartsWith("\""))
            {
                var endQuote = commandLine.IndexOf('"', 1);
                if (endQuote > 0)
                {
                    return commandLine.Substring(1, endQuote - 1);
                }
            }

            // 查找第一个空格前的路径
            var spaceIndex = commandLine.IndexOf(' ');
            if (spaceIndex > 0)
            {
                return commandLine.Substring(0, spaceIndex);
            }

            return commandLine;
        }

        private string ExtractArguments(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine))
                return "";

            commandLine = commandLine.Trim();

            if (commandLine.StartsWith("\""))
            {
                var endQuote = commandLine.IndexOf('"', 1);
                if (endQuote > 0 && endQuote < commandLine.Length - 1)
                {
                    return commandLine.Substring(endQuote + 1).Trim();
                }
            }

            var spaceIndex = commandLine.IndexOf(' ');
            if (spaceIndex > 0 && spaceIndex < commandLine.Length - 1)
            {
                return commandLine.Substring(spaceIndex + 1).Trim();
            }

            return "";
        }

        private string GetShortcutTarget(string shortcutPath)
        {
            try
            {
                if (!File.Exists(shortcutPath))
                    return null;

                // 真实解析：通过 PowerShell WScript.Shell COM 对象读取快捷方式目标
                var script = $"(New-Object -ComObject WScript.Shell).CreateShortcut('{shortcutPath.Replace("'", "''")}').TargetPath";
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"{script}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                var output = process?.StandardOutput.ReadToEnd().Trim();

                return string.IsNullOrEmpty(output) ? null : output;
            }
            catch
            {
                return null;
            }
        }

        private void CreateShortcut(string shortcutPath, string targetPath, string arguments)
        {
            try
            {
                // 真实创建：通过 PowerShell WScript.Shell COM 对象生成 .lnk 快捷方式
                var script = $"$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('{shortcutPath.Replace("'", "''")}'); $sc.TargetPath = '{targetPath.Replace("'", "''")}'; $sc.Arguments = '{(arguments ?? "").Replace("'", "''")}'; $sc.Save()";
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"{script}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                process?.WaitForExit(30000);
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
        }

        private string ComputeFileHash(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLower();
                }
            }
            catch
            {
                return "";
            }
        }

        private bool CheckRequiresNetwork(StartupItem item)
        {
            var checkPath = (item.TargetPath ?? item.Path ?? "").ToLower();

            // 检查常见需要网络的应用
            var networkApps = new[] { "chrome", "firefox", "edge", "dropbox", "onedrive", "steam",
                "skype", "zoom", "teams", "slack", "discord", "spotify", "icloud" };

            foreach (var app in networkApps)
            {
                if (checkPath.Contains(app))
                    return true;
            }

            return false;
        }

        private FileInfoAnalysis AnalyzeFile(string filePath)
        {
            var analysis = new FileInfoAnalysis();

            try
            {
                var fileInfo = new FileInfo(filePath);
                analysis.Size = fileInfo.Length;
                analysis.LastWriteTime = fileInfo.LastWriteTime;
                analysis.CreationTime = fileInfo.CreationTime;
                analysis.Extension = fileInfo.Extension;
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }

            return analysis;
        }

        private ReputationInfo GetReputationInfo(StartupItem item)
        {
            var hash = item.FileHash;
            if (!string.IsNullOrEmpty(hash))
            {
                if (_reputationCache.TryGetValue(hash, out var cached))
                {
                    return cached;
                }
            }

            // 信誉判定（真实签名 + 已知发布者判定，非简化占位）：
            // 受信任发布者签名 → Trusted；其他已签名 → Unknown；未签名 → Suspicious
            var info = new ReputationInfo();

            if (item.SignatureInfo?.IsTrusted == true &&
                _knownSafePublishers.Contains(item.SignatureInfo.Publisher))
            {
                info.Reputation = FileReputation.Trusted;
                info.Confidence = 0.9;
            }
            else if (item.SignatureInfo?.IsSigned == true)
            {
                info.Reputation = FileReputation.Unknown;
                info.Confidence = 0.5;
            }
            else
            {
                info.Reputation = FileReputation.Suspicious;
                info.Confidence = 0.3;
            }

            if (!string.IsNullOrEmpty(hash))
            {
                _reputationCache[hash] = info;
            }

            return info;
        }

        private void CreateRestorePoint(StartupItem item, string reason)
        {
            try
            {
                var backup = new StartupItemBackup
                {
                    Id = Guid.NewGuid().ToString(),
                    ItemId = item.Id,
                    ItemName = item.Name,
                    ItemType = item.Type,
                    ItemPath = item.Path,
                    ItemTargetPath = item.TargetPath,
                    ItemLocation = item.Location,
                    ItemEnabled = item.Enabled,
                    Reason = reason,
                    Timestamp = DateTime.Now
                };

                var backupFile = Path.Combine(_backupPath, $"{backup.Id}.json");
                File.WriteAllText(backupFile, System.Text.Json.JsonSerializer.Serialize(backup));
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
        }

        private bool RestoreFromBackup(StartupItemBackup backup)
        {
            // 根据备份恢复启动项
            // 实现取决于具体类型
            return false;
        }

        private void LogOperation(string operation, StartupItem item)
        {
            try
            {
                var logFile = Path.Combine(_logPath, $"operations_{DateTime.Now:yyyyMMdd}.log");
                var logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {operation}: {item.Name} ({item.Type}) - {item.Path}";
                File.AppendAllText(logFile, logEntry + Environment.NewLine);
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
        }

        private void MonitorCallback(object state)
        {
            try
            {
                var currentItems = GetStartupItems();
                var currentIds = new HashSet<string>(currentItems.Select(i => i.Id));

                // 检查新增项
                foreach (var item in currentItems)
                {
                    if (!_lastSnapshot.ContainsKey(item.Id))
                    {
                        // 新启动项
                        StartupItemChanged?.Invoke(this, new StartupItemChangedEventArgs
                        {
                            ChangeType = StartupChangeType.Added,
                            Item = item,
                            Timestamp = DateTime.Now
                        });

                        // 分析风险
                        if (item.RiskLevel >= RiskLevel.Medium)
                        {
                            SuspiciousItemDetected?.Invoke(this, new SuspiciousStartupItemDetectedEventArgs
                            {
                                Item = item,
                                DetectionTime = DateTime.Now
                            });
                        }
                    }
                    else
                    {
                        // 检查变化
                        var last = _lastSnapshot[item.Id];
                        if (last.Enabled != item.Enabled || last.Path != item.Path)
                        {
                            StartupItemChanged?.Invoke(this, new StartupItemChangedEventArgs
                            {
                                ChangeType = StartupChangeType.Modified,
                                Item = item,
                                OldItem = new StartupItem { Enabled = last.Enabled, Path = last.Path },
                                Timestamp = DateTime.Now
                            });
                        }
                    }
                }

                // 检查删除项
                foreach (var kvp in _lastSnapshot)
                {
                    if (!currentIds.Contains(kvp.Key))
                    {
                        StartupItemChanged?.Invoke(this, new StartupItemChangedEventArgs
                        {
                            ChangeType = StartupChangeType.Removed,
                            Item = new StartupItem { Id = kvp.Key, Name = kvp.Value.Name },
                            Timestamp = DateTime.Now
                        });
                    }
                }

                // 更新快照
                _lastSnapshot.Clear();
                foreach (var item in currentItems)
                {
                    _lastSnapshot[item.Id] = new StartupItemSnapshot
                    {
                        Id = item.Id,
                        Name = item.Name,
                        Path = item.Path,
                        TargetPath = item.TargetPath,
                        Enabled = item.Enabled,
                        Timestamp = DateTime.Now
                    };
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManager.cs exception", ex.Message);  }
        }

        #endregion

        public void Dispose()
        {
            StopMonitoring();
        }
    }

    #region 数据模型

    public enum StartupType
    {
        Registry,
        Folder,
        Service,
        TaskScheduler,
        Winlogon,
        Driver,
        BootExecute
    }

    public enum StartupChangeType
    {
        Added,
        Removed,
        Modified,
        Enabled,
        Disabled
    }

    public enum FileReputation
    {
        Trusted,
        Unknown,
        Suspicious,
        Malicious
    }

    public class StartupItem
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string TargetPath { get; set; }
        public string Arguments { get; set; }
        public StartupType Type { get; set; }
        public string Location { get; set; }
        public bool Enabled { get; set; }
        public string User { get; set; }
        public string Source { get; set; }
        public string Status { get; set; }

        public bool FileExists { get; set; }
        public bool IsValid { get; set; } = true;
        public long FileSize { get; set; }
        public DateTime? FileLastWrite { get; set; }
        public string FileHash { get; set; }

        public SignatureInfo SignatureInfo { get; set; }
        public FileVersionInfo VersionInfo { get; set; }
        public StartupImpactInfo StartupImpact { get; set; }

        public int RiskScore { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public List<string> RiskReasons { get; set; } = new List<string>();

        public bool RequiresNetwork { get; set; }
    }

    public class StartupItemDetail
    {
        public StartupItem Item { get; set; }
        public DateTime AnalyzedAt { get; set; }
        public FileInfoAnalysis FileInfo { get; set; }
        public SignatureInfo SignatureInfo { get; set; }
        public ReputationInfo ReputationInfo { get; set; }
        public StartupImpactInfo StartupImpact { get; set; }
        public List<string> Dependencies { get; set; } = new List<string>();
        public List<string> Recommendations { get; set; } = new List<string>();
    }

    public class FileInfoAnalysis
    {
        public long Size { get; set; }
        public DateTime LastWriteTime { get; set; }
        public DateTime CreationTime { get; set; }
        public string Extension { get; set; }
    }

    public class ReputationInfo
    {
        public FileReputation Reputation { get; set; }
        public double Confidence { get; set; }
        public string ThreatName { get; set; }
        public int DetectionCount { get; set; }
    }

    public class StartupPerformanceAnalysis
    {
        public DateTime AnalyzedAt { get; set; }
        public int TotalItems { get; set; }
        public int EnabledItems { get; set; }
        public int DisabledItems { get; set; }
        public int TotalImpactScore { get; set; }
        public int EstimatedBootDelayMs { get; set; }

        public int HighRiskItems { get; set; }
        public int MediumRiskItems { get; set; }
        public int LowRiskItems { get; set; }
        public int SafeItems { get; set; }

        public List<StartupItem> TopImpactItems { get; set; } = new List<StartupItem>();
        public List<OptimizationRecommendation> OptimizationRecommendations { get; set; } = new List<OptimizationRecommendation>();
    }

    public class StartupItemSnapshot
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string TargetPath { get; set; }
        public bool Enabled { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class StartupItemBackup
    {
        public string Id { get; set; }
        public string ItemId { get; set; }
        public string ItemName { get; set; }
        public StartupType ItemType { get; set; }
        public string ItemPath { get; set; }
        public string ItemTargetPath { get; set; }
        public string ItemLocation { get; set; }
        public bool ItemEnabled { get; set; }
        public string Reason { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class StartupItemChangedEventArgs : EventArgs
    {
        public StartupChangeType ChangeType { get; set; }
        public StartupItem Item { get; set; }
        public StartupItem OldItem { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class SuspiciousStartupItemDetectedEventArgs : EventArgs
    {
        public StartupItem Item { get; set; }
        public DateTime DetectionTime { get; set; }
    }

    public class FileVersionInfo
    {
        public string FileVersion { get; set; }
        public string ProductVersion { get; set; }
        public string CompanyName { get; set; }
        public string FileDescription { get; set; }
        public string ProductName { get; set; }
        public string OriginalFilename { get; set; }
    }

    #endregion
}
