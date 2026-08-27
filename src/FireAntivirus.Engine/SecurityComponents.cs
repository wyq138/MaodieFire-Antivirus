// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace FireAntivirus.Engine
{
    /// <summary>
    /// 恶意软件分析器 - 深度分析恶意软件特征
    /// </summary>
    public class MalwareAnalyzer
    {
        private readonly Dictionary<string, MalwareFamily> _malwareFamilies;
        
        public MalwareAnalyzer()
        {
            _malwareFamilies = InitializeMalwareFamilies();
        }

        /// <summary>
        /// 恶意软件家族特征从外部 JSON 加载（见 ThreatData/malware_families.json），
        /// 不编译进 DLL，既消除杀软误报，也便于程序自动更新特征库覆盖变种。
        /// </summary>
        private Dictionary<string, MalwareFamily> InitializeMalwareFamilies()
        {
            ExternalThreatData.EnsureLoaded();
            var families = new Dictionary<string, MalwareFamily>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in ExternalThreatData.MalwareFamilies)
            {
                var key = string.IsNullOrEmpty(entry.Key) ? entry.Name : entry.Key;
                families[key] = new MalwareFamily
                {
                    Name = entry.Name,
                    Type = entry.Type,
                    Patterns = entry.Patterns ?? Array.Empty<string>(),
                    FileExtensions = entry.FileExtensions,
                    RiskLevel = entry.RiskLevel
                };
            }
            return families;
        }
        
        public MalwareAnalysisResult Analyze(string filePath)
        {
            var result = new MalwareAnalysisResult
            {
                FilePath = filePath,
                IsMalware = false,
                Family = "Unknown",
                RiskLevel = "Low"
            };
            
            if (!File.Exists(filePath)) return result;
            
            try
            {
                var fileContent = File.ReadAllBytes(filePath);
                var fileText = Encoding.UTF8.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));
                var extension = Path.GetExtension(filePath);
                
                foreach (var family in _malwareFamilies.Values)
                {
                    bool matched = false;
                    
                    // 检查模式
                    foreach (var pattern in family.Patterns)
                    {
                        if (fileText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            matched = true;
                            result.MatchedPatterns.Add(pattern);
                        }
                    }
                    
                    // 检查文件扩展名
                    if (family.FileExtensions != null)
                    {
                        foreach (var ext in family.FileExtensions)
                        {
                            if (extension.Equals(ext, StringComparison.OrdinalIgnoreCase))
                            {
                                matched = true;
                                result.MatchedExtensions.Add(ext);
                            }
                        }
                    }
                    
                    if (matched)
                    {
                        result.IsMalware = true;
                        result.Family = family.Name;
                        result.Type = family.Type;
                        result.RiskLevel = family.RiskLevel;
                        result.Confidence += 0.3;
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            
            return result;
        }
    }
    
    /// <summary>
    /// 系统优化器 - 清理系统垃圾和优化性能
    /// </summary>
    public class SystemOptimizer
    {
        public OptimizationResult CleanTempFiles()
        {
            var result = new OptimizationResult { Items = new List<CleanupItem>() };
            
            var tempPaths = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch")
            };
            
            foreach (var tempPath in tempPaths)
            {
                if (Directory.Exists(tempPath))
                {
                    try
                    {
                        var files = Directory.GetFiles(tempPath, "*.*", SearchOption.TopDirectoryOnly);
                        foreach (var file in files)
                        {
                            try
                            {
                                var fileInfo = new FileInfo(file);
                                if (fileInfo.LastAccessTime < DateTime.Now.AddDays(-7))
                                {
                                    result.Items.Add(new CleanupItem
                                    {
                                        Path = file,
                                        Size = fileInfo.Length,
                                        Type = "TempFile"
                                    });
                                }
                            }
                            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
                }
            }
            
            result.TotalSize = result.Items.Sum(i => i.Size);
            return result;
        }
        
        public List<string> GetStartupItems()
        {
            var items = new List<string>();
            
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (key != null)
                    {
                        foreach (var name in key.GetValueNames())
                        {
                            items.Add($"HKCU\\Run\\{name}");
                        }
                    }
                }
                
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (key != null)
                    {
                        foreach (var name in key.GetValueNames())
                        {
                            items.Add($"HKLM\\Run\\{name}");
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            
            return items;
        }
    }
    
    /// <summary>
    /// 威胁猎手 - 主动搜索潜在威胁
    /// </summary>
    public class ThreatHunter
    {
        private readonly MalwareAnalyzer _malwareAnalyzer;
        private readonly List<string> _suspiciousProcesses;
        
        public ThreatHunter()
        {
            _malwareAnalyzer = new MalwareAnalyzer();
            // 可疑进程名从外部 JSON 加载（见 ThreatData/suspicious_processes.json），避免内嵌恶意字符串
            ExternalThreatData.EnsureLoaded();
            _suspiciousProcesses = ExternalThreatData.SuspiciousProcesses
                .Select(p => p.Name)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        
        public List<ThreatHuntResult> HuntThreats()
        {
            var results = new List<ThreatHuntResult>();
            
            // 搜索可疑进程
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var procName = proc.ProcessName.ToLower();
                    foreach (var suspicious in _suspiciousProcesses)
                    {
                        if (procName.Contains(suspicious))
                        {
                            results.Add(new ThreatHuntResult
                            {
                                Type = "SuspiciousProcess",
                                Name = proc.ProcessName,
                                Path = proc.MainModule?.FileName ?? "Unknown",
                                RiskLevel = "High"
                            });
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            }
            
            // 搜索可疑文件
            var suspiciousPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.GetTempPath()
            };
            
            foreach (var searchPath in suspiciousPaths)
            {
                if (Directory.Exists(searchPath))
                {
                    try
                    {
                        foreach (var file in Directory.GetFiles(searchPath, "*.exe", SearchOption.TopDirectoryOnly))
                        {
                            var analysis = _malwareAnalyzer.Analyze(file);
                            if (analysis.IsMalware)
                            {
                                results.Add(new ThreatHuntResult
                                {
                                    Type = "MalwareFile",
                                    Name = Path.GetFileName(file),
                                    Path = file,
                                    RiskLevel = analysis.RiskLevel
                                });
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
                }
            }
            
            return results;
        }
    }
    
    /// <summary>
    /// 事件响应器 - 自动响应安全事件
    /// </summary>
    public class IncidentResponder
    {
        public ResponseResult Respond(ThreatHuntResult threat)
        {
            var result = new ResponseResult { Success = false };
            
            try
            {
                switch (threat.Type)
                {
                    case "SuspiciousProcess":
                        var proc = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(threat.Path)).FirstOrDefault();
                        if (proc != null)
                        {
                            proc.Kill();
                            result.Actions.Add($"终止进程: {proc.ProcessName}");
                        }
                        break;
                        
                    case "MalwareFile":
                        if (File.Exists(threat.Path))
                        {
                            var quarantinePath = Path.Combine(
                                Path.GetTempPath(), 
                                "Quarantine", 
                                $"{Guid.NewGuid()}.{Path.GetExtension(threat.Path)}"
                            );
                            Directory.CreateDirectory(Path.GetDirectoryName(quarantinePath));
                            File.Move(threat.Path, quarantinePath);
                            result.Actions.Add($"隔离文件: {threat.Path}");
                        }
                        break;
                }
                
                result.Success = true;
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }
            
            return result;
        }
    }
    
    /// <summary>
    /// 取证分析器 - 收集和分析数字证据
    /// </summary>
    public class ForensicAnalyzer
    {
        public ForensicResult AnalyzeFile(string filePath)
        {
            var result = new ForensicResult { FilePath = filePath };
            
            if (!File.Exists(filePath)) return result;
            
            try
            {
                var fileInfo = new FileInfo(filePath);
                
                result.CreationTime = fileInfo.CreationTime;
                result.LastWriteTime = fileInfo.LastWriteTime;
                result.LastAccessTime = fileInfo.LastAccessTime;
                result.FileSize = fileInfo.Length;
                result.FileHash = ComputeHash(filePath);
                result.Attributes = fileInfo.Attributes.ToString();
                
                // 检查文件签名
                result.Signature = GetFileSignature(filePath);
                
                // 检查替代数据流
                result.AlternateDataStreams = GetAlternateDataStreams(filePath);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            
            return result;
        }
        
        private string ComputeHash(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            catch { return ""; }
        }
        
        private string GetFileSignature(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var header = new byte[4];
                stream.Read(header, 0, 4);
                return BitConverter.ToString(header).Replace("-", " ");
            }
            catch { return ""; }
        }
        
        private List<string> GetAlternateDataStreams(string filePath)
        {
            var streams = new List<string>();
            try
            {
                var fileInfo = new FileInfo(filePath);
                var dir = fileInfo.DirectoryName;
                var name = fileInfo.Name;

                using (var p = new System.Diagnostics.Process())
                {
                    p.StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c dir /R \"{dir}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true
                    };
                    p.Start();
                    var output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();

                    // 解析形如 "file:stream:$DATA" 的 ADS 条目
                    foreach (var line in output.Split('\n'))
                    {
                        var idx = line.IndexOf(":", StringComparison.Ordinal);
                        if (idx <= 0) continue;
                        var colon = line.IndexOf(":", idx + 1, StringComparison.Ordinal);
                        if (colon <= idx) continue;
                        var streamName = line.Substring(idx + 1, colon - idx - 1);
                        var baseName = line.Substring(0, idx).Trim();
                        if (string.IsNullOrEmpty(streamName) || streamName == "$DATA") continue;
                        if (string.Equals(baseName, name, StringComparison.OrdinalIgnoreCase) ||
                            baseName.StartsWith(filePath, StringComparison.OrdinalIgnoreCase))
                        {
                            streams.Add(baseName + streamName);
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            return streams;
        }
    }
    
    /// <summary>
    /// 恶意软件移除器 - 彻底清除恶意软件
    /// </summary>
    public class MalwareRemover
    {
        public RemovalResult Remove(string filePath)
        {
            var result = new RemovalResult { Success = false };
            
            if (!File.Exists(filePath)) return result;
            
            try
            {
                // 1. 终止相关进程
                var fileName = Path.GetFileNameWithoutExtension(filePath);
                var procs = Process.GetProcessesByName(fileName);
                foreach (var proc in procs)
                {
                    try
                    {
                        proc.Kill();
                        result.Actions.Add($"终止进程: {proc.ProcessName}");
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
                }
                
                // 2. 备份文件到隔离区
                var quarantinePath = Path.Combine(Path.GetTempPath(), "Quarantine", $"{Guid.NewGuid()}.quar");
                Directory.CreateDirectory(Path.GetDirectoryName(quarantinePath));
                File.Copy(filePath, quarantinePath);
                result.QuarantinePath = quarantinePath;
                result.Actions.Add($"备份到隔离区: {quarantinePath}");
                
                // 3. 删除原文件
                File.Delete(filePath);
                result.Actions.Add($"删除文件: {filePath}");
                
                // 4. 清理注册表
                RemoveRegistryEntries(fileName, result);
                
                result.Success = true;
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }
            
            return result;
        }
        
        private void RemoveRegistryEntries(string fileName, RemovalResult result)
        {
            var runKeys = new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
            };
            
            foreach (var keyPath in runKeys)
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath, true);
                    if (key != null)
                    {
                        foreach (var name in key.GetValueNames())
                        {
                            var value = key.GetValue(name)?.ToString() ?? "";
                            if (value.Contains(fileName, StringComparison.OrdinalIgnoreCase))
                            {
                                key.DeleteValue(name);
                                result.Actions.Add($"删除注册表项: HKCU\\{keyPath}\\{name}");
                            }
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            }
        }
    }
    
    /// <summary>
    /// 系统恢复器 - 恢复被恶意软件修改的系统设置
    /// </summary>
    public class SystemRestorer
    {
        public RestoreResult RestoreSystemSettings()
        {
            var result = new RestoreResult { Success = true };
            
            try
            {
                // 恢复Hosts文件
                RestoreHostsFile(result);
                
                // 恢复Windows防火墙设置
                RestoreFirewallSettings(result);
                
                // 恢复Windows Update设置
                RestoreWindowsUpdateSettings(result);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            
            return result;
        }
        
        private void RestoreHostsFile(RestoreResult result)
        {
            try
            {
                var hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
                if (File.Exists(hostsPath))
                {
                    var content = File.ReadAllText(hostsPath);
                    var lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    var cleanLines = lines.Where(l => !l.Contains("# Malware") && !l.Contains("# Redirect")).ToList();
                    
                    if (lines.Length != cleanLines.Count)
                    {
                        File.WriteAllLines(hostsPath, cleanLines);
                        result.Actions.Add("清理Hosts文件");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
        }
        
        private void RestoreFirewallSettings(RestoreResult result)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", 
                    true);
                if (key != null)
                {
                    var enableFirewall = key.GetValue("EnableFirewall") as int? ?? 0;
                    if (enableFirewall == 0)
                    {
                        key.SetValue("EnableFirewall", 1);
                        result.Actions.Add("启用Windows防火墙");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
        }
        
        private void RestoreWindowsUpdateSettings(RestoreResult result)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", 
                    true);
                if (key != null)
                {
                    var noAutoUpdate = key.GetValue("NoAutoUpdate") as int? ?? 0;
                    if (noAutoUpdate == 1)
                    {
                        key.SetValue("NoAutoUpdate", 0);
                        result.Actions.Add("启用Windows自动更新");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
        }
    }
    
    /// <summary>
    /// 备份分析器 - 分析系统备份状态
    /// </summary>
    public class BackupAnalyzer
    {
        public BackupAnalysisResult AnalyzeBackups()
        {
            var result = new BackupAnalysisResult();
            
            try
            {
                // 检查Windows备份
                CheckWindowsBackup(result);
                
                // 检查系统还原点
                CheckSystemRestorePoints(result);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            
            return result;
        }
        
        private void CheckWindowsBackup(BackupAnalysisResult result)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsBackup");
                if (key != null)
                {
                    result.HasWindowsBackup = true;
                    result.BackupLocations.Add("Windows Backup已配置");
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
        }
        
        private void CheckSystemRestorePoints(BackupAnalysisResult result)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ShadowCopy");
                var shadows = searcher.Get();
                result.RestorePointCount = shadows.Count;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
        }
    }
    
    /// <summary>
    /// 完整性验证器 - 验证系统文件完整性
    /// </summary>
    public class IntegrityVerifier
    {
        private readonly Dictionary<string, string> _systemFileHashes;
        
        public IntegrityVerifier()
        {
            _systemFileHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            LoadKnownHashes();
        }
        
        private void LoadKnownHashes()
        {
            // 动态加载系统文件哈希
            var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            var criticalFiles = new[] { "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll" };
            
            foreach (var file in criticalFiles)
            {
                var path = Path.Combine(system32, file);
                if (File.Exists(path))
                {
                    try
                    {
                        using var sha256 = SHA256.Create();
                        using var stream = File.OpenRead(path);
                        var hash = sha256.ComputeHash(stream);
                        _systemFileHashes[file] = BitConverter.ToString(hash).Replace("-", "").ToLower();
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
                }
            }
        }
        
        public List<IntegrityResult> VerifySystemFiles()
        {
            var results = new List<IntegrityResult>();
            var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            
            foreach (var kvp in _systemFileHashes)
            {
                var path = Path.Combine(system32, kvp.Key);
                if (File.Exists(path))
                {
                    try
                    {
                        using var sha256 = SHA256.Create();
                        using var stream = File.OpenRead(path);
                        var hash = sha256.ComputeHash(stream);
                        var currentHash = BitConverter.ToString(hash).Replace("-", "").ToLower();
                        
                        results.Add(new IntegrityResult
                        {
                            FilePath = path,
                            OriginalHash = kvp.Value,
                            CurrentHash = currentHash,
                            IsIntact = currentHash == kvp.Value
                        });
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
                }
            }
            
            return results;
        }
    }
    
    /// <summary>
    /// 沙箱分析器 - 在隔离环境中分析文件行为
    /// </summary>
    public class SandboxAnalyzer
    {
        public SandboxResult Analyze(string filePath)
        {
            var result = new SandboxResult
            {
                FilePath = filePath,
                Behaviors = new List<string>()
            };
            
            if (!File.Exists(filePath)) return result;
            
            try
            {
                var fileBytes = File.ReadAllBytes(filePath);
                var fileText = Encoding.UTF8.GetString(fileBytes, 0, Math.Min(fileBytes.Length, 100000));
                
                // 静态行为分析（基于特征码的沙箱行为检测）
                
                // 检查进程注入行为
                if (fileText.Contains("CreateRemoteThread") || fileText.Contains("WriteProcessMemory"))
                {
                    result.Behaviors.Add("Process Injection");
                    result.RiskScore += 30;
                }
                
                // 检查注册表持久化
                if (fileText.Contains("CurrentVersion\\Run") || fileText.Contains("RunOnce"))
                {
                    result.Behaviors.Add("Registry Persistence");
                    result.RiskScore += 20;
                }
                
                // 检查网络通信
                if (fileText.Contains("HttpWebRequest") || fileText.Contains("WebClient") || fileText.Contains("Socket"))
                {
                    result.Behaviors.Add("Network Communication");
                    result.RiskScore += 15;
                }
                
                // 检查文件加密
                if (fileText.Contains("CryptEncrypt") || fileText.Contains("Aes.Create"))
                {
                    result.Behaviors.Add("File Encryption");
                    result.RiskScore += 25;
                }
                
                // 检查反调试
                if (fileText.Contains("IsDebuggerPresent") || fileText.Contains("CheckRemoteDebuggerPresent"))
                {
                    result.Behaviors.Add("Anti-Debug");
                    result.RiskScore += 20;
                }
                
                // 检查虚拟机检测
                if (fileText.Contains("VirtualBox") || fileText.Contains("VMware") || fileText.Contains("Sandbox"))
                {
                    result.Behaviors.Add("VM Detection");
                    result.RiskScore += 15;
                }
                
                result.IsMalicious = result.RiskScore >= 50;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            
            return result;
        }
    }
    
    /// <summary>
    /// 机器学习检测器 - 基于特征向量的威胁检测
    /// </summary>
    public class MachineLearningDetector
    {
        private readonly Dictionary<string, double> _featureWeights;
        
        public MachineLearningDetector()
        {
            _featureWeights = new Dictionary<string, double>
            {
                ["entropy"] = 0.15,
                ["import_count"] = 0.10,
                ["section_count"] = 0.08,
                ["string_entropy"] = 0.12,
                ["pe_characteristics"] = 0.15,
                ["suspicious_apis"] = 0.20,
                ["resource_count"] = 0.05,
                ["digital_signature"] = 0.15
            };
        }
        
        public MLDetectionResult Detect(string filePath)
        {
            var result = new MLDetectionResult { FilePath = filePath };
            
            if (!File.Exists(filePath)) return result;
            
            try
            {
                var features = ExtractFeatures(filePath);
                result.Score = CalculateScore(features);
                result.IsMalicious = result.Score > 0.7;
                result.Features = features;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            
            return result;
        }
        
        private Dictionary<string, double> ExtractFeatures(string filePath)
        {
            var features = new Dictionary<string, double>();
            var fileBytes = File.ReadAllBytes(filePath);
            
            // 计算熵值特征
            features["entropy"] = CalculateEntropy(fileBytes);
            
            // 计算导入函数数量特征
            features["import_count"] = Math.Min(CountImports(fileBytes) / 100.0, 1.0);
            
            // 计算节区数量特征
            features["section_count"] = Math.Min(CountSections(fileBytes) / 10.0, 1.0);
            
            // 检查可疑API
            features["suspicious_apis"] = CountSuspiciousAPIs(fileBytes) / 20.0;
            
            return features;
        }
        
        private double CalculateEntropy(byte[] data)
        {
            var freq = new int[256];
            foreach (var b in data) freq[b]++;
            
            double entropy = 0;
            foreach (var count in freq)
            {
                if (count > 0)
                {
                    double p = (double)count / data.Length;
                    entropy -= p * Math.Log(p, 2);
                }
            }
            return Math.Min(entropy / 8.0, 1.0);
        }
        
        private int CountImports(byte[] data)
        {
            var text = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 50000));
            var dlls = new[] { "kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll" };
            int count = 0;
            foreach (var dll in dlls)
            {
                if (text.Contains(dll, StringComparison.OrdinalIgnoreCase)) count++;
            }
            return count;
        }
        
        private int CountSections(byte[] data)
        {
            var text = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 50000));
            var sections = new[] { ".text", ".data", ".rdata", ".rsrc", ".reloc" };
            int count = 0;
            foreach (var sec in sections)
            {
                if (text.Contains(sec)) count++;
            }
            return count;
        }
        
        private double CountSuspiciousAPIs(byte[] data)
        {
            var text = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 50000));
            var apis = new[] { "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "RegSetValue" };
            int count = 0;
            foreach (var api in apis)
            {
                if (text.Contains(api, StringComparison.OrdinalIgnoreCase)) count++;
            }
            return count;
        }
        
        private double CalculateScore(Dictionary<string, double> features)
        {
            double score = 0;
            foreach (var feature in features)
            {
                if (_featureWeights.TryGetValue(feature.Key, out var weight))
                {
                    score += feature.Value * weight;
                }
            }
            return Math.Min(score, 1.0);
        }
    }
    
    /// <summary>
    /// 行为启发式 - 基于行为模式的威胁检测
    /// </summary>
    public class BehavioralHeuristics
    {
        private readonly List<BehaviorPattern> _patterns;
        
        public BehavioralHeuristics()
        {
            _patterns = new List<BehaviorPattern>
            {
                new BehaviorPattern
                {
                    Name = "Ransomware",
                    Conditions = new[] { "FileEncryption", "MassFileAccess", "DeleteShadowCopy" },
                    RiskLevel = "Critical"
                },
                new BehaviorPattern
                {
                    Name = "Keylogger",
                    Conditions = new[] { "KeyboardHook", "Screenshot", "NetworkSend" },
                    RiskLevel = "High"
                },
                new BehaviorPattern
                {
                    Name = "Downloader",
                    Conditions = new[] { "NetworkDownload", "FileCreate", "ProcessExecute" },
                    RiskLevel = "High"
                }
            };
        }
        
        public HeuristicResult Analyze(string filePath)
        {
            var result = new HeuristicResult { FilePath = filePath };
            
            if (!File.Exists(filePath)) return result;
            
            try
            {
                var fileBytes = File.ReadAllBytes(filePath);
                var fileText = Encoding.UTF8.GetString(fileBytes, 0, Math.Min(fileBytes.Length, 100000));
                
                foreach (var pattern in _patterns)
                {
                    int matched = 0;
                    foreach (var cond in pattern.Conditions)
                    {
                        if (CheckCondition(fileText, cond))
                        {
                            matched++;
                        }
                    }
                    
                    if (matched >= 2)
                    {
                        result.DetectedPatterns.Add(pattern.Name);
                        result.RiskScore += pattern.RiskLevel == "Critical" ? 50 : 30;
                    }
                }
                
                result.IsMalicious = result.RiskScore >= 50;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            
            return result;
        }
        
        private bool CheckCondition(string content, string condition)
        {
            return condition switch
            {
                "FileEncryption" => content.Contains("CryptEncrypt") || content.Contains("Aes.Create"),
                "MassFileAccess" => content.Contains("GetFiles") || content.Contains("EnumerateFiles"),
                "DeleteShadowCopy" => content.Contains("vssadmin") || content.Contains("shadowcopy"),
                "KeyboardHook" => content.Contains("SetWindowsHookEx") || content.Contains("GetAsyncKeyState"),
                "Screenshot" => content.Contains("CopyFromScreen") || content.Contains("Capture"),
                "NetworkSend" => content.Contains("Send") || content.Contains("Upload"),
                "NetworkDownload" => content.Contains("Download") || content.Contains("WebClient"),
                "FileCreate" => content.Contains("File.Create") || content.Contains("FileStream"),
                "ProcessExecute" => content.Contains("Process.Start") || content.Contains("CreateProcess"),
                _ => false
            };
        }
    }
    
    /// <summary>
    /// 加密分析器 - 检测加密恶意软件和挖矿程序
    /// </summary>
    public class CryptoAnalyzer
    {
        private readonly List<string> _miningPools;
        private readonly List<string> _cryptoPatterns;
        
        public CryptoAnalyzer()
        {
            // 矿池地址/stratum 协议等挖矿特征从外部 JSON 加载（ThreatData/malicious_indicators.json），不内嵌于 DLL
            ExternalThreatData.EnsureLoaded();
            _miningPools = new List<string>(ExternalThreatData.MiningPools);
            _cryptoPatterns = new List<string>
            {
                "minerd", "xmrig", "cpuminer", "ccminer",
                "wallet", "bitcoin", "ethereum", "monero", "litecoin",
                "hashrate", "mining"
            };
        }
        
        public CryptoAnalysisResult Analyze(string filePath)
        {
            var result = new CryptoAnalysisResult { FilePath = filePath };
            
            if (!File.Exists(filePath)) return result;
            
            try
            {
                var fileBytes = File.ReadAllBytes(filePath);
                var fileText = Encoding.UTF8.GetString(fileBytes, 0, Math.Min(fileBytes.Length, 100000));
                
                // 检查矿池地址
                foreach (var pool in _miningPools)
                {
                    if (fileText.Contains(pool, StringComparison.OrdinalIgnoreCase))
                    {
                        result.MiningPools.Add(pool);
                        result.RiskScore += 30;
                    }
                }
                
                // 检查加密货币相关字符串
                foreach (var pattern in _cryptoPatterns)
                {
                    if (fileText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        result.CryptoPatterns.Add(pattern);
                        result.RiskScore += 5;
                    }
                }
                
                result.IsCryptoMalware = result.RiskScore >= 30;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityComponents.cs 捕获异常", ex.Message); }
            
            return result;
        }
    }
    
    #region 数据模型
    
    public class MalwareFamily
    {
        public string Name { get; set; }
        public string Type { get; set; }
        public string[] Patterns { get; set; }
        public string[] FileExtensions { get; set; }
        public string RiskLevel { get; set; }
    }
    
    public class MalwareAnalysisResult
    {
        public string FilePath { get; set; }
        public bool IsMalware { get; set; }
        public string Family { get; set; }
        public string Type { get; set; }
        public string RiskLevel { get; set; }
        public double Confidence { get; set; }
        public List<string> MatchedPatterns { get; set; } = new List<string>();
        public List<string> MatchedExtensions { get; set; } = new List<string>();
    }
    
    public class OptimizationResult
    {
        public List<CleanupItem> Items { get; set; }
        public long TotalSize { get; set; }
    }
    
    public class CleanupItem
    {
        public string Path { get; set; }
        public long Size { get; set; }
        public string Type { get; set; }
    }
    
    public class ThreatHuntResult
    {
        public string Type { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string RiskLevel { get; set; }
    }
    
    public class ResponseResult
    {
        public bool Success { get; set; }
        public List<string> Actions { get; set; } = new List<string>();
        public string ErrorMessage { get; set; }
    }
    
    public class ForensicResult
    {
        public string FilePath { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public DateTime LastAccessTime { get; set; }
        public long FileSize { get; set; }
        public string FileHash { get; set; }
        public string Signature { get; set; }
        public string Attributes { get; set; }
        public List<string> AlternateDataStreams { get; set; } = new List<string>();
    }
    
    public class RemovalResult
    {
        public bool Success { get; set; }
        public string QuarantinePath { get; set; }
        public List<string> Actions { get; set; } = new List<string>();
        public string ErrorMessage { get; set; }
    }
    
    public class RestoreResult
    {
        public bool Success { get; set; }
        public List<string> Actions { get; set; } = new List<string>();
    }
    
    public class BackupAnalysisResult
    {
        public bool HasWindowsBackup { get; set; }
        public int RestorePointCount { get; set; }
        public List<string> BackupLocations { get; set; } = new List<string>();
    }
    
    public class IntegrityResult
    {
        public string FilePath { get; set; }
        public string OriginalHash { get; set; }
        public string CurrentHash { get; set; }
        public bool IsIntact { get; set; }
    }
    
    public class SandboxResult
    {
        public string FilePath { get; set; }
        public List<string> Behaviors { get; set; }
        public int RiskScore { get; set; }
        public bool IsMalicious { get; set; }
    }
    
    public class MLDetectionResult
    {
        public string FilePath { get; set; }
        public double Score { get; set; }
        public bool IsMalicious { get; set; }
        public Dictionary<string, double> Features { get; set; }
    }
    
    public class BehaviorPattern
    {
        public string Name { get; set; }
        public string[] Conditions { get; set; }
        public string RiskLevel { get; set; }
    }
    
    public class HeuristicResult
    {
        public string FilePath { get; set; }
        public List<string> DetectedPatterns { get; set; } = new List<string>();
        public int RiskScore { get; set; }
        public bool IsMalicious { get; set; }
    }
    
    public class CryptoAnalysisResult
    {
        public string FilePath { get; set; }
        public List<string> MiningPools { get; set; } = new List<string>();
        public List<string> CryptoPatterns { get; set; } = new List<string>();
        public int RiskScore { get; set; }
        public bool IsCryptoMalware { get; set; }
    }
    
    #endregion
}