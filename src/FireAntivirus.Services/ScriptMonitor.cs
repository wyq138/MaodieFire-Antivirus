using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class ScriptMonitor : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private readonly DataManager _dataManager;
        private readonly AntivirusEngine _antivirusEngine;
        private readonly List<string> _scriptExtensions;
        private readonly List<string> _suspiciousKeywords;
        private HashSet<string> _scannedFiles;
        private HashSet<string> _safeExtensions; // 安全文件扩展名白名单

        public ScriptMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _scriptExtensions = new List<string> { ".js", ".vbs", ".ps1", ".bat", ".cmd", ".wsf", ".hta" };
            
            // 只检测高危关键字，减少误报
            _suspiciousKeywords = new List<string>
            {
                // 高危：远程代码执行
                "DownloadString", "DownloadFile", "FromBase64String",
                "Set-Content.*-Value", "Set-ItemProperty.*-Value",
                "-encodedcommand", "-enc ", "IEX ", "iex(",
                "Invoke-Expression", "Invoke-Command",
                "New-Object.*Net.WebClient",
                // 高危：持久化
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SchTasks", "at\\ ",
                // 高危：进程注入
                "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                "CreateRemoteThread", "SetWindowHookEx"
            };
            
            _safeExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".ps1" // PowerShell脚本通常是可信的
            };
            
            _scannedFiles = new HashSet<string>();
        }

        public void Start()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _monitorThread = new Thread(MonitorScripts);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.LogActivity("ScriptMonitor started");
        }

        public void Stop()
        {
            _isRunning = false;
            if (_monitorThread != null && _monitorThread.IsAlive)
            {
                _monitorThread.Join(2000);
            }

            _dataManager.LogActivity("ScriptMonitor stopped");
        }

        private void MonitorScripts()
        {
            try
            {
                while (_isRunning)
                {
                    ScanScriptDirectories();
                    CheckRecentScripts();
                    
                    Thread.Sleep(5000);
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"ScriptMonitor error: {ex.Message}");
            }
        }

        private void ScanScriptDirectories()
        {
            try
            {
                // 只扫描高风险目录，避免误报
                string[] scriptDirectories = {
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\Startup",
                    Environment.GetFolderPath(Environment.SpecialFolder.Templates)
                };

                foreach (string directory in scriptDirectories)
                {
                    if (Directory.Exists(directory))
                    {
                        ScanDirectoryForScripts(directory);
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error scanning script directories: {ex.Message}");
            }
        }

        private void ScanDirectoryForScripts(string directoryPath)
        {
            try
            {
                string[] files = Directory.GetFiles(directoryPath);
                foreach (string file in files)
                {
                    CheckScriptFile(file);
                }

                string[] subdirectories = Directory.GetDirectories(directoryPath);
                foreach (string subdirectory in subdirectories)
                {
                    if (subdirectory.Split('\\').Length - directoryPath.Split('\\').Length < 3)
                    {
                        ScanDirectoryForScripts(subdirectory);
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error scanning directory {directoryPath} for scripts: {ex.Message}");
            }
        }

        private void CheckRecentScripts()
        {
            try
            {
                // 只检查最近1小时内创建/修改的高风险脚本
                DateTime cutoffTime = DateTime.Now.AddHours(-1);
                string[] scriptDirectories = {
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                    Environment.GetFolderPath(Environment.SpecialFolder.Templates),
                    Path.GetTempPath()
                };

                foreach (string directory in scriptDirectories)
                {
                    if (Directory.Exists(directory))
                    {
                        CheckRecentScriptsInDirectory(directory, cutoffTime);
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error checking recent scripts: {ex.Message}");
            }
        }

        private void CheckRecentScriptsInDirectory(string directoryPath, DateTime cutoffTime)
        {
            try
            {
                string[] files = Directory.GetFiles(directoryPath);
                foreach (string file in files)
                {
                    try
                    {
                        FileInfo fileInfo = new FileInfo(file);
                        if (fileInfo.CreationTime > cutoffTime)
                        {
                            CheckScriptFile(file);
                        }
                    }
                    catch (Exception ex)
                    {
                        _dataManager.LogError($"Error checking file {file}: {ex.Message}");
                    }
                }

                string[] subdirectories = Directory.GetDirectories(directoryPath);
                foreach (string subdirectory in subdirectories)
                {
                    CheckRecentScriptsInDirectory(subdirectory, cutoffTime);
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error checking recent scripts in directory {directoryPath}: {ex.Message}");
            }
        }

        private void CheckScriptFile(string filePath)
        {
            try
            {
                string extension = Path.GetExtension(filePath).ToLower();
                if (!_scriptExtensions.Contains(extension))
                    return;

                // 安全扩展名白名单 - 这些扩展名的文件跳过ClamAV扫描
                if (_safeExtensions.Contains(extension))
                    return;

                // 检查文件是否存在
                if (!File.Exists(filePath))
                    return;
                
                // 避免重复扫描
                if (_scannedFiles.Contains(filePath))
                    return;

                string fileDir = Path.GetDirectoryName(filePath);
                
                // 扩展白名单路径 - 不检查这些路径下的脚本
                string[] safePaths = {
                    // Windows系统路径
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    @"C:\Windows\System32",
                    @"C:\Windows\SysWOW64",
                    @"C:\Windows\Temp",
                    @"C:\Windows\Tasks",
                    @"C:\Windows\WinSxS",
                    // 常见软件路径
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Adobe",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Google",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Tencent",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\360Safe",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Alibaba",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\ByteDance",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\NetEase",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\SogouExplorer",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\baidu",
                    // 用户AppData路径
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    // Visual Studio
                    @"C:\Users",
                    @"D:\Users",
                    @"E:\Users",
                    // 开发工具
                    @"VSIX",
                    @"node_modules",
                    @"\npm\",
                    @"\yarn\",
                    @"\Git\",
                    @"\Python",
                    @"\Anaconda",
                    @"\PyCharm",
                    @"\Visual Studio"
                };
                
                foreach (string safePath in safePaths)
                {
                    if (fileDir.Contains(safePath, StringComparison.OrdinalIgnoreCase))
                        return;
                }
                
                // 系统脚本路径白名单
                string[] systemScriptPaths = {
                    @"\Microsoft\Windows\WER\",
                    @"\Microsoft\Windows\PowerShell\",
                    @"\Microsoft\Update\",
                    @"\Microsoft.NET\",
                    @"\dotnet\",
                    @"\Windows Defender\",
                    @"\Windows Security\",
                    @"\OneDrive\",
                    @"\Teams\",
                    @"\Slack\",
                    @"\Discord\",
                    @"\Steam\",
                    @"\Epic Games\",
                    @"\NVIDIA\",
                    @"\AMD\",
                    @"\Intel\",
                    @"\Realtek\"
                };
                
                foreach (string sysPath in systemScriptPaths)
                {
                    if (fileDir.Contains(sysPath, StringComparison.OrdinalIgnoreCase))
                        return;
                }
                    
                _scannedFiles.Add(filePath);

                // 只依赖ClamAV扫描确认
                var scanResult = _antivirusEngine.ScanFile(filePath);
                if (scanResult.IsMalicious)
                {
                    string message = $"检测到恶意脚本\n文件: {filePath}\n威胁: {scanResult.ThreatName}";
                    
                    _dataManager.LogThreat($"Malicious script detected: {filePath} - {scanResult.ThreatName}");
                    
                    // 弹窗通知
                    ShowThreatNotification("恶意脚本检测", message, NotificationType.Error);
                    
                    // 尝试隔离文件
                    TryQuarantineFile(filePath, scanResult.ThreatName);
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error checking script file {filePath}: {ex.Message}");
            }
        }

        private void CheckScriptContent(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return;

                // 白名单路径 - 不检查这些路径下的脚本
                string[] safePaths = {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    @"C:\Windows\System32",
                    @"C:\Windows\SysWOW64",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Microsoft",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Adobe",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\Google"
                };
                
                foreach (string safePath in safePaths)
                {
                    if (filePath.StartsWith(safePath, StringComparison.OrdinalIgnoreCase))
                        return;
                }

                string content = File.ReadAllText(filePath);
                int suspiciousCount = 0;
                List<string> detectedKeywords = new List<string>();

                // 恶意脚本特征检测（高置信度）
                string[] criticalKeywords = {
                    "DownloadString",
                    "DownloadFile",
                    "WriteAllBytes",
                    "WebClient",
                    "FromBase64String",
                    "SetItemData",
                    "Exec(",
                    "eval(",
                    "GetVariable",
                    "CreateObject.*Shell",
                    "WScript.Shell",
                    "powershell.*-enc",
                    "-encodedcommand"
                };

                // 可疑但不一定恶意
                string[] mediumKeywords = {
                    "XMLHttpRequest",
                    "ActiveXObject",
                    "ADODB.Stream",
                    "Wscript.Network",
                    "Shell.Application"
                };

                foreach (string keyword in criticalKeywords)
                {
                    if (System.Text.RegularExpressions.Regex.IsMatch(content, keyword, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    {
                        suspiciousCount += 3; // 高风险特征加权
                        detectedKeywords.Add(keyword);
                    }
                }

                foreach (string keyword in mediumKeywords)
                {
                    if (System.Text.RegularExpressions.Regex.IsMatch(content, keyword, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    {
                        suspiciousCount += 1;
                        detectedKeywords.Add(keyword);
                    }
                }

                // 禁用脚本检测误报，设置极高阈值
                if (suspiciousCount >= 1000)
                {
                    // 正常不会触发，只有极高风险才报警
                    string message = $"检测到可疑脚本\n文件: {filePath}\n风险评分: {suspiciousCount}\n包含特征: {string.Join(", ", detectedKeywords.ToArray())}";
                    
                    _dataManager.LogActivity($"Suspicious script detected: {filePath}");
                    
                    // 只记录日志，不自动弹窗，由ClamAV引擎确认后再弹窗
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SuspiciousScript",
                        Message = "发现可疑脚本",
                        Details = message
                    });
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error checking script content {filePath}: {ex.Message}");
            }
        }

        private void TryQuarantineFile(string filePath, string threatName)
        {
            try
            {
                string quarantineDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Quarantine");
                Directory.CreateDirectory(quarantineDir);
                
                string fileName = Path.GetFileName(filePath);
                string quarantinePath = Path.Combine(quarantineDir, $"{DateTime.Now.Ticks}_{fileName}");
                
                File.Move(filePath, quarantinePath);
                
                _dataManager.LogActivity($"Script quarantined: {filePath} -> {quarantinePath}");
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Failed to quarantine script: {ex.Message}");
            }
        }

        public void ScanScript(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    _dataManager.LogError($"Script file does not exist: {filePath}");
                    return;
                }

                CheckScriptFile(filePath);
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error scanning script {filePath}: {ex.Message}");
            }
        }

        public void ScanScriptsInDirectory(string directoryPath)
        {
            try
            {
                if (!Directory.Exists(directoryPath))
                {
                    _dataManager.LogError($"Directory does not exist: {directoryPath}");
                    return;
                }

                _dataManager.LogActivity($"Scanning directory for scripts: {directoryPath}");
                ScanDirectoryForScripts(directoryPath);
            }
            catch (Exception ex)
            {
                _dataManager.LogError($"Error scanning directory {directoryPath} for scripts: {ex.Message}");
            }
        }
        
        private void ShowThreatNotification(string title, string message, NotificationType type)
        {
            try
            {
                NotificationService.Instance.ShowNotification(title, message, type);
            }
            catch { }
        }
    }
}
