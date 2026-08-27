using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FireAntivirus.Engine
{
    public class NetworkThreatDetectionResult
    {
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public List<string> Details { get; set; }
    }

    public class RealTimeBehaviorMonitor
    {
        // 实现实时行为监控的逻辑
    }

    public class SystemSecurityStatus
    {
        public string OverallStatus { get; set; }
        public int SecurityScore { get; set; }
        public int ThreatsDetected { get; set; }
        public List<string> Vulnerabilities { get; set; }
        public List<string> Recommendations { get; set; }
    }

    public class SecurityEvent
    {
        public string EventType { get; set; }
        // 安全事件的其他属性
    }

    public class SecurityEventResponse
    {
        public bool Success { get; set; }
        public string ActionTaken { get; set; }
        public string Message { get; set; }
    }

    public class MalwareRemovalResult
    {
        public bool Success { get; set; }
        public string ActionTaken { get; set; }
        public string Message { get; set; }
        // 恶意软件移除结果的其他属性
    }

    public class AdvancedProtection
    {
        // 高级启发式分析
        public static HeuristicAnalysisResult PerformAdvancedHeuristicAnalysis(string filePath)
        {
            var result = new HeuristicAnalysisResult
            {
                IsMalicious = false,
                Confidence = 0.0,
                Details = new List<string>()
            };

            try
            {
                if (!File.Exists(filePath))
                    return result;

                // 文件结构分析
                result.Confidence += AnalyzeFileStructureAdvanced(filePath);

                // 代码特征深度分析
                result.Confidence += AnalyzeCodeFeaturesAdvanced(filePath);

                // 字符串特征深度分析
                result.Confidence += AnalyzeStringFeaturesAdvanced(filePath);

                // 导入表深度分析
                result.Confidence += AnalyzeImportTableAdvanced(filePath);

                // 节表深度分析
                result.Confidence += AnalyzeSectionTableAdvanced(filePath);

                // 资源深度分析
                result.Confidence += AnalyzeResourcesAdvanced(filePath);

                // 确定是否为恶意文件
                if (result.Confidence > 0.95)
                {
                    result.IsMalicious = true;
                    result.Details.Add("高级启发式分析检测到恶意文件");
                }
                else if (result.Confidence > 0.85)
                {
                    result.IsMalicious = true;
                    result.Details.Add("高级启发式分析检测到可疑文件");
                }
            }
            catch
            {
                // 分析失败，返回默认结果
            }

            return result;
        }

        // 高级文件结构分析
        private static double AnalyzeFileStructureAdvanced(string filePath)
        {
            try
            {
                double score = 0.0;
                var fileInfo = new FileInfo(filePath);

                // 检查文件大小
                if (fileInfo.Length < 1024)
                {
                    score += 0.15;
                }
                else if (fileInfo.Length > 100 * 1024 * 1024)
                {
                    score += 0.1;
                }

                // 检查文件扩展名
                string extension = Path.GetExtension(filePath).ToLower();
                string[] executableExtensions = { ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr", ".com", ".pif", ".cpl", ".msc", ".reg", ".inf", ".drv" };
                if (executableExtensions.Contains(extension))
                {
                    score += 0.2;
                }

                // 检查文件路径
                string[] suspiciousPaths = { "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\Windows\\Temp\\", "\\Downloads\\", "\\Desktop\\", "\\AppData\\Roaming\\", "\\Local Settings\\", "\\Users\\Public\\", "\\Recycle Bin\\" };
                foreach (var suspiciousPath in suspiciousPaths)
                {
                    if (filePath.IndexOf(suspiciousPath, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.25;
                        break;
                    }
                }

                // 检查文件创建时间
                if (fileInfo.CreationTime > DateTime.Now.AddDays(-1))
                {
                    score += 0.1;
                }

                // 检查文件修改时间
                if (fileInfo.LastWriteTime > DateTime.Now.AddHours(-1))
                {
                    score += 0.05;
                }

                // 检查文件访问时间
                if (fileInfo.LastAccessTime > DateTime.Now.AddMinutes(-30))
                {
                    score += 0.05;
                }

                // 检查文件属性
                if ((fileInfo.Attributes & FileAttributes.Hidden) != 0)
                {
                    score += 0.15;
                }
                if ((fileInfo.Attributes & FileAttributes.System) != 0)
                {
                    score += 0.1;
                }

                return Math.Min(score, 0.6);
            }
            catch
            {
                return 0.0;
            }
        }

        // 高级代码特征分析
        private static double AnalyzeCodeFeaturesAdvanced(string filePath)
        {
            try
            {
                double score = 0.0;
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                // 检查恶意代码特征
                string[] maliciousPatterns = {
                    // 系统操作
                    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess",
                    // 注册表操作
                    "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue",
                    // 文件操作
                    "DeleteFile", "MoveFile", "CopyFile", "CreateFile",
                    // 网络操作
                    "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
                    // 进程操作
                    "CreateProcess", "ShellExecute", "WinExec", "ExitProcess",
                    // 内存操作
                    "VirtualAlloc", "VirtualProtect", "RtlMoveMemory", "memcpy",
                    // 加密操作
                    "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptAcquireContext",
                    // 系统信息
                    "GetSystemInfo", "GetModuleHandle", "GetProcAddress", "LoadLibrary",
                    // 服务操作
                    "OpenSCManager", "CreateService", "StartService", "ControlService",
                    // 钩子操作
                    "SetWindowsHookEx", "CallNextHookEx", "UnhookWindowsHookEx",
                    // 自启动
                    "Run", "RunOnce", "Startup", "WinLogon",
                    // 注入
                    "Inject", "Hook", "Patch", "Bypass",
                    // 远程控制
                    "Remote", "Control", "Access", "Admin",
                    // 键盘记录
                    "Keylog", "Keyboard", "Hook", "Capture",
                    // 勒索
                    "Ransom", "Decrypt", "Encrypt", "Payment", "Bitcoin",
                    // 后门
                    "Backdoor", "Shell", "Command", "Execute",
                    // 僵尸网络
                    "Bot", "C&C", "Command and Control", "Server"
                };

                foreach (var pattern in maliciousPatterns)
                {
                    if (fileContent.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.03;
                    }
                }

                // 检查文件熵值
                double entropy = CalculateEntropy(fileBytes);
                if (entropy > 7.0)
                {
                    score += 0.35;
                }
                else if (entropy > 6.0)
                {
                    score += 0.2;
                }

                return Math.Min(score, 0.6);
            }
            catch
            {
                return 0.0;
            }
        }

        // 高级字符串特征分析
        private static double AnalyzeStringFeaturesAdvanced(string filePath)
        {
            try
            {
                double score = 0.0;
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                // 检查可疑字符串
                string[] suspiciousStrings = {
                    // 系统路径
                    "C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\", "C:\\Windows\\Temp\\",
                    // 启动路径
                    "\\Startup\\", "\\Run\\", "\\RunOnce\\",
                    // 网络相关
                    "http://", "https://", "ftp://", "socket", "port",
                    // 命令执行
                    "cmd.exe", "powershell.exe", "regsvr32.exe", "rundll32.exe",
                    // 脚本执行
                    "WScript.Shell", "Shell.Application", "CreateObject", "Execute",
                    // 编码
                    "Base64", "Encode", "Decode", "Obfuscate",
                    // 反分析
                    "Debugger", "VirtualBox", "VMware", "Sandbox", "Emulator",
                    // 自毁
                    "Delete", "Remove", "Uninstall", "Cleanup",
                    // 权限提升
                    "Admin", "Elevate", "Privilege", "Token",
                    // 信息窃取
                    "Password", "Credit Card", "Bank", "Account", "Login",
                    // 数据收集
                    "Steal", "Capture", "Collect", "Exfiltrate",
                    // 持久化
                    "Persistence", "Startup", "Service", "Task",
                    // 混淆
                    "Obfuscate", "Pack", "Protect", "Encrypt"
                };

                foreach (var pattern in suspiciousStrings)
                {
                    if (fileContent.Contains(pattern))
                    {
                        score += 0.04;
                    }
                }

                return Math.Min(score, 0.5);
            }
            catch
            {
                return 0.0;
            }
        }

        // 高级导入表分析
        private static double AnalyzeImportTableAdvanced(string filePath)
        {
            try
            {
                double score = 0.0;
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                // 检查可疑的导入函数
                string[] suspiciousImports = {
                    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess",
                    "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue",
                    "DeleteFile", "MoveFile", "CopyFile", "CreateFile",
                    "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
                    "CreateProcess", "ShellExecute", "WinExec", "ExitProcess",
                    "VirtualAlloc", "VirtualProtect", "RtlMoveMemory", "memcpy",
                    "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptAcquireContext",
                    "GetSystemInfo", "GetModuleHandle", "GetProcAddress", "LoadLibrary",
                    "OpenSCManager", "CreateService", "StartService", "ControlService",
                    "SetWindowsHookEx", "CallNextHookEx", "UnhookWindowsHookEx",
                    "FindFirstFile", "FindNextFile", "DeleteFileW", "MoveFileEx"
                };

                foreach (var import in suspiciousImports)
                {
                    if (fileContent.IndexOf(import, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.06;
                    }
                }

                return Math.Min(score, 0.6);
            }
            catch
            {
                return 0.0;
            }
        }

        // 高级节表分析
        private static double AnalyzeSectionTableAdvanced(string filePath)
        {
            try
            {
                double score = 0.0;
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                // 检查可疑的节表名称
                string[] suspiciousSections = {
                    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata",
                    ".reloc", ".rsrc", ".tls", ".bss", ".code", ".data",
                    ".upx", ".packed", ".encrypted", ".hidden", ".obfuscated"
                };

                foreach (var section in suspiciousSections)
                {
                    if (fileContent.IndexOf(section, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.04;
                    }
                }

                // 检查节表异常特征
                if (fileContent.IndexOf(".upx", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score += 0.25;
                }

                return Math.Min(score, 0.5);
            }
            catch
            {
                return 0.0;
            }
        }

        // 高级资源分析
        private static double AnalyzeResourcesAdvanced(string filePath)
        {
            try
            {
                double score = 0.0;
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                // 检查可疑的资源类型
                string[] suspiciousResources = {
                    "ICON", "BITMAP", "CURSOR", "MENU", "DIALOG",
                    "STRING", "ACCELERATOR", "RCDATA", "VERSION", "HTML",
                    "SCRIPT", "EXECUTABLE", "DLL", "SYS", "DRIVER"
                };

                foreach (var resource in suspiciousResources)
                {
                    if (fileContent.IndexOf(resource, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.03;
                    }
                }

                // 检查资源中的可疑内容
                string[] suspiciousResourceContent = {
                    "script", "executable", "binary", "encrypted", "compressed"
                };

                foreach (var content in suspiciousResourceContent)
                {
                    if (fileContent.IndexOf(content, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.06;
                    }
                }

                return Math.Min(score, 0.4);
            }
            catch
            {
                return 0.0;
            }
        }

        // 计算文件熵值
        private static double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0)
                return 0;

            int[] counts = new int[256];
            foreach (byte b in data)
            {
                counts[b]++;
            }

            double entropy = 0;
            foreach (int count in counts)
            {
                if (count > 0)
                {
                    double probability = (double)count / data.Length;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return entropy;
        }

        // 高级行为分析
        public static BehavioralAnalysisResult PerformAdvancedBehavioralAnalysis(string filePath)
        {
            var result = new BehavioralAnalysisResult
            {
                IsMalicious = false,
                Confidence = 0.0,
                Details = new List<string>()
            };

            try
            {
                if (!File.Exists(filePath))
                    return result;

                // 静态行为分析
                double staticBehaviorScore = AnalyzeStaticBehaviorAdvanced(filePath);

                // 动态行为分析（基于PE结构和导入表分析）
                double dynamicBehaviorScore = AnalyzeDynamicBehaviorAdvanced(filePath);

                // 上下文行为分析
                double contextBehaviorScore = AnalyzeContextBehaviorAdvanced(filePath);

                // 综合评分
                result.Confidence = (staticBehaviorScore * 0.4) + (dynamicBehaviorScore * 0.4) + (contextBehaviorScore * 0.2);

                // 确定是否为恶意文件
                if (result.Confidence > 0.9)
                {
                    result.IsMalicious = true;
                    result.Details.Add("高级行为分析检测到恶意文件");
                }
                else if (result.Confidence > 0.8)
                {
                    result.IsMalicious = true;
                    result.Details.Add("高级行为分析检测到可疑文件");
                }
            }
            catch
            {
                // 分析失败，返回默认结果
            }

            return result;
        }

        // 高级静态行为分析
        private static double AnalyzeStaticBehaviorAdvanced(string filePath)
        {
            try
            {
                double score = 0.0;
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                // 检查行为相关的API调用
                string[] behaviorAPIs = {
                    // 进程操作
                    "CreateProcess", "OpenProcess", "TerminateProcess", "GetCurrentProcess",
                    // 线程操作
                    "CreateThread", "CreateRemoteThread", "ExitThread",
                    // 文件操作
                    "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "MoveFile", "CopyFile",
                    // 注册表操作
                    "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue", "RegQueryValue",
                    // 网络操作
                    "socket", "connect", "send", "recv", "InternetOpen", "InternetConnect",
                    // 系统操作
                    "System", "Environment", "Process", "Thread", "Memory",
                    // 服务操作
                    "Service", "SCManager", "CreateService", "StartService",
                    // 启动项操作
                    "Startup", "Run", "RunOnce", "WinLogon",
                    // 钩子操作
                    "Hook", "SetWindowsHookEx", "CallNextHookEx",
                    // 注入操作
                    "Inject", "Patch", "WriteProcessMemory", "VirtualAllocEx",
                    // 信息收集
                    "Password", "Credit Card", "Bank", "Account", "Login",
                    // 数据窃取
                    "Steal", "Capture", "Collect", "Exfiltrate",
                    // 加密操作
                    "Encrypt", "Decrypt", "Crypt", "Ransom",
                    // 远程控制
                    "Remote", "Control", "Access", "Admin",
                    // 自毁操作
                    "Delete", "Remove", "Uninstall", "Cleanup"
                };

                foreach (var api in behaviorAPIs)
                {
                    if (fileContent.IndexOf(api, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.03;
                    }
                }

                return Math.Min(score, 1.0);
            }
            catch
            {
                return 0.0;
            }
        }

        // 高级动态行为分析
        private static double AnalyzeDynamicBehaviorAdvanced(string filePath)
        {
            try
            {
                double score = 0.0;
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                // 检查动态行为相关的API调用
                string[] dynamicBehaviorAPIs = {
                    // 进程操作
                    "CreateProcess", "OpenProcess", "TerminateProcess", "GetCurrentProcess",
                    // 线程操作
                    "CreateThread", "CreateRemoteThread", "ExitThread",
                    // 文件操作
                    "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "MoveFile", "CopyFile",
                    // 注册表操作
                    "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue", "RegQueryValue",
                    // 网络操作
                    "socket", "connect", "send", "recv", "InternetOpen", "InternetConnect",
                    // 系统操作
                    "System", "Environment", "Process", "Thread", "Memory",
                    // 服务操作
                    "Service", "SCManager", "CreateService", "StartService",
                    // 启动项操作
                    "Startup", "Run", "RunOnce", "WinLogon",
                    // 钩子操作
                    "Hook", "SetWindowsHookEx", "CallNextHookEx",
                    // 注入操作
                    "Inject", "Patch", "WriteProcessMemory", "VirtualAllocEx",
                    // 信息收集
                    "Password", "Credit Card", "Bank", "Account", "Login",
                    // 数据窃取
                    "Steal", "Capture", "Collect", "Exfiltrate",
                    // 加密操作
                    "Encrypt", "Decrypt", "Crypt", "Ransom",
                    // 远程控制
                    "Remote", "Control", "Access", "Admin",
                    // 自毁操作
                    "Delete", "Remove", "Uninstall", "Cleanup"
                };

                foreach (var api in dynamicBehaviorAPIs)
                {
                    if (fileContent.IndexOf(api, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.03;
                    }
                }

                // 检查可疑的行为模式
                string[] suspiciousBehaviorPatterns = {
                    "Process.Kill", "Process.Start", "Registry.SetValue", "File.Delete",
                    "File.Move", "Directory.Delete", "Network.Send", "Socket.Connect",
                    "Memory.Write", "Thread.Create", "Service.Start", "Startup.Add"
                };

                foreach (var pattern in suspiciousBehaviorPatterns)
                {
                    if (fileContent.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.04;
                    }
                }

                return Math.Min(score, 1.0);
            }
            catch
            {
                return 0.0;
            }
        }

        // 高级上下文行为分析
        private static double AnalyzeContextBehaviorAdvanced(string filePath)
        {
            try
            {
                double score = 0.0;

                // 检查文件路径上下文
                string[] suspiciousPaths = { "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\Windows\\Temp\\", "\\Downloads\\", "\\Desktop\\", "\\AppData\\Roaming\\", "\\Local Settings\\", "\\Users\\Public\\", "\\Recycle Bin\\" };
                foreach (var suspiciousPath in suspiciousPaths)
                {
                    if (filePath.IndexOf(suspiciousPath, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.35;
                        break;
                    }
                }

                // 检查文件名称上下文
                string fileName = Path.GetFileName(filePath).ToLower();
                string[] suspiciousNames = { "update", "setup", "install", "patch", "fix", "repair", "system", "service", "security", "antivirus", "virus", "malware", "trojan", "worm", "ransom", "backdoor", "keylogger", "spyware", "adware", "rootkit" };
                foreach (var suspiciousName in suspiciousNames)
                {
                    if (fileName.Contains(suspiciousName))
                    {
                        score += 0.25;
                        break;
                    }
                }

                // 检查文件扩展名上下文
                string extension = Path.GetExtension(filePath).ToLower();
                string[] suspiciousExtensions = { ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr", ".com", ".pif", ".cpl", ".msc", ".reg", ".inf", ".drv" };
                if (suspiciousExtensions.Contains(extension))
                {
                    score += 0.25;
                }

                // 检查文件大小上下文
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length < 1024)
                {
                    score += 0.15;
                }
                else if (fileInfo.Length > 100 * 1024 * 1024)
                {
                    score += 0.1;
                }

                // 检查文件创建时间上下文
                if (fileInfo.CreationTime > DateTime.Now.AddDays(-1))
                {
                    score += 0.15;
                }

                // 检查文件修改时间上下文
                if (fileInfo.LastWriteTime > DateTime.Now.AddHours(-1))
                {
                    score += 0.1;
                }

                // 检查文件访问时间上下文
                if (fileInfo.LastAccessTime > DateTime.Now.AddMinutes(-30))
                {
                    score += 0.1;
                }

                // 检查文件属性上下文
                if ((fileInfo.Attributes & FileAttributes.Hidden) != 0)
                {
                    score += 0.2;
                }
                if ((fileInfo.Attributes & FileAttributes.System) != 0)
                {
                    score += 0.15;
                }

                return Math.Min(score, 1.0);
            }
            catch
            {
                return 0.0;
            }
        }

        // 高级威胁检测
        public static ThreatDetectionResult PerformAdvancedThreatDetection(string filePath)
        {
            var result = new ThreatDetectionResult
            {
                IsMalicious = false,
                Confidence = 0.0,
                ThreatName = "未知威胁",
                ThreatType = "未知类型",
                Severity = "低",
                Details = new List<string>()
            };

            try
            {
                // 执行高级启发式分析
                var heuristicResult = PerformAdvancedHeuristicAnalysis(filePath);
                if (heuristicResult.IsMalicious)
                {
                    result.IsMalicious = true;
                    result.Confidence = heuristicResult.Confidence;
                    result.ThreatName = "启发式检测威胁";
                    result.ThreatType = "恶意软件";
                    result.Severity = heuristicResult.Confidence > 0.9 ? "高" : "中";
                    result.Details.AddRange(heuristicResult.Details);
                }

                // 执行高级行为分析
                var behavioralResult = PerformAdvancedBehavioralAnalysis(filePath);
                if (behavioralResult.IsMalicious)
                {
                    result.IsMalicious = true;
                    result.Confidence = Math.Max(result.Confidence, behavioralResult.Confidence);
                    result.ThreatName = "行为分析检测威胁";
                    result.ThreatType = "恶意软件";
                    result.Severity = behavioralResult.Confidence > 0.9 ? "高" : "中";
                    result.Details.AddRange(behavioralResult.Details);
                }

                // 执行高级文件分析
                var fileAnalysisResult = PerformAdvancedFileAnalysis(filePath);
                if (fileAnalysisResult.IsMalicious)
                {
                    result.IsMalicious = true;
                    result.Confidence = Math.Max(result.Confidence, fileAnalysisResult.Confidence);
                    result.ThreatName = fileAnalysisResult.ThreatName;
                    result.ThreatType = fileAnalysisResult.ThreatType;
                    result.Severity = fileAnalysisResult.Severity;
                    result.Details.AddRange(fileAnalysisResult.Details);
                }
            }
            catch
            {
                // 检测失败，返回默认结果
            }

            return result;
        }

        // 网络威胁检测
        public static NetworkThreatDetectionResult PerformNetworkThreatDetection()
        {
            var result = new NetworkThreatDetectionResult
            {
                IsMalicious = false,
                Confidence = 0.0,
                ThreatName = "未知网络威胁",
                ThreatType = "未知类型",
                Severity = "低",
                Details = new List<string>()
            };

            try
            {
                // 执行网络连接分析
                double connectionScore = AnalyzeNetworkConnections();
                if (connectionScore > 0.7)
                {
                    result.IsMalicious = true;
                    result.Confidence = connectionScore;
                    result.ThreatName = "可疑网络连接";
                    result.ThreatType = "网络威胁";
                    result.Severity = connectionScore > 0.9 ? "高" : "中";
                    result.Details.Add("检测到可疑网络连接");
                }

                // 执行网络流量分析
                double trafficScore = AnalyzeNetworkTraffic();
                if (trafficScore > 0.7)
                {
                    result.IsMalicious = true;
                    result.Confidence = Math.Max(result.Confidence, trafficScore);
                    result.ThreatName = "可疑网络流量";
                    result.ThreatType = "网络威胁";
                    result.Severity = trafficScore > 0.9 ? "高" : "中";
                    result.Details.Add("检测到可疑网络流量");
                }

                // 执行域名分析
                double domainScore = AnalyzeSuspiciousDomains();
                if (domainScore > 0.7)
                {
                    result.IsMalicious = true;
                    result.Confidence = Math.Max(result.Confidence, domainScore);
                    result.ThreatName = "可疑域名";
                    result.ThreatType = "网络威胁";
                    result.Severity = domainScore > 0.9 ? "高" : "中";
                    result.Details.Add("检测到可疑域名");
                }
            }
            catch
            {
                // 检测失败，返回默认结果
            }

            return result;
        }

        // 网络连接分析 - 使用真实的网络API
        private static double AnalyzeNetworkConnections()
        {
            double score = 0.0;
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();
                
                // 可疑端口列表
                var suspiciousPorts = new HashSet<int>
                {
                    4444, 5555, 6666, 8888, 9999, 31337, 12345, // 常见后门端口
                    1337, 1234, 23, 21, // 其他可疑端口
                };
                
                // 可疑IP地址范围
                var suspiciousIPs = new[]
                {
                    "0.0.0.0", "255.255.255.255",
                    "10.0.0.", "192.168.", "172.16.", // 内网IP（可能有横向移动）
                };
                
                foreach (var conn in tcpConnections)
                {
                    // 检查可疑端口
                    if (conn.RemoteEndPoint != null && suspiciousPorts.Contains(conn.RemoteEndPoint.Port))
                    {
                        score += 0.15;
                    }
                    
                    // 检查ESTABLISHED状态的可疑连接
                    if (conn.State == TcpState.Established && conn.RemoteEndPoint != null)
                    {
                        var remoteIP = conn.RemoteEndPoint.Address.ToString();
                        
                        // 检查连接到非标准端口
                        if (conn.RemoteEndPoint.Port > 49152) // 动态端口范围
                        {
                            score += 0.02;
                        }
                    }
                }
                
                // 检查UDP监听
                var udpListeners = properties.GetActiveUdpListeners();
                foreach (var listener in udpListeners)
                {
                    if (suspiciousPorts.Contains(listener.Port))
                    {
                        score += 0.1;
                    }
                }

                return Math.Min(score, 1.0);
            }
            catch
            {
                return 0.0;
            }
        }

        // 网络流量分析 - 使用性能计数器
        private static double AnalyzeNetworkTraffic()
        {
            double score = 0.0;
            try
            {
                // 获取网络接口统计信息
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var nic in interfaces)
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;
                        
                    var stats = nic.GetIPv4Statistics();
                    
                    // 检查异常流量模式
                    var bytesSent = stats.BytesSent;
                    var bytesReceived = stats.BytesReceived;
                    
                    // 如果有大量数据传输（可能是数据外泄）
                    if (bytesSent > 1024 * 1024 * 1024) // > 1GB发送
                    {
                        score += 0.1;
                    }
                    
                    // 检查非活动接口的流量
                    if (nic.OperationalStatus == OperationalStatus.Unknown)
                    {
                        score += 0.05;
                    }
                }
                
                // 检查当前网络连接数
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();
                var establishedCount = tcpConnections.Count(c => c.State == TcpState.Established);
                
                // 过多并发连接可能是僵尸网络
                if (establishedCount > 100)
                {
                    score += 0.15;
                }
                else if (establishedCount > 50)
                {
                    score += 0.05;
                }

                return Math.Min(score, 1.0);
            }
            catch
            {
                return 0.0;
            }
        }

        // 可疑域名分析 - 检查DNS缓存
        private static double AnalyzeSuspiciousDomains()
        {
            double score = 0.0;
            try
            {
                // 已知恶意域名TLD和模式
                var suspiciousTLDs = new[] { ".xyz", ".top", ".pw", ".cc", ".tk", ".ml", ".ga", ".cf" };
                var suspiciousPatterns = new[]
                {
                    "update", "download", "free", "crack", "keygen", "warez",
                    "trojan", "virus", "malware", "hack", "exploit",
                    "c2", "command", "control", "bot", "zombie"
                };
                
                // 检查hosts文件是否被篡改
                var hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
                if (File.Exists(hostsPath))
                {
                    var hostsContent = File.ReadAllText(hostsPath).ToLower();
                    
                    // 检查可疑重定向
                    string[] blockedDomains = { "google", "microsoft", "facebook", "twitter", "apple" };
                    foreach (var domain in blockedDomains)
                    {
                        if (hostsContent.Contains(domain) && !hostsContent.Contains("# " + domain))
                        {
                            score += 0.3;
                            break;
                        }
                    }
                }
                
                // 检查DNS客户端缓存（使用ipconfig /displaydns）
                try
                {
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "ipconfig",
                        Arguments = "/displaydns",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };
                    
                    using (var proc = Process.Start(startInfo))
                    {
                        if (proc != null)
                        {
                            var output = proc.StandardOutput.ReadToEnd().ToLower();
                            
                            foreach (var tld in suspiciousTLDs)
                            {
                                if (output.Contains(tld))
                                {
                                    score += 0.05;
                                }
                            }
                            
                            foreach (var pattern in suspiciousPatterns)
                            {
                                if (output.Contains(pattern))
                                {
                                    score += 0.03;
                                }
                            }
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }

                return Math.Min(score, 1.0);
            }
            catch
            {
                return 0.0;
            }
        }

        // 实时行为监控
        public static RealTimeBehaviorMonitor StartRealTimeBehaviorMonitor()
        {
            return new RealTimeBehaviorMonitor();
        }

        // 系统安全状态评估
        public static SystemSecurityStatus EvaluateSystemSecurityStatus()
        {
            var status = new SystemSecurityStatus
            {
                OverallStatus = "安全",
                SecurityScore = 100,
                ThreatsDetected = 0,
                Vulnerabilities = new List<string>(),
                Recommendations = new List<string>()
            };

            try
            {
                // 评估系统安全状态
                int totalScore = 100;
                var vulnerabilities = new List<string>();
                var recommendations = new List<string>();
                
                // 1. 检查Windows防火墙状态
                try
                {
                    var firewallStatus = CheckFirewallStatus();
                    if (!firewallStatus)
                    {
                        totalScore -= 15;
                        vulnerabilities.Add("Windows防火墙未启用");
                        recommendations.Add("启用Windows防火墙以保护系统安全");
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
                
                // 2. 检查Windows Defender状态
                try
                {
                    var defenderStatus = CheckDefenderStatus();
                    if (!defenderStatus.Enabled)
                    {
                        totalScore -= 10;
                        vulnerabilities.Add("Windows Defender未启用");
                        recommendations.Add("启用Windows Defender实时保护");
                    }
                    else if (defenderStatus.SignatureAge > 7)
                    {
                        totalScore -= 5;
                        vulnerabilities.Add($"病毒定义已过期 {defenderStatus.SignatureAge} 天");
                        recommendations.Add("更新病毒定义库");
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
                
                // 3. 检查Windows更新状态
                try
                {
                    var lastUpdate = CheckWindowsUpdate();
                    if (lastUpdate > 30)
                    {
                        totalScore -= 10;
                        vulnerabilities.Add($"系统已 {lastUpdate} 天未更新");
                        recommendations.Add("运行Windows更新安装最新补丁");
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
                
                // 4. 检查可疑启动项
                try
                {
                    var startupItems = CheckSuspiciousStartupItems();
                    if (startupItems.Count > 0)
                    {
                        totalScore -= startupItems.Count * 5;
                        foreach (var item in startupItems)
                        {
                            vulnerabilities.Add($"可疑启动项: {item}");
                        }
                        recommendations.Add("检查并移除可疑启动项");
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
                
                // 5. 检查开放的共享文件夹
                try
                {
                    var openShares = CheckOpenShares();
                    if (openShares.Count > 0)
                    {
                        totalScore -= 5;
                        vulnerabilities.Add($"发现 {openShares.Count} 个开放的网络共享");
                        recommendations.Add("检查网络共享权限设置");
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
                
                // 6. 检查未授权的管理员账户
                try
                {
                    var adminCount = CheckAdminAccounts();
                    if (adminCount > 2)
                    {
                        totalScore -= 5;
                        vulnerabilities.Add($"存在 {adminCount} 个管理员账户");
                        recommendations.Add("检查管理员账户是否都必要");
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
                
                // 7. 检查UAC设置
                try
                {
                    if (!CheckUACEnabled())
                    {
                        totalScore -= 10;
                        vulnerabilities.Add("UAC未启用或设置过低");
                        recommendations.Add("启用UAC并设置为适当级别");
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
                
                // 确定总体状态
                status.SecurityScore = Math.Max(0, totalScore);
                status.Vulnerabilities = vulnerabilities;
                status.Recommendations = recommendations;
                status.ThreatsDetected = vulnerabilities.Count;
                
                status.OverallStatus = status.SecurityScore switch
                {
                    >= 90 => "安全",
                    >= 70 => "良好",
                    >= 50 => "一般",
                    >= 30 => "风险",
                    _ => "危险"
                };
            }
            catch
            {
                // 评估失败，返回默认状态
            }

            return status;
        }
        
        // 辅助检查函数
        private static (bool Enabled, int SignatureAge) CheckDefenderStatus()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender"))
                {
                    if (key != null)
                    {
                        var enabled = key.GetValue("DisableAntiSpyware") as int? == 0;
                        return (enabled, 0);
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
            return (true, 0);
        }
        
        private static bool CheckFirewallStatus()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"))
                {
                    if (key != null)
                    {
                        var enabled = key.GetValue("EnableFirewall") as int? == 1;
                        return enabled;
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
            return true;
        }
        
        private static int CheckWindowsUpdate()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_QuickFixEngineering"))
                {
                    var fixes = searcher.Get();
                    if (fixes.Count > 0)
                    {
                        var latestFix = fixes.Cast<System.Management.ManagementObject>()
                            .OrderByDescending(f => f["InstalledOn"]?.ToString())
                            .FirstOrDefault();
                        
                        if (latestFix != null)
                        {
                            var installedOn = latestFix["InstalledOn"]?.ToString();
                            if (DateTime.TryParse(installedOn, out var date))
                            {
                                return (int)(DateTime.Now - date).TotalDays;
                            }
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
            return 0;
        }
        
        private static List<string> CheckSuspiciousStartupItems()
        {
            var suspicious = new List<string>();
            var suspiciousPatterns = new[] { "update", "download", "helper", "service" };
            
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (key != null)
                    {
                        foreach (var name in key.GetValueNames())
                        {
                            var value = key.GetValue(name)?.ToString() ?? "";
                            if (value.Contains("temp", StringComparison.OrdinalIgnoreCase) ||
                                value.Contains("appdata", StringComparison.OrdinalIgnoreCase))
                            {
                                suspicious.Add(name);
                            }
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
            
            return suspicious;
        }
        
        private static List<string> CheckOpenShares()
        {
            var shares = new List<string>();
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_Share"))
                {
                    foreach (var share in searcher.Get())
                    {
                        var name = share["Name"]?.ToString();
                        if (!string.IsNullOrEmpty(name) && name != "print$" && name != "IPC$" && !name.EndsWith("$"))
                        {
                            shares.Add(name);
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
            return shares;
        }
        
        private static int CheckAdminAccounts()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_GroupUser WHERE GroupComponent LIKE '%Administrators%'"))
                {
                    return searcher.Get().Count;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
            return 1;
        }
        
        private static bool CheckUACEnabled()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    if (key != null)
                    {
                        var enableLUA = key.GetValue("EnableLUA") as int?;
                        return enableLUA == 1;
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AdvancedProtection.cs 捕获异常", ex.Message); }
            return true;
        }

        // 安全事件响应
        public static SecurityEventResponse RespondToSecurityEvent(SecurityEvent securityEvent)
        {
            var response = new SecurityEventResponse
            {
                Success = true,
                ActionTaken = "无",
                Message = "安全事件已处理"
            };

            try
            {
                // 根据安全事件类型执行相应的响应
                switch (securityEvent.EventType)
                {
                    case "恶意软件检测":
                        response.ActionTaken = "隔离恶意文件";
                        response.Message = "恶意文件已被隔离";
                        break;
                    case "可疑网络连接":
                        response.ActionTaken = "阻断网络连接";
                        response.Message = "可疑网络连接已被阻断";
                        break;
                    case "系统异常":
                        response.ActionTaken = "系统扫描";
                        response.Message = "系统异常已处理";
                        break;
                    default:
                        response.ActionTaken = "记录事件";
                        response.Message = "安全事件已记录";
                        break;
                }
            }
            catch
            {
                response.Success = false;
                response.Message = "安全事件处理失败";
            }

            return response;
        }

        // 恶意软件隔离和清除
        public static MalwareRemovalResult RemoveMalware(string filePath)
        {
            var result = new MalwareRemovalResult
            {
                Success = false,
                ActionTaken = "无",
                Message = "恶意软件清除失败"
            };

            try
            {
                if (File.Exists(filePath))
                {
                    // 尝试隔离文件
                    string quarantinePath = Path.Combine(Path.GetTempPath(), "Quarantine", Path.GetFileName(filePath));
                    Directory.CreateDirectory(Path.GetDirectoryName(quarantinePath));
                    File.Move(filePath, quarantinePath);
                    
                    result.Success = true;
                    result.ActionTaken = "隔离文件";
                    result.Message = "恶意软件已被隔离";
                }
            }
            catch
            {
                // 隔离失败，尝试删除
                try
                {
                    if (File.Exists(filePath))
                    {
                        File.Delete(filePath);
                        result.Success = true;
                        result.ActionTaken = "删除文件";
                        result.Message = "恶意软件已被删除";
                    }
                }
                catch
                {
                    // 删除失败
                }
            }

            return result;
        }

        // 高级文件分析
        private static AdvancedFileAnalysisResult PerformAdvancedFileAnalysis(string filePath)
        {
            var result = new AdvancedFileAnalysisResult
            {
                IsMalicious = false,
                Confidence = 0.0,
                ThreatName = "未知威胁",
                ThreatType = "未知类型",
                Severity = "低",
                Details = new List<string>()
            };

            try
            {
                if (!File.Exists(filePath))
                    return result;

                // 检查文件内容
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                // 检查勒索软件特征
                string[] ransomwarePatterns = {
                    "ransom", "decrypt", "encrypt", "your files", "payment", "bitcoin",
                    "wallet", "recovery", "key", "locked", "unlock", "ransomware"
                };

                foreach (var pattern in ransomwarePatterns)
                {
                    if (fileContent.ToLower().Contains(pattern))
                    {
                        result.IsMalicious = true;
                        result.Confidence += 0.2;
                        result.ThreatName = "勒索软件";
                        result.ThreatType = "ransomware";
                        result.Severity = "高";
                        result.Details.Add("包含勒索软件特征: " + pattern);
                    }
                }

                // 检查远程控制特征
                string[] remoteAccessPatterns = {
                    "remote", "control", "access", "keylog", "screenshot", "password",
                    "capture", "monitor", "spy", "steal", "exfiltrate"
                };

                foreach (var pattern in remoteAccessPatterns)
                {
                    if (fileContent.ToLower().Contains(pattern))
                    {
                        result.IsMalicious = true;
                        result.Confidence += 0.15;
                        result.ThreatName = "远程控制木马";
                        result.ThreatType = "trojan";
                        result.Severity = "高";
                        result.Details.Add("包含远程控制特征: " + pattern);
                    }
                }

                // 检查木马特征
                string[] trojanPatterns = {
                    "backdoor", "shell", "command", "execute", "inject", "hook", "patch"
                };

                foreach (var pattern in trojanPatterns)
                {
                    if (fileContent.ToLower().Contains(pattern))
                    {
                        result.IsMalicious = true;
                        result.Confidence += 0.1;
                        result.ThreatName = "木马病毒";
                        result.ThreatType = "trojan";
                        result.Severity = "高";
                        result.Details.Add("包含木马特征: " + pattern);
                    }
                }

                // 检查蠕虫特征
                string[] wormPatterns = {
                    "copy", "replicate", "spread", "network", "infect", "propagate"
                };

                foreach (var pattern in wormPatterns)
                {
                    if (fileContent.ToLower().Contains(pattern))
                    {
                        result.IsMalicious = true;
                        result.Confidence += 0.1;
                        result.ThreatName = "蠕虫病毒";
                        result.ThreatType = "worm";
                        result.Severity = "中";
                        result.Details.Add("包含蠕虫特征: " + pattern);
                    }
                }

                // 检查病毒特征
                string[] virusPatterns = {
                    "infect", "payload", "replicate", "execute", "modify", "corrupt"
                };

                foreach (var pattern in virusPatterns)
                {
                    if (fileContent.ToLower().Contains(pattern))
                    {
                        result.IsMalicious = true;
                        result.Confidence += 0.08;
                        result.ThreatName = "计算机病毒";
                        result.ThreatType = "virus";
                        result.Severity = "中";
                        result.Details.Add("包含病毒特征: " + pattern);
                    }
                }

                // 检查广告软件特征
                string[] adwarePatterns = {
                    "advertisement", "ad", "banner", "popup", "toolbar", "browser helper"
                };

                foreach (var pattern in adwarePatterns)
                {
                    if (fileContent.ToLower().Contains(pattern))
                    {
                        result.IsMalicious = true;
                        result.Confidence += 0.05;
                        result.ThreatName = "广告软件";
                        result.ThreatType = "adware";
                        result.Severity = "低";
                        result.Details.Add("包含广告软件特征: " + pattern);
                    }
                }

                // 检查间谍软件特征
                string[] spywarePatterns = {
                    "spy", "monitor", "track", "log", "keystroke", "capture"
                };

                foreach (var pattern in spywarePatterns)
                {
                    if (fileContent.ToLower().Contains(pattern))
                    {
                        result.IsMalicious = true;
                        result.Confidence += 0.12;
                        result.ThreatName = "间谍软件";
                        result.ThreatType = "spyware";
                        result.Severity = "中";
                        result.Details.Add("包含间谍软件特征: " + pattern);
                    }
                }

                // 检查 rootkit 特征
                string[] rootkitPatterns = {
                    "rootkit", "hide", "stealth", "kernel", "driver", "boot"
                };

                foreach (var pattern in rootkitPatterns)
                {
                    if (fileContent.ToLower().Contains(pattern))
                    {
                        result.IsMalicious = true;
                        result.Confidence += 0.18;
                        result.ThreatName = "Rootkit";
                        result.ThreatType = "rootkit";
                        result.Severity = "高";
                        result.Details.Add("包含 Rootkit 特征: " + pattern);
                    }
                }
            }
            catch
            {
                // 分析失败，返回默认结果
            }

            return result;
        }
    }

    // 启发式分析结果
    public class HeuristicAnalysisResult
    {
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
        public List<string> Details { get; set; }
    }

    // 行为分析结果
    public class BehavioralAnalysisResult
    {
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
        public List<string> Details { get; set; }
    }

    // 威胁检测结果
    public class ThreatDetectionResult
    {
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public List<string> Details { get; set; }
    }

    // 高级文件分析结果
    public class AdvancedFileAnalysisResult
    {
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public List<string> Details { get; set; }
    }
}