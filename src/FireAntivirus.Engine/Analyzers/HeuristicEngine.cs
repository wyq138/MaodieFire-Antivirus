using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Engine.Analyzers
{
    public class HeuristicEngine
    {
        private DataManager dataManager;
        private Dictionary<string, double> fileHashCache;
        private Dictionary<string, double> heuristicScores;
        private Dictionary<string, List<string>> maliciousPatterns;
        private Dictionary<string, List<string>> suspiciousPatterns;
        private Dictionary<string, List<string>> benignPatterns;

        public HeuristicEngine()
        {
            dataManager = new DataManager();
            fileHashCache = new Dictionary<string, double>();
            heuristicScores = new Dictionary<string, double>();
            InitializePatterns();
        }

        private void InitializePatterns()
        {
            maliciousPatterns = new Dictionary<string, List<string>>
            {
                { "SystemCalls", new List<string> { "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess" } },
                { "Registry", new List<string> { "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue" } },
                { "FileOperations", new List<string> { "DeleteFile", "MoveFile", "CopyFile", "CreateFile" } },
                { "Network", new List<string> { "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest" } },
                { "Process", new List<string> { "CreateProcess", "ShellExecute", "WinExec", "ExitProcess" } },
                { "Memory", new List<string> { "VirtualAlloc", "VirtualProtect", "RtlMoveMemory", "memcpy" } },
                { "Encryption", new List<string> { "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptAcquireContext" } },
                { "SystemInfo", new List<string> { "GetSystemInfo", "GetModuleHandle", "GetProcAddress", "LoadLibrary" } },
                { "Services", new List<string> { "OpenSCManager", "CreateService", "StartService", "ControlService" } },
                { "Hooks", new List<string> { "SetWindowsHookEx", "CallNextHookEx", "UnhookWindowsHookEx" } },
                { "Startup", new List<string> { "Run", "RunOnce", "Startup", "WinLogon" } },
                { "Injection", new List<string> { "Inject", "Hook", "Patch", "Bypass" } },
                { "RemoteControl", new List<string> { "Remote", "Control", "Access", "Admin" } },
                { "Keylogging", new List<string> { "Keylog", "Keyboard", "Hook", "Capture" } },
                { "Ransomware", new List<string> { "Ransom", "Decrypt", "Encrypt", "Payment", "Bitcoin" } },
                { "Backdoor", new List<string> { "Backdoor", "Shell", "Command", "Execute" } },
                { "Botnet", new List<string> { "Bot", "C&C", "Command and Control", "Server" } }
            };

            suspiciousPatterns = new Dictionary<string, List<string>>
            {
                { "SystemCalls", new List<string> { "GetProcesses", "GetProcessModules", "EnumProcesses", "EnumProcessModules" } },
                { "Registry", new List<string> { "RegOpenKey", "RegQueryValue", "RegEnumKey", "RegEnumValue" } },
                { "FileOperations", new List<string> { "GetFileAttributes", "SetFileAttributes", "FindFirstFile", "FindNextFile" } },
                { "Network", new List<string> { "GetHostByName", "GetHostEntry", "Dns.GetHostEntry", "Dns.GetHostAddresses" } },
                { "Process", new List<string> { "GetProcessById", "GetProcessesByName", "StartProcess", "KillProcess" } },
                { "Memory", new List<string> { "GetProcessMemoryInfo", "VirtualQuery", "ReadProcessMemory", "WriteProcessMemory" } },
                { "Encryption", new List<string> { "ComputeHash", "GetHashCode", "SHA1", "MD5" } },
                { "SystemInfo", new List<string> { "GetSystemDirectory", "GetWindowsDirectory", "GetCurrentDirectory", "GetEnvironmentVariable" } },
                { "Services", new List<string> { "GetServices", "GetServiceStatus", "EnumServicesStatus", "QueryServiceStatus" } },
                { "Hooks", new List<string> { "GetMessage", "PeekMessage", "DispatchMessage", "TranslateMessage" } },
                { "Startup", new List<string> { "StartupPath", "Application.StartupPath", "Environment.SpecialFolder.Startup", "Registry.CurrentUser.Run" } },
                { "Injection", new List<string> { "Reflection", "InvokeMember", "CreateInstance", "GetMethod" } },
                { "RemoteControl", new List<string> { "TcpClient", "TcpListener", "Socket", "NetworkStream" } },
                { "Keylogging", new List<string> { "KeyDown", "KeyUp", "KeyPress", "GetAsyncKeyState" } },
                { "Ransomware", new List<string> { "FileStream", "StreamReader", "StreamWriter", "BinaryReader" } },
                { "Backdoor", new List<string> { "Process.Start", "ShellExecute", "System.Diagnostics.Process", "Execute" } },
                { "Botnet", new List<string> { "HttpClient", "WebClient", "HttpWebRequest", "HttpWebResponse" } }
            };

            benignPatterns = new Dictionary<string, List<string>>
            {
                { "SystemCalls", new List<string> { "MessageBox", "GetModuleFileName", "GetCommandLine", "ExitProcess" } },
                { "Registry", new List<string> { "Registry.CurrentUser", "Registry.LocalMachine", "Registry.GetValue", "Registry.SetValue" } },
                { "FileOperations", new List<string> { "File.Exists", "Directory.Exists", "Path.Combine", "Path.GetFileName" } },
                { "Network", new List<string> { "WebRequest.Create", "HttpWebRequest.Create", "WebClient.DownloadString", "HttpClient.GetAsync" } },
                { "Process", new List<string> { "Process.GetCurrentProcess", "Process.GetProcesses", "Process.MainModule", "Process.Modules" } },
                { "Memory", new List<string> { "GC.Collect", "GC.GetTotalMemory", "Marshal.AllocHGlobal", "Marshal.FreeHGlobal" } },
                { "Encryption", new List<string> { "SHA256.Create", "MD5.Create", "Aes.Create", "RSA.Create" } },
                { "SystemInfo", new List<string> { "Environment.MachineName", "Environment.UserName", "Environment.OSVersion", "Environment.Version" } },
                { "Services", new List<string> { "ServiceController.GetServices", "ServiceController.Status", "ServiceController.Start", "ServiceController.Stop" } },
                { "Hooks", new List<string> { "Application.Run", "Form.Show", "Form.Hide", "Form.Close" } },
                { "Startup", new List<string> { "Application.ExecutablePath", "Assembly.GetExecutingAssembly", "Assembly.GetEntryAssembly", "AppDomain.CurrentDomain.BaseDirectory" } },
                { "Injection", new List<string> { "Assembly.Load", "Assembly.LoadFrom", "Assembly.LoadFile", "AppDomain.Load" } },
                { "RemoteControl", new List<string> { "Ping", "Dns.GetHostName", "IPAddress.Parse", "IPEndPoint" } },
                { "Keylogging", new List<string> { "Console.ReadKey", "Console.ReadLine", "TextBox.Text", "RichTextBox.Text" } },
                { "Ransomware", new List<string> { "File.ReadAllText", "File.WriteAllText", "File.ReadAllBytes", "File.WriteAllBytes" } },
                { "Backdoor", new List<string> { "Console.WriteLine", "Debug.WriteLine", "Trace.WriteLine", "EventLog.WriteEntry" } },
                { "Botnet", new List<string> { "Uri.Create", "UriBuilder", "HttpUtility.UrlEncode", "HttpUtility.UrlDecode" } }
            };
        }

        public List<ScanResult> AnalyzeFile(string filePath)
        {
            var results = new List<ScanResult>();
            
            if (!File.Exists(filePath))
            {
                return results;
            }

            try
            {
                double heuristicScore = CalculateHeuristicScore(filePath);
                var result = CreateScanResult(filePath, heuristicScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"启发式检测到恶意文件: {filePath}", $"评分: {heuristicScore:P}", "HeuristicEngine");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"启发式分析失败: {filePath}", ex.Message, "HeuristicEngine");
            }

            return results;
        }

        public double CalculateHeuristicScore(string filePath)
        {
            if (fileHashCache.TryGetValue(filePath, out double cachedScore))
            {
                return cachedScore;
            }

            double score = 0.0;

            try
            {
                score += AnalyzeFileStructure(filePath);
                score += AnalyzeCodeFeatures(filePath);
                score += AnalyzeStringFeatures(filePath);
                score += AnalyzeImportTable(filePath);
                score += AnalyzeSectionTable(filePath);
                score += AnalyzeResources(filePath);
                score += AnalyzeBehavioralPatterns(filePath);
                score += AnalyzeContextualFactors(filePath);
                score += AnalyzeHistoricalData(filePath);
                score += AnalyzeReputationData(filePath);

                score = Math.Min(score, 1.0);
                score = Math.Max(score, 0.0);

                fileHashCache[filePath] = score;
                heuristicScores[filePath] = score;
            }
            catch
            {
                score = 0.0;
            }

            return score;
        }

        private double AnalyzeFileStructure(string filePath)
        {
            double score = 0.0;

            try
            {
                var fileInfo = new FileInfo(filePath);

                if (fileInfo.Length < 1024)
                {
                    score += 0.1;
                }
                else if (fileInfo.Length > 100 * 1024 * 1024)
                {
                    score += 0.05;
                }

                string extension = Path.GetExtension(filePath).ToLower();
                string[] executableExtensions = { ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr" };
                string[] documentExtensions = { ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf" };
                string[] archiveExtensions = { ".zip", ".rar", ".7z", ".tar", ".gz", ".iso" };

                if (executableExtensions.Contains(extension))
                {
                    score += 0.15;
                }
                else if (documentExtensions.Contains(extension))
                {
                    score += 0.1;
                }
                else if (archiveExtensions.Contains(extension))
                {
                    score += 0.08;
                }

                string[] suspiciousPaths = { "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\Windows\\Temp\\", "\\Downloads\\", "\\Desktop\\", "\\Documents\\", "\\Music\\", "\\Pictures\\", "\\Videos\\" };
                foreach (var suspiciousPath in suspiciousPaths)
                {
                    if (filePath.IndexOf(suspiciousPath, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.2;
                        break;
                    }
                }

                if (fileInfo.CreationTime > DateTime.Now.AddDays(-1))
                {
                    score += 0.05;
                }

                if (fileInfo.LastWriteTime > DateTime.Now.AddHours(-1))
                {
                    score += 0.05;
                }

                if (fileInfo.LastAccessTime > DateTime.Now.AddMinutes(-30))
                {
                    score += 0.05;
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Min(score, 0.5);
        }

        private double AnalyzeCodeFeatures(string filePath)
        {
            double score = 0.0;

            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                foreach (var patternCategory in maliciousPatterns)
                {
                    foreach (var pattern in patternCategory.Value)
                    {
                        if (fileContent.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            score += 0.02;
                        }
                    }
                }

                foreach (var patternCategory in suspiciousPatterns)
                {
                    foreach (var pattern in patternCategory.Value)
                    {
                        if (fileContent.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            score += 0.01;
                        }
                    }
                }

                foreach (var patternCategory in benignPatterns)
                {
                    foreach (var pattern in patternCategory.Value)
                    {
                        if (fileContent.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            score -= 0.01;
                        }
                    }
                }

                double entropy = CalculateEntropy(fileBytes);
                if (entropy > 7.0)
                {
                    score += 0.3;
                }
                else if (entropy > 6.0)
                {
                    score += 0.15;
                }
                else if (entropy < 2.0)
                {
                    score += 0.05;
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 0.5));
        }

        private double AnalyzeStringFeatures(string filePath)
        {
            double score = 0.0;

            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                string[] maliciousStrings = {
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
                    "Run", "RunOnce", "Startup", "WinLogon",
                    "Inject", "Hook", "Patch", "Bypass",
                    "Remote", "Control", "Access", "Admin",
                    "Keylog", "Keyboard", "Hook", "Capture",
                    "Ransom", "Decrypt", "Encrypt", "Payment", "Bitcoin",
                    "Backdoor", "Shell", "Command", "Execute",
                    "Bot", "C&C", "Command and Control", "Server"
                };

                string[] suspiciousStrings = {
                    "GetProcesses", "GetProcessModules", "EnumProcesses", "EnumProcessModules",
                    "RegOpenKey", "RegQueryValue", "RegEnumKey", "RegEnumValue",
                    "GetFileAttributes", "SetFileAttributes", "FindFirstFile", "FindNextFile",
                    "GetHostByName", "GetHostEntry", "Dns.GetHostEntry", "Dns.GetHostAddresses",
                    "GetProcessById", "GetProcessesByName", "StartProcess", "KillProcess",
                    "GetProcessMemoryInfo", "VirtualQuery", "ReadProcessMemory", "WriteProcessMemory",
                    "ComputeHash", "GetHashCode", "SHA1", "MD5",
                    "GetSystemDirectory", "GetWindowsDirectory", "GetCurrentDirectory", "GetEnvironmentVariable",
                    "GetServices", "GetServiceStatus", "EnumServicesStatus", "QueryServiceStatus",
                    "GetMessage", "PeekMessage", "DispatchMessage", "TranslateMessage",
                    "StartupPath", "Application.StartupPath", "Environment.SpecialFolder.Startup", "Registry.CurrentUser.Run",
                    "Reflection", "InvokeMember", "CreateInstance", "GetMethod",
                    "TcpClient", "TcpListener", "Socket", "NetworkStream",
                    "KeyDown", "KeyUp", "KeyPress", "GetAsyncKeyState",
                    "FileStream", "StreamReader", "StreamWriter", "BinaryReader",
                    "Process.Start", "ShellExecute", "System.Diagnostics.Process", "Execute",
                    "HttpClient", "WebClient", "HttpWebRequest", "HttpWebResponse"
                };

                foreach (var str in maliciousStrings)
                {
                    if (fileContent.Contains(str, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 0.03;
                    }
                }

                foreach (var str in suspiciousStrings)
                {
                    if (fileContent.Contains(str, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 0.01;
                    }
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Min(score, 0.4);
        }

        private double AnalyzeImportTable(string filePath)
        {
            double score = 0.0;

            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

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

                foreach (string import in suspiciousImports)
                {
                    if (fileContent.IndexOf(import, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.05;
                    }
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Min(score, 0.5);
        }

        private double AnalyzeSectionTable(string filePath)
        {
            double score = 0.0;

            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                string[] suspiciousSections = {
                    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata",
                    ".reloc", ".rsrc", ".tls", ".bss", ".code", ".data",
                    ".upx", ".packed", ".encrypted", ".hidden", ".obfuscated"
                };

                foreach (string section in suspiciousSections)
                {
                    if (fileContent.IndexOf(section, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.03;
                    }
                }

                if (fileContent.IndexOf(".upx", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score += 0.2;
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Min(score, 0.4);
        }

        private double AnalyzeResources(string filePath)
        {
            double score = 0.0;

            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileContent = Encoding.UTF8.GetString(fileBytes);

                string[] suspiciousResources = {
                    "ICON", "BITMAP", "CURSOR", "MENU", "DIALOG",
                    "STRING", "ACCELERATOR", "RCDATA", "VERSION", "HTML",
                    "SCRIPT", "EXECUTABLE", "DLL", "SYS", "DRIVER"
                };

                string[] suspiciousResourceContent = {
                    "script", "executable", "binary", "encrypted", "compressed"
                };

                foreach (string resource in suspiciousResources)
                {
                    if (fileContent.IndexOf(resource, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.02;
                    }
                }

                foreach (string content in suspiciousResourceContent)
                {
                    if (fileContent.IndexOf(content, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.05;
                    }
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Min(score, 0.3);
        }

        private double AnalyzeBehavioralPatterns(string filePath)
        {
            double score = 0.0;

            try
            {
                string fileName = Path.GetFileName(filePath);
                string fileExtension = Path.GetExtension(filePath);
                string directoryName = Path.GetDirectoryName(filePath);

                string[] suspiciousFileNames = {
                    "svchost.exe", "explorer.exe", "winlogon.exe", "lsass.exe",
                    "csrss.exe", "smss.exe", "services.exe", "wininit.exe",
                    "taskhost.exe", "dwm.exe", "conhost.exe", "cmd.exe",
                    "powershell.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe"
                };

                string[] suspiciousExtensions = {
                    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                    ".jse", ".wsf", ".hta", ".scr", ".com", ".pif", ".url", ".lnk"
                };

                string[] suspiciousDirectories = {
                    "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\Windows\\Temp\\", "\\Downloads\\",
                    "\\Desktop\\", "\\Documents\\", "\\Music\\", "\\Pictures\\", "\\Videos\\",
                    "\\AppData\\Local\\", "\\AppData\\Roaming\\", "\\LocalLow\\", "\\ProgramData\\"
                };

                if (suspiciousFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                {
                    score += 0.3;
                }

                if (suspiciousExtensions.Contains(fileExtension, StringComparer.OrdinalIgnoreCase))
                {
                    score += 0.2;
                }

                foreach (string dir in suspiciousDirectories)
                {
                    if (directoryName.IndexOf(dir, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        score += 0.2;
                        break;
                    }
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Min(score, 0.5);
        }

        private double AnalyzeContextualFactors(string filePath)
        {
            double score = 0.0;

            try
            {
                var fileInfo = new FileInfo(filePath);

                if (fileInfo.CreationTime > DateTime.Now.AddDays(-1))
                {
                    score += 0.1;
                }

                if (fileInfo.LastWriteTime > DateTime.Now.AddHours(-1))
                {
                    score += 0.1;
                }

                if (fileInfo.LastAccessTime > DateTime.Now.AddMinutes(-30))
                {
                    score += 0.1;
                }

                if (fileInfo.Length < 1024)
                {
                    score += 0.1;
                }
                else if (fileInfo.Length > 100 * 1024 * 1024)
                {
                    score += 0.05;
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Min(score, 0.4);
        }

        private double AnalyzeHistoricalData(string filePath)
        {
            double score = 0.0;

            try
            {
                string fileHash = GetFileHash(filePath);
                var signature = dataManager.GetSignatureByHash(fileHash);

                if (signature != null)
                {
                    score += 1.0;
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Min(score, 1.0);
        }

        private double AnalyzeReputationData(string filePath)
        {
            double score = 0.0;

            try
            {
                string fileName = Path.GetFileName(filePath);
                string fileExtension = Path.GetExtension(filePath);

                string[] knownBenignExtensions = {
                    ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
                    ".mp3", ".wav", ".mp4", ".avi", ".mov", ".wmv", ".flv",
                    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img"
                };

                if (knownBenignExtensions.Contains(fileExtension, StringComparer.OrdinalIgnoreCase))
                {
                    score -= 0.2;
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(-0.2, score);
        }

        private ScanResult CreateScanResult(string filePath, double score)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = score > 0.85,
                Confidence = score,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Heuristic"
            };

            if (result.IsInfected)
            {
                if (score > 0.95)
                {
                    result.ThreatName = "高级启发式检测到的恶意文件";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "高级启发式检测到的可疑文件";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"启发式评分: {score:P}";
            }

            return result;
        }

        private string GetFileHash(string filePath)
        {
            try
            {
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        byte[] hash = md5.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToLower();
                    }
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        private double CalculateEntropy(byte[] data)
        {
            try
            {
                var frequency = new Dictionary<byte, int>();
                foreach (byte b in data)
                {
                    if (frequency.ContainsKey(b))
                    {
                        frequency[b]++;
                    }
                    else
                    {
                        frequency[b] = 1;
                    }
                }

                double entropy = 0.0;
                double totalBytes = data.Length;

                foreach (var pair in frequency)
                {
                    double probability = pair.Value / totalBytes;
                    entropy -= probability * Math.Log(probability, 2);
                }

                return entropy;
            }
            catch
            {
                return 0.0;
            }
        }

        public void ClearCache()
        {
            fileHashCache.Clear();
            heuristicScores.Clear();
        }

        public Dictionary<string, double> GetHeuristicScores()
        {
            return heuristicScores;
        }

        public int GetCacheSize()
        {
            return fileHashCache.Count;
        }
    }
}
