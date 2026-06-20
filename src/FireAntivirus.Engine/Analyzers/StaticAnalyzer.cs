using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Engine.Analyzers
{
    public class StaticAnalyzer
    {
        private DataManager dataManager;
        private Dictionary<string, string> fileHashCache;
        private Dictionary<string, List<string>> staticPatterns;
        private Dictionary<string, List<string>> maliciousSignatures;
        private Dictionary<string, List<string>> suspiciousSignatures;
        private Dictionary<string, List<string>> benignSignatures;
        
        // 专业检测阈值 - 减少误报
        private const double HIGH_RISK_THRESHOLD = 0.92;
        private const double SUSPICIOUS_THRESHOLD = 0.88;

        public StaticAnalyzer()
        {
            dataManager = new DataManager();
            fileHashCache = new Dictionary<string, string>();
            InitializeStaticPatterns();
            InitializeSignatures();
        }

        private void InitializeStaticPatterns()
        {
            staticPatterns = new Dictionary<string, List<string>>
            {
                { "PEHeader", new List<string> { "MZ", "PE", "IMAGE_DOS_HEADER", "IMAGE_NT_HEADERS" } },
                { "Sections", new List<string> { ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".reloc", ".rsrc", ".tls", ".bss" } },
                { "Imports", new List<string> { "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll", "netapi32.dll", "ws2_32.dll", "wininet.dll", "urlmon.dll" } },
                { "Exports", new List<string> { "DllMain", "GetProcAddress", "GetModuleHandle", "LoadLibrary" } },
                { "Resources", new List<string> { "ICON", "BITMAP", "CURSOR", "MENU", "DIALOG", "STRING", "ACCELERATOR", "RCDATA", "VERSION", "HTML" } },
                { "Packers", new List<string> { "UPX", "ASPack", "PECompact", "MPRESS", "FSG", "Petite", "Themida", "VMProtect" } },
                { "Compilers", new List<string> { "Microsoft Visual C++", "GCC", "Delphi", "Borland C++", "Visual Basic", "C#", "Java", "Python" } },
                { "DebugInfo", new List<string> { "PDB", "DEBUG", "COFF", "CodeView" } },
                { "Security", new List<string> { "ASLR", "DEP", "SEH", "CFG", "StrongNaming", "Authenticode" } },
                { "Obfuscation", new List<string> { "Confuser", "Eazfuscator", "Dotfuscator", "SmartAssembly", "NetReactor" } }
            };
        }

        private void InitializeSignatures()
        {
            maliciousSignatures = new Dictionary<string, List<string>>
            {
                { "Ransomware", new List<string> { "Ransom", "Decrypt", "Encrypt", "Payment", "Bitcoin", "Ethereum", "Wallet", "Key" } },
                { "Trojan", new List<string> { "Trojan", "Backdoor", "Remote", "Control", "Access", "Admin", "Shell", "Command" } },
                { "Spyware", new List<string> { "Spy", "Keylog", "Capture", "Monitor", "Steal", "Password", "Credit", "Card" } },
                { "Adware", new List<string> { "Ad", "Advertisement", "Banner", "Popup", "Commercial", "Sponsor", "Promotion", "Marketing" } },
                { "Keylogger", new List<string> { "Keylog", "Keyboard", "Hook", "Log", "Capture", "Key", "Press", "Stroke" } },
                { "Backdoor", new List<string> { "Backdoor", "Remote", "Access", "Shell", "Command", "Execute", "Control", "Admin" } },
                { "Worm", new List<string> { "Worm", "Spread", "Replicate", "Network", "Share", "Copy", "Duplicate", "Propagate" } },
                { "Virus", new List<string> { "Virus", "Infect", "Replicate", "Payload", "Boot", "File", "System", "Execute" } },
                { "Miner", new List<string> { "Miner", "Cryptocurrency", "Bitcoin", "Ethereum", "Hash", "Mining", "Wallet", "Pool" } },
                { "PUP", new List<string> { "PUP", "Potentially Unwanted", "Toolbar", "Browser", "Extension", "Plugin", "Addon", "Helper" } }
            };

            suspiciousSignatures = new Dictionary<string, List<string>>
            {
                { "Injection", new List<string> { "Inject", "Hook", "Patch", "Bypass", "Memory", "Process", "Thread", "Remote" } },
                { "Network", new List<string> { "Socket", "TcpClient", "TcpListener", "HttpWebRequest", "HttpClient", "WebClient", "Download", "Upload" } },
                { "File", new List<string> { "FileStream", "StreamReader", "StreamWriter", "BinaryReader", "BinaryWriter", "DeleteFile", "MoveFile", "CopyFile" } },
                { "Registry", new List<string> { "Registry", "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue", "RegOpenKey", "RegQueryValue", "RegEnumKey" } },
                { "Process", new List<string> { "Process", "Start", "Kill", "CreateProcess", "ShellExecute", "WinExec", "ExitProcess", "GetProcesses" } },
                { "Memory", new List<string> { "VirtualAlloc", "VirtualProtect", "RtlMoveMemory", "memcpy", "ReadProcessMemory", "WriteProcessMemory", "OpenProcess", "VirtualAllocEx" } },
                { "Encryption", new List<string> { "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptAcquireContext", "Aes", "RSA", "SHA1", "MD5" } },
                { "System", new List<string> { "GetSystemInfo", "GetModuleHandle", "GetProcAddress", "LoadLibrary", "GetSystemDirectory", "GetWindowsDirectory", "GetCurrentDirectory", "GetEnvironmentVariable" } },
                { "Services", new List<string> { "OpenSCManager", "CreateService", "StartService", "ControlService", "GetServices", "GetServiceStatus", "EnumServicesStatus", "QueryServiceStatus" } },
                { "Startup", new List<string> { "Run", "RunOnce", "Startup", "WinLogon", "Registry.CurrentUser.Run", "Registry.LocalMachine.Run", "Application.StartupPath", "Environment.SpecialFolder.Startup" } }
            };

            benignSignatures = new Dictionary<string, List<string>>
            {
                { "UserInterface", new List<string> { "MessageBox", "Form", "Button", "TextBox", "Label", "ListBox", "ComboBox", "CheckBox" } },
                { "FileOperations", new List<string> { "File.Exists", "Directory.Exists", "Path.Combine", "Path.GetFileName", "File.ReadAllText", "File.WriteAllText", "File.ReadAllBytes", "File.WriteAllBytes" } },
                { "NetworkOperations", new List<string> { "Ping", "Dns.GetHostName", "IPAddress.Parse", "IPEndPoint", "WebRequest.Create", "HttpWebRequest.Create", "WebClient.DownloadString", "HttpClient.GetAsync" } },
                { "ProcessOperations", new List<string> { "Process.GetCurrentProcess", "Process.GetProcesses", "Process.MainModule", "Process.Modules", "Process.StartInfo", "Process.ExitCode", "Process.Kill", "Process.WaitForExit" } },
                { "MemoryOperations", new List<string> { "GC.Collect", "GC.GetTotalMemory", "Marshal.AllocHGlobal", "Marshal.FreeHGlobal", "Array.Resize", "List<T>", "Dictionary<K,V>", "HashSet<T>" } },
                { "Cryptography", new List<string> { "SHA256.Create", "MD5.Create", "Aes.Create", "RSA.Create", "ComputeHash", "GetHashCode", "Encrypt", "Decrypt" } },
                { "SystemInformation", new List<string> { "Environment.MachineName", "Environment.UserName", "Environment.OSVersion", "Environment.Version", "Environment.GetFolderPath", "Environment.GetCommandLineArgs", "Environment.CurrentDirectory", "Environment.ProcessorCount" } },
                { "Services", new List<string> { "ServiceController.GetServices", "ServiceController.Status", "ServiceController.Start", "ServiceController.Stop", "ServiceController.DisplayName", "ServiceController.ServiceName", "ServiceController.DependentServices", "ServiceController.ServicesDependedOn" } },
                { "Assembly", new List<string> { "Assembly.GetExecutingAssembly", "Assembly.GetEntryAssembly", "Assembly.Load", "Assembly.LoadFrom", "Assembly.LoadFile", "AppDomain.Load", "Assembly.GetName", "Assembly.GetFile" } }
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
                var fileInfo = new FileInfo(filePath);
                string fileHash = GetFileHash(filePath);
                var fileContent = File.ReadAllBytes(filePath);

                var peAnalysis = AnalyzePEHeader(fileContent);
                var sectionAnalysis = AnalyzeSections(fileContent);
                var importAnalysis = AnalyzeImports(fileContent);
                var exportAnalysis = AnalyzeExports(fileContent);
                var resourceAnalysis = AnalyzeResources(fileContent);
                var signatureAnalysis = AnalyzeSignatures(fileContent);
                var hashAnalysis = AnalyzeHash(fileHash);
                var entropyAnalysis = AnalyzeEntropy(fileContent);

                double staticScore = CalculateStaticScore(
                    peAnalysis, sectionAnalysis, importAnalysis, exportAnalysis,
                    resourceAnalysis, signatureAnalysis, hashAnalysis, entropyAnalysis
                );

                var result = CreateScanResult(filePath, staticScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"静态分析检测到恶意文件: {filePath}", $"评分: {staticScore:P}", "StaticAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"静态分析失败: {filePath}", ex.Message, "StaticAnalyzer");
            }

            return results;
        }

        public List<ScanResult> AnalyzeDirectory(string directoryPath)
        {
            var results = new List<ScanResult>();
            
            if (!Directory.Exists(directoryPath))
            {
                return results;
            }

            try
            {
                var files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    try
                    {
                        var fileResults = AnalyzeFile(file);
                        results.AddRange(fileResults);
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"目录静态分析失败: {directoryPath}", ex.Message, "StaticAnalyzer");
            }

            return results;
        }

        private Dictionary<string, object> AnalyzePEHeader(byte[] fileContent)
        {
            var analysis = new Dictionary<string, object>();
            
            try
            {
                string fileContentStr = Encoding.UTF8.GetString(fileContent);
                analysis["HasMZHeader"] = fileContentStr.Contains("MZ");
                analysis["HasPEHeader"] = fileContentStr.Contains("PE");
                analysis["IsExecutable"] = fileContentStr.Contains("MZ") && fileContentStr.Contains("PE");
            }
            catch
            {
                analysis["HasMZHeader"] = false;
                analysis["HasPEHeader"] = false;
                analysis["IsExecutable"] = false;
            }

            return analysis;
        }

        private Dictionary<string, object> AnalyzeSections(byte[] fileContent)
        {
            var analysis = new Dictionary<string, object>();
            
            try
            {
                string fileContentStr = Encoding.UTF8.GetString(fileContent);
                var sections = new List<string>();
                
                foreach (var section in staticPatterns["Sections"])
                {
                    if (fileContentStr.Contains(section))
                    {
                        sections.Add(section);
                    }
                }
                
                analysis["Sections"] = sections;
                analysis["SectionCount"] = sections.Count;
                analysis["HasTextSection"] = sections.Contains(".text");
                analysis["HasDataSection"] = sections.Contains(".data");
                analysis["HasRDataSection"] = sections.Contains(".rdata");
                analysis["HasIDataSection"] = sections.Contains(".idata");
                analysis["HasRelocSection"] = sections.Contains(".reloc");
                analysis["HasRsrcSection"] = sections.Contains(".rsrc");
            }
            catch
            {
                analysis["Sections"] = new List<string>();
                analysis["SectionCount"] = 0;
                analysis["HasTextSection"] = false;
                analysis["HasDataSection"] = false;
                analysis["HasRDataSection"] = false;
                analysis["HasIDataSection"] = false;
                analysis["HasRelocSection"] = false;
                analysis["HasRsrcSection"] = false;
            }

            return analysis;
        }

        private Dictionary<string, object> AnalyzeImports(byte[] fileContent)
        {
            var analysis = new Dictionary<string, object>();
            
            try
            {
                string fileContentStr = Encoding.UTF8.GetString(fileContent);
                var imports = new List<string>();
                
                foreach (var import in staticPatterns["Imports"])
                {
                    if (fileContentStr.Contains(import))
                    {
                        imports.Add(import);
                    }
                }
                
                analysis["Imports"] = imports;
                analysis["ImportCount"] = imports.Count;
                analysis["HasKernel32"] = imports.Contains("kernel32.dll");
                analysis["HasUser32"] = imports.Contains("user32.dll");
                analysis["HasAdvapi32"] = imports.Contains("advapi32.dll");
                analysis["HasShell32"] = imports.Contains("shell32.dll");
                analysis["HasNetapi32"] = imports.Contains("netapi32.dll");
                analysis["HasWs2_32"] = imports.Contains("ws2_32.dll");
                analysis["HasWininet"] = imports.Contains("wininet.dll");
                analysis["HasUrlmon"] = imports.Contains("urlmon.dll");
            }
            catch
            {
                analysis["Imports"] = new List<string>();
                analysis["ImportCount"] = 0;
                analysis["HasKernel32"] = false;
                analysis["HasUser32"] = false;
                analysis["HasAdvapi32"] = false;
                analysis["HasShell32"] = false;
                analysis["HasNetapi32"] = false;
                analysis["HasWs2_32"] = false;
                analysis["HasWininet"] = false;
                analysis["HasUrlmon"] = false;
            }

            return analysis;
        }

        private Dictionary<string, object> AnalyzeExports(byte[] fileContent)
        {
            var analysis = new Dictionary<string, object>();
            
            try
            {
                string fileContentStr = Encoding.UTF8.GetString(fileContent);
                var exports = new List<string>();
                
                foreach (var export in staticPatterns["Exports"])
                {
                    if (fileContentStr.Contains(export))
                    {
                        exports.Add(export);
                    }
                }
                
                analysis["Exports"] = exports;
                analysis["ExportCount"] = exports.Count;
                analysis["HasDllMain"] = exports.Contains("DllMain");
                analysis["HasGetProcAddress"] = exports.Contains("GetProcAddress");
                analysis["HasGetModuleHandle"] = exports.Contains("GetModuleHandle");
                analysis["HasLoadLibrary"] = exports.Contains("LoadLibrary");
            }
            catch
            {
                analysis["Exports"] = new List<string>();
                analysis["ExportCount"] = 0;
                analysis["HasDllMain"] = false;
                analysis["HasGetProcAddress"] = false;
                analysis["HasGetModuleHandle"] = false;
                analysis["HasLoadLibrary"] = false;
            }

            return analysis;
        }

        private Dictionary<string, object> AnalyzeResources(byte[] fileContent)
        {
            var analysis = new Dictionary<string, object>();
            
            try
            {
                string fileContentStr = Encoding.UTF8.GetString(fileContent);
                var resources = new List<string>();
                
                foreach (var resource in staticPatterns["Resources"])
                {
                    if (fileContentStr.Contains(resource))
                    {
                        resources.Add(resource);
                    }
                }
                
                analysis["Resources"] = resources;
                analysis["ResourceCount"] = resources.Count;
                analysis["HasIcon"] = resources.Contains("ICON");
                analysis["HasBitmap"] = resources.Contains("BITMAP");
                analysis["HasCursor"] = resources.Contains("CURSOR");
                analysis["HasMenu"] = resources.Contains("MENU");
                analysis["HasDialog"] = resources.Contains("DIALOG");
                analysis["HasString"] = resources.Contains("STRING");
                analysis["HasVersion"] = resources.Contains("VERSION");
                analysis["HasHtml"] = resources.Contains("HTML");
            }
            catch
            {
                analysis["Resources"] = new List<string>();
                analysis["ResourceCount"] = 0;
                analysis["HasIcon"] = false;
                analysis["HasBitmap"] = false;
                analysis["HasCursor"] = false;
                analysis["HasMenu"] = false;
                analysis["HasDialog"] = false;
                analysis["HasString"] = false;
                analysis["HasVersion"] = false;
                analysis["HasHtml"] = false;
            }

            return analysis;
        }

        private Dictionary<string, object> AnalyzeSignatures(byte[] fileContent)
        {
            var analysis = new Dictionary<string, object>();
            
            try
            {
                string fileContentStr = Encoding.UTF8.GetString(fileContent);
                var maliciousSignaturesFound = new List<string>();
                var suspiciousSignaturesFound = new List<string>();
                var benignSignaturesFound = new List<string>();
                
                foreach (var signatureCategory in maliciousSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (fileContentStr.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            maliciousSignaturesFound.Add($"{signatureCategory.Key}: {signature}");
                        }
                    }
                }
                
                foreach (var signatureCategory in suspiciousSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (fileContentStr.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            suspiciousSignaturesFound.Add($"{signatureCategory.Key}: {signature}");
                        }
                    }
                }
                
                foreach (var signatureCategory in benignSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (fileContentStr.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            benignSignaturesFound.Add($"{signatureCategory.Key}: {signature}");
                        }
                    }
                }
                
                analysis["MaliciousSignatures"] = maliciousSignaturesFound;
                analysis["MaliciousSignatureCount"] = maliciousSignaturesFound.Count;
                analysis["SuspiciousSignatures"] = suspiciousSignaturesFound;
                analysis["SuspiciousSignatureCount"] = suspiciousSignaturesFound.Count;
                analysis["BenignSignatures"] = benignSignaturesFound;
                analysis["BenignSignatureCount"] = benignSignaturesFound.Count;
            }
            catch
            {
                analysis["MaliciousSignatures"] = new List<string>();
                analysis["MaliciousSignatureCount"] = 0;
                analysis["SuspiciousSignatures"] = new List<string>();
                analysis["SuspiciousSignatureCount"] = 0;
                analysis["BenignSignatures"] = new List<string>();
                analysis["BenignSignatureCount"] = 0;
            }

            return analysis;
        }

        private Dictionary<string, object> AnalyzeHash(string fileHash)
        {
            var analysis = new Dictionary<string, object>();
            
            try
            {
                var signature = dataManager.GetSignatureByHash(fileHash);
                analysis["FileHash"] = fileHash;
                analysis["IsKnownMalware"] = signature != null;
                analysis["Signature"] = signature;
            }
            catch
            {
                analysis["FileHash"] = fileHash;
                analysis["IsKnownMalware"] = false;
                analysis["Signature"] = null;
            }

            return analysis;
        }

        private Dictionary<string, object> AnalyzeEntropy(byte[] fileContent)
        {
            var analysis = new Dictionary<string, object>();
            
            try
            {
                double entropy = CalculateEntropy(fileContent);
                analysis["Entropy"] = entropy;
                analysis["IsCompressed"] = entropy > 6.0;
                analysis["IsEncrypted"] = entropy > 7.0;
                analysis["IsUncompressed"] = entropy < 2.0;
            }
            catch
            {
                analysis["Entropy"] = 0.0;
                analysis["IsCompressed"] = false;
                analysis["IsEncrypted"] = false;
                analysis["IsUncompressed"] = false;
            }

            return analysis;
        }

        private double CalculateStaticScore(
            Dictionary<string, object> peAnalysis,
            Dictionary<string, object> sectionAnalysis,
            Dictionary<string, object> importAnalysis,
            Dictionary<string, object> exportAnalysis,
            Dictionary<string, object> resourceAnalysis,
            Dictionary<string, object> signatureAnalysis,
            Dictionary<string, object> hashAnalysis,
            Dictionary<string, object> entropyAnalysis
        )
        {
            double score = 0.0;
            int riskIndicators = 0;

            try
            {
                // 可执行文件基础分析
                if ((bool)peAnalysis["IsExecutable"])
                {
                    score += 0.02;
                }

                // 节区数量异常
                int sectionCount = (int)sectionAnalysis["SectionCount"];
                if (sectionCount > 10)
                {
                    score += 0.03;
                    riskIndicators++;
                }

                // 导入函数分析
                int importCount = (int)importAnalysis["ImportCount"];
                if (importCount > 20)
                {
                    score += 0.02;
                }

                // 导出函数分析
                int exportCount = (int)exportAnalysis["ExportCount"];
                if (exportCount > 10)
                {
                    score += 0.01;
                }

                // 资源数量分析
                int resourceCount = (int)resourceAnalysis["ResourceCount"];
                if (resourceCount > 10)
                {
                    score += 0.01;
                }

                // 恶意签名分析 - 降低权重，需要多个匹配
                int maliciousSignatureCount = (int)signatureAnalysis["MaliciousSignatureCount"];
                if (maliciousSignatureCount > 3)
                {
                    score += (maliciousSignatureCount - 3) * 0.03;
                    riskIndicators++;
                }
                else if (maliciousSignatureCount > 0)
                {
                    // 少量恶意签名降低权重
                    score += maliciousSignatureCount * 0.01;
                }

                // 可疑签名分析 - 降低权重
                int suspiciousSignatureCount = (int)signatureAnalysis["SuspiciousSignatureCount"];
                if (suspiciousSignatureCount > 5)
                {
                    score += (suspiciousSignatureCount - 5) * 0.01;
                    riskIndicators++;
                }

                // 良性签名降低评分
                int benignSignatureCount = (int)signatureAnalysis["BenignSignatureCount"];
                if (benignSignatureCount > 10)
                {
                    score -= 0.1;
                }

                // 已知恶意哈希 - 直接确认为恶意
                if ((bool)hashAnalysis["IsKnownMalware"])
                {
                    score += 1.0;
                    riskIndicators += 3;
                }

                // 熵值分析
                double entropy = (double)entropyAnalysis["Entropy"];
                if (entropy > 7.5)
                {
                    score += 0.15;
                    riskIndicators++;
                }
                else if (entropy > 7.0)
                {
                    score += 0.08;
                }
                else if (entropy > 6.0)
                {
                    score += 0.03;
                }

                // 组合检测：需要多个风险指标才触发高评分
                if (riskIndicators >= 3)
                {
                    score += riskIndicators * 0.05;
                }
                else if (riskIndicators <= 1 && score > 0.5)
                {
                    // 单一指标降低评分
                    score *= 0.6;
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private ScanResult CreateScanResult(string filePath, double staticScore)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = staticScore > HIGH_RISK_THRESHOLD,
                Confidence = staticScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Static"
            };

            if (result.IsInfected)
            {
                if (staticScore > 0.97)
                {
                    result.ThreatName = "静态分析检测到恶意文件";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "静态分析检测到可疑文件";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"静态评分: {staticScore:P}";
            }
            else if (staticScore > SUSPICIOUS_THRESHOLD)
            {
                result.ThreatName = "静态分析检测到潜在风险";
                result.ThreatType = "Risk";
                result.Severity = "Low";
                result.AdditionalInfo = $"静态评分: {staticScore:P}";
            }

            return result;
        }

        private string GetFileHash(string filePath)
        {
            if (fileHashCache.TryGetValue(filePath, out string cachedHash))
            {
                return cachedHash;
            }

            string hash = string.Empty;

            try
            {
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        byte[] hashBytes = md5.ComputeHash(stream);
                        hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                    }
                }

                fileHashCache[filePath] = hash;
            }
            catch
            {
                hash = string.Empty;
            }

            return hash;
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
        }

        public int GetCacheSize()
        {
            return fileHashCache.Count;
        }
    }
}
