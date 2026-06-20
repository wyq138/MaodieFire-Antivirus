using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Engine.Analyzers
{
    public class FileAnalyzer
    {
        private DataManager dataManager;
        private Dictionary<string, string> fileHashCache;
        private Dictionary<string, List<string>> filePatterns;
        private Dictionary<string, List<string>> maliciousFileSignatures;
        private Dictionary<string, List<string>> suspiciousFileSignatures;
        private Dictionary<string, List<string>> benignFileSignatures;

        public FileAnalyzer()
        {
            dataManager = new DataManager();
            fileHashCache = new Dictionary<string, string>();
            InitializeFilePatterns();
            InitializeFileSignatures();
        }

        private void InitializeFilePatterns()
        {
            filePatterns = new Dictionary<string, List<string>>
            {
                { "Extensions", new List<string> {
                    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                    ".jse", ".wsf", ".hta", ".scr", ".com", ".pif", ".url", ".lnk",
                    ".msi", ".msp", ".mst", ".cab", ".zip", ".rar", ".7z", ".tar"
                }},
                { "Paths", new List<string> {
                    "C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Program Files",
                    "C:\\Program Files (x86)", "C:\\Users", "C:\\AppData", "C:\\Temp",
                    "C:\\Windows\\Temp", "C:\\Downloads", "C:\\Desktop"
                }},
                { "Names", new List<string> {
                    "svchost.exe", "explorer.exe", "winlogon.exe", "lsass.exe",
                    "csrss.exe", "smss.exe", "services.exe", "wininit.exe",
                    "taskhost.exe", "dwm.exe", "conhost.exe", "cmd.exe"
                }},
                { "Attributes", new List<string> {
                    "ReadOnly", "Hidden", "System", "Archive", "Compressed", "Encrypted"
                }}
            };
        }

        private void InitializeFileSignatures()
        {
            maliciousFileSignatures = new Dictionary<string, List<string>>
            {
                { "Malware", new List<string> {
                    "virus", "trojan", "worm", "ransomware", "spyware", "adware",
                    "keylogger", "backdoor", "bot", "rootkit", "miner", "pup"
                }},
                { "Signatures", new List<string> {
                    "MZ", "PE", "IMAGE_DOS_HEADER", "IMAGE_NT_HEADERS",
                    "UPX", "ASPack", "PECompact", "MPRESS", "FSG", "Petite"
                }},
                { "Patterns", new List<string> {
                    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess",
                    "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue"
                }}
            };

            suspiciousFileSignatures = new Dictionary<string, List<string>>
            {
                { "Extensions", new List<string> {
                    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js"
                }},
                { "Paths", new List<string> {
                    "C:\\Temp", "C:\\Windows\\Temp", "C:\\AppData\\Local\\Temp",
                    "C:\\Downloads", "C:\\Desktop", "C:\\Users\\Public"
                }},
                { "Attributes", new List<string> {
                    "Hidden", "System", "Compressed", "Encrypted"
                }}
            };

            benignFileSignatures = new Dictionary<string, List<string>>
            {
                { "Extensions", new List<string> {
                    ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
                    ".mp3", ".wav", ".mp4", ".avi", ".mov", ".wmv", ".flv"
                }},
                { "Paths", new List<string> {
                    "C:\\Program Files", "C:\\Program Files (x86)", "C:\\Windows",
                    "C:\\System32", "C:\\SysWOW64", "C:\\ProgramData"
                }},
                { "Names", new List<string> {
                    "notepad.exe", "wordpad.exe", "mspaint.exe", "calc.exe",
                    "explorer.exe", "cmd.exe", "powershell.exe", "regedit.exe"
                }}
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

                var fileProperties = GetFileProperties(filePath);
                var fileSignatures = GetFileSignatures(fileContent);
                var fileEntropy = CalculateEntropy(fileContent);
                var fileExtensions = GetFileExtensions(filePath);

                double fileScore = CalculateFileScore(
                    fileProperties, fileSignatures, fileEntropy, fileExtensions
                );

                var result = CreateFileScanResult(filePath, fileScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"文件分析检测到恶意文件: {filePath}", $"评分: {fileScore:P}", "FileAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"文件分析失败: {filePath}", ex.Message, "FileAnalyzer");
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
                dataManager.LogError($"目录分析失败: {directoryPath}", ex.Message, "FileAnalyzer");
            }

            return results;
        }

        private Dictionary<string, object> GetFileProperties(string filePath)
        {
            var properties = new Dictionary<string, object>();
            
            try
            {
                var fileInfo = new FileInfo(filePath);
                properties["Name"] = fileInfo.Name;
                properties["Length"] = fileInfo.Length;
                properties["CreationTime"] = fileInfo.CreationTime;
                properties["LastWriteTime"] = fileInfo.LastWriteTime;
                properties["LastAccessTime"] = fileInfo.LastAccessTime;
                properties["Attributes"] = fileInfo.Attributes;
                properties["DirectoryName"] = fileInfo.DirectoryName;
                properties["Extension"] = fileInfo.Extension;
            }
            catch
            {
                properties.Clear();
            }

            return properties;
        }

        private List<string> GetFileSignatures(byte[] fileContent)
        {
            var signatures = new List<string>();
            
            try
            {
                string fileContentStr = Encoding.UTF8.GetString(fileContent);
                
                foreach (var signatureCategory in maliciousFileSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (fileContentStr.Contains(signature, StringComparison.OrdinalIgnoreCase))
                        {
                            signatures.Add($"{signatureCategory.Key}: {signature}");
                        }
                    }
                }
            }
            catch
            {
                signatures.Clear();
            }

            return signatures;
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

        private List<string> GetFileExtensions(string filePath)
        {
            var extensions = new List<string>();
            
            try
            {
                string extension = Path.GetExtension(filePath);
                extensions.Add(extension);
            }
            catch
            {
                extensions.Clear();
            }

            return extensions;
        }

        private double CalculateFileScore(
            Dictionary<string, object> fileProperties,
            List<string> fileSignatures,
            double fileEntropy,
            List<string> fileExtensions
        )
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousFileSignatures(fileSignatures);
                score += AnalyzeSuspiciousFileProperties(fileProperties, fileExtensions);
                score += AnalyzeFileEntropy(fileEntropy);
                score += AnalyzeBenignFileProperties(fileProperties, fileExtensions);
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double AnalyzeMaliciousFileSignatures(List<string> fileSignatures)
        {
            double score = 0.0;

            foreach (var signature in fileSignatures)
            {
                score += 0.1;
            }

            return score;
        }

        private double AnalyzeSuspiciousFileProperties(Dictionary<string, object> fileProperties, List<string> fileExtensions)
        {
            double score = 0.0;

            if (fileProperties.ContainsKey("Extension"))
            {
                string extension = fileProperties["Extension"].ToString();
                foreach (var suspiciousExtension in suspiciousFileSignatures["Extensions"])
                {
                    if (extension.Equals(suspiciousExtension, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 0.2;
                        break;
                    }
                }
            }

            if (fileProperties.ContainsKey("DirectoryName"))
            {
                string directoryName = fileProperties["DirectoryName"].ToString();
                foreach (var suspiciousPath in suspiciousFileSignatures["Paths"])
                {
                    if (directoryName.Contains(suspiciousPath, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 0.2;
                        break;
                    }
                }
            }

            if (fileProperties.ContainsKey("Attributes"))
            {
                FileAttributes attributes = (FileAttributes)fileProperties["Attributes"];
                foreach (var suspiciousAttribute in suspiciousFileSignatures["Attributes"])
                {
                    if (attributes.ToString().Contains(suspiciousAttribute, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 0.1;
                    }
                }
            }

            return score;
        }

        private double AnalyzeFileEntropy(double fileEntropy)
        {
            double score = 0.0;

            if (fileEntropy > 7.0)
            {
                score += 0.3;
            }
            else if (fileEntropy > 6.0)
            {
                score += 0.15;
            }
            else if (fileEntropy < 2.0)
            {
                score += 0.05;
            }

            return score;
        }

        private double AnalyzeBenignFileProperties(Dictionary<string, object> fileProperties, List<string> fileExtensions)
        {
            double score = 0.0;

            if (fileProperties.ContainsKey("Extension"))
            {
                string extension = fileProperties["Extension"].ToString();
                foreach (var benignExtension in benignFileSignatures["Extensions"])
                {
                    if (extension.Equals(benignExtension, StringComparison.OrdinalIgnoreCase))
                    {
                        score -= 0.2;
                        break;
                    }
                }
            }

            if (fileProperties.ContainsKey("DirectoryName"))
            {
                string directoryName = fileProperties["DirectoryName"].ToString();
                foreach (var benignPath in benignFileSignatures["Paths"])
                {
                    if (directoryName.Contains(benignPath, StringComparison.OrdinalIgnoreCase))
                    {
                        score -= 0.2;
                        break;
                    }
                }
            }

            if (fileProperties.ContainsKey("Name"))
            {
                string name = fileProperties["Name"].ToString();
                foreach (var benignName in benignFileSignatures["Names"])
                {
                    if (name.Equals(benignName, StringComparison.OrdinalIgnoreCase))
                    {
                        score -= 0.2;
                        break;
                    }
                }
            }

            return score;
        }

        private ScanResult CreateFileScanResult(string filePath, double fileScore)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = fileScore > 0.85,
                Confidence = fileScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "File"
            };

            if (result.IsInfected)
            {
                if (fileScore > 0.95)
                {
                    result.ThreatName = "文件分析检测到恶意文件";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "文件分析检测到可疑文件";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"文件评分: {fileScore:P}";
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
