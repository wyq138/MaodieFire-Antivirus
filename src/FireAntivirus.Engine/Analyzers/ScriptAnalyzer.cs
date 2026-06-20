using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Engine.Analyzers
{
    public class ScriptAnalyzer
    {
        private DataManager dataManager;
        private Dictionary<string, List<string>> scriptCache;
        private Dictionary<string, List<string>> scriptPatterns;
        private Dictionary<string, List<string>> maliciousScriptSignatures;
        private Dictionary<string, List<string>> suspiciousScriptSignatures;
        private Dictionary<string, List<string>> benignScriptSignatures;

        public ScriptAnalyzer()
        {
            dataManager = new DataManager();
            scriptCache = new Dictionary<string, List<string>>();
            InitializeScriptPatterns();
            InitializeScriptSignatures();
        }

        private void InitializeScriptPatterns()
        {
            scriptPatterns = new Dictionary<string, List<string>>
            {
                { "Extensions", new List<string> {
                    ".js", ".jse", ".wsf", ".hta", ".vbs", ".ps1", ".bat", ".cmd"
                }},
                { "Keywords", new List<string> {
                    "eval", "exec", "execute", "run", "shell", "command", "process", "spawn",
                    "require", "import", "load", "include", "source", "dot", "read", "write"
                }},
                { "Functions", new List<string> {
                    "WScript.Shell", "Shell.Application", "CreateObject", "GetObject",
                    "New-Object", "Invoke-Command", "Start-Process", "Get-Process"
                }},
                { "Methods", new List<string> {
                    "Run", "Exec", "Execute", "CreateProcess", "ShellExecute", "WinExec"
                }}
            };
        }

        private void InitializeScriptSignatures()
        {
            maliciousScriptSignatures = new Dictionary<string, List<string>>
            {
                { "Malware", new List<string> {
                    "virus", "trojan", "worm", "ransomware", "spyware", "adware",
                    "keylogger", "backdoor", "bot", "rootkit", "miner", "pup"
                }},
                { "Injection", new List<string> {
                    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess"
                }},
                { "Network", new List<string> {
                    "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest"
                }},
                { "Registry", new List<string> {
                    "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue"
                }},
                { "File", new List<string> {
                    "DeleteFile", "MoveFile", "CopyFile", "CreateFile"
                }}
            };

            suspiciousScriptSignatures = new Dictionary<string, List<string>>
            {
                { "Execution", new List<string> {
                    "eval", "exec", "execute", "run", "shell", "command", "process", "spawn"
                }},
                { "Network", new List<string> {
                    "fetch", "axios", "http", "https", "request", "socket", "tcp", "udp"
                }},
                { "File", new List<string> {
                    "fs", "File", "Stream", "Reader", "Writer", "Binary"
                }},
                { "System", new List<string> {
                    "system", "env", "os", "process", "child_process", "net"
                }}
            };

            benignScriptSignatures = new Dictionary<string, List<string>>
            {
                { "Functions", new List<string> {
                    "console.log", "alert", "confirm", "prompt", "document.write", "document.getElementById"
                }},
                { "Methods", new List<string> {
                    "toString", "parseInt", "parseFloat", "Math.random", "Array.push", "Array.pop"
                }},
                { "Objects", new List<string> {
                    "window", "document", "navigator", "screen", "location", "history", "localStorage", "sessionStorage"
                }},
                { "Libraries", new List<string> {
                    "jQuery", "React", "Angular", "Vue", "Bootstrap", "Tailwind", "Express", "Node"
                }}
            };
        }

        public List<ScanResult> AnalyzeScript(string filePath)
        {
            var results = new List<ScanResult>();
            
            if (!File.Exists(filePath))
            {
                return results;
            }

            try
            {
                var scriptContent = File.ReadAllText(filePath);
                var scriptProperties = GetScriptProperties(filePath);
                var scriptSignatures = GetScriptSignatures(scriptContent);
                var scriptKeywords = GetScriptKeywords(scriptContent);

                double scriptScore = CalculateScriptScore(
                    scriptContent, scriptProperties, scriptSignatures, scriptKeywords
                );

                var result = CreateScriptScanResult(filePath, scriptScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"脚本分析检测到恶意脚本: {filePath}", $"评分: {scriptScore:P}", "ScriptAnalyzer");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"脚本分析失败: {filePath}", ex.Message, "ScriptAnalyzer");
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
                        if (scriptPatterns["Extensions"].Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
                        {
                            var fileResults = AnalyzeScript(file);
                            results.AddRange(fileResults);
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"目录脚本分析失败: {directoryPath}", ex.Message, "ScriptAnalyzer");
            }

            return results;
        }

        private Dictionary<string, object> GetScriptProperties(string filePath)
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
                properties["Extension"] = fileInfo.Extension;
                properties["DirectoryName"] = fileInfo.DirectoryName;
            }
            catch
            {
                properties.Clear();
            }

            return properties;
        }

        private List<string> GetScriptSignatures(string scriptContent)
        {
            var signatures = new List<string>();
            
            try
            {
                foreach (var signatureCategory in maliciousScriptSignatures)
                {
                    foreach (var signature in signatureCategory.Value)
                    {
                        if (scriptContent.Contains(signature, StringComparison.OrdinalIgnoreCase))
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

        private List<string> GetScriptKeywords(string scriptContent)
        {
            var keywords = new List<string>();
            
            try
            {
                foreach (var keywordCategory in scriptPatterns)
                {
                    foreach (var keyword in keywordCategory.Value)
                    {
                        if (scriptContent.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            keywords.Add($"{keywordCategory.Key}: {keyword}");
                        }
                    }
                }
            }
            catch
            {
                keywords.Clear();
            }

            return keywords;
        }

        private double CalculateScriptScore(
            string scriptContent,
            Dictionary<string, object> scriptProperties,
            List<string> scriptSignatures,
            List<string> scriptKeywords
        )
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousScriptSignatures(scriptSignatures);
                score += AnalyzeSuspiciousScriptPatterns(scriptContent);
                score += AnalyzeScriptKeywords(scriptKeywords);
                score += AnalyzeBenignScriptPatterns(scriptContent);
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double AnalyzeMaliciousScriptSignatures(List<string> scriptSignatures)
        {
            double score = 0.0;

            foreach (var signature in scriptSignatures)
            {
                score += 0.1;
            }

            return score;
        }

        private double AnalyzeSuspiciousScriptPatterns(string scriptContent)
        {
            double score = 0.0;

            foreach (var patternCategory in suspiciousScriptSignatures)
            {
                foreach (var pattern in patternCategory.Value)
                {
                    if (scriptContent.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 0.05;
                    }
                }
            }

            return score;
        }

        private double AnalyzeScriptKeywords(List<string> scriptKeywords)
        {
            double score = 0.0;

            foreach (var keyword in scriptKeywords)
            {
                score += 0.02;
            }

            return score;
        }

        private double AnalyzeBenignScriptPatterns(string scriptContent)
        {
            double score = 0.0;

            foreach (var patternCategory in benignScriptSignatures)
            {
                foreach (var pattern in patternCategory.Value)
                {
                    if (scriptContent.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        score -= 0.03;
                    }
                }
            }

            return score;
        }

        private ScanResult CreateScriptScanResult(string filePath, double scriptScore)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = scriptScore > 0.85,
                Confidence = scriptScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Script"
            };

            if (result.IsInfected)
            {
                if (scriptScore > 0.95)
                {
                    result.ThreatName = "脚本分析检测到恶意脚本";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "脚本分析检测到可疑脚本";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"脚本评分: {scriptScore:P}";
            }

            return result;
        }

        public void ClearCache()
        {
            scriptCache.Clear();
        }

        public int GetCacheSize()
        {
            return scriptCache.Count;
        }
    }
}
