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

        // 具体、且良性脚本极少出现的脱混淆/绕行语法；命中数达到阈值才构成可靠的"混淆证据"，
        // 避免仅凭 "run/http" 这类普通词就把正常脚本误报。
        private static readonly string[] ObfuscationSignals =
        {
            "FromBase64String", "ToBase64String", "EncodedCommand", "-enc ",
            "Invoke-Expression", "IEX(", "Start-Process -WindowStyle Hidden", "-w hidden",
            "certutil -decode", "regsvr32 /s /u /i:", "rundll32 javascript:",
            "mshta", "powershell -w hidden", "-exec bypass", "ExecutionPolicy Bypass",
            "WebClient", "DownloadString", "DownloadFile", "Add-Type -TypeDefinition",
            "[Runtime.InteropServices]", "-replace '-', ''", "FromXml", "System.Net.Http",
            "${env:APPDATA}", "Split('char')", "char[])", "wmic process call create"
        };

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
                // 脱混淆证据：只有达到可靠阈值才显著加分
                score += AnalyzeObfuscation(scriptContent);
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

            // 只按"类别"计一次，避免同一类里多个普通词重复刷分
            var categories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var patternCategory in suspiciousScriptSignatures)
            {
                foreach (var pattern in patternCategory.Value)
                {
                    if (scriptContent.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        categories.Add(patternCategory.Key);
                        break; // 该类别命中一次即视为一份证据
                    }
                }
            }
            score += categories.Count * 0.06; // 例如 网络+文件+系统 三类才 0.18
            return score;
        }

        /// <summary>
        /// 脱混淆/绕行证据：对攻击型脚本（PowerShell/JS/BAT/HTA）这个信号比任何单个关键词都更可靠。
        /// 规则：独立混淆手法数量 ≥2 才开始加权，≥3 显著；叠加内嵌 base64 大块则再增强。
        /// </summary>
        private double AnalyzeObfuscation(string scriptContent)
        {
            if (string.IsNullOrWhiteSpace(scriptContent)) return 0.0;
            double score = 0.0;

            var distinct = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var sig in ObfuscationSignals)
            {
                if (scriptContent.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    distinct.Add(sig);
            }
            int count = distinct.Count;

            // base64 大块：长度 >40 的纯 base64 令牌
            int base64Blobs = 0;
            foreach (var token in scriptContent.Split(new[] { ' ', '\t', '\r', '\n', '"', '\'' , '(', ')', ';', ',', '=' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (token.Length > 40 && IsBase64(token)) base64Blobs++;
                if (base64Blobs >= 2) break;
            }

            // 长行占比（典型的编码混淆脚本：大量超长单行）
            int totalLines = 0, longLines = 0;
            var lines = scriptContent.Replace("\r\n", "\n").Split('\n');
            foreach (var line in lines)
            {
                totalLines++;
                if (line.Length > 500) longLines++;
            }
            double longRatio = totalLines > 0 ? (double)longLines / totalLines : 0.0;

            if (count >= 2) score += Math.Min(0.12, (count - 1) * 0.05);
            if (count >= 3) score += 0.05;
            if (base64Blobs >= 2) score += 0.08;
            if (longRatio > 0.5) score += 0.06;

            return Math.Min(0.25, score);
        }

        private static bool IsBase64(string s)
        {
            if (string.IsNullOrEmpty(s) || (s.Length % 4) != 0 || s.Length < 40) return false;
            int valid = 0;
            foreach (char c in s)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
                          c == '-' || c == '_';
                if (ok) valid++;
            }
            return valid >= (s.Length * 9) / 10;
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
