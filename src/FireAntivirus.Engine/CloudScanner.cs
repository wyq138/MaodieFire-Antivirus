// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Engine
{
    /// <summary>
    /// 云扫描器 - 使用云端病毒库进行扫描
    /// 专业实现：多引擎查询、本地哈希库、VirusTotal API
    /// </summary>
    public class CloudScanner
    {
        private readonly HttpClient _httpClient;
        private readonly TimeSpan _timeout = TimeSpan.FromSeconds(30);
        private readonly int _maxFileSize = 32 * 1024 * 1024; // 32MB
        
        // 已知恶意哈希数据库（内置）
        private readonly Dictionary<string, MalwareSignature> _knownMaliciousHashes;
        
        // 可信哈希数据库
        private readonly HashSet<string> _trustedHashes;
        
        // API配置
        private string _virusTotalApiKey;
        private string _hybridAnalysisApiKey;
        private string _metaDefenderApiKey;

        public event Action<string, int> OnProgress;
        public event Action<CloudScanResult> OnResult;

        public bool IsEnabled { get; set; } = true;
        public bool IsAvailable { get; private set; }
        public bool UseLocalDatabase { get; set; } = true;
        public bool UseVirusTotal { get; set; } = true;
        public bool UseHybridAnalysis { get; set; } = false;
        public bool UseMetaDefender { get; set; } = false;

        public CloudScanner()
        {
            _httpClient = new HttpClient { Timeout = _timeout };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus/2.0");
            
            // 初始化内置恶意哈希数据库
            _knownMaliciousHashes = InitializeMaliciousHashes();
            _trustedHashes = InitializeTrustedHashes();
            
            CheckAvailability();
        }

        /// <summary>
        /// 初始化内置恶意哈希数据库
        /// 包含知名恶意软件的SHA256哈希
        /// </summary>
        private Dictionary<string, MalwareSignature> InitializeMaliciousHashes()
        {
            var hashes = new Dictionary<string, MalwareSignature>(StringComparer.OrdinalIgnoreCase);

            // 内置已知恶意哈希从外部 JSON 加载（ThreatData/known_hashes.json），
            // 不把家族名/哈希串编译进 DLL，避免杀软误报；真实大规模哈希由特征库更新器运行时注入 AddMaliciousHash。
            try
            {
                var file = Path.Combine(AppContext.BaseDirectory, "ThreatData", "known_hashes.json");
                if (File.Exists(file))
                {
                    var list = System.Text.Json.JsonSerializer.Deserialize<List<MalwareHashEntry>>(File.ReadAllText(file));
                    if (list != null)
                    {
                        foreach (var e in list)
                        {
                            if (!string.IsNullOrEmpty(e.Sha256))
                            {
                                hashes[e.Sha256] = new MalwareSignature
                                {
                                    ThreatName = e.ThreatName,
                                    ThreatType = e.ThreatType,
                                    Severity = e.Severity,
                                    FirstSeen = DateTime.TryParse(e.FirstSeen, out var dt) ? dt : DateTime.MinValue
                                };
                            }
                        }
                    }
                }
            }
            catch { /* 外置文件损坏时保持空集合，不崩扫描 */ }

            return hashes;
        }

        /// <summary>
        /// 初始化可信哈希数据库
        /// 动态获取Windows系统文件和知名安全软件的哈希
        /// </summary>
        private HashSet<string> InitializeTrustedHashes()
        {
            var trustedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            try
            {
                // 动态获取Windows系统文件哈希
                var system32Path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
                var trustedFiles = new[]
                {
                    "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll",
                    "ntdll.dll", "ole32.dll", "oleaut32.dll", "msvcrt.dll",
                    "gdi32.dll", "comdlg32.dll", "comctl32.dll", "ws2_32.dll",
                    "wininet.dll", "urlmon.dll", "crypt32.dll", "secur32.dll",
                    "rpcrt4.dll", "setupapi.dll", "winspool.drv", "version.dll",
                    "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe",
                    "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
                    "dwm.exe", "taskmgr.exe", "mmc.exe", "regedit.exe",
                    "cmd.exe", "powershell.exe", "notepad.exe", "calc.exe"
                };
                
                foreach (var file in trustedFiles)
                {
                    var filePath = Path.Combine(system32Path, file);
                    if (File.Exists(filePath))
                    {
                        try
                        {
                            using var sha256 = SHA256.Create();
                            using var stream = File.OpenRead(filePath);
                            var hash = sha256.ComputeHash(stream);
                            var hashStr = BitConverter.ToString(hash).Replace("-", "").ToLower();
                            trustedHashes.Add(hashStr);
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudScanner.cs 捕获异常", ex.Message); }
                    }
                }
                
                // 添加知名安全软件路径检测
                var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
                
                var avPaths = new[]
                {
                    Path.Combine(programFiles, "Windows Defender"),
                    Path.Combine(programFiles, "Microsoft Security Client"),
                    Path.Combine(programFilesX86 ?? programFiles, "Microsoft Security Client")
                };
                
                foreach (var avPath in avPaths)
                {
                    if (Directory.Exists(avPath))
                    {
                        foreach (var dllFile in Directory.GetFiles(avPath, "*.dll", SearchOption.TopDirectoryOnly))
                        {
                            try
                            {
                                using var sha256 = SHA256.Create();
                                using var stream = File.OpenRead(dllFile);
                                var hash = sha256.ComputeHash(stream);
                                var hashStr = BitConverter.ToString(hash).Replace("-", "").ToLower();
                                trustedHashes.Add(hashStr);
                            }
                            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudScanner.cs 捕获异常", ex.Message); }
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudScanner.cs 捕获异常", ex.Message); }
            
            return trustedHashes;
        }

        private async void CheckAvailability()
        {
            try
            {
                // 检查网络连接
                using var request = new HttpRequestMessage(HttpMethod.Head, "https://www.google.com");
                request.Headers.ConnectionClose = true;
                var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
                IsAvailable = response.IsSuccessStatusCode;
            }
            catch
            {
                IsAvailable = false;
            }
        }

        public async Task<CloudScanResult> ScanFileAsync(string filePath)
        {
            var result = new CloudScanResult
            {
                FilePath = filePath,
                ScanTime = DateTime.Now,
                IsMalicious = false,
                Detections = new List<CloudDetection>(),
                Warnings = new List<string>()
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Warnings.Add("文件不存在");
                    return result;
                }

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > _maxFileSize)
                {
                    result.Warnings.Add($"文件过大 ({fileInfo.Length / (1024 * 1024)} MB)，最大支持 32 MB");
                    return result;
                }

                OnProgress?.Invoke("计算文件哈希...", 10);

                // 计算哈希
                var hash = await ComputeFileHashAsync(filePath);
                result.FileHash = hash;

                // 1. 首先检查本地可信哈希库
                if (_trustedHashes.Contains(hash))
                {
                    result.IsMalicious = false;
                    result.Confidence = 1.0;
                    result.ScanMethod = "本地可信库";
                    result.Detections.Add(new CloudDetection
                    {
                        Engine = "TrustedDatabase",
                        ThreatName = "可信文件",
                        IsMalicious = false
                    });
                    OnResult?.Invoke(result);
                    return result;
                }

                // 2. 检查本地恶意哈希库
                if (UseLocalDatabase && _knownMaliciousHashes.TryGetValue(hash, out var signature))
                {
                    result.IsMalicious = true;
                    result.Confidence = 1.0;
                    result.ScanMethod = "本地恶意软件库";
                    result.Detections.Add(new CloudDetection
                    {
                        Engine = "LocalDatabase",
                        ThreatName = signature.ThreatName,
                        ThreatType = signature.ThreatType,
                        IsMalicious = true
                    });
                    OnResult?.Invoke(result);
                    return result;
                }

                OnProgress?.Invoke("查询云端数据库...", 30);

                // 3. 并发查询多个云端服务
                var detectionTasks = new List<Task<CloudDetection>>();
                
                if (UseVirusTotal && !string.IsNullOrEmpty(_virusTotalApiKey))
                {
                    detectionTasks.Add(QueryVirusTotalAsync(hash));
                }
                
                if (UseHybridAnalysis && !string.IsNullOrEmpty(_hybridAnalysisApiKey))
                {
                    detectionTasks.Add(QueryHybridAnalysisAsync(hash));
                }
                
                if (UseMetaDefender && !string.IsNullOrEmpty(_metaDefenderApiKey))
                {
                    detectionTasks.Add(QueryMetaDefenderAsync(hash));
                }

                if (detectionTasks.Count > 0)
                {
                    OnProgress?.Invoke("多引擎查询中...", 50);
                    
                    var detections = await Task.WhenAll(detectionTasks);
                    var validDetections = detections.Where(d => d != null).ToList();
                    
                    if (validDetections.Any(d => d.IsMalicious))
                    {
                        result.IsMalicious = true;
                        result.Detections.AddRange(validDetections.Where(d => d.IsMalicious));
                        result.Confidence = CalculateConfidence(validDetections);
                        result.ScanMethod = "多引擎云端分析";
                    }
                    else if (validDetections.Any())
                    {
                        result.IsMalicious = false;
                        result.Detections.AddRange(validDetections);
                        result.Confidence = 0.8;
                        result.ScanMethod = "云端分析";
                    }
                }
                else
                {
                    // 没有可用的云端服务，使用本地分析
                    result.ScanMethod = "本地分析";
                    result.Confidence = 0.5;
                    result.Warnings.Add("未配置云端API密钥，仅使用本地检测");
                }

                OnProgress?.Invoke("扫描完成", 100);
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"扫描错误: {ex.Message}");
                result.ScanMethod = "错误";
            }

            OnResult?.Invoke(result);
            return result;
        }

        private async Task<string> ComputeFileHashAsync(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = await Task.Run(() => sha256.ComputeHash(stream));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        /// <summary>
        /// 查询VirusTotal API
        /// </summary>
        private async Task<CloudDetection> QueryVirusTotalAsync(string hash)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, 
                    $"https://www.virustotal.com/api/v3/files/{hash}");
                request.Headers.Add("x-apikey", _virusTotalApiKey);

                var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                    return null;

                var json = await response.Content.ReadAsStringAsync();
                var vtResult = JsonSerializer.Deserialize<VirusTotalResponse>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (vtResult?.Data?.Attributes?.LastAnalysisStats != null)
                {
                    var stats = vtResult.Data.Attributes.LastAnalysisStats;
                    var malicious = stats.Malicious ?? 0;
                    var total = (stats.Malicious ?? 0) + (stats.Harmless ?? 0) + 
                                (stats.Suspicious ?? 0) + (stats.Undetected ?? 0);

                    return new CloudDetection
                    {
                        Engine = "VirusTotal",
                        ThreatName = malicious > 0 ? $"{malicious}/{total} 引擎检测为恶意" : "未检测到威胁",
                        IsMalicious = malicious > 5, // 至少5个引擎报毒才认为是恶意
                        Definition = $"检测率: {malicious}/{total}"
                    };
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"VirusTotal查询失败: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// 查询Hybrid Analysis API
        /// </summary>
        private async Task<CloudDetection> QueryHybridAnalysisAsync(string hash)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, 
                    $"https://www.hybrid-analysis.com/api/v2/summary/{hash}");
                request.Headers.Add("api-key", _hybridAnalysisApiKey);
                request.Headers.Add("user-agent", "FireAntivirus");

                var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                    return null;

                var json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var verdict = root.GetProperty("verdict").GetString();
                var threatScore = root.GetProperty("threat_score").GetInt32();

                return new CloudDetection
                {
                    Engine = "HybridAnalysis",
                    ThreatName = verdict ?? "未知",
                    IsMalicious = threatScore > 50,
                    Definition = $"威胁评分: {threatScore}"
                };
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"HybridAnalysis查询失败: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// 查询MetaDefender API
        /// </summary>
        private async Task<CloudDetection> QueryMetaDefenderAsync(string hash)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, 
                    $"https://api.metadefender.com/v4/hash/{hash}");
                request.Headers.Add("apikey", _metaDefenderApiKey);

                var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                    return null;

                var json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (root.TryGetProperty("scan_results", out var scanResults))
                {
                    var total = scanResults.GetProperty("total_detected_avs").GetInt32();
                    var totalAvs = scanResults.GetProperty("total_avs").GetInt32();

                    return new CloudDetection
                    {
                        Engine = "MetaDefender",
                        ThreatName = total > 0 ? $"{total} 个引擎检测为恶意" : "未检测到威胁",
                        IsMalicious = total > 3,
                        Definition = $"检测率: {total}/{totalAvs}"
                    };
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"MetaDefender查询失败: {ex.Message}");
            }

            return null;
        }

        private double CalculateConfidence(List<CloudDetection> detections)
        {
            if (detections == null || detections.Count == 0)
                return 0.0;

            var maliciousCount = detections.Count(d => d.IsMalicious);
            var ratio = (double)maliciousCount / detections.Count;
            
            // 至少需要2个引擎确认
            if (maliciousCount >= 2)
                return 0.9 + (ratio * 0.1);
            else if (maliciousCount == 1)
                return 0.7;
            
            return 0.3;
        }

        public async Task<List<CloudScanResult>> ScanFilesAsync(IEnumerable<string> filePaths)
        {
            var results = new ConcurrentBag<CloudScanResult>();
            var totalFiles = filePaths.Count();
            var processed = 0;

            // 并发扫描（最多5个并发）
            var options = new ParallelOptions { MaxDegreeOfParallelism = 5 };
            
            await Parallel.ForEachAsync(filePaths, options, async (filePath, cancellationToken) =>
            {
                var result = await ScanFileAsync(filePath);
                results.Add(result);
                
                var current = Interlocked.Increment(ref processed);
                OnProgress?.Invoke($"已扫描 {current}/{totalFiles} 个文件", (current * 100) / totalFiles);
            });

            return results.ToList();
        }

        public async Task<ReputationResult> GetFileReputation(string filePath)
        {
            var result = new ReputationResult
            {
                FilePath = filePath,
                Reputation = "未知",
                Score = 50
            };

            try
            {
                var hash = await ComputeFileHashAsync(filePath);

                // 检查本地数据库
                if (_knownMaliciousHashes.ContainsKey(hash))
                {
                    result.Reputation = "恶意";
                    result.Score = 0;
                    return result;
                }

                if (_trustedHashes.Contains(hash))
                {
                    result.Reputation = "可信";
                    result.Score = 100;
                    return result;
                }

                // 检查文件属性
                var fileInfo = new FileInfo(filePath);
                
                // 签名检查
                var isSigned = CheckSignature(filePath);
                if (isSigned)
                {
                    result.Score += 20;
                    result.Reputation = "已签名";
                }

                // 文件年龄
                if (fileInfo.CreationTime < DateTime.Now.AddYears(-1))
                {
                    result.Score += 10;
                }

                // 文件位置
                if (filePath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase))
                {
                    result.Score += 15;
                }

                // 确定最终信誉
                result.Reputation = result.Score switch
                {
                    >= 80 => "可信",
                    >= 60 => "良好",
                    >= 40 => "一般",
                    >= 20 => "可疑",
                    _ => "危险"
                };
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudScanner.cs 捕获异常", ex.Message); }

            return result;
        }

        private bool CheckSignature(string filePath)
        {
            try
            {
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
                return cert != null;
            }
            catch
            {
                return false;
            }
        }

        public void SetApiKey(string provider, string apiKey)
        {
            switch (provider.ToLower())
            {
                case "virustotal":
                    _virusTotalApiKey = apiKey;
                    break;
                case "hybridanalysis":
                    _hybridAnalysisApiKey = apiKey;
                    break;
                case "metadefender":
                    _metaDefenderApiKey = apiKey;
                    break;
            }
        }

        /// <summary>
        /// 添加自定义恶意哈希到本地数据库
        /// </summary>
        public void AddMaliciousHash(string sha256, string threatName, string threatType, string severity)
        {
            if (!_knownMaliciousHashes.ContainsKey(sha256))
            {
                _knownMaliciousHashes[sha256] = new MalwareSignature
                {
                    ThreatName = threatName,
                    ThreatType = threatType,
                    Severity = severity,
                    FirstSeen = DateTime.Now
                };
            }
        }

        /// <summary>
        /// 添加可信哈希到本地数据库
        /// </summary>
        public void AddTrustedHash(string sha256)
        {
            _trustedHashes.Add(sha256);
        }

        public int GetLocalDatabaseCount()
        {
            return _knownMaliciousHashes.Count;
        }

        public int GetTrustedDatabaseCount()
        {
            return _trustedHashes.Count;
        }
    }

    #region 数据模型

    public class CloudScanResult
    {
        public string FilePath { get; set; }
        public string FileHash { get; set; }
        public DateTime ScanTime { get; set; }
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
        public string ScanMethod { get; set; }
        public List<CloudDetection> Detections { get; set; }
        public List<string> Warnings { get; set; }
    }

    public class CloudDetection
    {
        public string Engine { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public bool IsMalicious { get; set; }
        public string Definition { get; set; }
    }

    public class ReputationResult
    {
        public string FilePath { get; set; }
        public string Reputation { get; set; }
        public int Score { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public int Prevalence { get; set; }
    }

    internal class MalwareSignature
    {
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public DateTime FirstSeen { get; set; }
    }

    /// <summary>外置已知哈希条目（ThreatData/known_hashes.json）</summary>
    public class MalwareHashEntry
    {
        public string Sha256 { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public string FirstSeen { get; set; }
    }

    internal class VirusTotalResponse
    {
        public VirusTotalData Data { get; set; }
    }

    internal class VirusTotalData
    {
        public VirusTotalAttributes Attributes { get; set; }
    }

    internal class VirusTotalAttributes
    {
        public VirusTotalAnalysisStats LastAnalysisStats { get; set; }
    }

    internal class VirusTotalAnalysisStats
    {
        public int? Malicious { get; set; }
        public int? Harmless { get; set; }
        public int? Suspicious { get; set; }
        public int? Undetected { get; set; }
    }

    #endregion
}