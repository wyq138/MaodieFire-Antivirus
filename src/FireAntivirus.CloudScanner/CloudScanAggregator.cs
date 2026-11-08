// 云查杀多引擎聚合器 - 对标国际大厂的多引擎云查杀架构
// 聚合 MalwareBazaar + VirusTotal(70+引擎) + HybridAnalysis沙箱 + AlienVault OTX
// 架构: Hash查询 -> 多引擎并行查询 -> 阈值判定 -> 可选上传VirusTotal深度分析
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using FireAntivirus.ThreatIntelligence;

namespace FireAntivirus.CloudScanner
{
    /// <summary>
    /// 云查杀多引擎聚合器 - 真实可用的国际大厂级云查杀架构
    /// </summary>
    public class CloudScanAggregator : IDisposable
    {
        private readonly CloudScanConfig _config;
        private readonly MalwareBazaarClient _malwareBazaar;
        private readonly VirusTotalClient _virusTotal;
        private readonly HybridAnalysisClient _hybridAnalysis;
        private readonly ThreatIntelligenceManager _otx;
        private readonly HttpClient _otxHttpClient;

        // 本地缓存(避免重复查询相同哈希)
        private static readonly Dictionary<string, (CloudScanResult result, DateTime cached)> _cache =
            new Dictionary<string, (CloudScanResult, DateTime)>();
        private static readonly object _cacheLock = new object();
        private static readonly TimeSpan CacheExpiry = TimeSpan.FromHours(24);

        /// <summary>聚合查询进度事件</summary>
        public event EventHandler<string> ProgressChanged;

        public CloudScanAggregator(CloudScanConfig config = null)
        {
            _config = config ?? CloudScanConfig.Load();
            _malwareBazaar = _config.EnableMalwareBazaar ? new MalwareBazaarClient() : null;
            _virusTotal = _config.EnableVirusTotal ? new VirusTotalClient(_config.VirusTotalApiKey) : null;
            _hybridAnalysis = _config.EnableHybridAnalysis ? new HybridAnalysisClient(_config.HybridAnalysisApiKey) : null;
            _otx = _config.EnableOTX ? new ThreatIntelligenceManager() : null;
            _otxHttpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(_config.TimeoutSeconds) };
            _otxHttpClient.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus/1.0");
        }

        /// <summary>当前配置</summary>
        public CloudScanConfig Configuration => _config;

        /// <summary>所有云查杀引擎是否就绪</summary>
        public bool IsAnyEngineEnabled =>
            _malwareBazaar != null || _virusTotal != null || _hybridAnalysis != null || _otx != null;

        /// <summary>
        /// 扫描文件 - 主入口
        /// 流程: 计算哈希 -> 缓存查询 -> 并行调用各云引擎 -> 阈值判定 -> (可选)上传VirusTotal
        /// </summary>
        public async Task<CloudScanResult> ScanFileAsync(string filePath)
        {
            var result = new CloudScanResult
            {
                FilePath = filePath,
                ScanTime = DateTime.Now,
                DetectionMethod = "Cloud-Aggregator"
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Success = false;
                    result.Message = "文件不存在";
                    return result;
                }

                // 计算SHA256(主流云引擎主键)
                string sha256 = await Task.Run(() => CalculateFileHash(filePath, "SHA256"));
                string md5 = await Task.Run(() => CalculateFileHash(filePath, "MD5"));

                result.FileHash = sha256;

                // 1. 检查本地缓存
                var cached = CheckCache(sha256);
                if (cached != null)
                {
                    cached.FilePath = filePath;
                    cached.DetectionMethod = "(cached) " + cached.DetectionMethod;
                    return cached;
                }

                // 2. 并行查询所有启用的云引擎
                var tasks = new List<Task>();
                var engineResults = new List<EngineDetection>();

                // MalwareBazaar
                Task<EngineDetection> mbTask = null;
                if (_malwareBazaar != null)
                {
                    mbTask = _malwareBazaar.QueryHashAsync(sha256);
                    tasks.Add(mbTask.ContinueWith(t =>
                    {
                        if (t.Result != null) lock (engineResults) engineResults.Add(t.Result);
                    }));
                }

                // VirusTotal (返回多个引擎)
                Task<List<EngineDetection>> vtTask = null;
                if (_virusTotal != null && _virusTotal.IsConfigured)
                {
                    vtTask = _virusTotal.QueryHashAsync(sha256);
                    tasks.Add(vtTask.ContinueWith(t =>
                    {
                        if (t.Result != null) lock (engineResults) engineResults.AddRange(t.Result);
                    }));
                }

                // HybridAnalysis
                Task<EngineDetection> haTask = null;
                if (_hybridAnalysis != null && _hybridAnalysis.IsConfigured)
                {
                    haTask = _hybridAnalysis.QueryHashAsync(sha256);
                    tasks.Add(haTask.ContinueWith(t =>
                    {
                        if (t.Result != null) lock (engineResults) engineResults.Add(t.Result);
                    }));
                }

                // OTX (使用内置 HttpClient 直接查询, 避免与 ThreatIntelligenceManager 缓存冲突)
                Task<EngineDetection> otxTask = null;
                if (_otx != null)
                {
                    otxTask = QueryOtxHashAsync(sha256);
                    tasks.Add(otxTask.ContinueWith(t =>
                    {
                        if (t.Result != null) lock (engineResults) engineResults.Add(t.Result);
                    }));
                }

                // 等待所有查询完成(最多30秒)
                if (tasks.Count > 0)
                {
                    var allTask = Task.WhenAll(tasks);
                    var completed = await Task.WhenAny(allTask, Task.Delay(_config.TimeoutSeconds * 1000));
                    if (completed != allTask)
                    {
                        ProgressChanged?.Invoke(this, "部分云引擎超时");
                    }
                }

                // 3. 聚合判定
                AggregateResults(result, engineResults);

                // 4. 若哈希未命中且配置允许上传, 则上传到 VirusTotal 进行深度扫描
                if (!result.IsInfected && _config.AutoUploadUnknownFiles
                    && _virusTotal != null && _virusTotal.IsConfigured
                    && result.TotalEngines > 0 && result.PositiveEngines == 0)
                {
                    bool allNotFound = engineResults.All(e =>
                        e.ThreatName == "NotFound" || e.ThreatName == "NotAnalyzed");
                    if (allNotFound)
                    {
                        ProgressChanged?.Invoke(this, "上传文件到VirusTotal深度分析...");
                        var analysisId = await _virusTotal.UploadFileAsync(filePath);
                        if (!string.IsNullOrEmpty(analysisId))
                        {
                            var uploadResults = await _virusTotal.GetAnalysisResultAsync(analysisId, maxWaitSeconds: 90);
                            if (uploadResults.Count > 0)
                            {
                                engineResults.AddRange(uploadResults);
                                AggregateResults(result, engineResults);
                            }
                        }
                    }
                }

                // 5. 写入缓存
                result.Success = true;
                if (result.IsInfected)
                {
                    result.Message = $"云查杀确认: {result.PositiveEngines}/{result.TotalEngines} 引擎检测到威胁 - {result.ThreatName}";
                }
                else if (result.TotalEngines > 0)
                {
                    result.Message = $"云查杀未发现威胁 ({result.TotalEngines} 引擎查询)";
                }
                else
                {
                    result.Message = "云查杀: 无可用引擎或全部超时";
                }

                AddToCache(sha256, result);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"云查杀错误: {ex.Message}";
                ProgressChanged?.Invoke(this, $"错误: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// 通过文件哈希直接查询(无需文件路径)
        /// </summary>
        public async Task<CloudScanResult> ScanHashAsync(string sha256Hash)
        {
            var result = new CloudScanResult
            {
                FileHash = sha256Hash,
                ScanTime = DateTime.Now,
                DetectionMethod = "Cloud-Aggregator"
            };

            try
            {
                var cached = CheckCache(sha256Hash);
                if (cached != null)
                {
                    cached.DetectionMethod = "(cached) " + cached.DetectionMethod;
                    return cached;
                }

                var engineResults = new List<EngineDetection>();
                var tasks = new List<Task>();

                if (_malwareBazaar != null)
                {
                    var t = _malwareBazaar.QueryHashAsync(sha256Hash);
                    tasks.Add(t.ContinueWith(r => { if (r.Result != null) lock (engineResults) engineResults.Add(r.Result); }));
                }
                if (_virusTotal != null && _virusTotal.IsConfigured)
                {
                    var t = _virusTotal.QueryHashAsync(sha256Hash);
                    tasks.Add(t.ContinueWith(r => { if (r.Result != null) lock (engineResults) engineResults.AddRange(r.Result); }));
                }
                if (_hybridAnalysis != null && _hybridAnalysis.IsConfigured)
                {
                    var t = _hybridAnalysis.QueryHashAsync(sha256Hash);
                    tasks.Add(t.ContinueWith(r => { if (r.Result != null) lock (engineResults) engineResults.Add(r.Result); }));
                }
                if (_otx != null)
                {
                    var t = QueryOtxHashAsync(sha256Hash);
                    tasks.Add(t.ContinueWith(r => { if (r.Result != null) lock (engineResults) engineResults.Add(r.Result); }));
                }

                if (tasks.Count > 0)
                    await Task.WhenAny(Task.WhenAll(tasks), Task.Delay(_config.TimeoutSeconds * 1000));

                AggregateResults(result, engineResults);
                result.Success = true;
                AddToCache(sha256Hash, result);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"云查杀错误: {ex.Message}";
            }
            return result;
        }

        /// <summary>
        /// 聚合各引擎结果, 形成最终判定
        /// </summary>
        private void AggregateResults(CloudScanResult result, List<EngineDetection> engineResults)
        {
            // 过滤掉错误结果(Timeout/Error)
            var validResults = engineResults
                .Where(e => e.ThreatName == null ||
                           (!e.ThreatName.StartsWith("Error", StringComparison.OrdinalIgnoreCase) &&
                            !e.ThreatName.Equals("Timeout", StringComparison.OrdinalIgnoreCase) &&
                            !e.ThreatName.Equals("RateLimit", StringComparison.OrdinalIgnoreCase) &&
                            !e.ThreatName.Equals("RateLimitExceeded", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            result.TotalEngines = validResults.Count;

            // 检测到威胁的引擎
            var positiveResults = validResults.Where(e => e.Detected).ToList();
            result.PositiveEngines = positiveResults.Count;

            foreach (var e in validResults)
            {
                result.EngineResults[e.EngineName] = e;
            }

            // 判定逻辑: 达到阈值则确认感染
            int threshold = Math.Max(1, _config.PositiveThreshold);

            if (result.PositiveEngines >= threshold)
            {
                result.IsInfected = true;

                // 选取威胁名(优先使用主流AV引擎的命名)
                var mainAV = positiveResults.FirstOrDefault(e =>
                    e.EngineName.Contains("Kaspersky") || e.EngineName.Contains("Bitdefender") ||
                    e.EngineName.Contains("Microsoft") || e.EngineName.Contains("ESET") ||
                    e.EngineName.Contains("Symantec") || e.EngineName.Contains("McAfee"));
                result.ThreatName = mainAV?.ThreatName ?? positiveResults.First().ThreatName ?? "Malware";
                result.ThreatType = "Malware";
                result.Confidence = Math.Min(1.0, (double)result.PositiveEngines / Math.Max(1, result.TotalEngines));
                result.Severity = result.PositiveEngines >= 10 ? "Critical"
                                : result.PositiveEngines >= 5 ? "High"
                                : result.PositiveEngines >= 3 ? "Medium"
                                : "Low";
            }
            else if (result.PositiveEngines > 0)
            {
                // 低于阈值但有引擎报毒 -> 可疑
                result.IsInfected = false; // 不直接判定为恶意, 让本地引擎决定
                result.ThreatName = $"Suspicious({result.PositiveEngines} engines)";
                result.Confidence = 0.3;
                result.Severity = "Low";
            }
            else
            {
                result.IsInfected = false;
                result.Confidence = result.TotalEngines > 0 ? 0.8 : 0.0;
                result.Severity = "Clean";
            }
        }

        /// <summary>
        /// 直接通过 HttpClient 查询 OTX 文件哈希
        /// </summary>
        private async Task<EngineDetection> QueryOtxHashAsync(string fileHash)
        {
            var detection = new EngineDetection
            {
                EngineName = "AlienVault-OTX",
                Method = "cloud-threat-intel"
            };

            try
            {
                string url = $"https://otx.alienvault.com/api/v1/indicators/file/{fileHash}/general";
                var response = await _otxHttpClient.GetStringAsync(url);
                var json = JObject.Parse(response);

                int pulseCount = json["pulse_info"]?["count"]?.Value<int>() ?? 0;
                var pulses = json["pulse_info"]?["pulses"] as JArray;
                var analysis = json["analysis"];

                if (pulseCount > 0 && pulses != null && pulses.Count > 0)
                {
                    detection.Detected = true;
                    detection.ThreatName = pulses[0]?["name"]?.ToString() ?? "OTX威胁情报命中";
                    detection.EngineVersion = $"pulses:{pulseCount}";
                }
                else if (analysis != null && analysis["malware"] != null && analysis["malware"].Value<bool>())
                {
                    detection.Detected = true;
                    detection.ThreatName = "OTX沙箱确认为恶意软件";
                }
                else
                {
                    detection.ThreatName = pulseCount == 0 ? "NotFound" : null;
                }
            }
            catch (TaskCanceledException)
            {
                detection.ThreatName = "Timeout";
            }
            catch (Exception ex)
            {
                detection.ThreatName = $"Error: {ex.Message}";
            }

            return detection;
        }

        #region 哈希计算

        private static string CalculateFileHash(string filePath, string algorithm)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var hashAlg = algorithm.Equals("MD5", StringComparison.OrdinalIgnoreCase)
                    ? (HashAlgorithm)MD5.Create()
                    : SHA256.Create();
                byte[] hashBytes = hashAlg.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        #endregion

        #region 缓存管理

        private static CloudScanResult CheckCache(string key)
        {
            if (string.IsNullOrEmpty(key)) return null;
            lock (_cacheLock)
            {
                if (_cache.TryGetValue(key, out var entry))
                {
                    if (DateTime.Now - entry.cached < CacheExpiry)
                    {
                        // 返回深拷贝避免外部修改
                        return CloneResult(entry.result);
                    }
                    _cache.Remove(key);
                }
            }
            return null;
        }

        private static void AddToCache(string key, CloudScanResult result)
        {
            if (string.IsNullOrEmpty(key) || result == null) return;
            lock (_cacheLock)
            {
                _cache[key] = (CloneResult(result), DateTime.Now);

                // 清理过期项
                if (_cache.Count > 10000)
                {
                    var expired = _cache.Where(k => DateTime.Now - k.Value.cached > CacheExpiry)
                                       .Select(k => k.Key).ToList();
                    foreach (var k in expired) _cache.Remove(k);
                }
            }
        }

        private static CloudScanResult CloneResult(CloudScanResult src)
        {
            return new CloudScanResult
            {
                FilePath = src.FilePath,
                Url = src.Url,
                FileHash = src.FileHash,
                Success = src.Success,
                IsInfected = src.IsInfected,
                ThreatName = src.ThreatName,
                Confidence = src.Confidence,
                Message = src.Message,
                ScanTime = src.ScanTime,
                DetectionMethod = src.DetectionMethod,
                ThreatType = src.ThreatType,
                Severity = src.Severity,
                TotalEngines = src.TotalEngines,
                PositiveEngines = src.PositiveEngines,
                EngineResults = new Dictionary<string, EngineDetection>(src.EngineResults)
            };
        }

        /// <summary>清理过期缓存</summary>
        public static void CleanExpiredCache()
        {
            lock (_cacheLock)
            {
                var expired = _cache.Where(k => DateTime.Now - k.Value.cached > CacheExpiry)
                                   .Select(k => k.Key).ToList();
                foreach (var k in expired) _cache.Remove(k);
            }
        }

        #endregion

        public void Dispose()
        {
            _malwareBazaar?.Dispose();
            _virusTotal?.Dispose();
            _hybridAnalysis?.Dispose();
            _otxHttpClient?.Dispose();
        }
    }
}
