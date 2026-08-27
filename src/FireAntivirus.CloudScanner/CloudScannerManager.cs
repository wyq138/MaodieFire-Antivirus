// 耄耋软件工作室 开发，严禁非法反编译
// 云扫描管理器 - 集成多引擎云查杀聚合器
// 架构: CloudScanAggregator (MalwareBazaar + VirusTotal + HybridAnalysis + OTX)
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.ThreatIntelligence;

namespace FireAntivirus.CloudScanner
{
    /// <summary>
    /// 云扫描管理器 - 真实可用的多引擎云查杀
    /// 聚合 70+ 国际杀软引擎 + 沙箱分析 + 威胁情报
    /// </summary>
    public class CloudScannerManager
    {
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private HttpClient _httpClient;
        private ThreatIntelligenceManager _tiManager;
        private CloudScanAggregator _aggregator;
        private CloudScanConfig _config;
        private bool _isOnline;
        private Dictionary<string, (CloudScanResult result, DateTime cached)> _localCache;
        private static readonly TimeSpan CacheExpiry = TimeSpan.FromHours(24);
        private readonly object _cacheLock = new object();

        /// <summary>
        /// AlienVault OTX API基础地址(无需API密钥,保留用于URL/IP/Domain查询)
        /// </summary>
        private const string OTX_BASE_URL = "https://otx.alienvault.com/api/v1";

        public CloudScannerManager(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus/1.0");
            _httpClient.Timeout = TimeSpan.FromSeconds(20);
            _localCache = new Dictionary<string, (CloudScanResult, DateTime)>();
            _tiManager = new ThreatIntelligenceManager();

            // 加载云查杀配置并初始化聚合器
            _config = CloudScanConfig.Load();
            _aggregator = new CloudScanAggregator(_config);
            _aggregator.ProgressChanged += (s, msg) =>
            {
                LogScanEvent("CloudScanProgress", string.Empty, msg);
            };

            _isOnline = _config.EnableCloudScan && _aggregator.IsAnyEngineEnabled;
        }

        /// <summary>
        /// 扫描文件 - 流程: 本地缓存 -> 云聚合器查询 -> 本地引擎扫描兜底
        /// </summary>
        public async Task<CloudScanResult> ScanFile(string filePath)
        {
            var result = new CloudScanResult
            {
                FilePath = filePath,
                ScanTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Success = false;
                    result.Message = "文件不存在";
                    return result;
                }

                // 计算文件哈希
                string fileHash = CalculateFileHash(filePath);
                result.FileHash = fileHash;

                // 1. 检查本地缓存
                var cached = CheckLocalCache(fileHash);
                if (cached != null)
                {
                    cached.FilePath = filePath;
                    cached.DetectionMethod = "(cached) " + cached.DetectionMethod;
                    return cached;
                }

                // 2. 云聚合器查询(多引擎并行)
                if (_isOnline && _aggregator != null)
                {
                    var cloudResult = await _aggregator.ScanFileAsync(filePath);

                    // 云引擎达到阈值时直接返回结果
                    if (cloudResult != null && cloudResult.Success && cloudResult.IsInfected)
                    {
                        CacheScanResult(fileHash, cloudResult);
                        return cloudResult;
                    }

                    // 云引擎未命中或可疑, 继续本地扫描以补充检测
                    if (cloudResult != null && cloudResult.Success)
                    {
                        result = cloudResult;
                    }
                }

                // 3. 本地引擎扫描兜底(用于未知文件)
                var localResult = await ScanFileLocally(filePath);
                if (localResult.IsInfected)
                {
                    // 本地引擎检测到威胁, 与云结果合并
                    result.IsInfected = true;
                    result.ThreatName = localResult.ThreatName;
                    result.ThreatType = localResult.ThreatType;
                    result.Confidence = Math.Max(result.Confidence, localResult.Confidence);
                    result.Severity = localResult.Severity;
                    result.DetectionMethod = "Local+Cloud";
                    result.Message = $"本地引擎检测: {localResult.ThreatName}";
                }
                else if (!result.IsInfected)
                {
                    result.IsInfected = false;
                    result.ThreatName = localResult.ThreatName;
                    result.Confidence = Math.Max(result.Confidence, 0.0);
                    result.DetectionMethod = "Local+Cloud";
                    result.Message = result.Message ?? "云查杀+本地引擎: 未发现威胁";
                }

                CacheScanResult(fileHash, result);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"扫描错误: {ex.Message}";
                LogScanEvent("CloudScanError", filePath, ex.Message);
            }

            return result;
        }

        /// <summary>
        /// 仅通过哈希查询云端(不读取文件, 速度最快)
        /// </summary>
        public async Task<CloudScanResult> ScanByHashAsync(string sha256Hash)
        {
            if (_aggregator == null || !_isOnline)
            {
                return new CloudScanResult
                {
                    FileHash = sha256Hash,
                    Success = false,
                    Message = "云查杀未启用"
                };
            }
            return await _aggregator.ScanHashAsync(sha256Hash);
        }

        /// <summary>
        /// 扫描URL - OTX URL信誉查询 + VirusTotal URL查询
        /// </summary>
        public async Task<CloudScanResult> ScanUrl(string url)
        {
            var result = new CloudScanResult
            {
                Url = url,
                ScanTime = DateTime.Now,
                DetectionMethod = "Cloud-URL"
            };

            try
            {
                if (!_isOnline)
                {
                    result.Success = false;
                    result.Message = "离线状态，无法进行云查询";
                    return result;
                }

                string cacheKey = ComputeStringSha256(url);
                var cached = CheckLocalCache(cacheKey);
                if (cached != null) return cached;

                bool detected = false;
                var messages = new List<string>();

                // 1. OTX URL查询
                try
                {
                    string encodedUrl = Convert.ToBase64String(
                        System.Text.Encoding.UTF8.GetBytes(url));
                    string apiUrl = $"{OTX_BASE_URL}/indicators/url/{encodedUrl}/general";
                    var response = await _httpClient.GetStringAsync(apiUrl);
                    var json = JObject.Parse(response);

                    int pulseCount = json["pulse_info"]?["count"]?.Value<int>() ?? 0;

                    if (pulseCount > 0)
                    {
                        detected = true;
                        result.ThreatName = "恶意URL";
                        result.ThreatType = "MaliciousURL";
                        result.Confidence = pulseCount >= 10 ? 0.90 : pulseCount >= 3 ? 0.75 : 0.60;
                        result.Severity = pulseCount >= 10 ? "High" : pulseCount >= 3 ? "Medium" : "Low";
                        messages.Add($"OTX: {pulseCount}条社区威胁报告");
                    }
                    else
                    {
                        messages.Add("OTX: 未发现威胁情报");
                    }
                }
                catch (Exception ex)
                {
                    messages.Add($"OTX查询失败: {ex.Message}");
                }

                // 2. VirusTotal URL查询(如果配置了API Key)
                if (_aggregator != null && _config.EnableVirusTotal && !string.IsNullOrEmpty(_config.VirusTotalApiKey))
                {
                    try
                    {
                        var vtClient = new VirusTotalClient(_config.VirusTotalApiKey);
                        using (vtClient)
                        {
                            var vtResult = await vtClient.QueryUrlAsync(url);
                            if (vtResult != null && vtResult.Detected)
                            {
                                detected = true;
                                if (string.IsNullOrEmpty(result.ThreatName))
                                    result.ThreatName = vtResult.ThreatName;
                                result.Confidence = Math.Max(result.Confidence, 0.85);
                                result.Severity = "High";
                                messages.Add($"VirusTotal: {vtResult.ThreatName}");
                            }
                            else if (vtResult != null)
                            {
                                messages.Add($"VirusTotal: {vtResult.ThreatName ?? "Clean"}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        messages.Add($"VirusTotal URL查询失败: {ex.Message}");
                    }
                }

                result.IsInfected = detected;
                result.Success = true;
                result.Message = string.Join(" | ", messages);

                CacheScanResult(cacheKey, result);

                LogScanEvent("CloudUrlScan", url,
                    $"Result: {(result.IsInfected ? "威胁" : "安全")}, {result.Message}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"URL查询失败: {ex.Message}";
                LogScanEvent("OTXUrlScanError", url, ex.Message);
            }

            return result;
        }

        /// <summary>
        /// 查询IP地址信誉
        /// </summary>
        public async Task<CloudScanResult> ScanIpAddress(string ipAddress)
        {
            var result = new CloudScanResult
            {
                FilePath = ipAddress,
                ScanTime = DateTime.Now,
                DetectionMethod = "Cloud-IP"
            };

            try
            {
                if (!_isOnline)
                {
                    result.Success = false;
                    result.Message = "离线状态";
                    return result;
                }

                string cacheKey = $"ip:{ipAddress}";
                var cached = CheckLocalCache(cacheKey);
                if (cached != null) return cached;

                string apiUrl = $"{OTX_BASE_URL}/indicators/IPv4/{ipAddress}/general";
                var response = await _httpClient.GetStringAsync(apiUrl);
                var json = JObject.Parse(response);

                int pulseCount = json["pulse_info"]?["count"]?.Value<int>() ?? 0;

                if (pulseCount > 0)
                {
                    result.IsInfected = true;
                    result.ThreatName = "恶意IP地址";
                    result.ThreatType = "MaliciousIP";
                    result.Confidence = pulseCount >= 10 ? 0.90 : pulseCount >= 3 ? 0.75 : 0.60;
                    result.Severity = pulseCount >= 10 ? "High" : pulseCount >= 3 ? "Medium" : "Low";
                    result.Message = $"OTX: {pulseCount}条威胁报告";
                }
                else
                {
                    result.IsInfected = false;
                    result.Message = "OTX: 未发现威胁";
                }

                result.Success = true;
                CacheScanResult(cacheKey, result);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"IP查询失败: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// 查询域名信誉
        /// </summary>
        public async Task<CloudScanResult> ScanDomain(string domain)
        {
            var result = new CloudScanResult
            {
                FilePath = domain,
                ScanTime = DateTime.Now,
                DetectionMethod = "Cloud-Domain"
            };

            try
            {
                if (!_isOnline)
                {
                    result.Success = false;
                    result.Message = "离线状态";
                    return result;
                }

                string cacheKey = $"domain:{domain}";
                var cached = CheckLocalCache(cacheKey);
                if (cached != null) return cached;

                string apiUrl = $"{OTX_BASE_URL}/indicators/domain/{domain}/general";
                var response = await _httpClient.GetStringAsync(apiUrl);
                var json = JObject.Parse(response);

                int pulseCount = json["pulse_info"]?["count"]?.Value<int>() ?? 0;

                if (pulseCount > 0)
                {
                    result.IsInfected = true;
                    result.ThreatName = "恶意域名";
                    result.ThreatType = "MaliciousDomain";
                    result.Confidence = pulseCount >= 10 ? 0.90 : pulseCount >= 3 ? 0.75 : 0.60;
                    result.Severity = pulseCount >= 10 ? "High" : pulseCount >= 3 ? "Medium" : "Low";
                    result.Message = $"OTX: {pulseCount}条威胁报告";
                }
                else
                {
                    result.IsInfected = false;
                    result.Message = "OTX: 未发现威胁";
                }

                result.Success = true;
                CacheScanResult(cacheKey, result);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"域名查询失败: {ex.Message}";
            }

            return result;
        }

        #region 本地引擎扫描与缓存

        private async Task<CloudScanResult> ScanFileLocally(string filePath)
        {
            var result = new CloudScanResult
            {
                FilePath = filePath,
                ScanTime = DateTime.Now,
                DetectionMethod = "Local Engine"
            };

            try
            {
                var localResult = _antivirusEngine.ScanFile(filePath);
                result.Success = true;
                result.IsInfected = localResult.IsInfected;
                result.ThreatName = localResult.ThreatName;
                result.ThreatType = localResult.ThreatType;
                result.Confidence = localResult.Confidence;
                result.Severity = localResult.Severity;
                result.Message = "本地引擎扫描完成";
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"本地扫描失败: {ex.Message}";
            }

            return result;
        }

        private CloudScanResult CheckLocalCache(string key)
        {
            lock (_cacheLock)
            {
                if (_localCache.TryGetValue(key, out var entry))
                {
                    if (DateTime.Now - entry.cached < CacheExpiry)
                        return entry.result;
                    _localCache.Remove(key);
                }
            }
            return null;
        }

        private void CacheScanResult(string key, CloudScanResult result)
        {
            lock (_cacheLock)
            {
                _localCache[key] = (result, DateTime.Now);
            }
        }

        private string CalculateFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                byte[] hashBytes = sha256.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        private static string ComputeStringSha256(string input)
        {
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        private void LogScanEvent(string type, string target, string details)
        {
            try
            {
                _dataManager?.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = type,
                    Message = target,
                    Details = details
                });
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudScannerManager.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 公开属性与方法

        /// <summary>是否在线(任一云引擎可用即视为在线)</summary>
        public bool IsOnline() => _isOnline;

        /// <summary>手动设置在线/离线</summary>
        public void SetOnline(bool online) => _isOnline = online;

        /// <summary>获取威胁情报管理器实例</summary>
        public ThreatIntelligenceManager GetThreatIntelligenceManager() => _tiManager;

        /// <summary>获取云查杀聚合器实例</summary>
        public CloudScanAggregator GetAggregator() => _aggregator;

        /// <summary>获取当前云查杀配置</summary>
        public CloudScanConfig GetConfig() => _config;

        /// <summary>更新云查杀配置(立即生效)</summary>
        public void UpdateConfig(CloudScanConfig newConfig)
        {
            _config = newConfig;
            _config.Save();
            _aggregator?.Dispose();
            _aggregator = new CloudScanAggregator(_config);
            _isOnline = _config.EnableCloudScan && _aggregator.IsAnyEngineEnabled;
        }

        /// <summary>获取已启用的云引擎列表</summary>
        public List<string> GetEnabledEngines()
        {
            var engines = new List<string>();
            if (_config.EnableMalwareBazaar) engines.Add("MalwareBazaar");
            if (_config.EnableOTX) engines.Add("AlienVault-OTX");
            if (_config.EnableVirusTotal && !string.IsNullOrEmpty(_config.VirusTotalApiKey))
                engines.Add($"VirusTotal(+70 engines)");
            if (_config.EnableHybridAnalysis && !string.IsNullOrEmpty(_config.HybridAnalysisApiKey))
                engines.Add("HybridAnalysis-Sandbox");
            return engines;
        }

        /// <summary>清理过期缓存</summary>
        public void CleanExpiredCache()
        {
            lock (_cacheLock)
            {
                var expiredKeys = new List<string>();
                foreach (var kv in _localCache)
                {
                    if (DateTime.Now - kv.Value.cached > CacheExpiry)
                        expiredKeys.Add(kv.Key);
                }
                foreach (var k in expiredKeys)
                    _localCache.Remove(k);
            }

            CloudScanAggregator.CleanExpiredCache();
        }

        #endregion
    }
}