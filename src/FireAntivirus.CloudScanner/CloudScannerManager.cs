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
    /// 云扫描管理器 - 基于 AlienVault OTX 威胁情报API
    /// 免费使用,无需API密钥。OTX是全球最大的开放威胁情报社区之一。
    /// </summary>
    public class CloudScannerManager
    {
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private HttpClient _httpClient;
        private ThreatIntelligenceManager _tiManager;
        private bool _isOnline;
        private Dictionary<string, (CloudScanResult result, DateTime cached)> _localCache;
        private static readonly TimeSpan CacheExpiry = TimeSpan.FromHours(24);
        private readonly object _cacheLock = new object();

        /// <summary>
        /// AlienVault OTX API基础地址(无需API密钥)
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

            // OTX无需API密钥,默认在线
            _isOnline = true;
        }

        /// <summary>
        /// 扫描文件 - 流程: 本地缓存 → OTX哈希查询 → 本地引擎扫描
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
                    return cached;
                }

                // 2. OTX威胁情报查询
                if (_isOnline)
                {
                    var otxResult = await QueryOtxFileHashAsync(filePath, fileHash);
                    if (otxResult.Success)
                    {
                        CacheScanResult(fileHash, otxResult);
                        return otxResult;
                    }
                }

                // 3. 本地引擎扫描
                result = await ScanFileLocally(filePath);
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
        /// 通过OTX API查询文件哈希的信誉
        /// </summary>
        private async Task<CloudScanResult> QueryOtxFileHashAsync(string filePath, string fileHash)
        {
            var result = new CloudScanResult
            {
                FilePath = filePath,
                FileHash = fileHash,
                ScanTime = DateTime.Now,
                DetectionMethod = "OTX Cloud"
            };

            try
            {
                string url = $"{OTX_BASE_URL}/indicators/file/{fileHash}/general";
                var response = await _httpClient.GetStringAsync(url);
                var json = JObject.Parse(response);

                int pulseCount = json["pulse_info"]?["count"]?.Value<int>() ?? 0;
                var pulses = json["pulse_info"]?["pulses"] as JArray;
                var analysis = json["analysis"];

                if (pulseCount > 0 && pulses != null && pulses.Count > 0)
                {
                    var firstPulse = pulses[0];
                    result.IsInfected = true;
                    result.ThreatName = firstPulse["name"]?.ToString() ?? "OTX威胁情报命中";
                    result.ThreatType = "Malware";
                    result.Confidence = pulseCount >= 10 ? 0.95 : pulseCount >= 3 ? 0.80 : 0.65;
                    result.Severity = pulseCount >= 10 ? "High" : pulseCount >= 3 ? "Medium" : "Low";
                    result.Message = $"OTX: {pulseCount}条社区威胁报告";
                    result.Success = true;
                }
                else
                {
                    // 检查是否有OTX沙箱分析
                    if (analysis != null && analysis["malware"] != null && analysis["malware"].Value<bool>())
                    {
                        result.IsInfected = true;
                        result.ThreatName = "OTX沙箱确认为恶意软件";
                        result.ThreatType = "Malware";
                        result.Confidence = 0.95;
                        result.Severity = "High";
                        result.Message = "OTX沙箱分析: 恶意";
                        result.Success = true;
                    }
                    else
                    {
                        result.IsInfected = false;
                        result.Confidence = 0.0;
                        result.Message = "OTX: 未发现威胁情报";
                        result.Success = true;
                    }
                }

                LogScanEvent("OTXCloudScan", filePath,
                    $"Hash: {fileHash}, Pulses: {pulseCount}, " +
                    $"Result: {(result.IsInfected ? "威胁" : "安全")}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"OTX查询失败: {ex.Message}";
                LogScanEvent("OTXCloudScanError", filePath, ex.Message);
            }

            return result;
        }

        /// <summary>
        /// 扫描URL - OTX URL信誉查询
        /// </summary>
        public async Task<CloudScanResult> ScanUrl(string url)
        {
            var result = new CloudScanResult
            {
                Url = url,
                ScanTime = DateTime.Now,
                DetectionMethod = "OTX URL"
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

                // OTX URL查询需要base64编码
                string encodedUrl = Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes(url));
                string apiUrl = $"{OTX_BASE_URL}/indicators/url/{encodedUrl}/general";
                var response = await _httpClient.GetStringAsync(apiUrl);
                var json = JObject.Parse(response);

                int pulseCount = json["pulse_info"]?["count"]?.Value<int>() ?? 0;

                if (pulseCount > 0)
                {
                    result.IsInfected = true;
                    result.ThreatName = "恶意URL";
                    result.ThreatType = "MaliciousURL";
                    result.Confidence = pulseCount >= 10 ? 0.90 : pulseCount >= 3 ? 0.75 : 0.60;
                    result.Severity = pulseCount >= 10 ? "High" : pulseCount >= 3 ? "Medium" : "Low";
                    result.Message = $"OTX: {pulseCount}条社区威胁报告";
                }
                else
                {
                    result.IsInfected = false;
                    result.Confidence = 0.0;
                    result.Message = "OTX: 未发现威胁情报";
                }

                result.Success = true;
                CacheScanResult(cacheKey, result);

                LogScanEvent("OTXUrlScan", url,
                    $"Pulses: {pulseCount}, Result: {(result.IsInfected ? "威胁" : "安全")}");
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
                DetectionMethod = "OTX IP"
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
                DetectionMethod = "OTX Domain"
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
            catch { }
        }

        #endregion

        #region 公开属性与方法

        /// <summary>是否在线(OTX免费且通常可用)</summary>
        public bool IsOnline() => _isOnline;

        /// <summary>手动设置在线/离线</summary>
        public void SetOnline(bool online) => _isOnline = online;

        /// <summary>获取威胁情报管理器实例</summary>
        public ThreatIntelligenceManager GetThreatIntelligenceManager() => _tiManager;

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
        }

        #endregion
    }
}
