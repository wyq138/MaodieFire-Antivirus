using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.CloudSecurity
{
    /// <summary>
    /// 云安全管理器 - 基于 AlienVault OTX 免费威胁情报平台
    /// 提供: 文件哈希查询、IP/域名/URL 信誉查询、本地结果缓存
    /// OTX无需API密钥, 24小时缓存以避免频繁请求
    /// </summary>
    public class CloudSecurityManager
    {
        private HttpClient _httpClient;
        private int _timeout = 15000;
        private int _maxRetries = 2;
        private int _retryDelay = 1500;
        private int _cacheExpirationSeconds = 86400; // 24小时
        private string _cacheDirectory;
        private Dictionary<string, CloudCacheItem> _memoryCache;
        private readonly object _cacheLock = new object();

        /// <summary>OTX API 基础地址</summary>
        private const string OTX_BASE = "https://otx.alienvault.com/api/v1";

        public event EventHandler<CloudSecurityEventArgs> CloudSecurityEvent;

        public CloudSecurityManager()
        {
            _memoryCache = new Dictionary<string, CloudCacheItem>();
            _cacheDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireAntivirus", "CloudCache");
            InitHttpClient();
            InitCacheDir();
        }

        #region 初始化

        private void InitHttpClient()
        {
            _httpClient = new HttpClient(new HttpClientHandler())
            {
                Timeout = TimeSpan.FromMilliseconds(_timeout)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus/2.0");
        }

        private void InitCacheDir()
        {
            if (!Directory.Exists(_cacheDirectory))
                Directory.CreateDirectory(_cacheDirectory);
        }

        #endregion

        #region OTX 威胁情报查询

        /// <summary>
        /// 查询文件哈希信誉 (OTX)
        /// </summary>
        public async Task<ThreatIntelResult> QueryFileHashAsync(string sha256Hash)
        {
            return await QueryOtxAsync("file", sha256Hash.ToLowerInvariant());
        }

        /// <summary>
        /// 查询IP地址信誉 (OTX)
        /// </summary>
        public async Task<ThreatIntelResult> QueryIpAsync(string ipAddress)
        {
            return await QueryOtxAsync("IPv4", ipAddress);
        }

        /// <summary>
        /// 查询域名信誉 (OTX)
        /// </summary>
        public async Task<ThreatIntelResult> QueryDomainAsync(string domain)
        {
            return await QueryOtxAsync("domain", domain);
        }

        /// <summary>
        /// 查询URL信誉 (OTX)
        /// </summary>
        public async Task<ThreatIntelResult> QueryUrlAsync(string url)
        {
            string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(url));
            return await QueryOtxAsync("url", encoded);
        }

        /// <summary>
        /// 通用OTX查询
        /// </summary>
        private async Task<ThreatIntelResult> QueryOtxAsync(string indicatorType, string indicatorValue)
        {
            string cacheKey = $"otx_{indicatorType}_{SHA256Str(indicatorValue)}";

            // 检查缓存
            var cached = GetFromCache<ThreatIntelResult>(cacheKey);
            if (cached != null)
            {
                cached.FromCache = true;
                return cached;
            }

            var result = new ThreatIntelResult
            {
                Indicator = indicatorValue,
                IndicatorType = indicatorType,
                QueryTime = DateTime.UtcNow
            };

            try
            {
                string url = $"{OTX_BASE}/indicators/{indicatorType}/{indicatorValue}/general";
                string response = await RetryHttpGetAsync(url);

                var json = Newtonsoft.Json.Linq.JObject.Parse(response);
                int pulseCount = json["pulse_info"]?["count"]?.Value<int>() ?? 0;

                result.PulseCount = pulseCount;
                result.Exists = pulseCount > 0;
                result.Severity = pulseCount >= 10 ? ThreatSeverity.High :
                                  pulseCount >= 3 ? ThreatSeverity.Medium :
                                  pulseCount > 0 ? ThreatSeverity.Low :
                                  ThreatSeverity.Clean;
                result.Confidence = pulseCount >= 10 ? 90 : pulseCount >= 3 ? 70 : pulseCount > 0 ? 50 : 0;

                if (pulseCount > 0)
                {
                    var pulses = json["pulse_info"]?["pulses"] as Newtonsoft.Json.Linq.JArray;
                    result.Description = $"OTX社区报告 {pulseCount} 条威胁情报";
                    if (pulses != null && pulses.Count > 0)
                        result.ThreatName = pulses[0]?["name"]?.ToString() ?? "威胁情报命中";
                }
                else
                {
                    result.Description = "OTX社区未发现威胁情报";
                }

                result.Success = true;
                AddToCache(cacheKey, result);

                FireEvent(CloudSecurityEventType.ScanComplete,
                    $"OTX查询完成: {indicatorType}={indicatorValue}, 结果={(result.Exists ? "威胁" : "安全")}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                result.Severity = ThreatSeverity.Unknown;
                FireEvent(CloudSecurityEventType.Error, $"OTX查询失败: {ex.Message}");
            }

            return result;
        }

        #endregion

        #region HTTP 请求与重试

        private async Task<string> RetryHttpGetAsync(string url)
        {
            int attempt = 0;
            Exception lastEx = null;

            while (attempt < _maxRetries)
            {
                try
                {
                    return await _httpClient.GetStringAsync(url);
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                    attempt++;
                    if (attempt < _maxRetries)
                        await Task.Delay(_retryDelay * attempt);
                }
            }

            throw lastEx ?? new Exception("Request failed");
        }

        #endregion

        #region 缓存管理

        private T GetFromCache<T>(string key) where T : class
        {
            lock (_cacheLock)
            {
                if (_memoryCache.TryGetValue(key, out var item))
                {
                    if (DateTime.UtcNow < item.Expiration)
                        return item.Value as T;
                    _memoryCache.Remove(key);
                }
            }

            // 检查磁盘缓存
            var cacheFile = Path.Combine(_cacheDirectory, $"{SHA256Str(key)}.cache");
            if (File.Exists(cacheFile))
            {
                try
                {
                    var json = File.ReadAllText(cacheFile, Encoding.UTF8);
                    var value = Newtonsoft.Json.JsonConvert.DeserializeObject<T>(json);
                    _memoryCache[key] = new CloudCacheItem
                    {
                        Value = value,
                        Expiration = DateTime.UtcNow.AddSeconds(_cacheExpirationSeconds)
                    };
                    return value;
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudSecurityManager.cs 捕获异常", ex.Message); }
            }

            return null;
        }

        private void AddToCache(string key, object value)
        {
            lock (_cacheLock)
            {
                _memoryCache[key] = new CloudCacheItem
                {
                    Value = value,
                    Expiration = DateTime.UtcNow.AddSeconds(_cacheExpirationSeconds)
                };
            }

            // 持久化到磁盘
            try
            {
                var cacheFile = Path.Combine(_cacheDirectory, $"{SHA256Str(key)}.cache");
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(value);
                File.WriteAllText(cacheFile, json, Encoding.UTF8);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudSecurityManager.cs 捕获异常", ex.Message); }
        }

        /// <summary>
        /// 清除所有缓存
        /// </summary>
        public void ClearCache()
        {
            lock (_cacheLock)
            {
                _memoryCache.Clear();
            }

            try
            {
                foreach (var f in Directory.GetFiles(_cacheDirectory, "*.cache"))
                    File.Delete(f);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CloudSecurityManager.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 配置方法

        public void SetTimeout(int milliseconds)
        {
            _timeout = milliseconds;
            _httpClient.Timeout = TimeSpan.FromMilliseconds(milliseconds);
        }

        public void SetRetryPolicy(int maxRetries, int retryDelayMs)
        {
            _maxRetries = maxRetries;
            _retryDelay = retryDelayMs;
        }

        public void SetCacheExpirationSeconds(int seconds) => _cacheExpirationSeconds = seconds;

        #endregion

        #region 事件与工具

        private void FireEvent(CloudSecurityEventType type, string message)
        {
            CloudSecurityEvent?.Invoke(this, new CloudSecurityEventArgs(type, message));
        }

        private static string SHA256Str(string input)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        #endregion
    }

    #region 数据模型

    public class ThreatIntelResult
    {
        public string Indicator { get; set; }
        public string IndicatorType { get; set; }
        public bool Exists { get; set; }
        public int PulseCount { get; set; }
        public ThreatSeverity Severity { get; set; } = ThreatSeverity.Unknown;
        public int Confidence { get; set; }
        public string ThreatName { get; set; }
        public string Description { get; set; }
        public string Error { get; set; }
        public bool Success { get; set; }
        public bool FromCache { get; set; }
        public DateTime QueryTime { get; set; }
        public bool IsThreat => Severity == ThreatSeverity.High || Severity == ThreatSeverity.Medium;
    }

    public enum ThreatSeverity
    {
        Unknown = 0,
        Clean = 1,
        Low = 2,
        Medium = 3,
        High = 4
    }

    public class CloudCacheItem
    {
        public object Value { get; set; }
        public DateTime Expiration { get; set; }
    }

    public class CloudSecurityEventArgs : EventArgs
    {
        public CloudSecurityEventType EventType { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }

        public CloudSecurityEventArgs(CloudSecurityEventType eventType, string message)
        {
            EventType = eventType;
            Message = message;
            Timestamp = DateTime.Now;
        }
    }

    public enum CloudSecurityEventType
    {
        Information,
        Warning,
        Error,
        Success,
        ScanComplete,
        ThreatDetected
    }

    #endregion
}