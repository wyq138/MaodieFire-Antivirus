// VirusTotal v3 客户端 - 接入 70+ 国际杀毒引擎聚合查询
// API 文档: https://docs.virustotal.com/reference/api
// 免费 API Key 额度: 每分钟 4 次请求, 每日 500 次
// 用户可在 https://www.virustotal.com/gui/my-apikey 免费申请
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace FireAntivirus.CloudScanner
{
    /// <summary>
    /// VirusTotal v3 API 客户端
    /// 聚合 70+ 国际杀软引擎(Kaspersky/Bitdefender/ESET/McAfee/ Symantec/Microsoft/Avast/AVG等)
    /// </summary>
    public class VirusTotalClient : IDisposable
    {
        private const string BaseUrl = "https://www.virustotal.com/api/v3";
        private const int RateLimitPerMinute = 4; // 免费额度限制
        private const int RateLimitPerDay = 500;

        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

        // 速率限制跟踪
        private static readonly object _rateLock = new object();
        private static readonly Queue<DateTime> _requestTimestamps = new Queue<DateTime>();
        private static int _dailyCount = 0;
        private static DateTime _dailyResetDate = DateTime.UtcNow.Date;

        public bool IsConfigured => !string.IsNullOrWhiteSpace(_apiKey);

        /// <summary>
        /// 构造 VirusTotal 客户端
        /// </summary>
        /// <param name="apiKey">VirusTotal API Key, 可在 https://www.virustotal.com/gui/my-apikey 免费申请</param>
        public VirusTotalClient(string apiKey)
        {
            _apiKey = apiKey ?? string.Empty;
            _httpClient = new HttpClient
            {
                Timeout = DefaultTimeout
            };
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus/1.0");
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
        }

        /// <summary>
        /// 通过文件哈希查询 VirusTotal (无需上传文件, 速度快, 不消耗上传额度)
        /// </summary>
        /// <param name="hash">SHA256/SHA1/MD5 哈希</param>
        /// <returns>多引擎聚合检测结果</returns>
        public async Task<List<EngineDetection>> QueryHashAsync(string hash)
        {
            var results = new List<EngineDetection>();

            if (!IsConfigured)
            {
                results.Add(new EngineDetection
                {
                    EngineName = "VirusTotal",
                    Detected = false,
                    ThreatName = "API Key未配置",
                    Method = "cloud-hash"
                });
                return results;
            }

            if (!WaitForRateLimit())
            {
                results.Add(new EngineDetection
                {
                    EngineName = "VirusTotal",
                    Detected = false,
                    ThreatName = "RateLimit",
                    Method = "cloud-hash"
                });
                return results;
            }

            try
            {
                string url = $"{BaseUrl}/files/{hash.ToLowerInvariant()}";
                var response = await _httpClient.GetAsync(url);

                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    // VirusTotal 数据库中无此文件 - 未知文件
                    results.Add(new EngineDetection
                    {
                        EngineName = "VirusTotal",
                        Detected = false,
                        ThreatName = "NotFound",
                        Method = "cloud-hash"
                    });
                    return results;
                }

                if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                {
                    // 速率限制被触发
                    RegisterRateLimitHit();
                    results.Add(new EngineDetection
                    {
                        EngineName = "VirusTotal",
                        Detected = false,
                        ThreatName = "RateLimitExceeded",
                        Method = "cloud-hash"
                    });
                    return results;
                }

                if (!response.IsSuccessStatusCode)
                {
                    results.Add(new EngineDetection
                    {
                        EngineName = "VirusTotal",
                        Detected = false,
                        ThreatName = $"HTTP {(int)response.StatusCode}",
                        Method = "cloud-hash"
                    });
                    return results;
                }

                var jsonStr = await response.Content.ReadAsStringAsync();
                var json = JObject.Parse(jsonStr);

                // 解析 last_analysis_results (各引擎检测结果)
                var analysisResults = json["data"]?["attributes"]?["last_analysis_results"] as JObject;
                if (analysisResults == null)
                {
                    // 文件存在但还未被扫描
                    results.Add(new EngineDetection
                    {
                        EngineName = "VirusTotal",
                        Detected = false,
                        ThreatName = "NotAnalyzed",
                        Method = "cloud-hash"
                    });
                    return results;
                }

                // 解析每个引擎的结果
                foreach (var prop in analysisResults.Properties())
                {
                    var engineName = prop.Name;
                    var engineData = prop.Value as JObject;
                    if (engineData == null) continue;

                    string category = engineData["category"]?.ToString() ?? string.Empty;
                    string result = engineData["result"]?.ToString();
                    string engineVersion = engineData["engine_version"]?.ToString();
                    string method = engineData["method"]?.ToString();

                    bool detected = category.Equals("malicious", StringComparison.OrdinalIgnoreCase)
                                  || category.Equals("suspicious", StringComparison.OrdinalIgnoreCase);

                    results.Add(new EngineDetection
                    {
                        EngineName = engineName,
                        Detected = detected,
                        ThreatName = detected ? (result ?? "Malicious") : null,
                        EngineVersion = engineVersion,
                        Method = method ?? "cloud-hash"
                    });
                }

                return results;
            }
            catch (TaskCanceledException)
            {
                results.Add(new EngineDetection
                {
                    EngineName = "VirusTotal",
                    Detected = false,
                    ThreatName = "Timeout",
                    Method = "cloud-hash"
                });
            }
            catch (Exception ex)
            {
                results.Add(new EngineDetection
                {
                    EngineName = "VirusTotal",
                    Detected = false,
                    ThreatName = $"Error: {ex.Message}",
                    Method = "cloud-hash"
                });
            }

            return results;
        }

        /// <summary>
        /// 上传文件到 VirusTotal 进行扫描 (消耗上传额度, 适合哈希查询未命中的可疑文件)
        /// </summary>
        public async Task<string> UploadFileAsync(string filePath)
        {
            if (!IsConfigured) return null;
            if (!WaitForRateLimit()) return null;

            try
            {
                // VirusTotal v3 上传文件大小限制: 32MB (免费)
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 32 * 1024 * 1024)
                    return null;

                string uploadUrl = $"{BaseUrl}/files";
                using var fileStream = File.OpenRead(filePath);
                using var formData = new MultipartFormDataContent();
                var fileContent = new StreamContent(fileStream);
                fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                formData.Add(fileContent, "file", Path.GetFileName(filePath));

                var response = await _httpClient.PostAsync(uploadUrl, formData);
                if (!response.IsSuccessStatusCode) return null;

                var jsonStr = await response.Content.ReadAsStringAsync();
                var json = JObject.Parse(jsonStr);
                return json["data"]?["id"]?.ToString();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 获取上传文件的分析结果
        /// </summary>
        public async Task<List<EngineDetection>> GetAnalysisResultAsync(string analysisId, int maxWaitSeconds = 60)
        {
            var results = new List<EngineDetection>();
            if (!IsConfigured || string.IsNullOrEmpty(analysisId)) return results;

            var deadline = DateTime.UtcNow.AddSeconds(maxWaitSeconds);
            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    string url = $"{BaseUrl}/analyses/{analysisId}";
                    var response = await _httpClient.GetAsync(url);
                    if (!response.IsSuccessStatusCode) break;

                    var jsonStr = await response.Content.ReadAsStringAsync();
                    var json = JObject.Parse(jsonStr);
                    string status = json["data"]?["attributes"]?["status"]?.ToString() ?? string.Empty;

                    if (status.Equals("completed", StringComparison.OrdinalIgnoreCase))
                    {
                        // 解析结果
                        var analysisResults = json["data"]?["attributes"]?["results"] as JObject;
                        if (analysisResults != null)
                        {
                            foreach (var prop in analysisResults.Properties())
                            {
                                var engineData = prop.Value as JObject;
                                if (engineData == null) continue;

                                string category = engineData["category"]?.ToString() ?? string.Empty;
                                string result = engineData["result"]?.ToString();

                                bool detected = category.Equals("malicious", StringComparison.OrdinalIgnoreCase)
                                              || category.Equals("suspicious", StringComparison.OrdinalIgnoreCase);

                                results.Add(new EngineDetection
                                {
                                    EngineName = prop.Name,
                                    Detected = detected,
                                    ThreatName = detected ? (result ?? "Malicious") : null,
                                    Method = "cloud-upload"
                                });
                            }
                        }
                        return results;
                    }

                    await Task.Delay(3000); // 等3秒再查
                }
                catch
                {
                    break;
                }
            }
            return results;
        }

        /// <summary>
        /// 查询 URL 信誉
        /// </summary>
        public async Task<EngineDetection> QueryUrlAsync(string url)
        {
            var detection = new EngineDetection
            {
                EngineName = "VirusTotal-URL",
                Method = "cloud-url"
            };

            if (!IsConfigured || !WaitForRateLimit())
            {
                detection.ThreatName = IsConfigured ? "RateLimit" : "API Key未配置";
                return detection;
            }

            try
            {
                string urlId = Base64EncodeUrl(url);
                string apiUrl = $"{BaseUrl}/urls/{urlId}";
                var response = await _httpClient.GetAsync(apiUrl);

                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    detection.ThreatName = "NotFound";
                    return detection;
                }

                if (!response.IsSuccessStatusCode)
                {
                    detection.ThreatName = $"HTTP {(int)response.StatusCode}";
                    return detection;
                }

                var jsonStr = await response.Content.ReadAsStringAsync();
                var json = JObject.Parse(jsonStr);

                var stats = json["data"]?["attributes"]?["last_analysis_stats"];
                if (stats != null)
                {
                    int malicious = stats["malicious"]?.Value<int>() ?? 0;
                    int suspicious = stats["suspicious"]?.Value<int>() ?? 0;
                    int harmless = stats["harmless"]?.Value<int>() ?? 0;
                    int total = malicious + suspicious + harmless;

                    if (malicious > 0 || suspicious > 0)
                    {
                        detection.Detected = true;
                        detection.ThreatName = $"Malicious({malicious}/{total})";
                    }
                    else
                    {
                        detection.ThreatName = $"Clean(0/{total})";
                    }
                }
            }
            catch (Exception ex)
            {
                detection.ThreatName = $"Error: {ex.Message}";
            }

            return detection;
        }

        #region 速率限制

        private bool WaitForRateLimit()
        {
            lock (_rateLock)
            {
                // 检查日额度重置
                if (DateTime.UtcNow.Date != _dailyResetDate)
                {
                    _dailyCount = 0;
                    _dailyResetDate = DateTime.UtcNow.Date;
                }

                if (_dailyCount >= RateLimitPerDay)
                    return false;

                // 移除1分钟前的时间戳
                var cutoff = DateTime.UtcNow.AddMinutes(-1);
                while (_requestTimestamps.Count > 0 && _requestTimestamps.Peek() < cutoff)
                    _requestTimestamps.Dequeue();

                if (_requestTimestamps.Count >= RateLimitPerMinute)
                    return false;

                _requestTimestamps.Enqueue(DateTime.UtcNow);
                _dailyCount++;
                return true;
            }
        }

        private void RegisterRateLimitHit()
        {
            // 收到429时, 短暂退避
            lock (_rateLock)
            {
                // 将所有最近时间戳保留, 暂停1分钟
                var cutoff = DateTime.UtcNow.AddSeconds(-50);
                while (_requestTimestamps.Count > 0 && _requestTimestamps.Peek() < cutoff)
                    _requestTimestamps.Dequeue();
            }
        }

        private static string Base64EncodeUrl(string url)
        {
            // VirusTotal URL ID = base64(url) without padding
            var bytes = System.Text.Encoding.UTF8.GetBytes(url);
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        #endregion

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
