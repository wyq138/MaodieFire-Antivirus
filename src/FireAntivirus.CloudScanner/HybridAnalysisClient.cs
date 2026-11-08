// Hybrid Analysis 客户端 - Payload Security 提供的免费沙箱检测服务
// API 文档: https://www.hybrid-analysis.com/docs/api/v2
// 免费注册: https://www.hybrid-analysis.com (免费 API Key, 每月 2000 次查询)
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FireAntivirus.CloudScanner
{
    /// <summary>
    /// Hybrid Analysis (Falcon Sandbox) API 客户端
    /// 提供深度沙箱分析和哈希查询
    /// </summary>
    public class HybridAnalysisClient : IDisposable
    {
        private const string BaseUrl = "https://www.hybrid-analysis.com/api/v2";
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

        public bool IsConfigured => !string.IsNullOrWhiteSpace(_apiKey);

        /// <summary>
        /// 构造 Hybrid Analysis 客户端
        /// </summary>
        /// <param name="apiKey">Hybrid Analysis API Key, 可在 https://www.hybrid-analysis.com 免费注册获取</param>
        public HybridAnalysisClient(string apiKey)
        {
            _apiKey = apiKey ?? string.Empty;
            _httpClient = new HttpClient
            {
                Timeout = DefaultTimeout
            };
            _httpClient.DefaultRequestHeaders.Add("api-key", _apiKey);
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "Falcon Sandbox");
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
        }

        /// <summary>
        /// 通过哈希查询 Hybrid Analysis 沙箱报告
        /// </summary>
        public async Task<EngineDetection> QueryHashAsync(string hash)
        {
            var detection = new EngineDetection
            {
                EngineName = "HybridAnalysis",
                Method = "cloud-sandbox"
            };

            if (!IsConfigured)
            {
                detection.ThreatName = "API Key未配置";
                return detection;
            }

            try
            {
                // HA v2 哈希查询用 POST + form-data
                var formData = new MultipartFormDataContent
                {
                    { new StringContent(hash), "hash" }
                };

                string url = $"{BaseUrl}/search/hash";
                var response = await _httpClient.PostAsync(url, formData);

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
                var items = JArray.Parse(jsonStr);

                if (items.Count > 0)
                {
                    var first = items[0];
                    string verdict = first["verdict"]?.ToString() ?? string.Empty;

                    // verdict: "malicious" / "suspicious" / "no specific threat" / "whitelisted"
                    if (verdict.Equals("malicious", StringComparison.OrdinalIgnoreCase))
                    {
                        detection.Detected = true;
                        detection.ThreatName = first["threat_name"]?.ToString()
                                             ?? first["vxfamily"]?.ToString()
                                             ?? "Malicious";
                    }
                    else if (verdict.Equals("suspicious", StringComparison.OrdinalIgnoreCase))
                    {
                        detection.Detected = true;
                        detection.ThreatName = first["threat_name"]?.ToString() ?? "Suspicious";
                    }
                    else
                    {
                        detection.ThreatName = verdict;
                    }

                    detection.EngineVersion = first["environment"]?["architecture"]?.ToString();
                }
                else
                {
                    detection.ThreatName = "NotFound";
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

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
