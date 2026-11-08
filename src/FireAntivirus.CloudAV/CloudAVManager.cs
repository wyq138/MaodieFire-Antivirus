// CloudAVManager - 多引擎云杀毒管理器
// 真实可用的云查杀聚合: MalwareBazaar + VirusTotal + HybridAnalysis + AlienVault OTX
// 旧版本引用了不存在的 https://api.clamav.net/v1/scan (ClamAV 无公共云 API), 已废弃
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FireAntivirus.CloudAV
{
    /// <summary>
    /// 云杀毒管理器 - 真实多引擎聚合 (替代旧版模拟实现)
    /// </summary>
    public class CloudAVManager
    {
        private readonly HttpClient _httpClient;
        private readonly string _virusTotalApiKey;
        private readonly string _hybridAnalysisApiKey;

        /// <summary>MalwareBazaar API (abuse.ch 免费, 无需 Key)</summary>
        private const string MalwareBazaarUrl = "https://mb-api.abuse.ch/api/v1/";

        /// <summary>VirusTotal v3 API (用户配置 Key)</summary>
        private const string VirusTotalBaseUrl = "https://www.virustotal.com/api/v3";

        /// <summary>Hybrid Analysis v2 API (用户配置 Key)</summary>
        private const string HybridAnalysisBaseUrl = "https://www.hybrid-analysis.com/api/v2";

        /// <summary>AlienVault OTX API (免费, 无需 Key)</summary>
        private const string OtxBaseUrl = "https://otx.alienvault.com/api/v1";

        public List<CloudAVProvider> Providers { get; private set; }

        public event EventHandler<CloudAVScanCompleteEventArgs> ScanComplete;

        public CloudAVManager()
        {
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus/1.0");

            // 从配置文件加载 API Key
            _virusTotalApiKey = LoadConfigKey("virustotal_api_key");
            _hybridAnalysisApiKey = LoadConfigKey("hybridanalysis_api_key");

            Providers = new List<CloudAVProvider>
            {
                new CloudAVProvider { Name = "MalwareBazaar", ApiUrl = MalwareBazaarUrl, IsEnabled = true },
                new CloudAVProvider { Name = "AlienVault-OTX", ApiUrl = OtxBaseUrl, IsEnabled = true },
                new CloudAVProvider
                {
                    Name = "VirusTotal",
                    ApiUrl = VirusTotalBaseUrl,
                    ApiKey = _virusTotalApiKey,
                    IsEnabled = !string.IsNullOrEmpty(_virusTotalApiKey)
                },
                new CloudAVProvider
                {
                    Name = "HybridAnalysis",
                    ApiUrl = HybridAnalysisBaseUrl,
                    ApiKey = _hybridAnalysisApiKey,
                    IsEnabled = !string.IsNullOrEmpty(_hybridAnalysisApiKey)
                }
            };
        }

        /// <summary>
        /// 扫描文件 - 多引擎并行哈希查询
        /// </summary>
        public async Task<CloudAVScanResult> ScanFileAsync(string filePath)
        {
            if (!File.Exists(filePath))
                return new CloudAVScanResult { FilePath = filePath, IsInfected = false, ErrorMessage = "文件不存在" };

            string sha256 = CalculateFileHash(filePath, "SHA256");

            var results = new List<CloudAVProviderResult>();
            int positiveCount = 0;
            int totalEngines = 0;

            // 并行查询所有启用的引擎
            var tasks = new List<Task<CloudAVProviderResult>>();

            foreach (var provider in Providers)
            {
                if (!provider.IsEnabled) continue;

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        return provider.Name switch
                        {
                            "MalwareBazaar" => await QueryMalwareBazaarAsync(filePath, sha256),
                            "AlienVault-OTX" => await QueryOtxAsync(filePath, sha256),
                            "VirusTotal" => await QueryVirusTotalAsync(filePath, sha256),
                            "HybridAnalysis" => await QueryHybridAnalysisAsync(filePath, sha256),
                            _ => new CloudAVProviderResult { ProviderName = provider.Name, ErrorMessage = "未知提供商" }
                        };
                    }
                    catch (Exception ex)
                    {
                        return new CloudAVProviderResult
                        {
                            ProviderName = provider.Name,
                            ErrorMessage = ex.Message
                        };
                    }
                }));
            }

            // 等待所有查询完成(30秒超时)
            var allTask = Task.WhenAll(tasks);
            var completed = await Task.WhenAny(allTask, Task.Delay(30000));

            foreach (var t in tasks)
            {
                if (t.IsCompletedSuccessfully && t.Result != null)
                {
                    results.Add(t.Result);
                    if (t.Result.IsInfected)
                        positiveCount++;
                    if (t.Result.TotalEngines > 0)
                        totalEngines += t.Result.TotalEngines;
                }
            }

            // 聚合判定
            var finalResult = new CloudAVScanResult
            {
                FilePath = filePath,
                IsInfected = positiveCount >= 2, // 多引擎阈值: 至少2个引擎报毒
                ProviderResults = results,
                TotalEngines = totalEngines,
                PositiveEngines = positiveCount
            };

            if (finalResult.IsInfected)
            {
                var mostConfident = results.Find(r => r.IsInfected && !string.IsNullOrEmpty(r.ThreatName));
                finalResult.ThreatName = mostConfident?.ThreatName ?? "Malware";
                finalResult.Confidence = totalEngines > 0 ? (double)positiveCount / totalEngines : 0.9;
            }
            else if (positiveCount == 1)
            {
                // 单引擎报毒 -> 可疑,不直接判定
                finalResult.ThreatName = "Suspicious";
                finalResult.Confidence = 0.4;
            }
            else
            {
                finalResult.ThreatName = "Clean";
                finalResult.Confidence = totalEngines > 0 ? 0.9 : 0.0;
            }

            OnScanComplete(new CloudAVScanCompleteEventArgs { Result = finalResult });
            return finalResult;
        }

        /// <summary>通过哈希查询(无需文件)</summary>
        public async Task<CloudAVScanResult> ScanHashAsync(string sha256Hash)
        {
            var results = new List<CloudAVProviderResult>();
            int positiveCount = 0;
            int totalEngines = 0;

            var tasks = new List<Task<CloudAVProviderResult>>();
            foreach (var provider in Providers)
            {
                if (!provider.IsEnabled) continue;
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        return provider.Name switch
                        {
                            "MalwareBazaar" => await QueryMalwareBazaarAsync(null, sha256Hash),
                            "AlienVault-OTX" => await QueryOtxAsync(null, sha256Hash),
                            "VirusTotal" => await QueryVirusTotalAsync(null, sha256Hash),
                            "HybridAnalysis" => await QueryHybridAnalysisAsync(null, sha256Hash),
                            _ => new CloudAVProviderResult { ProviderName = provider.Name }
                        };
                    }
                    catch (Exception ex)
                    {
                        return new CloudAVProviderResult { ProviderName = provider.Name, ErrorMessage = ex.Message };
                    }
                }));
            }

            await Task.WhenAny(Task.WhenAll(tasks), Task.Delay(30000));

            foreach (var t in tasks)
            {
                if (t.IsCompletedSuccessfully && t.Result != null)
                {
                    results.Add(t.Result);
                    if (t.Result.IsInfected) positiveCount++;
                    if (t.Result.TotalEngines > 0) totalEngines += t.Result.TotalEngines;
                }
            }

            return new CloudAVScanResult
            {
                FilePath = sha256Hash,
                IsInfected = positiveCount >= 2,
                ThreatName = positiveCount >= 2 ? "Malware" : positiveCount == 1 ? "Suspicious" : "Clean",
                Confidence = totalEngines > 0 ? (double)positiveCount / totalEngines : 0,
                ProviderResults = results,
                TotalEngines = totalEngines,
                PositiveEngines = positiveCount
            };
        }

        #region 各引擎查询实现

        private async Task<CloudAVProviderResult> QueryMalwareBazaarAsync(string filePath, string hash)
        {
            var result = new CloudAVProviderResult { ProviderName = "MalwareBazaar" };

            try
            {
                var formData = new MultipartFormDataContent
                {
                    { new StringContent("get_info"), "query" },
                    { new StringContent(hash), "hash" }
                };

                var response = await _httpClient.PostAsync(MalwareBazaarUrl, formData);
                if (!response.IsSuccessStatusCode)
                {
                    result.ErrorMessage = $"HTTP {(int)response.StatusCode}";
                    return result;
                }

                var json = JObject.Parse(await response.Content.ReadAsStringAsync());
                string status = json["query_status"]?.ToString() ?? "";

                if (status.Equals("ok", StringComparison.OrdinalIgnoreCase))
                {
                    var data = json["data"] as JArray;
                    if (data != null && data.Count > 0)
                    {
                        result.IsInfected = true;
                        result.ThreatName = data[0]["signature"]?.ToString() ?? "Malware";
                        result.TotalEngines = 1;
                    }
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private async Task<CloudAVProviderResult> QueryOtxAsync(string filePath, string hash)
        {
            var result = new CloudAVProviderResult { ProviderName = "AlienVault-OTX" };

            try
            {
                string url = $"{OtxBaseUrl}/indicators/file/{hash}/general";
                var response = await _httpClient.GetStringAsync(url);
                var json = JObject.Parse(response);

                int pulseCount = json["pulse_info"]?["count"]?.Value<int>() ?? 0;
                var pulses = json["pulse_info"]?["pulses"] as JArray;

                result.TotalEngines = 1;
                if (pulseCount > 0 && pulses != null && pulses.Count > 0)
                {
                    result.IsInfected = true;
                    result.ThreatName = pulses[0]?["name"]?.ToString() ?? "OTX Threat";
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private async Task<CloudAVProviderResult> QueryVirusTotalAsync(string filePath, string hash)
        {
            var result = new CloudAVProviderResult { ProviderName = "VirusTotal" };

            if (string.IsNullOrEmpty(_virusTotalApiKey))
            {
                result.ErrorMessage = "API Key 未配置";
                return result;
            }

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"{VirusTotalBaseUrl}/files/{hash.ToLowerInvariant()}");
                req.Headers.Add("x-apikey", _virusTotalApiKey);

                var response = await _httpClient.SendAsync(req);
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    result.ErrorMessage = "NotFound";
                    return result;
                }
                if (!response.IsSuccessStatusCode)
                {
                    result.ErrorMessage = $"HTTP {(int)response.StatusCode}";
                    return result;
                }

                var json = JObject.Parse(await response.Content.ReadAsStringAsync());
                var analysisResults = json["data"]?["attributes"]?["last_analysis_results"] as JObject;

                if (analysisResults != null)
                {
                    int total = 0, positive = 0;
                    string threatName = null;

                    foreach (var prop in analysisResults.Properties())
                    {
                        total++;
                        var engineData = prop.Value as JObject;
                        string category = engineData?["category"]?.ToString() ?? "";
                        if (category.Equals("malicious", StringComparison.OrdinalIgnoreCase) ||
                            category.Equals("suspicious", StringComparison.OrdinalIgnoreCase))
                        {
                            positive++;
                            threatName ??= engineData?["result"]?.ToString();
                        }
                    }

                    result.TotalEngines = total;
                    result.IsInfected = positive > 0;
                    result.ThreatName = threatName;
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private async Task<CloudAVProviderResult> QueryHybridAnalysisAsync(string filePath, string hash)
        {
            var result = new CloudAVProviderResult { ProviderName = "HybridAnalysis" };

            if (string.IsNullOrEmpty(_hybridAnalysisApiKey))
            {
                result.ErrorMessage = "API Key 未配置";
                return result;
            }

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, $"{HybridAnalysisBaseUrl}/search/hash");
                req.Headers.Add("api-key", _hybridAnalysisApiKey);
                req.Headers.Add("User-Agent", "Falcon Sandbox");
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var formData = new MultipartFormDataContent
                {
                    { new StringContent(hash), "hash" }
                };
                req.Content = formData;

                var response = await _httpClient.SendAsync(req);
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    result.ErrorMessage = "NotFound";
                    return result;
                }
                if (!response.IsSuccessStatusCode)
                {
                    result.ErrorMessage = $"HTTP {(int)response.StatusCode}";
                    return result;
                }

                var items = JArray.Parse(await response.Content.ReadAsStringAsync());
                result.TotalEngines = 1;

                if (items.Count > 0)
                {
                    string verdict = items[0]["verdict"]?.ToString() ?? "";
                    if (verdict.Equals("malicious", StringComparison.OrdinalIgnoreCase) ||
                        verdict.Equals("suspicious", StringComparison.OrdinalIgnoreCase))
                    {
                        result.IsInfected = true;
                        result.ThreatName = items[0]["threat_name"]?.ToString() ?? verdict;
                    }
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        #endregion

        #region 辅助方法

        private static string CalculateFileHash(string filePath, string algorithm)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var hashAlg = algorithm.Equals("MD5", StringComparison.OrdinalIgnoreCase)
                    ? (HashAlgorithm)MD5.Create()
                    : SHA256.Create();
                var hashBytes = hashAlg.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string LoadConfigKey(string key)
        {
            try
            {
                string configPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FireAntivirus", "cloud_scan_config.json");
                if (!File.Exists(configPath)) return string.Empty;

                var json = File.ReadAllText(configPath);
                var obj = JObject.Parse(json);
                return obj[key]?.ToString() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        public void AddProvider(CloudAVProvider provider) => Providers.Add(provider);
        public void RemoveProvider(string name) => Providers.RemoveAll(p => p.Name == name);

        public void UpdateProvider(CloudAVProvider provider)
        {
            var existing = Providers.Find(p => p.Name == provider.Name);
            if (existing != null)
            {
                existing.ApiUrl = provider.ApiUrl;
                existing.ApiKey = provider.ApiKey;
                existing.IsEnabled = provider.IsEnabled;
            }
        }

        public List<CloudAVProvider> GetProviders() => Providers;

        protected virtual void OnScanComplete(CloudAVScanCompleteEventArgs e)
        {
            ScanComplete?.Invoke(this, e);
        }

        #endregion
    }

    public class CloudAVProvider
    {
        public string Name { get; set; }
        public string ApiUrl { get; set; }
        public string ApiKey { get; set; }
        public bool IsEnabled { get; set; }
    }

    public class CloudAVScanResult
    {
        public string FilePath { get; set; }
        public bool IsInfected { get; set; }
        public string ThreatName { get; set; }
        public double Confidence { get; set; }
        public string ErrorMessage { get; set; }
        public List<CloudAVProviderResult> ProviderResults { get; set; } = new List<CloudAVProviderResult>();
        public int TotalEngines { get; set; }
        public int PositiveEngines { get; set; }
        public DateTime ScanTime { get; set; } = DateTime.Now;
    }

    public class CloudAVProviderResult
    {
        public string ProviderName { get; set; }
        public bool IsInfected { get; set; }
        public string ThreatName { get; set; }
        public string ErrorMessage { get; set; }
        public int TotalEngines { get; set; }
    }

    public class CloudAVScanCompleteEventArgs : EventArgs
    {
        public CloudAVScanResult Result { get; set; }
    }
}
