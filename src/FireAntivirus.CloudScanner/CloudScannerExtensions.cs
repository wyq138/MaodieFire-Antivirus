// 云扫描扩展模块 - 包含更多真实云查杀功能
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.CloudScanner
{
    /// <summary>
    /// 云威胁情报管理器
    /// </summary>
    public class CloudThreatIntelligenceManager
    {
        private readonly DataManager _dataManager;
        private HttpClient _httpClient;
        private List<ThreatIntelligenceFeed> _feeds;

        public CloudThreatIntelligenceManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
            _feeds = new List<ThreatIntelligenceFeed>();
            InitializeFeeds();
        }

        private void InitializeFeeds()
        {
            _feeds.Add(new ThreatIntelligenceFeed
            {
                Name = "AlienVault OTX",
                Url = "https://otx.alienvault.com/api/v1",
                Type = FeedType.MalwareIndicators,
                Enabled = true
            });

            _feeds.Add(new ThreatIntelligenceFeed
            {
                Name = "Abuse.ch URLhaus",
                Url = "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                Type = FeedType.MaliciousURLs,
                Enabled = true
            });

            _feeds.Add(new ThreatIntelligenceFeed
            {
                Name = "Abuse.ch Feodo Tracker",
                Url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                Type = FeedType.BotnetC2,
                Enabled = true
            });

            _feeds.Add(new ThreatIntelligenceFeed
            {
                Name = "Emerging Threats",
                Url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                Type = FeedType.MaliciousIPs,
                Enabled = true
            });
        }

        public async Task<List<ThreatIndicator>> FetchThreatIntelligence()
        {
            var indicators = new List<ThreatIndicator>();

            foreach (var feed in _feeds)
            {
                if (!feed.Enabled) continue;

                try
                {
                    switch (feed.Type)
                    {
                        case FeedType.MaliciousIPs:
                            indicators.AddRange(await FetchMaliciousIPs(feed));
                            break;
                        case FeedType.MaliciousURLs:
                            indicators.AddRange(await FetchMaliciousURLs(feed));
                            break;
                        case FeedType.MalwareIndicators:
                            indicators.AddRange(await FetchMalwareIndicators(feed));
                            break;
                        case FeedType.BotnetC2:
                            indicators.AddRange(await FetchBotnetC2(feed));
                            break;
                    }
                }
                catch (Exception ex)
                {
                    LogHelper.Error($"获取威胁情报失败: {feed.Name}", ex.Message);
                }
            }

            return indicators;
        }

        private async Task<List<ThreatIndicator>> FetchMaliciousIPs(ThreatIntelligenceFeed feed)
        {
            var indicators = new List<ThreatIndicator>();
            try
            {
                var response = await _httpClient.GetStringAsync(feed.Url);
                var lines = response.Split('\n');

                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    var ip = line.Trim();
                    if (IsValidIP(ip))
                    {
                        indicators.Add(new ThreatIndicator
                        {
                            Type = IndicatorType.IP,
                            Value = ip,
                            Source = feed.Name,
                            Confidence = 0.8,
                            LastSeen = DateTime.Now
                        });
                    }
                }
            }
            catch { }

            return indicators;
        }

        private async Task<List<ThreatIndicator>> FetchMaliciousURLs(ThreatIntelligenceFeed feed)
        {
            var indicators = new List<ThreatIndicator>();
            try
            {
                var response = await _httpClient.GetStringAsync(feed.Url);
                // 解析JSON响应
            }
            catch { }

            return indicators;
        }

        private async Task<List<ThreatIndicator>> FetchMalwareIndicators(ThreatIntelligenceFeed feed)
        {
            var indicators = new List<ThreatIndicator>();
            // 实现MalwareBazaar API调用
            await Task.Delay(100);
            return indicators;
        }

        private async Task<List<ThreatIndicator>> FetchBotnetC2(ThreatIntelligenceFeed feed)
        {
            var indicators = new List<ThreatIndicator>();
            try
            {
                var response = await _httpClient.GetStringAsync(feed.Url);
                var json = JsonDocument.Parse(response);

                if (json.RootElement.TryGetProperty("botnetc2", out var c2List))
                {
                    foreach (var c2 in c2List.EnumerateArray())
                    {
                        if (c2.TryGetProperty("ip_address", out var ipElement))
                        {
                            indicators.Add(new ThreatIndicator
                            {
                                Type = IndicatorType.IP,
                                Value = ipElement.GetString(),
                                Source = feed.Name,
                                Confidence = 0.95,
                                LastSeen = DateTime.Now
                            });
                        }
                    }
                }
            }
            catch { }

            return indicators;
        }

        private bool IsValidIP(string ip)
        {
            return System.Net.IPAddress.TryParse(ip, out _);
        }
    }

    /// <summary>
    /// 多引擎云扫描聚合器
    /// </summary>
    public class MultiEngineCloudScanner
    {
        private readonly DataManager _dataManager;
        private HttpClient _httpClient;
        private List<CloudScanEngine> _engines;
        private int _maxConcurrentScans;

        public MultiEngineCloudScanner(DataManager dataManager)
        {
            _dataManager = dataManager;
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(60);
            _engines = new List<CloudScanEngine>();
            _maxConcurrentScans = 5;
            InitializeEngines();
        }

        private void InitializeEngines()
        {
            _engines.Add(new CloudScanEngine
            {
                Name = "VirusTotal",
                ApiUrl = "https://www.virustotal.com/api/v3",
                Enabled = true,
                Weight = 1.0
            });

            _engines.Add(new CloudScanEngine
            {
                Name = "Hybrid Analysis",
                ApiUrl = "https://www.hybrid-analysis.com/api/v2",
                Enabled = true,
                Weight = 1.0
            });

            _engines.Add(new CloudScanEngine
            {
                Name = "Any.Run",
                ApiUrl = "https://any.run/api/v1",
                Enabled = false,
                Weight = 1.0
            });

            _engines.Add(new CloudScanEngine
            {
                Name = "Joe Sandbox",
                ApiUrl = "https://jbxcloud.joesecurity.org/api",
                Enabled = false,
                Weight = 1.0
            });

            _engines.Add(new CloudScanEngine
            {
                Name = "Cuckoo Sandbox",
                ApiUrl = "https://cuckoo.sh/api",
                Enabled = false,
                Weight = 1.0
            });
        }

        public async Task<MultiEngineScanResult> ScanWithMultipleEngines(string filePath)
        {
            var result = new MultiEngineScanResult
            {
                FilePath = filePath,
                ScanTime = DateTime.Now,
                EngineResults = new List<EngineScanResult>()
            };

            var enabledEngines = _engines.Where(e => e.Enabled).ToList();

            foreach (var engine in enabledEngines)
            {
                try
                {
                    var engineResult = await ScanWithEngine(engine, filePath);
                    result.EngineResults.Add(engineResult);
                }
                catch (Exception ex)
                {
                    result.EngineResults.Add(new EngineScanResult
                    {
                        EngineName = engine.Name,
                        Success = false,
                        ErrorMessage = ex.Message
                    });
                }
            }

            result.CalculateAggregatedResult();
            return result;
        }

        private async Task<EngineScanResult> ScanWithEngine(CloudScanEngine engine, string filePath)
        {
            var result = new EngineScanResult
            {
                EngineName = engine.Name,
                ScanTime = DateTime.Now
            };

            try
            {
                // 计算文件哈希
                using var stream = File.OpenRead(filePath);
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(stream);

                // 根据不同引擎调用API
                switch (engine.Name)
                {
                    case "VirusTotal":
                        result = await ScanVirusTotal(hash, result);
                        break;
                    case "Hybrid Analysis":
                        result = await ScanHybridAnalysis(filePath, result);
                        break;
                }

                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private async Task<EngineScanResult> ScanVirusTotal(byte[] hash, EngineScanResult result)
        {
            // 真实调用 VirusTotal v3 API（需配置环境变量 VIRUSTOTAL_API_KEY）
            var apiKey = Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY");
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                result.ErrorMessage = "未配置 VIRUSTOTAL_API_KEY，跳过 VirusTotal 云查杀";
                result.Success = false;
                return result;
            }

            var hashHex = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();

            using (var request = new HttpRequestMessage(HttpMethod.Get,
                $"https://www.virustotal.com/api/v3/files/{hashHex}"))
            {
                request.Headers.Add("x-apikey", apiKey);

                using (var response = await _httpClient.SendAsync(request))
                {
                    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        // 文件未被提交分析过
                        result.Detections = 0;
                        result.TotalEngines = 0;
                        return result;
                    }

                    response.EnsureSuccessStatusCode();

                    var json = await response.Content.ReadAsStringAsync();
                    using (var doc = System.Text.Json.JsonDocument.Parse(json))
                    {
                        var stats = doc.RootElement.GetProperty("data").GetProperty("attributes")
                            .GetProperty("last_analysis_stats");

                        result.Detections = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
                        result.TotalEngines = stats.TryGetProperty("total", out var t) ? t.GetInt32() : 0;
                        result.MalwareNames = new List<string>();

                        if (result.Detections > 0 &&
                            doc.RootElement.GetProperty("data").GetProperty("attributes")
                                .TryGetProperty("popular_threat_classification", out var pcl) &&
                            pcl.TryGetProperty("suggested_threat_label", out var label))
                        {
                            result.MalwareNames.Add(label.GetString());
                        }
                    }
                }
            }

            return result;
        }

        private async Task<EngineScanResult> ScanHybridAnalysis(string filePath, EngineScanResult result)
        {
            // 真实调用 Hybrid Analysis v2 API（需配置环境变量 HYBRIDANALYSIS_API_KEY）
            var apiKey = Environment.GetEnvironmentVariable("HYBRIDANALYSIS_API_KEY");
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                result.ErrorMessage = "未配置 HYBRIDANALYSIS_API_KEY，跳过 Hybrid Analysis 云查杀";
                result.Success = false;
                return result;
            }

            string hashHex;
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                hashHex = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            }

            using (var request = new HttpRequestMessage(HttpMethod.Post,
                "https://www.hybrid-analysis.com/api/v2/search/hash"))
            {
                request.Headers.Add("api-key", apiKey);
                request.Headers.UserAgent.ParseAdd("FireAntivirus");
                request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["hash"] = hashHex
                });

                using (var response = await _httpClient.SendAsync(request))
                {
                    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        result.ThreatLevel = "unknown";
                        return result;
                    }

                    response.EnsureSuccessStatusCode();

                    var json = await response.Content.ReadAsStringAsync();
                    using (var doc = System.Text.Json.JsonDocument.Parse(json))
                    {
                        if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Array &&
                            doc.RootElement.GetArrayLength() > 0)
                        {
                            var first = doc.RootElement[0];
                            result.ThreatLevel = first.TryGetProperty("verdict", out var v) ? v.GetString() : "unknown";
                        }
                        else
                        {
                            result.ThreatLevel = "unknown";
                        }
                    }
                }
            }

            return result;
        }
    }

    /// <summary>
    /// 云沙箱分析器
    /// </summary>
    public class CloudSandboxAnalyzer
    {
        private readonly DataManager _dataManager;
        private HttpClient _httpClient;

        public CloudSandboxAnalyzer(DataManager dataManager)
        {
            _dataManager = dataManager;
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromMinutes(5);
        }

        public async Task<SandboxAnalysisResult> AnalyzeInSandbox(string filePath)
        {
            var result = new SandboxAnalysisResult
            {
                FilePath = filePath,
                SubmittedAt = DateTime.Now
            };

            try
            {
                // 提交到沙箱
                var submissionId = await SubmitToSandbox(filePath);

                // 等待分析完成
                result = await PollAnalysisResult(submissionId);

                result.AnalysisCompleted = true;
            }
            catch (Exception ex)
            {
                result.AnalysisCompleted = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private async Task<string> SubmitToSandbox(string filePath)
        {
            // 真实提交：通过 Hybrid Analysis v2 API 上传文件进行云端沙箱分析
            var apiKey = Environment.GetEnvironmentVariable("HYBRIDANALYSIS_API_KEY");
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new InvalidOperationException("未配置 HYBRIDANALYSIS_API_KEY，无法提交云端沙箱分析");

            using (var content = new MultipartFormDataContent())
            using (var fileStream = File.OpenRead(filePath))
            {
                var fileContent = new StreamContent(fileStream);
                fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                content.Add(fileContent, "file", Path.GetFileName(filePath));
                content.Add(new StringContent("win7_x64"), "environment_id");
                content.Add(new StringContent("submitted by FireAntivirus"), "comment");

                using (var request = new HttpRequestMessage(HttpMethod.Post,
                    "https://www.hybrid-analysis.com/api/v2/submit/file"))
                {
                    request.Headers.Add("api-key", apiKey);
                    request.Headers.UserAgent.ParseAdd("FireAntivirus");
                    request.Content = content;

                    using (var response = await _httpClient.SendAsync(request))
                    {
                        response.EnsureSuccessStatusCode();
                        var json = await response.Content.ReadAsStringAsync();
                        using (var doc = System.Text.Json.JsonDocument.Parse(json))
                        {
                            if (doc.RootElement.TryGetProperty("job_id", out var jobId))
                                return jobId.GetString();
                            if (doc.RootElement.TryGetProperty("submission_id", out var submissionId))
                                return submissionId.GetString();
                            throw new InvalidOperationException("沙箱响应中缺少任务标识");
                        }
                    }
                }
            }
        }

        private async Task<SandboxAnalysisResult> PollAnalysisResult(string submissionId)
        {
            // 真实轮询：查询 Hybrid Analysis 任务状态直至分析完成
            var apiKey = Environment.GetEnvironmentVariable("HYBRIDANALYSIS_API_KEY");
            var deadline = DateTime.Now.AddMinutes(5);

            while (DateTime.Now < deadline)
            {
                using (var request = new HttpRequestMessage(HttpMethod.Get,
                    $"https://www.hybrid-analysis.com/api/v2/report/{submissionId}/state"))
                {
                    request.Headers.Add("api-key", apiKey);
                    request.Headers.UserAgent.ParseAdd("FireAntivirus");

                    using (var response = await _httpClient.SendAsync(request))
                    {
                        response.EnsureSuccessStatusCode();
                        var json = await response.Content.ReadAsStringAsync();
                        using (var doc = System.Text.Json.JsonDocument.Parse(json))
                        {
                            var state = doc.RootElement.TryGetProperty("state", out var s) ? s.GetString() : null;

                            if (string.Equals(state, "FINISHED", StringComparison.OrdinalIgnoreCase))
                            {
                                return new SandboxAnalysisResult
                                {
                                    SubmissionId = submissionId,
                                    ThreatLevel = doc.RootElement.TryGetProperty("verdict", out var v) ? v.GetString() : "unknown",
                                    SuspiciousScore = doc.RootElement.TryGetProperty("score", out var sc) &&
                                                      sc.ValueKind == System.Text.Json.JsonValueKind.Number ? sc.GetInt32() : 0,
                                    NetworkIndicators = new List<string>(),
                                    FileIndicators = new List<string>(),
                                    RegistryIndicators = new List<string>()
                                };
                            }
                        }
                    }
                }

                await Task.Delay(TimeSpan.FromSeconds(15));
            }

            throw new TimeoutException("云端沙箱分析超时，请稍后查询结果");
        }
    }

    /// <summary>
    /// 辅助类
    /// </summary>
    public class ThreatIntelligenceFeed
    {
        public string Name { get; set; }
        public string Url { get; set; }
        public FeedType Type { get; set; }
        public bool Enabled { get; set; }
    }

    public enum FeedType
    {
        MaliciousIPs,
        MaliciousURLs,
        MalwareIndicators,
        BotnetC2,
        PhishingDomains
    }

    public class ThreatIndicator
    {
        public IndicatorType Type { get; set; }
        public string Value { get; set; }
        public string Source { get; set; }
        public double Confidence { get; set; }
        public DateTime LastSeen { get; set; }
    }

    public enum IndicatorType
    {
        IP,
        URL,
        Domain,
        FileHash,
        Registry
    }

    public class CloudScanEngine
    {
        public string Name { get; set; }
        public string ApiUrl { get; set; }
        public bool Enabled { get; set; }
        public double Weight { get; set; }
    }

    public class MultiEngineScanResult
    {
        public string FilePath { get; set; }
        public DateTime ScanTime { get; set; }
        public List<EngineScanResult> EngineResults { get; set; }
        public string AggregatedVerdict { get; set; }
        public double AggregatedScore { get; set; }

        public void CalculateAggregatedResult()
        {
            var detections = EngineResults.Where(r => r.Detections > 0).Count();
            var totalEngines = EngineResults.Count;

            if (detections == 0)
            {
                AggregatedVerdict = "benign";
                AggregatedScore = 0;
            }
            else if (detections > totalEngines * 0.5)
            {
                AggregatedVerdict = "malicious";
                AggregatedScore = (double)detections / totalEngines * 100;
            }
            else if (detections > 0)
            {
                AggregatedVerdict = "suspicious";
                AggregatedScore = (double)detections / totalEngines * 50;
            }
        }
    }

    public class EngineScanResult
    {
        public string EngineName { get; set; }
        public DateTime ScanTime { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public int Detections { get; set; }
        public int TotalEngines { get; set; }
        public List<string> MalwareNames { get; set; }
        public string ThreatLevel { get; set; }
    }

    public class SandboxAnalysisResult
    {
        public string SubmissionId { get; set; }
        public string FilePath { get; set; }
        public DateTime SubmittedAt { get; set; }
        public bool AnalysisCompleted { get; set; }
        public string ErrorMessage { get; set; }
        public string ThreatLevel { get; set; }
        public int SuspiciousScore { get; set; }
        public List<string> NetworkIndicators { get; set; }
        public List<string> FileIndicators { get; set; }
        public List<string> RegistryIndicators { get; set; }
    }

    internal static class LogHelper
    {
        public static void Error(string message, string details = "")
        {
            System.Diagnostics.Debug.WriteLine($"[ERROR] {message}: {details}");
        }
    }


}
