using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace FireAntivirus.Engine.Intelligence
{
    /// <summary>
    /// 威胁情报集成服务 - 集成全球威胁情报数据
    /// </summary>
    public class ThreatIntelligenceService
    {
        private readonly HttpClient _httpClient;
        private readonly LocalIntelligenceCache _localCache;
        private readonly ThreatIntelligenceAggregator _aggregator;
        private readonly MachineLearningAnalyzer _mlAnalyzer;

        public ThreatIntelligenceService()
        {
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            
            _localCache = new LocalIntelligenceCache();
            _aggregator = new ThreatIntelligenceAggregator();
            _mlAnalyzer = new MachineLearningAnalyzer();
        }

        /// <summary>
        /// 分析文件威胁情报
        /// </summary>
        public async Task<ThreatIntelligenceReport> AnalyzeFileAsync(string filePath)
        {
            var report = new ThreatIntelligenceReport
            {
                FilePath = filePath,
                AnalysisStartTime = DateTime.Now,
                FileHash = await CalculateFileHashAsync(filePath)
            };

            try
            {
                // 1. 检查本地缓存
                var cachedResult = await _localCache.GetCachedIntelligenceAsync(report.FileHash);
                if (cachedResult != null)
                {
                    report.CachedResponse = true;
                    report.ThreatLevel = cachedResult.ThreatLevel;
                    report.Confidence = cachedResult.Confidence;
                    report.SourcesConsolidated = cachedResult.Sources;
                    report.AnalysisEndTime = DateTime.Now;
                    report.Success = true;
                    return report;
                }

                // 2. 并行查询多个威胁情报源
                var intelligenceTasks = QueryMultipleIntelligenceSourcesAsync(report.FileHash, filePath);
                var intelResults = await Task.WhenAll(intelligenceTasks);

                // 3. 聚合和分析结果
                var aggregatedResult = await _aggregator.AggregateIntelligenceAsync(intelResults.ToList());
                report.ThreatLevel = aggregatedResult.OverallThreatLevel;
                report.Confidence = aggregatedResult.Confidence;
                report.SourcesConsolidated = aggregatedResult.Sources;

                // 无有效情报源时如实上报（不得伪装为确认安全）
                if (!string.IsNullOrEmpty(aggregatedResult.Error))
                {
                    report.Error = aggregatedResult.Error;
                }

                // 4. 机器学习增强分析
                var mlAnalysis = await _mlAnalyzer.EnhanceAnalysisAsync(filePath, aggregatedResult);
                if (mlAnalysis.Confidence > report.Confidence)
                {
                    report.ThreatLevel = mlAnalysis.EnhancedThreatLevel;
                    report.Confidence = mlAnalysis.Confidence;
                    report.MachineLearningData = mlAnalysis;
                }

                // 5. 更新缓存
                await _localCache.CacheIntelligenceAsync(report.FileHash, new CachedIntelligence
                {
                    FileHash = report.FileHash,
                    ThreatLevel = report.ThreatLevel,
                    Confidence = report.Confidence,
                    Sources = report.SourcesConsolidated,
                    CacheTime = DateTime.Now
                });

                report.AnalysisEndTime = DateTime.Now;
                report.Success = true;
            }
            catch (Exception ex)
            {
                report.Error = ex.Message;
                report.Success = false;
            }

            return report;
        }

        /// <summary>
        /// 计算文件哈希值
        /// </summary>
        private async Task<string> CalculateFileHashAsync(string filePath)
        {
            try
            {
                using var fileStream = File.OpenRead(filePath);
                using var sha256 = SHA256.Create();
                var hashBytes = await sha256.ComputeHashAsync(fileStream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// 查询多个威胁情报源
        /// </summary>
        private IEnumerable<Task<ThreatIntelligenceSourceResult>> QueryMultipleIntelligenceSourcesAsync(string fileHash, string filePath)
        {
            var sources = new List<Task<ThreatIntelligenceSourceResult>>
            {
                // 公开威胁情报源
                QueryVirusTotalAsync(fileHash),
                QueryHybridAnalysisAsync(fileHash),
                QueryMetaDefenderAsync(fileHash),
                
                // 私有威胁情报源（需要API密钥）
                QueryEnterpriseThreatFeedAsync(fileHash),
                QueryCustomIntelligenceSourceAsync(filePath)
            };

            return sources;
        }

        /// <summary>
        /// VirusTotal查询 - 真实调用 VirusTotal v3 API（需配置环境变量 VIRUSTOTAL_API_KEY）
        /// </summary>
        private async Task<ThreatIntelligenceSourceResult> QueryVirusTotalAsync(string fileHash)
        {
            var result = new ThreatIntelligenceSourceResult
            {
                SourceName = "VirusTotal",
                QueryTime = DateTime.Now
            };

            try
            {
                var apiKey = Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY");
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    result.Error = "VirusTotal API key not configured (set VIRUSTOTAL_API_KEY)";
                    return result;
                }

                using var request = new HttpRequestMessage(HttpMethod.Get,
                    $"https://www.virustotal.com/api/v3/files/{fileHash}");
                request.Headers.Add("x-apikey", apiKey);

                using var response = await _httpClient.SendAsync(request);
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    // 文件从未被提交分析：如实返回无情报记录
                    result.ThreatLevel = ThreatLevel.Safe;
                    result.Confidence = 0.5;
                    result.Tags.Add("not-submitted");
                    return result;
                }

                if (!response.IsSuccessStatusCode)
                {
                    result.Error = $"VirusTotal API returned HTTP {(int)response.StatusCode}";
                    return result;
                }

                var json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);

                var attributes = doc.RootElement.GetProperty("data").GetProperty("attributes");
                var stats = attributes.GetProperty("last_analysis_stats");

                int malicious = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
                int suspicious = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;
                int harmless = stats.TryGetProperty("harmless", out var h) ? h.GetInt32() : 0;
                int undetected = stats.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0;

                int totalEngines = malicious + suspicious + harmless + undetected;
                result.DetectionCount = malicious + suspicious;
                result.Confidence = totalEngines > 0
                    ? Math.Min((malicious + suspicious + harmless) / (double)totalEngines, 1.0)
                    : 0.5;

                if (malicious >= 5) result.ThreatLevel = ThreatLevel.High;
                else if (malicious + suspicious > 0) result.ThreatLevel = ThreatLevel.Medium;
                else result.ThreatLevel = ThreatLevel.Safe;

                // 提取已知恶意软件家族名
                if (attributes.TryGetProperty("popular_threat_classification", out var classification) &&
                    classification.TryGetProperty("popular_threat_name", out var families))
                {
                    foreach (var family in families.EnumerateArray())
                    {
                        if (family.TryGetProperty("value", out var value) && value.GetString() is string name)
                            result.MalwareFamilies.Add(name);
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// HybridAnalysis查询 - 真实调用 Hybrid Analysis v2 API（需配置环境变量 HYBRIDANALYSIS_API_KEY）
        /// </summary>
        private async Task<ThreatIntelligenceSourceResult> QueryHybridAnalysisAsync(string fileHash)
        {
            var result = new ThreatIntelligenceSourceResult
            {
                SourceName = "HybridAnalysis",
                QueryTime = DateTime.Now
            };

            try
            {
                var apiKey = Environment.GetEnvironmentVariable("HYBRIDANALYSIS_API_KEY");
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    result.Error = "Hybrid Analysis API key not configured (set HYBRIDANALYSIS_API_KEY)";
                    return result;
                }

                using var request = new HttpRequestMessage(HttpMethod.Post,
                    "https://www.hybrid-analysis.com/api/v2/search/hash");
                request.Headers.Add("api-key", apiKey);
                request.Headers.UserAgent.ParseAdd("FireAntivirus");
                request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["hash"] = fileHash
                });

                using var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                {
                    result.Error = $"Hybrid Analysis API returned HTTP {(int)response.StatusCode}";
                    return result;
                }

                var json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);

                if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
                {
                    var first = doc.RootElement[0];
                    var verdict = first.TryGetProperty("verdict", out var v) ? v.GetString() : null;

                    switch (verdict)
                    {
                        case "malicious":
                            result.ThreatLevel = ThreatLevel.High;
                            result.Confidence = 0.9;
                            break;
                        case "suspicious":
                            result.ThreatLevel = ThreatLevel.Medium;
                            result.Confidence = 0.7;
                            break;
                        case "no specific threat":
                            result.ThreatLevel = ThreatLevel.Safe;
                            result.Confidence = 0.8;
                            break;
                        default:
                            result.ThreatLevel = ThreatLevel.Safe;
                            result.Confidence = 0.5;
                            break;
                    }

                    if (first.TryGetProperty("count", out var countEl))
                        result.DetectionCount = countEl.GetInt32();

                    if (first.TryGetProperty("mitre_attack", out var mitre) && mitre.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var technique in mitre.EnumerateArray())
                        {
                            if (technique.TryGetProperty("element_identifier", out var id) && id.GetString() is string name)
                                result.BehaviorIndicators.Add(name);
                        }
                    }
                }
                else
                {
                    // 沙箱无此样本记录
                    result.ThreatLevel = ThreatLevel.Safe;
                    result.Confidence = 0.5;
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// MetaDefender查询 - 真实调用 MetaDefender Cloud v4 API（需配置环境变量 METADEFENDER_API_KEY）
        /// </summary>
        private async Task<ThreatIntelligenceSourceResult> QueryMetaDefenderAsync(string fileHash)
        {
            var result = new ThreatIntelligenceSourceResult
            {
                SourceName = "MetaDefender",
                QueryTime = DateTime.Now
            };

            try
            {
                var apiKey = Environment.GetEnvironmentVariable("METADEFENDER_API_KEY");
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    result.Error = "MetaDefender API key not configured (set METADEFENDER_API_KEY)";
                    return result;
                }

                using var request = new HttpRequestMessage(HttpMethod.Get,
                    $"https://api.metadefender.com/v4/hash/{fileHash}");
                request.Headers.Add("apikey", apiKey);

                using var response = await _httpClient.SendAsync(request);
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    result.ThreatLevel = ThreatLevel.Safe;
                    result.Confidence = 0.5;
                    return result;
                }

                if (!response.IsSuccessStatusCode)
                {
                    result.Error = $"MetaDefender API returned HTTP {(int)response.StatusCode}";
                    return result;
                }

                var json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);

                if (doc.RootElement.TryGetProperty("scan_results", out var scanResults))
                {
                    int detected = scanResults.TryGetProperty("total_detected_avs", out var det) ? det.GetInt32() : 0;
                    int totalAvs = scanResults.TryGetProperty("total_avs", out var tot) ? tot.GetInt32() : 0;

                    result.DetectionCount = detected;
                    result.Confidence = totalAvs > 0 ? Math.Min((double)detected / totalAvs + 0.5, 1.0) : 0.5;

                    if (detected >= 5) result.ThreatLevel = ThreatLevel.High;
                    else if (detected > 0) result.ThreatLevel = ThreatLevel.Medium;
                    else result.ThreatLevel = ThreatLevel.Safe;
                }
                else
                {
                    result.ThreatLevel = ThreatLevel.Safe;
                    result.Confidence = 0.5;
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 企业威胁情报源 - 真实查询可配置的私有情报源（需配置环境变量 ENTERPRISE_THREAT_FEED_URL）
        /// 接口约定：GET {url}/{sha256}，响应 JSON {"threatLevel": "High", "confidence": 0.9}
        /// </summary>
        private async Task<ThreatIntelligenceSourceResult> QueryEnterpriseThreatFeedAsync(string fileHash)
        {
            var result = new ThreatIntelligenceSourceResult
            {
                SourceName = "EnterpriseThreatFeed",
                QueryTime = DateTime.Now
            };

            try
            {
                var feedUrl = Environment.GetEnvironmentVariable("ENTERPRISE_THREAT_FEED_URL");
                if (string.IsNullOrWhiteSpace(feedUrl))
                {
                    result.Error = "Enterprise threat feed not configured (set ENTERPRISE_THREAT_FEED_URL)";
                    return result;
                }

                var requestUrl = $"{feedUrl.TrimEnd('/')}/{fileHash}";
                using var response = await _httpClient.GetAsync(requestUrl);

                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    // 私有情报库中无此哈希记录
                    result.ThreatLevel = ThreatLevel.Safe;
                    result.Confidence = 0.5;
                    return result;
                }

                if (!response.IsSuccessStatusCode)
                {
                    result.Error = $"Enterprise feed returned HTTP {(int)response.StatusCode}";
                    return result;
                }

                var json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);

                if (doc.RootElement.TryGetProperty("threatLevel", out var levelEl) &&
                    Enum.TryParse<ThreatLevel>(levelEl.GetString(), true, out var level))
                {
                    result.ThreatLevel = level;
                }
                else
                {
                    result.ThreatLevel = ThreatLevel.Safe;
                }

                result.Confidence = doc.RootElement.TryGetProperty("confidence", out var confEl) && confEl.ValueKind == JsonValueKind.Number
                    ? confEl.GetDouble()
                    : 0.6;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 自定义情报源
        /// </summary>
        private async Task<ThreatIntelligenceSourceResult> QueryCustomIntelligenceSourceAsync(string filePath)
        {
            try
            {
                var result = new ThreatIntelligenceSourceResult
                {
                    SourceName = "CustomIntelligence",
                    QueryTime = DateTime.Now
                };

                // 基于文件特征的本地分析
                var fileAnalysis = await AnalyzeFileFeaturesAsync(filePath);
                
                result.ThreatLevel = fileAnalysis.ThreatLevel;
                result.Confidence = fileAnalysis.Confidence;
                result.FileFeatures = fileAnalysis.Features;

                return result;
            }
            catch (Exception ex)
            {
                return new ThreatIntelligenceSourceResult
                {
                    SourceName = "CustomIntelligence",
                    Error = ex.Message,
                    QueryTime = DateTime.Now
                };
            }
        }

        /// <summary>
        /// 分析文件特征
        /// </summary>
        private async Task<FileFeatureAnalysis> AnalyzeFileFeaturesAsync(string filePath)
        {
            var analysis = new FileFeatureAnalysis();
            
            try
            {
                var fileInfo = new FileInfo(filePath);
                
                // 文件大小分析
                analysis.Features.FileSize = fileInfo.Length;
                analysis.Features.FileExtension = Path.GetExtension(filePath).ToLower();
                
                // 简单特征评分
                var threatScore = CalculateBasicThreatScore(analysis.Features);
                
                analysis.ThreatLevel = threatScore >= 0.7 ? ThreatLevel.Medium : ThreatLevel.Safe;
                analysis.Confidence = Math.Min(threatScore * 0.8, 1.0);

                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                analysis.Error = ex.Message;
            }

            return analysis;
        }

        /// <summary>
        /// 计算基本威胁评分
        /// </summary>
        private double CalculateBasicThreatScore(FileFeatures features)
        {
            var score = 0.0;

            // 可执行文件风险
            var executableExtensions = new HashSet<string>
            {
                ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs"
            };

            if (executableExtensions.Contains(features.FileExtension))
            {
                score += 0.4;
            }

            // 极小或极大文件风险
            if (features.FileSize < 1024 || features.FileSize > 100 * 1024 * 1024)
            {
                score += 0.3;
            }

            // 常见恶意文件扩展名
            var suspiciousExtensions = new HashSet<string>
            {
                ".scr", ".pif", ".cmd", ".bat", ".vbs", ".js", ".jar"
            };

            if (suspiciousExtensions.Contains(features.FileExtension))
            {
                score += 0.3;
            }

            return Math.Min(score, 1.0);
        }

        /// <summary>
        /// 批量查询威胁情报
        /// </summary>
        public async Task<BatchThreatIntelligenceReport> AnalyzeFilesBatchAsync(IEnumerable<string> filePaths)
        {
            var batchReport = new BatchThreatIntelligenceReport
            {
                StartTime = DateTime.Now,
                TotalFiles = filePaths.Count()
            };

            try
            {
                var analysisTasks = filePaths.Select(AnalyzeFileAsync).ToList();
                var results = await Task.WhenAll(analysisTasks);

                batchReport.FileReports = results.ToList();
                batchReport.SuccessfulAnalyses = results.Count(r => r.Success);
                batchReport.MaliciousFiles = results.Count(r => r.ThreatLevel >= ThreatLevel.Medium);
                batchReport.EndTime = DateTime.Now;
                batchReport.Success = true;
            }
            catch (Exception ex)
            {
                batchReport.Error = ex.Message;
                batchReport.Success = false;
            }

            return batchReport;
        }

        /// <summary>
        /// 更新本地威胁情报数据库
        /// </summary>
        public async Task<bool> UpdateLocalIntelligenceDatabaseAsync()
        {
            try
            {
                // 下载最新的威胁情报数据
                var updatedIntelligence = await DownloadLatestIntelligenceAsync();
                
                // 更新本地数据库
                await _localCache.UpdateDatabaseAsync(updatedIntelligence);
                
                // 清理过期数据
                await _localCache.CleanupExpiredDataAsync();

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"威胁情报数据库更新失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 下载最新威胁情报 - 真实从可配置情报源下载 JSON 数据（需配置环境变量 THREAT_INTEL_FEED_URL）
        /// 数据格式：JSON 数组 [{"hash": "...", "threatLevel": "High", "threatType": "Trojan", "detectionCount": 25, "lastSeen": "2026-01-01"}]
        /// </summary>
        private async Task<List<ThreatIntelligenceData>> DownloadLatestIntelligenceAsync()
        {
            var intelligenceData = new List<ThreatIntelligenceData>();

            try
            {
                var feedUrl = Environment.GetEnvironmentVariable("THREAT_INTEL_FEED_URL");
                if (string.IsNullOrWhiteSpace(feedUrl))
                {
                    Console.WriteLine("威胁情报源未配置（设置环境变量 THREAT_INTEL_FEED_URL 后启用在线更新）");
                    return intelligenceData;
                }

                var json = await _httpClient.GetStringAsync(feedUrl);
                using var doc = JsonDocument.Parse(json);

                if (doc.RootElement.ValueKind != JsonValueKind.Array)
                {
                    Console.WriteLine("威胁情报源返回的数据格式不正确（期望 JSON 数组）");
                    return intelligenceData;
                }

                foreach (var element in doc.RootElement.EnumerateArray())
                {
                    var data = new ThreatIntelligenceData
                    {
                        Hash = element.TryGetProperty("hash", out var hashEl) ? hashEl.GetString() : null,
                        ThreatType = element.TryGetProperty("threatType", out var typeEl) ? typeEl.GetString() : null,
                        DetectionCount = element.TryGetProperty("detectionCount", out var countEl) && countEl.ValueKind == JsonValueKind.Number
                            ? countEl.GetInt32() : 0
                    };

                    if (element.TryGetProperty("threatLevel", out var levelEl) &&
                        Enum.TryParse<ThreatLevel>(levelEl.GetString(), true, out var level))
                    {
                        data.ThreatLevel = level;
                    }

                    if (element.TryGetProperty("lastSeen", out var seenEl) &&
                        DateTime.TryParse(seenEl.GetString(), out var seen))
                    {
                        data.LastSeen = seen;
                    }

                    if (!string.IsNullOrEmpty(data.Hash))
                        intelligenceData.Add(data);
                }

                Console.WriteLine($"已从情报源下载 {intelligenceData.Count} 条威胁情报记录");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"威胁情报下载失败: {ex.Message}");
            }

            return intelligenceData;
        }

        /// <summary>
        /// 获取威胁情报统计
        /// </summary>
        public async Task<ThreatIntelligenceStats> GetStatisticsAsync()
        {
            var stats = new ThreatIntelligenceStats
            {
                GeneratedAt = DateTime.Now
            };

            try
            {
                var cacheStats = await _localCache.GetCacheStatisticsAsync();
                
                stats.TotalCachedEntries = cacheStats.TotalEntries;
                stats.CacheHitRate = cacheStats.HitRate;
                stats.LastUpdateTime = cacheStats.LastUpdate;
                stats.DatabaseSizeMB = cacheStats.DatabaseSize;

                return stats;
            }
            catch (Exception ex)
            {
                stats.Error = ex.Message;
                return stats;
            }
        }
    }

    // 支持的类型定义
    public class ThreatIntelligenceReport
    {
        public string FilePath { get; set; }
        public string FileHash { get; set; }
        public DateTime AnalysisStartTime { get; set; }
        public DateTime AnalysisEndTime { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public double Confidence { get; set; }
        public List<ThreatIntelligenceSource> SourcesConsolidated { get; set; } = new List<ThreatIntelligenceSource>();
        public MachineLearningAnalysis MachineLearningData { get; set; }
        public bool CachedResponse { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }

    public class ThreatIntelligenceSourceResult
    {
        public string SourceName { get; set; }
        public DateTime QueryTime { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public double Confidence { get; set; }
        public int DetectionCount { get; set; }
        public List<string> MalwareFamilies { get; set; } = new List<string>();
        public List<string> BehaviorIndicators { get; set; } = new List<string>();
        public List<string> Tags { get; set; } = new List<string>();
        public FileFeatures FileFeatures { get; set; }
        public string Error { get; set; }
    }

    public class BatchThreatIntelligenceReport
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public int TotalFiles { get; set; }
        public int SuccessfulAnalyses { get; set; }
        public int MaliciousFiles { get; set; }
        public List<ThreatIntelligenceReport> FileReports { get; set; } = new List<ThreatIntelligenceReport>();
        public bool Success { get; set; }
        public string Error { get; set; }
    }

    public class FileFeatureAnalysis
    {
        public FileFeatures Features { get; set; } = new FileFeatures();
        public ThreatLevel ThreatLevel { get; set; }
        public double Confidence { get; set; }
        public string Error { get; set; }
    }

    public class FileFeatures
    {
        public long FileSize { get; set; }
        public string FileExtension { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastWriteTime { get; set; }
    }

    public class ThreatIntelligenceStats
    {
        public DateTime GeneratedAt { get; set; }
        public int TotalCachedEntries { get; set; }
        public double CacheHitRate { get; set; }
        public DateTime LastUpdateTime { get; set; }
        public double DatabaseSizeMB { get; set; }
        public string Error { get; set; }
    }

    // 聚合器：基于多个情报源的真实查询结果进行聚合
    public class ThreatIntelligenceAggregator
    {
        public async Task<AggregatedIntelligenceResult> AggregateIntelligenceAsync(List<ThreatIntelligenceSourceResult> results)
        {
            await Task.CompletedTask;

            // 只统计真实返回结果的源；查询失败或未配置密钥的源不参与判定
            var validResults = results.Where(r => string.IsNullOrEmpty(r.Error)).ToList();

            var aggregated = new AggregatedIntelligenceResult
            {
                Sources = results.Select(r => new ThreatIntelligenceSource
                {
                    Name = r.SourceName,
                    ThreatLevel = r.ThreatLevel,
                    Confidence = string.IsNullOrEmpty(r.Error) ? r.Confidence : 0
                }).ToList()
            };

            if (validResults.Count == 0)
            {
                // 没有任何有效情报源时如实上报，不得伪装成"确认安全"
                aggregated.Error = "No threat intelligence source returned a valid result";
                aggregated.OverallThreatLevel = ThreatLevel.Safe;
                aggregated.Confidence = 0;
                return aggregated;
            }

            // 保守聚合：取所有有效源中的最高威胁级别，置信度取平均
            aggregated.OverallThreatLevel = validResults.Max(r => r.ThreatLevel);
            aggregated.Confidence = validResults.Average(r => r.Confidence);

            return aggregated;
        }
    }

    public class LocalIntelligenceCache
    {
        private readonly Dictionary<string, CachedIntelligence> _cache = new Dictionary<string, CachedIntelligence>();
        private readonly Dictionary<string, ThreatIntelligenceData> _intelligenceDatabase = new Dictionary<string, ThreatIntelligenceData>();
        private long _hits;
        private long _misses;

        public async Task<CachedIntelligence> GetCachedIntelligenceAsync(string fileHash)
        {
            await Task.CompletedTask;

            if (_cache.TryGetValue(fileHash, out var cached) &&
                cached.CacheTime > DateTime.Now.AddHours(-24))
            {
                System.Threading.Interlocked.Increment(ref _hits);
                return cached;
            }

            System.Threading.Interlocked.Increment(ref _misses);
            return null;
        }

        public async Task CacheIntelligenceAsync(string fileHash, CachedIntelligence intelligence)
        {
            await Task.CompletedTask;
            _cache[fileHash] = intelligence;
        }

        public async Task UpdateDatabaseAsync(List<ThreatIntelligenceData> intelligenceData)
        {
            await Task.CompletedTask;

            foreach (var data in intelligenceData)
            {
                if (!string.IsNullOrEmpty(data.Hash))
                    _intelligenceDatabase[data.Hash] = data;
            }
        }

        /// <summary>
        /// 查询本地情报数据库中的哈希记录
        /// </summary>
        public ThreatIntelligenceData LookupDatabase(string fileHash)
        {
            return fileHash != null && _intelligenceDatabase.TryGetValue(fileHash, out var data) ? data : null;
        }

        public async Task CleanupExpiredDataAsync()
        {
            await Task.CompletedTask;
            var expiredKeys = _cache.Where(kvp =>
                kvp.Value.CacheTime < DateTime.Now.AddDays(-7)).Select(kvp => kvp.Key).ToList();

            foreach (var key in expiredKeys)
            {
                _cache.Remove(key);
            }
        }

        public async Task<CacheStatistics> GetCacheStatisticsAsync()
        {
            await Task.CompletedTask;
            var hits = System.Threading.Interlocked.Read(ref _hits);
            var misses = System.Threading.Interlocked.Read(ref _misses);
            var totalQueries = hits + misses;

            return new CacheStatistics
            {
                TotalEntries = _cache.Count,
                HitRate = totalQueries > 0 ? (double)hits / totalQueries : 0,
                LastUpdate = _cache.Count > 0 ? _cache.Values.Max(c => c.CacheTime) : DateTime.MinValue,
                DatabaseSize = (_cache.Count + _intelligenceDatabase.Count) * 0.1 // 每条记录约0.1MB估算
            };
        }
    }

    public class MachineLearningAnalyzer
    {
        public async Task<MachineLearningAnalysis> EnhanceAnalysisAsync(string filePath, AggregatedIntelligenceResult baseResult)
        {
            await Task.CompletedTask;

            var analysis = new MachineLearningAnalysis
            {
                EnhancedThreatLevel = baseResult.OverallThreatLevel,
                Confidence = baseResult.Confidence,
                ModelVersion = "v1.2.0"
            };

            try
            {
                if (!File.Exists(filePath)) return analysis;

                // 真实的本地启发式增强：熵值 + 文件特征评分
                var fileInfo = new FileInfo(filePath);
                double entropy = CalculateFileEntropy(filePath);

                bool isExecutable = string.Equals(fileInfo.Extension, ".exe", StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(fileInfo.Extension, ".dll", StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(fileInfo.Extension, ".scr", StringComparison.OrdinalIgnoreCase);

                int score = 0;
                if (entropy > 7.2) score += 2;          // 高熵：加壳/加密内容
                else if (entropy > 6.5) score += 1;
                if (isExecutable && fileInfo.Length < 50 * 1024) score += 1;   // 小体积可执行文件
                if (isExecutable && fileInfo.CreationTime > DateTime.Now.AddDays(-1)) score += 1;

                if (score >= 3 && baseResult.OverallThreatLevel < ThreatLevel.High)
                {
                    analysis.EnhancedThreatLevel = ThreatLevel.High;
                    analysis.Confidence = Math.Min(0.6 + score * 0.1, 0.9);
                }
                else if (score >= 2 && baseResult.OverallThreatLevel == ThreatLevel.Safe)
                {
                    analysis.EnhancedThreatLevel = ThreatLevel.Low;
                    analysis.Confidence = Math.Min(0.4 + score * 0.1, 0.7);
                }
                else
                {
                    analysis.Confidence = Math.Max(baseResult.Confidence, 0.3);
                }
            }
            catch
            {
                // 本地增强分析失败时不影响基础情报结论
            }

            return analysis;
        }

        private static double CalculateFileEntropy(string filePath)
        {
            var counts = new long[256];
            long totalBytes = 0;
            var buffer = new byte[65536];

            using var stream = File.OpenRead(filePath);
            int bytesRead;
            while (totalBytes < buffer.Length * 8 && (bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                for (int i = 0; i < bytesRead; i++)
                    counts[buffer[i]]++;
                totalBytes += bytesRead;
            }

            if (totalBytes == 0) return 0;

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double probability = (double)counts[i] / totalBytes;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return entropy;
        }
    }

    // 支持的数据类型
    public class CachedIntelligence
    {
        public string FileHash { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public double Confidence { get; set; }
        public List<ThreatIntelligenceSource> Sources { get; set; }
        public DateTime CacheTime { get; set; }
    }

    public class AggregatedIntelligenceResult
    {
        public ThreatLevel OverallThreatLevel { get; set; }
        public double Confidence { get; set; }
        public List<ThreatIntelligenceSource> Sources { get; set; }
        public string Error { get; set; }
    }

    public class ThreatIntelligenceSource
    {
        public string Name { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public double Confidence { get; set; }
    }

    public class ThreatIntelligenceData
    {
        public string Hash { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public string ThreatType { get; set; }
        public DateTime LastSeen { get; set; }
        public int DetectionCount { get; set; }
    }

    public class MachineLearningAnalysis
    {
        public ThreatLevel EnhancedThreatLevel { get; set; }
        public double Confidence { get; set; }
        public string ModelVersion { get; set; }
    }

    public class CacheStatistics
    {
        public int TotalEntries { get; set; }
        public double HitRate { get; set; }
        public DateTime LastUpdate { get; set; }
        public double DatabaseSize { get; set; }
    }
}