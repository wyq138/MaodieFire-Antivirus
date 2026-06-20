using FireAntivirus.Common;
using FireAntivirus.Data;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    public class CloudSecurity
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private readonly string _cloudEndpoint;
        private readonly int _timeoutMs;
        private readonly int _retryCount;
        private readonly int _retryDelayMs;

        public CloudSecurity(string apiKey, string cloudEndpoint, int timeoutMs = 30000, int retryCount = 3, int retryDelayMs = 1000)
        {
            _apiKey = apiKey;
            _cloudEndpoint = cloudEndpoint;
            _timeoutMs = timeoutMs;
            _retryCount = retryCount;
            _retryDelayMs = retryDelayMs;

            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromMilliseconds(timeoutMs);
            _httpClient.DefaultRequestHeaders.Add("X-API-Key", apiKey);
        }

        public async Task<CloudScanResult> ScanFileAsync(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found", filePath);
            }

            try
            {
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    var fileHash = CalculateFileHash(fileStream);
                    var fileName = Path.GetFileName(filePath);
                    var fileSize = new FileInfo(filePath).Length;

                    var scanRequest = new CloudScanRequest
                    {
                        FileHash = fileHash,
                        FileName = fileName,
                        FileSize = fileSize,
                        Timestamp = DateTime.UtcNow
                    };

                    for (int attempt = 0; attempt < _retryCount; attempt++)
                    {
                        try
                        {
                            var content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(scanRequest), Encoding.UTF8, "application/json");
                            var response = await _httpClient.PostAsync($"{_cloudEndpoint}/scan/file", content);
                            response.EnsureSuccessStatusCode();

                            var responseContent = await response.Content.ReadAsStringAsync();
                            var scanResult = Newtonsoft.Json.JsonConvert.DeserializeObject<CloudScanResult>(responseContent);
                            return scanResult;
                        }
                        catch (HttpRequestException ex)
                        {
                            if (attempt == _retryCount - 1)
                            {
                                throw;
                            }
                            await Task.Delay(_retryDelayMs * (attempt + 1));
                        }
                    }

                    throw new Exception("Cloud scan failed after multiple attempts");
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Cloud scan error: {ex.Message}");
                throw;
            }
        }

        public async Task<CloudScanResult> ScanUrlAsync(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                throw new ArgumentNullException(nameof(url));
            }

            try
            {
                var scanRequest = new CloudUrlScanRequest
                {
                    Url = url,
                    Timestamp = DateTime.UtcNow
                };

                for (int attempt = 0; attempt < _retryCount; attempt++)
                {
                    try
                    {
                        var content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(scanRequest), Encoding.UTF8, "application/json");
                        var response = await _httpClient.PostAsync($"{_cloudEndpoint}/scan/url", content);
                        response.EnsureSuccessStatusCode();

                        var responseContent = await response.Content.ReadAsStringAsync();
                        var scanResult = Newtonsoft.Json.JsonConvert.DeserializeObject<CloudScanResult>(responseContent);
                        return scanResult;
                    }
                    catch (HttpRequestException ex)
                    {
                        if (attempt == _retryCount - 1)
                        {
                            throw;
                        }
                        await Task.Delay(_retryDelayMs * (attempt + 1));
                    }
                }

                throw new Exception("Cloud URL scan failed after multiple attempts");
            }
            catch (Exception ex)
            {
                Logger.Error($"Cloud URL scan error: {ex.Message}");
                throw;
            }
        }

        public async Task<CloudIntelligenceResult> GetThreatIntelligenceAsync(string indicator)
        {
            if (string.IsNullOrWhiteSpace(indicator))
            {
                throw new ArgumentNullException(nameof(indicator));
            }

            try
            {
                for (int attempt = 0; attempt < _retryCount; attempt++)
                {
                    try
                    {
                        var response = await _httpClient.GetAsync($"{_cloudEndpoint}/intelligence/{Uri.EscapeDataString(indicator)}");
                        response.EnsureSuccessStatusCode();

                        var responseContent = await response.Content.ReadAsStringAsync();
                        var intelligenceResult = Newtonsoft.Json.JsonConvert.DeserializeObject<CloudIntelligenceResult>(responseContent);
                        return intelligenceResult;
                    }
                    catch (HttpRequestException ex)
                    {
                        if (attempt == _retryCount - 1)
                        {
                            throw;
                        }
                        await Task.Delay(_retryDelayMs * (attempt + 1));
                    }
                }

                throw new Exception("Failed to get threat intelligence after multiple attempts");
            }
            catch (Exception ex)
            {
                Logger.Error($"Threat intelligence error: {ex.Message}");
                throw;
            }
        }

        public async Task<CloudUpdateResult> UpdateLocalDatabaseAsync()
        {
            try
            {
                var updateRequest = new CloudUpdateRequest
                {
                    CurrentDatabaseVersion = GetCurrentDatabaseVersion(),
                    Timestamp = DateTime.UtcNow
                };

                for (int attempt = 0; attempt < _retryCount; attempt++)
                {
                    try
                    {
                        var content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(updateRequest), Encoding.UTF8, "application/json");
                        var response = await _httpClient.PostAsync($"{_cloudEndpoint}/update/database", content);
                        response.EnsureSuccessStatusCode();

                        var responseContent = await response.Content.ReadAsStringAsync();
                        var updateResult = Newtonsoft.Json.JsonConvert.DeserializeObject<CloudUpdateResult>(responseContent);
                        
                        if (updateResult.HasUpdates)
                        {
                            await DownloadAndApplyUpdates(updateResult.UpdatePackages);
                        }

                        return updateResult;
                    }
                    catch (HttpRequestException ex)
                    {
                        if (attempt == _retryCount - 1)
                        {
                            throw;
                        }
                        await Task.Delay(_retryDelayMs * (attempt + 1));
                    }
                }

                throw new Exception("Database update failed after multiple attempts");
            }
            catch (Exception ex)
            {
                Logger.Error($"Database update error: {ex.Message}");
                throw;
            }
        }

        public async Task<CloudSubmitResult> SubmitSampleAsync(string filePath, ThreatCategory category, string notes = null)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found", filePath);
            }

            try
            {
                using (var content = new MultipartFormDataContent())
                {
                    var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                    var fileContent = new StreamContent(fileStream);
                    content.Add(fileContent, "sample", Path.GetFileName(filePath));
                    content.Add(new StringContent(category.ToString()), "category");
                    
                    if (!string.IsNullOrWhiteSpace(notes))
                    {
                        content.Add(new StringContent(notes), "notes");
                    }

                    for (int attempt = 0; attempt < _retryCount; attempt++)
                    {
                        try
                        {
                            var response = await _httpClient.PostAsync($"{_cloudEndpoint}/submit/sample", content);
                            response.EnsureSuccessStatusCode();

                            var responseContent = await response.Content.ReadAsStringAsync();
                            var submitResult = Newtonsoft.Json.JsonConvert.DeserializeObject<CloudSubmitResult>(responseContent);
                            return submitResult;
                        }
                        catch (HttpRequestException ex)
                        {
                            if (attempt == _retryCount - 1)
                            {
                                throw;
                            }
                            await Task.Delay(_retryDelayMs * (attempt + 1));
                        }
                    }
                }

                throw new Exception("Sample submission failed after multiple attempts");
            }
            catch (Exception ex)
            {
                Logger.Error($"Sample submission error: {ex.Message}");
                throw;
            }
        }

        public async Task<CloudStatisticsResult> GetStatisticsAsync(TimeRange timeRange)
        {
            try
            {
                var request = new CloudStatisticsRequest
                {
                    TimeRange = timeRange,
                    Timestamp = DateTime.UtcNow
                };

                for (int attempt = 0; attempt < _retryCount; attempt++)
                {
                    try
                    {
                        var content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(request), Encoding.UTF8, "application/json");
                        var response = await _httpClient.PostAsync($"{_cloudEndpoint}/statistics", content);
                        response.EnsureSuccessStatusCode();

                        var responseContent = await response.Content.ReadAsStringAsync();
                        var statisticsResult = Newtonsoft.Json.JsonConvert.DeserializeObject<CloudStatisticsResult>(responseContent);
                        return statisticsResult;
                    }
                    catch (HttpRequestException ex)
                    {
                        if (attempt == _retryCount - 1)
                        {
                            throw;
                        }
                        await Task.Delay(_retryDelayMs * (attempt + 1));
                    }
                }

                throw new Exception("Failed to get statistics after multiple attempts");
            }
            catch (Exception ex)
            {
                Logger.Error($"Statistics error: {ex.Message}");
                throw;
            }
        }

        private string CalculateFileHash(Stream stream)
        {
            using (var sha256 = SHA256.Create())
            {
                stream.Position = 0;
                var hashBytes = sha256.ComputeHash(stream);
                stream.Position = 0;
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        private string GetCurrentDatabaseVersion()
        {
            // 实现获取当前本地数据库版本的逻辑
            return "1.0.0.0";
        }

        private async Task DownloadAndApplyUpdates(List<UpdatePackage> updatePackages)
        {
            foreach (var package in updatePackages)
            {
                try
                {
                    var response = await _httpClient.GetAsync(package.DownloadUrl);
                    response.EnsureSuccessStatusCode();

                    var packageContent = await response.Content.ReadAsByteArrayAsync();
                    // 实现应用更新包的逻辑
                    Logger.Info($"Applied update package: {package.PackageId}");
                }
                catch (Exception ex)
                {
                    Logger.Error($"Failed to apply update package {package.PackageId}: {ex.Message}");
                }
            }
        }
    }

    public class CloudScanRequest
    {
        public string FileHash { get; set; }
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class CloudUrlScanRequest
    {
        public string Url { get; set; }
        public DateTime Timestamp { get; set; }
    }



    public class CloudIntelligenceResult
    {
        public string Indicator { get; set; }
        public IndicatorType IndicatorType { get; set; }
        public bool IsMalicious { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public ThreatCategory ThreatCategory { get; set; }
        public string ThreatName { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public int DetectionCount { get; set; }
        public List<string> RelatedIndicators { get; set; }
        public string DetailedInformation { get; set; }
    }

    public class CloudUpdateRequest
    {
        public string CurrentDatabaseVersion { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class CloudUpdateResult
    {
        public bool HasUpdates { get; set; }
        public string NewVersion { get; set; }
        public List<UpdatePackage> UpdatePackages { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class UpdatePackage
    {
        public string PackageId { get; set; }
        public string PackageType { get; set; }
        public string Version { get; set; }
        public long Size { get; set; }
        public string DownloadUrl { get; set; }
        public string Checksum { get; set; }
    }

    public class CloudSubmitResult
    {
        public string SubmissionId { get; set; }
        public bool IsSuccess { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class CloudStatisticsRequest
    {
        public TimeRange TimeRange { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class CloudStatisticsResult
    {
        public TimeRange TimeRange { get; set; }
        public int TotalScans { get; set; }
        public int MaliciousDetected { get; set; }
        public int FalsePositives { get; set; }
        public Dictionary<ThreatCategory, int> ThreatCategoryBreakdown { get; set; }
        public Dictionary<string, int> TopDetectedThreats { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum ThreatLevel
    {
        Low,
        Medium,
        High,
        Critical
    }

    public enum ThreatCategory
    {
        Virus,
        Trojan,
        Worm,
        Ransomware,
        Spyware,
        Adware,
        Phishing,
        MaliciousUrl,
        Exploit,
        Rootkit,
        Backdoor,
        Keylogger,
        Other
    }

    public enum IndicatorType
    {
        FileHash,
        Url,
        IpAddress,
        Domain,
        Email,
        Certificate
    }

    public enum TimeRange
    {
        Last24Hours,
        Last7Days,
        Last30Days,
        Last90Days,
        Custom
    }
}
