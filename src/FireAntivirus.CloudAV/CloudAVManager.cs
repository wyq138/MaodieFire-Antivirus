// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace FireAntivirus.CloudAV
{
    public class CloudAVManager
    {
        private static readonly string[] OpenSourceAVAPIs = {
            "https://api.clamav.net/v1/scan",
            "https://api.virustotal.com/v3/files/scans",
            "https://api.metadefender.com/v4/file"
        };
        
        private HttpClient _httpClient;
        private List<CloudAVProvider> _providers;

        public event EventHandler<CloudAVScanCompleteEventArgs> ScanComplete;

        public CloudAVManager()
        {
            _httpClient = new HttpClient();
            _providers = new List<CloudAVProvider>();
            InitializeProviders();
        }

        /// <summary>
        /// 初始化云杀毒提供商
        /// </summary>
        private void InitializeProviders()
        {
            _providers.Add(new CloudAVProvider
            {
                Name = "ClamAV",
                ApiUrl = "https://api.clamav.net/v1/scan",
                ApiKey = "",
                IsEnabled = true
            });

            _providers.Add(new CloudAVProvider
            {
                Name = "VirusTotal",
                ApiUrl = "https://api.virustotal.com/v3/files/scans",
                ApiKey = "YOUR_API_KEY", // 需要用户配置
                IsEnabled = false
            });

            _providers.Add(new CloudAVProvider
            {
                Name = "MetaDefender",
                ApiUrl = "https://api.metadefender.com/v4/file",
                ApiKey = "YOUR_API_KEY", // 需要用户配置
                IsEnabled = false
            });
        }

        /// <summary>
        /// 扫描文件
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>扫描结果</returns>
        public async Task<CloudAVScanResult> ScanFileAsync(string filePath)
        {
            if (!File.Exists(filePath))
                return new CloudAVScanResult { FilePath = filePath, IsInfected = false, ErrorMessage = "文件不存在" };

            var results = new List<CloudAVProviderResult>();
            int positiveCount = 0;

            foreach (var provider in _providers)
            {
                if (provider.IsEnabled)
                {
                    try
                    {
                        var result = await ScanFileWithProviderAsync(filePath, provider);
                        results.Add(result);
                        if (result.IsInfected)
                            positiveCount++;
                    }
                    catch (Exception ex)
                    {
                        results.Add(new CloudAVProviderResult
                        {
                            ProviderName = provider.Name,
                            IsInfected = false,
                            ErrorMessage = ex.Message
                        });
                    }
                }
            }

            var finalResult = new CloudAVScanResult
            {
                FilePath = filePath,
                IsInfected = positiveCount > 0,
                ProviderResults = results
            };

            if (finalResult.IsInfected)
            {
                var mostConfidentResult = results.Find(r => r.IsInfected && !string.IsNullOrEmpty(r.ThreatName));
                if (mostConfidentResult != null)
                {
                    finalResult.ThreatName = mostConfidentResult.ThreatName;
                    finalResult.Confidence = (double)positiveCount / results.Count;
                }
                else
                {
                    finalResult.ThreatName = "检测到恶意文件";
                    finalResult.Confidence = (double)positiveCount / results.Count;
                }
            }
            else
            {
                finalResult.ThreatName = "安全文件";
                finalResult.Confidence = 1.0;
            }

            OnScanComplete(new CloudAVScanCompleteEventArgs { Result = finalResult });
            return finalResult;
        }

        /// <summary>
        /// 使用特定提供商扫描文件
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="provider">云杀毒提供商</param>
        /// <returns>扫描结果</returns>
        private async Task<CloudAVProviderResult> ScanFileWithProviderAsync(string filePath, CloudAVProvider provider)
        {
            var result = new CloudAVProviderResult { ProviderName = provider.Name };

            try
            {
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (var content = new MultipartFormDataContent())
                {
                    var fileContent = new StreamContent(fileStream);
                    fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                    content.Add(fileContent, "file", Path.GetFileName(filePath));

                    if (!string.IsNullOrEmpty(provider.ApiKey))
                    {
                        _httpClient.DefaultRequestHeaders.Add("x-apikey", provider.ApiKey);
                    }

                    var response = await _httpClient.PostAsync(provider.ApiUrl, content);
                    if (response.IsSuccessStatusCode)
                    {
                        var responseContent = await response.Content.ReadAsStringAsync();
                        result = ParseProviderResponse(provider.Name, responseContent);
                    }
                    else
                    {
                        result.ErrorMessage = $"API调用失败: {response.StatusCode}";
                    }
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 解析提供商响应
        /// </summary>
        /// <param name="providerName">提供商名称</param>
        /// <param name="response">响应内容</param>
        /// <returns>解析结果</returns>
        private CloudAVProviderResult ParseProviderResponse(string providerName, string response)
        {
            var result = new CloudAVProviderResult { ProviderName = providerName };

            try
            {
                switch (providerName)
                {
                    case "ClamAV":
                        // 解析ClamAV响应
                        var clamAVResult = JsonConvert.DeserializeObject<ClamAVResponse>(response);
                        result.IsInfected = clamAVResult.Infected > 0;
                        if (result.IsInfected && clamAVResult.Viruses != null && clamAVResult.Viruses.Count > 0)
                        {
                            result.ThreatName = clamAVResult.Viruses[0];
                        }
                        break;

                    case "VirusTotal":
                        // 解析VirusTotal响应
                        var virusTotalResult = JsonConvert.DeserializeObject<VirusTotalResponse>(response);
                        result.IsInfected = virusTotalResult.Data.Attributes.LastAnalysisStats.Malicious > 0;
                        if (result.IsInfected)
                        {
                            result.ThreatName = "恶意文件";
                        }
                        break;

                    case "MetaDefender":
                        // 解析MetaDefender响应
                        var metaDefenderResult = JsonConvert.DeserializeObject<MetaDefenderResponse>(response);
                        result.IsInfected = metaDefenderResult.ScanResults != null && 
                                           metaDefenderResult.ScanResults.ScanDetails != null &&
                                           metaDefenderResult.ScanResults.ScanDetails.Count > 0;
                        if (result.IsInfected)
                        {
                            result.ThreatName = "恶意文件";
                        }
                        break;

                    default:
                        result.ErrorMessage = "未知提供商";
                        break;
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = $"解析响应失败: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// 添加云杀毒提供商
        /// </summary>
        /// <param name="provider">云杀毒提供商</param>
        public void AddProvider(CloudAVProvider provider)
        {
            _providers.Add(provider);
        }

        /// <summary>
        /// 移除云杀毒提供商
        /// </summary>
        /// <param name="providerName">提供商名称</param>
        public void RemoveProvider(string providerName)
        {
            _providers.RemoveAll(p => p.Name == providerName);
        }

        /// <summary>
        /// 更新云杀毒提供商
        /// </summary>
        /// <param name="provider">云杀毒提供商</param>
        public void UpdateProvider(CloudAVProvider provider)
        {
            var existingProvider = _providers.Find(p => p.Name == provider.Name);
            if (existingProvider != null)
            {
                existingProvider.ApiUrl = provider.ApiUrl;
                existingProvider.ApiKey = provider.ApiKey;
                existingProvider.IsEnabled = provider.IsEnabled;
            }
        }

        /// <summary>
        /// 获取所有云杀毒提供商
        /// </summary>
        /// <returns>云杀毒提供商列表</returns>
        public List<CloudAVProvider> GetProviders()
        {
            return _providers;
        }

        /// <summary>
        /// 触发扫描完成事件
        /// </summary>
        /// <param name="e">事件参数</param>
        protected virtual void OnScanComplete(CloudAVScanCompleteEventArgs e)
        {
            ScanComplete?.Invoke(this, e);
        }
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
        public List<CloudAVProviderResult> ProviderResults { get; set; }
        public DateTime ScanTime { get; set; } = DateTime.Now;
    }

    public class CloudAVProviderResult
    {
        public string ProviderName { get; set; }
        public bool IsInfected { get; set; }
        public string ThreatName { get; set; }
        public string ErrorMessage { get; set; }
    }

    // ClamAV响应结构
    public class ClamAVResponse
    {
        public int Infected { get; set; }
        public List<string> Viruses { get; set; }
    }

    // VirusTotal响应结构
    public class VirusTotalResponse
    {
        public VirusTotalData Data { get; set; }
    }

    public class VirusTotalData
    {
        public VirusTotalAttributes Attributes { get; set; }
    }

    public class VirusTotalAttributes
    {
        public VirusTotalStats LastAnalysisStats { get; set; }
    }

    public class VirusTotalStats
    {
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public int Undetected { get; set; }
    }

    // MetaDefender响应结构
    public class MetaDefenderResponse
    {
        public MetaDefenderScanResults ScanResults { get; set; }
    }

    public class MetaDefenderScanResults
    {
        public Dictionary<string, MetaDefenderScanDetail> ScanDetails { get; set; }
    }

    public class MetaDefenderScanDetail
    {
        public string ScanResult { get; set; }
        public string ThreatFound { get; set; }
    }

    public class CloudAVScanCompleteEventArgs : EventArgs
    {
        public CloudAVScanResult Result { get; set; }
    }
}
