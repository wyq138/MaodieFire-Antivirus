// 耄耋软件工作室 开发，严禁非法反编译
// 云查杀配置 - 管理用户配置的各云查杀服务 API Key
using System;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FireAntivirus.CloudScanner
{
    /// <summary>
    /// 云查杀配置 - 管理各云查杀服务的 API Key 和开关
    /// 配置文件存储在 %APPDATA%/FireAntivirus/cloud_scan_config.json
    /// </summary>
    public class CloudScanConfig
    {
        /// <summary>是否启用云查杀</summary>
        public bool EnableCloudScan { get; set; } = true;

        /// <summary>是否启用 MalwareBazaar (abuse.ch 免费, 无需 Key)</summary>
        public bool EnableMalwareBazaar { get; set; } = true;

        /// <summary>是否启用 AlienVault OTX (免费, 无需 Key)</summary>
        public bool EnableOTX { get; set; } = true;

        /// <summary>是否启用 VirusTotal (需用户配置 API Key)</summary>
        public bool EnableVirusTotal { get; set; } = true;

        /// <summary>是否启用 HybridAnalysis (需用户配置 API Key)</summary>
        public bool EnableHybridAnalysis { get; set; } = false;

        /// <summary>VirusTotal API Key (https://www.virustotal.com/gui/my-apikey 免费申请)</summary>
        public string VirusTotalApiKey { get; set; } = string.Empty;

        /// <summary>Hybrid Analysis API Key (https://www.hybrid-analysis.com 免费注册)</summary>
        public string HybridAnalysisApiKey { get; set; } = string.Empty;

        /// <summary>遇到哈希未命中的可疑文件是否自动上传到 VirusTotal</summary>
        public bool AutoUploadUnknownFiles { get; set; } = false;

        /// <summary>云查杀判定阈值: 多少引擎报毒算确认 (默认 2)</summary>
        public int PositiveThreshold { get; set; } = 2;

        /// <summary>请求超时秒数</summary>
        public int TimeoutSeconds { get; set; } = 30;

        private static readonly string ConfigDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "FireAntivirus");

        private static readonly string ConfigPath = Path.Combine(ConfigDirectory, "cloud_scan_config.json");

        /// <summary>加载配置</summary>
        public static CloudScanConfig Load()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    var json = File.ReadAllText(ConfigPath);
                    return JsonConvert.DeserializeObject<CloudScanConfig>(json) ?? new CloudScanConfig();
                }
            }
            catch
            {
                // 配置加载失败使用默认值
            }
            return new CloudScanConfig();
        }

        /// <summary>保存配置</summary>
        public void Save()
        {
            try
            {
                Directory.CreateDirectory(ConfigDirectory);
                var json = JsonConvert.SerializeObject(this, Formatting.Indented);
                File.WriteAllText(ConfigPath, json);
            }
            catch
            {
                // 保存失败静默处理
            }
        }

        /// <summary>配置文件路径 (用于UI显示)</summary>
        public static string GetConfigPath() => ConfigPath;
    }
}
