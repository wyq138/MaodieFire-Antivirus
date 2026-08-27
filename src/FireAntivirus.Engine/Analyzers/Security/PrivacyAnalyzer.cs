// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace FireAntivirus.Engine.Analyzers.Security
{
    /// <summary>
    /// 隐私分析器 - 分析系统隐私风险
    /// </summary>
    public class PrivacyAnalyzer
    {
        private readonly List<PrivacyIssue> _issues;

        public PrivacyAnalyzer()
        {
            _issues = new List<PrivacyIssue>();
        }

        public PrivacyResult Analyze()
        {
            var result = new PrivacyResult
            {
                Issues = new List<PrivacyIssue>(),
                Warnings = new List<string>(),
                Score = 100
            };

            try
            {
                // 检查浏览器隐私
                CheckBrowserPrivacy(result);

                // 检查系统隐私设置
                CheckSystemPrivacy(result);

                // 检查最近文件记录
                CheckRecentFiles(result);

                // 检查剪贴板历史
                CheckClipboardHistory(result);

                // 检查位置服务
                CheckLocationServices(result);

                // 检查摄像头/麦克风权限
                CheckDevicePermissions(result);

                // 计算隐私分数
                result.Score = CalculatePrivacyScore(result.Issues);
                
                if (result.Issues.Count > 0)
                {
                    result.Warnings.Add($"发现 {result.Issues.Count} 个隐私风险项");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"隐私分析错误: {ex.Message}");
            }

            return result;
        }

        private void CheckBrowserPrivacy(PrivacyResult result)
        {
            try
            {
                // 检查Chrome
                var chromePaths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "History"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Cookies")
                };

                foreach (var path in chromePaths)
                {
                    if (File.Exists(path))
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "浏览器",
                            Description = "Chrome浏览历史或Cookie存在",
                            Severity = "中",
                            Location = path,
                            Recommendation = "定期清理浏览历史和Cookie"
                        });
                    }
                }

                // 检查Edge
                var edgePaths = new[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "History"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "Cookies")
                };

                foreach (var path in edgePaths)
                {
                    if (File.Exists(path))
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "浏览器",
                            Description = "Edge浏览历史或Cookie存在",
                            Severity = "中",
                            Location = path,
                            Recommendation = "定期清理浏览历史和Cookie"
                        });
                    }
                }

                // 检查Firefox
                var firefoxPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mozilla", "Firefox", "Profiles");
                if (Directory.Exists(firefoxPath))
                {
                    var profiles = Directory.GetDirectories(firefoxPath);
                    if (profiles.Length > 0)
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "浏览器",
                            Description = "Firefox配置文件存在",
                            Severity = "低",
                            Location = firefoxPath,
                            Recommendation = "定期清理Firefox数据"
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyAnalyzer.cs 捕获异常", ex.Message); }
        }

        private void CheckSystemPrivacy(PrivacyResult result)
        {
            try
            {
                // 检查Windows遥测
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection");
                if (key != null)
                {
                    var value = key.GetValue("AllowTelemetry");
                    if (value != null && Convert.ToInt32(value) > 1)
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "系统",
                            Description = "Windows遥测数据收集已启用",
                            Severity = "高",
                            Location = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
                            Recommendation = "降低遥测级别到基本"
                        });
                    }
                }

                // 检查广告ID
                using var adKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo");
                if (adKey != null)
                {
                    var enabled = adKey.GetValue("Enabled");
                    if (enabled != null && Convert.ToInt32(enabled) == 1)
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "广告",
                            Description = "广告ID已启用",
                            Severity = "中",
                            Location = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
                            Recommendation = "禁用广告ID"
                        });
                    }
                }

                // 检查活动历史
                using var activityKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy");
                if (activityKey != null)
                {
                    var activityEnabled = activityKey.GetValue("ActivityHistoryEnabled");
                    if (activityEnabled != null && Convert.ToInt32(activityEnabled) != 0)
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "活动历史",
                            Description = "活动历史记录已启用",
                            Severity = "中",
                            Location = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Privacy",
                            Recommendation = "禁用活动历史记录"
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyAnalyzer.cs 捕获异常", ex.Message); }
        }

        private void CheckRecentFiles(PrivacyResult result)
        {
            try
            {
                var recentPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Recent));
                if (Directory.Exists(recentPath))
                {
                    var files = Directory.GetFiles(recentPath, "*.lnk");
                    if (files.Length > 20)
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "最近文件",
                            Description = $"最近文件记录较多 ({files.Length}个)",
                            Severity = "低",
                            Location = recentPath,
                            Recommendation = "定期清理最近文件记录"
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyAnalyzer.cs 捕获异常", ex.Message); }
        }

        private void CheckClipboardHistory(PrivacyResult result)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Clipboard");
                if (key != null)
                {
                    var enabled = key.GetValue("EnableClipboardHistory");
                    if (enabled != null && Convert.ToInt32(enabled) == 1)
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "剪贴板",
                            Description = "剪贴板历史记录已启用",
                            Severity = "中",
                            Location = "HKCU\\SOFTWARE\\Microsoft\\Clipboard",
                            Recommendation = "禁用剪贴板历史记录"
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyAnalyzer.cs 捕获异常", ex.Message); }
        }

        private void CheckLocationServices(PrivacyResult result)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location");
                if (key != null)
                {
                    var value = key.GetValue("Value");
                    if (value != null && value.ToString() == "Allow")
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "位置",
                            Description = "位置服务已启用",
                            Severity = "中",
                            Location = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location",
                            Recommendation = "禁用位置服务或限制应用访问"
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyAnalyzer.cs 捕获异常", ex.Message); }
        }

        private void CheckDevicePermissions(PrivacyResult result)
        {
            try
            {
                // 检查摄像头权限
                using var cameraKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam");
                if (cameraKey != null)
                {
                    var value = cameraKey.GetValue("Value");
                    if (value != null && value.ToString() == "Allow")
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "摄像头",
                            Description = "摄像头权限已开启",
                            Severity = "中",
                            Location = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam",
                            Recommendation = "检查摄像头权限设置"
                        });
                    }
                }

                // 检查麦克风权限
                using var micKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone");
                if (micKey != null)
                {
                    var value = micKey.GetValue("Value");
                    if (value != null && value.ToString() == "Allow")
                    {
                        result.Issues.Add(new PrivacyIssue
                        {
                            Category = "麦克风",
                            Description = "麦克风权限已开启",
                            Severity = "中",
                            Location = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone",
                            Recommendation = "检查麦克风权限设置"
                        });
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyAnalyzer.cs 捕获异常", ex.Message); }
        }

        private int CalculatePrivacyScore(List<PrivacyIssue> issues)
        {
            int score = 100;
            foreach (var issue in issues)
            {
                score -= issue.Severity switch
                {
                    "高" => 15,
                    "中" => 8,
                    "低" => 3,
                    _ => 0
                };
            }
            return Math.Max(0, score);
        }
    }

    public class PrivacyResult
    {
        public List<PrivacyIssue> Issues { get; set; }
        public List<string> Warnings { get; set; }
        public int Score { get; set; }
    }

    public class PrivacyIssue
    {
        public string Category { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public string Location { get; set; }
        public string Recommendation { get; set; }
    }
}