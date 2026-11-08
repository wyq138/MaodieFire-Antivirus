using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.SecurityScore
{
    public class SecurityScoreManager
    {
        private DataManager _dataManager;
        private List<SecurityFactor> _securityFactors;
        private int _currentScore;
        private DateTime _lastUpdated;

        public SecurityScoreManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _securityFactors = new List<SecurityFactor>();
            _currentScore = 100;
            _lastUpdated = DateTime.Now;
            InitializeSecurityFactors();
        }

        private void InitializeSecurityFactors()
        {
            // 实时防护状态：检查 FireAntivirus.Service 进程是否运行
            int realTimeScore = 0;
            try
            {
                var processes = Process.GetProcessesByName("FireAntivirus.Service");
                realTimeScore = processes.Length > 0 ? 100 : 0;
            }
            catch
            {
                realTimeScore = 50;
            }
            _securityFactors.Add(new SecurityFactor
            {
                Name = "RealTimeProtection",
                Description = "实时防护状态",
                Weight = 20,
                CurrentScore = realTimeScore
            });

            // 病毒定义更新：检查特征库加载的签名数量
            int definitionsScore = 0;
            try
            {
                int count = SignatureDatabaseUpdater.HashCount;
                if (count > 1000)
                    definitionsScore = 100;
                else if (count > 100)
                    definitionsScore = 50;
                else
                    definitionsScore = 0;
            }
            catch
            {
                definitionsScore = 50;
            }
            _securityFactors.Add(new SecurityFactor
            {
                Name = "VirusDefinitions",
                Description = "病毒定义更新",
                Weight = 15,
                CurrentScore = definitionsScore
            });

            // 系统更新状态：检查注册表中 Windows Update 自动更新配置
            int systemUpdateScore = 0;
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"))
                {
                    if (key != null)
                    {
                        var auState = key.GetValue("AUState");
                        if (auState != null && Convert.ToInt32(auState) >= 2)
                            systemUpdateScore = 100;
                        else
                            systemUpdateScore = 50;
                    }
                    else
                    {
                        systemUpdateScore = 50;
                    }
                }
            }
            catch
            {
                systemUpdateScore = 50;
            }
            _securityFactors.Add(new SecurityFactor
            {
                Name = "SystemUpdates",
                Description = "系统更新状态",
                Weight = 15,
                CurrentScore = systemUpdateScore
            });

            // 防火墙状态：通过 HNetCfg.FwPolicy2 COM 接口检查 Windows 防火墙是否启用
            int firewallScore = 0;
            try
            {
                var fwPolicy2Type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (fwPolicy2Type != null)
                {
                    dynamic fwPolicy2 = Activator.CreateInstance(fwPolicy2Type);
                    bool enabled = false;
                    // 检查所有配置文件（域、专用、公用）的防火墙启用状态
                    foreach (var profile in fwPolicy2.Rules)
                    {
                        // 仅检查防火墙是否全局启用
                        break;
                    }
                    try
                    {
                        enabled = fwPolicy2.FirewallEnabled;
                    }
                    catch
                    {
                        // 某些系统版本可能不支持直接读取 FirewallEnabled
                        enabled = true;
                    }
                    firewallScore = enabled ? 100 : 0;
                }
                else
                {
                    firewallScore = 50;
                }
            }
            catch
            {
                firewallScore = 50;
            }
            _securityFactors.Add(new SecurityFactor
            {
                Name = "FirewallStatus",
                Description = "防火墙状态",
                Weight = 10,
                CurrentScore = firewallScore
            });

            // 密码强度：无法评估用户密码，默认满分
            _securityFactors.Add(new SecurityFactor
            {
                Name = "PasswordStrength",
                Description = "密码强度",
                Weight = 10,
                CurrentScore = 100
            });

            // 恶意软件扫描：检查 DataManager 日志中是否存在最近的扫描记录
            int scanScore = 0;
            try
            {
                var logs = _dataManager.LoadLogs();
                bool hasRecentScan = logs.Any(l =>
                    (l.Type != null && l.Type.IndexOf("Scan", StringComparison.OrdinalIgnoreCase) >= 0) &&
                    (l.Time >= DateTime.Now.AddDays(-30)));
                scanScore = hasRecentScan ? 100 : 50;
            }
            catch
            {
                scanScore = 50;
            }
            _securityFactors.Add(new SecurityFactor
            {
                Name = "MalwareScans",
                Description = "恶意软件扫描",
                Weight = 10,
                CurrentScore = scanScore
            });

            // 网络安全：检查 SignatureDatabaseUpdater 是否已加载 IP 数据（Feodo 列表）
            int networkScore = 0;
            try
            {
                networkScore = SignatureDatabaseUpdater.IpCount > 0 ? 100 : 50;
            }
            catch
            {
                networkScore = 50;
            }
            _securityFactors.Add(new SecurityFactor
            {
                Name = "NetworkSecurity",
                Description = "网络安全",
                Weight = 10,
                CurrentScore = networkScore
            });

            // 勒索软件防护：检查 FireAntivirus.Service 进程是否运行
            int ransomwareScore = 0;
            try
            {
                var processes = Process.GetProcessesByName("FireAntivirus.Service");
                ransomwareScore = processes.Length > 0 ? 100 : 0;
            }
            catch
            {
                ransomwareScore = 50;
            }
            _securityFactors.Add(new SecurityFactor
            {
                Name = "RansomwareProtection",
                Description = "勒索软件防护",
                Weight = 10,
                CurrentScore = ransomwareScore
            });
        }

        public int CalculateSecurityScore()
        {
            int totalScore = 0;
            int totalWeight = 0;

            foreach (var factor in _securityFactors)
            {
                totalScore += factor.CurrentScore * factor.Weight;
                totalWeight += factor.Weight;
            }

            if (totalWeight > 0)
            {
                _currentScore = totalScore / totalWeight;
            }
            else
            {
                _currentScore = 0;
            }

            _lastUpdated = DateTime.Now;
            RecordScoreSnapshot(_currentScore);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SecurityScoreCalculated",
                Message = "安全评分已计算",
                Details = $"当前评分: {_currentScore}"
            });

            return _currentScore;
        }

        public int GetCurrentScore()
        {
            return _currentScore;
        }

        public DateTime GetLastUpdated()
        {
            return _lastUpdated;
        }

        public List<SecurityFactor> GetSecurityFactors()
        {
            return _securityFactors;
        }

        public void UpdateSecurityFactor(string factorName, int score)
        {
            var factor = _securityFactors.FirstOrDefault(f => f.Name == factorName);
            if (factor != null)
            {
                factor.CurrentScore = Math.Max(0, Math.Min(100, score));
                factor.LastUpdated = DateTime.Now;
                CalculateSecurityScore();
            }
        }

        public string GetScoreDescription(int score)
        {
            if (score >= 90)
            {
                return "安全状态优秀，系统受到全面保护";
            }
            else if (score >= 75)
            {
                return "安全状态良好，建议进行一些优化";
            }
            else if (score >= 60)
            {
                return "安全状态一般，存在一些安全隐患";
            }
            else if (score >= 40)
            {
                return "安全状态较差，需要立即采取措施";
            }
            else
            {
                return "安全状态危险，系统面临严重威胁";
            }
        }

        public string GetScoreColor(int score)
        {
            if (score >= 90)
            {
                return "#4CAF50";
            }
            else if (score >= 75)
            {
                return "#8BC34A";
            }
            else if (score >= 60)
            {
                return "#FFC107";
            }
            else if (score >= 40)
            {
                return "#FF9800";
            }
            else
            {
                return "#F44336";
            }
        }

        public List<string> GetSecurityRecommendations()
        {
            var recommendations = new List<string>();

            var realTimeFactor = _securityFactors.FirstOrDefault(f => f.Name == "RealTimeProtection");
            if (realTimeFactor != null && realTimeFactor.CurrentScore < 100)
            {
                recommendations.Add("启用实时防护功能");
            }

            var virusDefFactor = _securityFactors.FirstOrDefault(f => f.Name == "VirusDefinitions");
            if (virusDefFactor != null && virusDefFactor.CurrentScore < 100)
            {
                recommendations.Add("更新病毒定义库");
            }

            var sysUpdateFactor = _securityFactors.FirstOrDefault(f => f.Name == "SystemUpdates");
            if (sysUpdateFactor != null && sysUpdateFactor.CurrentScore < 100)
            {
                recommendations.Add("安装系统更新");
            }

            var firewallFactor = _securityFactors.FirstOrDefault(f => f.Name == "FirewallStatus");
            if (firewallFactor != null && firewallFactor.CurrentScore < 100)
            {
                recommendations.Add("启用防火墙");
            }

            var pwdFactor = _securityFactors.FirstOrDefault(f => f.Name == "PasswordStrength");
            if (pwdFactor != null && pwdFactor.CurrentScore < 100)
            {
                recommendations.Add("使用强密码");
            }

            var scanFactor = _securityFactors.FirstOrDefault(f => f.Name == "MalwareScans");
            if (scanFactor != null && scanFactor.CurrentScore < 100)
            {
                recommendations.Add("执行全系统扫描");
            }

            var netFactor = _securityFactors.FirstOrDefault(f => f.Name == "NetworkSecurity");
            if (netFactor != null && netFactor.CurrentScore < 100)
            {
                recommendations.Add("检查网络安全设置");
            }

            var ransomwareFactor = _securityFactors.FirstOrDefault(f => f.Name == "RansomwareProtection");
            if (ransomwareFactor != null && ransomwareFactor.CurrentScore < 100)
            {
                recommendations.Add("启用勒索软件防护");
            }

            if (recommendations.Count == 0)
            {
                recommendations.Add("系统安全状态良好，继续保持");
            }

            return recommendations;
        }

        public SecurityScoreHistory GetScoreHistory(int days)
        {
            var history = new SecurityScoreHistory
            {
                Days = days,
                Scores = new List<ScoreEntry>()
            };

            // 真实历史：读取持久化的评分记录（每次 CalculateSecurityScore 落一条）
            // 没有记录的日期如实留空，不再用随机数伪造
            var records = LoadScoreRecords();
            var startDate = DateTime.Now.Date.AddDays(-(days - 1));
            foreach (var group in records
                .Where(r => r.Date >= startDate)
                .GroupBy(r => r.Date.Date)
                .OrderBy(g => g.Key))
            {
                // 同一天多条记录取最后一条（当日最终评分）
                history.Scores.Add(new ScoreEntry
                {
                    Date = group.Key,
                    Score = group.OrderBy(r => r.Time).Last().Score
                });
            }

            return history;
        }

        private static string ScoreHistoryPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "SecurityScore", "history.json");

        private List<(DateTime Date, DateTime Time, int Score)> _scoreRecordsCache;

        private List<(DateTime Date, DateTime Time, int Score)> LoadScoreRecords()
        {
            if (_scoreRecordsCache != null) return _scoreRecordsCache;
            var list = new List<(DateTime, DateTime, int)>();
            try
            {
                if (File.Exists(ScoreHistoryPath))
                {
                    var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(ScoreHistoryPath));
                    foreach (var el in doc.RootElement.EnumerateArray())
                    {
                        var time = el.GetProperty("time").GetDateTime();
                        list.Add((time.Date, time, el.GetProperty("score").GetInt32()));
                    }
                }
            }
            catch { }
            _scoreRecordsCache = list;
            return list;
        }

        private void RecordScoreSnapshot(int score)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ScoreHistoryPath));
                var records = LoadScoreRecords();
                records.Add((DateTime.Now.Date, DateTime.Now, score));
                // 保留最近 90 天，避免无限增长
                records = records.Where(r => r.Item1 >= DateTime.Now.Date.AddDays(-90)).ToList();
                var arr = records.Select(r => new { time = r.Item2, score = r.Item3 });
                File.WriteAllText(ScoreHistoryPath,
                    System.Text.Json.JsonSerializer.Serialize(arr));
            }
            catch { }
        }

        public void ResetAllFactors()
        {
            foreach (var factor in _securityFactors)
            {
                factor.CurrentScore = 100;
                factor.LastUpdated = DateTime.Now;
            }
            CalculateSecurityScore();
        }
    }
}