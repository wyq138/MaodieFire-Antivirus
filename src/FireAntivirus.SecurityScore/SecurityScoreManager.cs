using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

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
            // 初始化安全因素
            _securityFactors.Add(new SecurityFactor
            {
                Name = "RealTimeProtection",
                Description = "实时防护状态",
                Weight = 20,
                CurrentScore = 100
            });

            _securityFactors.Add(new SecurityFactor
            {
                Name = "VirusDefinitions",
                Description = "病毒定义更新",
                Weight = 15,
                CurrentScore = 100
            });

            _securityFactors.Add(new SecurityFactor
            {
                Name = "SystemUpdates",
                Description = "系统更新状态",
                Weight = 15,
                CurrentScore = 100
            });

            _securityFactors.Add(new SecurityFactor
            {
                Name = "FirewallStatus",
                Description = "防火墙状态",
                Weight = 10,
                CurrentScore = 100
            });

            _securityFactors.Add(new SecurityFactor
            {
                Name = "PasswordStrength",
                Description = "密码强度",
                Weight = 10,
                CurrentScore = 100
            });

            _securityFactors.Add(new SecurityFactor
            {
                Name = "MalwareScans",
                Description = "恶意软件扫描",
                Weight = 10,
                CurrentScore = 100
            });

            _securityFactors.Add(new SecurityFactor
            {
                Name = "NetworkSecurity",
                Description = "网络安全",
                Weight = 10,
                CurrentScore = 100
            });

            _securityFactors.Add(new SecurityFactor
            {
                Name = "RansomwareProtection",
                Description = "勒索软件防护",
                Weight = 10,
                CurrentScore = 100
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

            if (_securityFactors.FirstOrDefault(f => f.Name == "RealTimeProtection").CurrentScore < 100)
            {
                recommendations.Add("启用实时防护功能");
            }

            if (_securityFactors.FirstOrDefault(f => f.Name == "VirusDefinitions").CurrentScore < 100)
            {
                recommendations.Add("更新病毒定义库");
            }

            if (_securityFactors.FirstOrDefault(f => f.Name == "SystemUpdates").CurrentScore < 100)
            {
                recommendations.Add("安装系统更新");
            }

            if (_securityFactors.FirstOrDefault(f => f.Name == "FirewallStatus").CurrentScore < 100)
            {
                recommendations.Add("启用防火墙");
            }

            if (_securityFactors.FirstOrDefault(f => f.Name == "PasswordStrength").CurrentScore < 100)
            {
                recommendations.Add("使用强密码");
            }

            if (_securityFactors.FirstOrDefault(f => f.Name == "MalwareScans").CurrentScore < 100)
            {
                recommendations.Add("执行全系统扫描");
            }

            if (_securityFactors.FirstOrDefault(f => f.Name == "NetworkSecurity").CurrentScore < 100)
            {
                recommendations.Add("检查网络安全设置");
            }

            if (_securityFactors.FirstOrDefault(f => f.Name == "RansomwareProtection").CurrentScore < 100)
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

            // 模拟历史数据
            for (int i = days - 1; i >= 0; i--)
            {
                var date = DateTime.Now.AddDays(-i);
                var score = 100 - (i * 2); // 模拟评分逐渐下降
                score = Math.Max(70, score); // 最低70分

                history.Scores.Add(new ScoreEntry
                {
                    Date = date,
                    Score = score
                });
            }

            return history;
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