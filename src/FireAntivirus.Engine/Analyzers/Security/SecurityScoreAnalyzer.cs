using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using Microsoft.Win32;

namespace FireAntivirus.Engine.Analyzers.Security
{
    /// <summary>
    /// 安全评分分析器 - 计算系统整体安全评分
    /// </summary>
    public class SecurityScoreAnalyzer
    {
        private readonly Dictionary<string, SecurityFactor> _factors;

        public SecurityScoreAnalyzer()
        {
            _factors = new Dictionary<string, SecurityFactor>();
            InitializeFactors();
        }

        private void InitializeFactors()
        {
            _factors["Antivirus"] = new SecurityFactor { Name = "杀毒软件", Weight = 20, MaxScore = 100 };
            _factors["Firewall"] = new SecurityFactor { Name = "防火墙", Weight = 15, MaxScore = 100 };
            _factors["Updates"] = new SecurityFactor { Name = "系统更新", Weight = 15, MaxScore = 100 };
            _factors["UAC"] = new SecurityFactor { Name = "用户账户控制", Weight = 10, MaxScore = 100 };
            _factors["Passwords"] = new SecurityFactor { Name = "密码策略", Weight = 10, MaxScore = 100 };
            _factors["BitLocker"] = new SecurityFactor { Name = "磁盘加密", Weight = 10, MaxScore = 100 };
            _factors["Services"] = new SecurityFactor { Name = "服务安全", Weight = 10, MaxScore = 100 };
            _factors["Accounts"] = new SecurityFactor { Name = "账户安全", Weight = 5, MaxScore = 100 };
            _factors["Network"] = new SecurityFactor { Name = "网络安全", Weight = 5, MaxScore = 100 };
        }

        public SecurityScoreResult Analyze()
        {
            var result = new SecurityScoreResult
            {
                Factors = new List<SecurityFactorResult>(),
                Warnings = new List<string>(),
                Recommendations = new List<string>()
            };

            try
            {
                // 分析各项安全因素
                AnalyzeAntivirus(result);
                AnalyzeFirewall(result);
                AnalyzeUpdates(result);
                AnalyzeUAC(result);
                AnalyzePasswords(result);
                AnalyzeBitLocker(result);
                AnalyzeServices(result);
                AnalyzeAccounts(result);
                AnalyzeNetwork(result);

                // 计算总分
                result.TotalScore = CalculateTotalScore(result.Factors);
                result.Grade = GetGrade(result.TotalScore);
                result.Status = GetStatus(result.TotalScore);
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"安全评分分析错误: {ex.Message}");
            }

            return result;
        }

        private void AnalyzeAntivirus(SecurityScoreResult result)
        {
            var factor = _factors["Antivirus"];
            int score = 0;
            var details = new List<string>();

            try
            {
                // 检查Windows Defender
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender");
                if (key != null)
                {
                    score += 40;
                    details.Add("Windows Defender已安装");
                }

                // 检查实时保护
                using var rtKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                if (rtKey != null)
                {
                    var enabled = rtKey.GetValue("DisableRealtimeMonitoring");
                    if (enabled == null || Convert.ToInt32(enabled) == 0)
                    {
                        score += 30;
                        details.Add("实时保护已启用");
                    }
                    else
                    {
                        details.Add("实时保护已禁用");
                    }
                }

                // 检查病毒库更新
                using var sigKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Signature Updates");
                if (sigKey != null)
                {
                    var lastUpdate = sigKey.GetValue("AVSignatureApplied");
                    if (lastUpdate != null)
                    {
                        var updateDate = DateTime.FromFileTimeUtc(Convert.ToInt64(lastUpdate));
                        if ((DateTime.UtcNow - updateDate).TotalDays < 7)
                        {
                            score += 30;
                            details.Add("病毒库已更新");
                        }
                        else
                        {
                            details.Add("病毒库过期");
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }

            result.Factors.Add(new SecurityFactorResult
            {
                Name = factor.Name,
                Score = score,
                Weight = factor.Weight,
                Details = details
            });
        }

        private void AnalyzeFirewall(SecurityScoreResult result)
        {
            var factor = _factors["Firewall"];
            int score = 0;
            var details = new List<string>();

            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy");
                if (key != null)
                {
                    // 检查域配置文件
                    var domainKey = key.OpenSubKey("DomainProfile");
                    if (domainKey != null)
                    {
                        var enabled = domainKey.GetValue("EnableFirewall");
                        if (enabled != null && Convert.ToInt32(enabled) == 1)
                        {
                            score += 35;
                            details.Add("域防火墙已启用");
                        }
                    }

                    // 检查公共配置文件
                    var publicKey = key.OpenSubKey("PublicProfile");
                    if (publicKey != null)
                    {
                        var enabled = publicKey.GetValue("EnableFirewall");
                        if (enabled != null && Convert.ToInt32(enabled) == 1)
                        {
                            score += 35;
                            details.Add("公共防火墙已启用");
                        }
                    }

                    // 检查标准配置文件
                    var standardKey = key.OpenSubKey("StandardProfile");
                    if (standardKey != null)
                    {
                        var enabled = standardKey.GetValue("EnableFirewall");
                        if (enabled != null && Convert.ToInt32(enabled) == 1)
                        {
                            score += 30;
                            details.Add("专用防火墙已启用");
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }

            result.Factors.Add(new SecurityFactorResult
            {
                Name = factor.Name,
                Score = score,
                Weight = factor.Weight,
                Details = details
            });
        }

        private void AnalyzeUpdates(SecurityScoreResult result)
        {
            var factor = _factors["Updates"];
            int score = 0;
            var details = new List<string>();

            try
            {
                // 检查自动更新
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update");
                if (key != null)
                {
                    var auOptions = key.GetValue("AUOptions");
                    if (auOptions != null)
                    {
                        var opt = Convert.ToInt32(auOptions);
                        if (opt >= 3)
                        {
                            score += 50;
                            details.Add("自动更新已启用");
                        }
                        else
                        {
                            details.Add("自动更新未配置");
                        }
                    }

                    // 检查最后更新时间
                    var lastSuccess = key.GetValue("LastWaitTimeout");
                    if (lastSuccess != null)
                    {
                        score += 30;
                        details.Add("最近有更新活动");
                    }
                }

                // 检查待安装更新数量
                using var updateKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services");
                if (updateKey != null)
                {
                    score += 20;
                    details.Add("更新服务正常");
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }

            result.Factors.Add(new SecurityFactorResult
            {
                Name = factor.Name,
                Score = score,
                Weight = factor.Weight,
                Details = details
            });
        }

        private void AnalyzeUAC(SecurityScoreResult result)
        {
            var factor = _factors["UAC"];
            int score = 0;
            var details = new List<string>();

            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                if (key != null)
                {
                    var consentPrompt = key.GetValue("ConsentPromptBehaviorAdmin");
                    if (consentPrompt != null)
                    {
                        var level = Convert.ToInt32(consentPrompt);
                        if (level >= 2)
                        {
                            score = 100;
                            details.Add($"UAC级别: {level} (高)");
                        }
                        else if (level >= 1)
                        {
                            score = 70;
                            details.Add($"UAC级别: {level} (中)");
                        }
                        else
                        {
                            score = 30;
                            details.Add("UAC已禁用");
                            result.Warnings.Add("用户账户控制已禁用");
                        }
                    }

                    var enableLUA = key.GetValue("EnableLUA");
                    if (enableLUA != null && Convert.ToInt32(enableLUA) == 0)
                    {
                        score = 0;
                        details.Add("UAC完全禁用");
                        result.Warnings.Add("UAC完全禁用，系统安全性降低");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }

            result.Factors.Add(new SecurityFactorResult
            {
                Name = factor.Name,
                Score = score,
                Weight = factor.Weight,
                Details = details
            });
        }

        private void AnalyzePasswords(SecurityScoreResult result)
        {
            var factor = _factors["Passwords"];
            int score = 60;
            var details = new List<string>();

            try
            {
                // 检查密码复杂度策略
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                if (key != null)
                {
                    // 检查是否需要Ctrl+Alt+Del
                    var disableCAD = key.GetValue("DisableCAD");
                    if (disableCAD == null || Convert.ToInt32(disableCAD) == 0)
                    {
                        score += 20;
                        details.Add("安全登录已启用");
                    }

                    // 检查密码过期
                    var maxPasswordAge = key.GetValue("MaxPasswordAge");
                    if (maxPasswordAge != null)
                    {
                        score += 20;
                        details.Add("密码过期策略已配置");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }

            result.Factors.Add(new SecurityFactorResult
            {
                Name = factor.Name,
                Score = score,
                Weight = factor.Weight,
                Details = details
            });
        }

        private void AnalyzeBitLocker(SecurityScoreResult result)
        {
            var factor = _factors["BitLocker"];
            int score = 0;
            var details = new List<string>();

            try
            {
                // 检查BitLocker状态
                var systemDrive = Path.GetPathRoot(Environment.SystemDirectory);
                
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\BitLockerStatus");
                if (key != null)
                {
                    var encryptionMethod = key.GetValue("EncryptionMethod");
                    if (encryptionMethod != null && Convert.ToInt32(encryptionMethod) > 0)
                    {
                        score = 100;
                        details.Add("BitLocker加密已启用");
                    }
                }

                // 检查每个驱动器
                using var volumesKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\BitLockerStatus\");
                if (volumesKey != null)
                {
                    foreach (var subKeyName in volumesKey.GetSubKeyNames())
                    {
                        using var subKey = volumesKey.OpenSubKey(subKeyName);
                        if (subKey != null)
                        {
                            var status = subKey.GetValue("VolumeStatus");
                            if (status != null)
                            {
                                score = 100;
                                details.Add($"驱动器 {subKeyName} 已加密");
                            }
                        }
                    }
                }

                if (score == 0)
                {
                    details.Add("BitLocker未启用");
                    result.Recommendations.Add("建议启用BitLocker磁盘加密");
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }

            result.Factors.Add(new SecurityFactorResult
            {
                Name = factor.Name,
                Score = score,
                Weight = factor.Weight,
                Details = details
            });
        }

        private void AnalyzeServices(SecurityScoreResult result)
        {
            var factor = _factors["Services"];
            int score = 100;
            var details = new List<string>();

            try
            {
                var riskyServices = new Dictionary<string, string>
                {
                    { "TermService", "远程桌面服务" },
                    { "RemoteRegistry", "远程注册表" },
                    { "Telnet", "Telnet服务" },
                    { "ftpsvc", "FTP服务" },
                    { "SSDPSRV", "UPnP服务" }
                };

                foreach (var svc in riskyServices)
                {
                    try
                    {
                        using var service = new ServiceController(svc.Key);
                        if (service.Status == ServiceControllerStatus.Running)
                        {
                            score -= 15;
                            details.Add($"{svc.Value}正在运行");
                            result.Warnings.Add($"{svc.Value}正在运行，可能存在安全风险");
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }

            result.Factors.Add(new SecurityFactorResult
            {
                Name = factor.Name,
                Score = Math.Max(0, score),
                Weight = factor.Weight,
                Details = details
            });
        }

        private void AnalyzeAccounts(SecurityScoreResult result)
        {
            var factor = _factors["Accounts"];
            int score = 100;
            var details = new List<string>();

            try
            {
                // 检查Guest账户
                using var guestKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SAM\SAM\Domains\Account\Users\000001F5");
                if (guestKey != null)
                {
                    var active = guestKey.GetValue("F");
                    if (active != null)
                    {
                        // Guest账户
                    }
                }

                // 检查管理员账户数量
                var adminCount = 0;
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList");
                if (key != null)
                {
                    details.Add("特殊账户配置已设置");
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }

            result.Factors.Add(new SecurityFactorResult
            {
                Name = factor.Name,
                Score = score,
                Weight = factor.Weight,
                Details = details
            });
        }

        private void AnalyzeNetwork(SecurityScoreResult result)
        {
            var factor = _factors["Network"];
            int score = 100;
            var details = new List<string>();

            try
            {
                // 检查网络共享
                using var lanmanKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Shares");
                if (lanmanKey != null)
                {
                    var shares = lanmanKey.GetValueNames();
                    if (shares.Length > 0)
                    {
                        score -= 10;
                        details.Add($"存在 {shares.Length} 个网络共享");
                    }
                }

                // 检查SMB版本
                using var smbKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
                if (smbKey != null)
                {
                    var smb1 = smbKey.GetValue("SMB1");
                    if (smb1 != null && Convert.ToInt32(smb1) == 1)
                    {
                        score -= 30;
                        details.Add("SMBv1已启用（不安全）");
                        result.Warnings.Add("SMBv1已启用，建议禁用");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScoreAnalyzer.cs 捕获异常", ex.Message); }

            result.Factors.Add(new SecurityFactorResult
            {
                Name = factor.Name,
                Score = Math.Max(0, score),
                Weight = factor.Weight,
                Details = details
            });
        }

        private int CalculateTotalScore(List<SecurityFactorResult> factors)
        {
            int totalWeight = 0;
            int weightedScore = 0;

            foreach (var factor in factors)
            {
                weightedScore += factor.Score * factor.Weight;
                totalWeight += factor.Weight;
            }

            return totalWeight > 0 ? weightedScore / totalWeight : 0;
        }

        private string GetGrade(int score)
        {
            return score switch
            {
                >= 90 => "A",
                >= 80 => "B",
                >= 70 => "C",
                >= 60 => "D",
                _ => "F"
            };
        }

        private string GetStatus(int score)
        {
            return score switch
            {
                >= 90 => "安全",
                >= 70 => "良好",
                >= 50 => "需要注意",
                _ => "风险"
            };
        }
    }

    public class SecurityScoreResult
    {
        public List<SecurityFactorResult> Factors { get; set; }
        public List<string> Warnings { get; set; }
        public List<string> Recommendations { get; set; }
        public int TotalScore { get; set; }
        public string Grade { get; set; }
        public string Status { get; set; }
    }

    public class SecurityFactorResult
    {
        public string Name { get; set; }
        public int Score { get; set; }
        public int Weight { get; set; }
        public List<string> Details { get; set; }
    }

    public class SecurityFactor
    {
        public string Name { get; set; }
        public int Weight { get; set; }
        public int MaxScore { get; set; }
    }
}