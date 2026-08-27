using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Common.Notification;
using MailKit;
using MailKit.Net.Imap;
using MailKit.Search;
using MimeKit;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 邮件安全服务 - 通过IMAP协议实现邮件安全扫描
    /// </summary>
    public class EmailSecurity : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private List<EmailAccount> _accounts;
        private bool _enableAttachmentScan = true;
        private bool _enablePhishingDetection = true;
        private bool _enableSpamFilter = true;
        private int _scanIntervalMinutes = 5;
        private CancellationTokenSource _cts;

        public bool IsRunning => _isRunning;
        public int AccountsCount => _accounts?.Count ?? 0;

        public EmailSecurity(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _accounts = new List<EmailAccount>();
            LoadAccounts();
            LoadSettings();
        }

        public void Start()
        {
            if (_isRunning) return;
            
            _isRunning = true;
            _cts = new CancellationTokenSource();
            
            _monitorThread = new Thread(() => MonitorEmailSecurity(_cts.Token));
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "EmailSecurityStart",
                Message = "邮件安全服务已启动",
                Details = $"账户数: {_accounts.Count}"
            });
        }

        public void Stop()
        {
            if (!_isRunning) return;
            
            _isRunning = false;
            _cts?.Cancel();
            _monitorThread?.Join(2000);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "EmailSecurityStop",
                Message = "邮件安全服务已停止"
            });
        }

        #region 邮件监控

        private void MonitorEmailSecurity(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    // 扫描所有配置的邮箱
                    foreach (var account in _accounts)
                    {
                        if (token.IsCancellationRequested) break;
                        
                        try
                        {
                            ScanMailbox(account, token);
                        }
                        catch (Exception ex)
                        {
                            _dataManager.AddLog(new LogEntry
                            {
                                Id = Guid.NewGuid().ToString(),
                                Time = DateTime.Now,
                                Type = "EmailScanError",
                                Message = $"扫描邮箱失败: {account.Email}",
                                Details = ex.Message
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "EmailSecurityError",
                        Message = "邮件安全服务错误",
                        Details = ex.Message
                    });
                }

                // 等待下一次扫描
                Thread.Sleep(TimeSpan.FromMinutes(_scanIntervalMinutes));
            }
        }

        private void ScanMailbox(EmailAccount account, CancellationToken token)
        {
            if (!account.IsEnabled) return;

            using var client = new ImapClient();
            
            try
            {
                // 连接到邮件服务器
                client.Connect(account.ImapServer, account.ImapPort, account.UseSsl, token);
                
                // 认证
                client.Authenticate(account.Username, account.Password, token);
                
                // 获取收件箱
                var inbox = client.Inbox;
                inbox.Open(FolderAccess.ReadOnly, token);
                
                // 搜索未读邮件
                var unreadMessages = inbox.Search(SearchQuery.NotSeen, token);
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "EmailScanStarted",
                    Message = "开始扫描邮件",
                    Details = $"邮箱: {account.Email}, 未读邮件: {unreadMessages.Count}"
                });

                foreach (var uid in unreadMessages)
                {
                    if (token.IsCancellationRequested) break;
                    
                    var message = inbox.GetMessage(uid, token);
                    
                    // 扫描邮件内容
                    ScanEmailMessage(message, account);
                }
                
                client.Disconnect(true, token);
            }
            catch (Exception ex)
            {
                throw new Exception($"IMAP连接错误: {ex.Message}");
            }
        }

        private void ScanEmailMessage(MimeMessage message, EmailAccount account)
        {
            var emailInfo = new EmailMessage
            {
                Sender = message.From?.Mailboxes?.FirstOrDefault()?.Address ?? "Unknown",
                SenderDisplayName = message.From?.ToString() ?? "Unknown",
                Subject = message.Subject ?? "(无主题)",
                Body = message.TextBody ?? message.HtmlBody ?? "",
                Headers = new Dictionary<string, string>()
            };

            // 提取附件信息
            var attachments = new List<string>();
            foreach (var attachment in message.Attachments)
            {
                if (attachment is MimePart part)
                {
                    attachments.Add(part.FileName ?? "Unknown");
                }
            }
            emailInfo.Attachments = attachments;

            // 提取关键邮件头
            if (message.Headers != null)
            {
                foreach (var header in message.Headers)
                {
                    emailInfo.Headers[header.Field] = header.Value;
                }
            }

            // 钓鱼检测
            if (_enablePhishingDetection)
            {
                var phishingResult = DetectPhishing(message, emailInfo);
                if (phishingResult.IsPhishing)
                {
                    HandlePhishingEmail(message, emailInfo, phishingResult, account);
                    return; // 钓鱼邮件不需要继续扫描附件
                }
            }

            // 垃圾邮件检测
            if (_enableSpamFilter)
            {
                var spamScore = CalculateSpamScore(message, emailInfo);
                if (spamScore > 80)
                {
                    HandleSpamEmail(message, emailInfo, spamScore, account);
                    return;
                }
            }

            // 附件扫描
            if (_enableAttachmentScan && message.Attachments.Any())
            {
                ScanAttachments(message, emailInfo, account);
            }
        }

        #endregion

        #region 钓鱼检测

        private PhishingResult DetectPhishing(MimeMessage message, EmailMessage emailInfo)
        {
            var result = new PhishingResult { IsPhishing = false };
            var suspicionScore = 0;
            var reasons = new List<string>();

            // 检查发件人地址
            var fromAddress = message.From?.Mailboxes?.FirstOrDefault()?.Address ?? "";
            
            // 检查可疑域名
            var suspiciousDomains = new[] { "secure", "verify", "account", "update", "confirm", "login" };
            var domain = fromAddress.Split('@').LastOrDefault()?.Split('.').FirstOrDefault() ?? "";
            if (suspiciousDomains.Any(sd => domain.Contains(sd, StringComparison.OrdinalIgnoreCase)))
            {
                suspicionScore += 30;
                reasons.Add("发件人域名可疑");
            }

            // 检查主题中的紧急词汇
            var urgentKeywords = new[] { "紧急", "重要", "验证", "确认", "密码", "账户", "安全", "urgent", "verify", "confirm", "password", "account" };
            foreach (var keyword in urgentKeywords)
            {
                if (emailInfo.Subject.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    suspicionScore += 15;
                    reasons.Add($"主题包含紧急词汇: {keyword}");
                    break;
                }
            }

            // 检查正文中的钓鱼链接特征
            var body = emailInfo.Body.ToLower();
            var phishingPatterns = new[] { "点击链接", "验证您的账户", "您的账户已被锁定", "请更新您的信息", 
                "click here", "verify your account", "your account has been locked", "update your information" };
            
            foreach (var pattern in phishingPatterns)
            {
                if (body.Contains(pattern.ToLower()))
                {
                    suspicionScore += 25;
                    reasons.Add($"正文包含钓鱼模式: {pattern}");
                    break;
                }
            }

            // 检查链接数量
            var linkCount = CountLinks(body);
            if (linkCount > 5)
            {
                suspicionScore += 20;
                reasons.Add("包含过多链接");
            }

            // 检查附件类型
            var dangerousExtensions = new[] { ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js" };
            foreach (var attachment in emailInfo.Attachments)
            {
                var ext = Path.GetExtension(attachment).ToLower();
                if (dangerousExtensions.Contains(ext))
                {
                    suspicionScore += 40;
                    reasons.Add($"包含危险附件类型: {ext}");
                }
            }

            result.IsPhishing = suspicionScore >= 50;
            result.SuspicionScore = Math.Min(100, suspicionScore);
            result.DetectionReason = string.Join("; ", reasons);

            return result;
        }

        private int CountLinks(string body)
        {
            try
            {
                var count = 0;
                var index = 0;
                while ((index = body.IndexOf("http", index)) != -1)
                {
                    count++;
                    index++;
                }
                return count;
            }
            catch { return 0; }
        }

        private void HandlePhishingEmail(MimeMessage message, EmailMessage emailInfo, PhishingResult result, EmailAccount account)
        {
            NotificationService.Instance.ShowNotification(
                "钓鱼邮件警告",
                $"检测到可疑钓鱼邮件: {emailInfo.Subject}",
                NotificationType.Error
            );

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "PhishingEmailDetected",
                Message = "检测到钓鱼邮件",
                Details = $"发件人: {emailInfo.Sender}, 主题: {emailInfo.Subject}, 可疑分数: {result.SuspicionScore}, 原因: {result.DetectionReason}"
            });

            // 记录钓鱼邮件
            SaveThreatEmail(emailInfo, "Phishing", result.DetectionReason);
        }

        #endregion

        #region 垃圾邮件检测

        private int CalculateSpamScore(MimeMessage message, EmailMessage emailInfo)
        {
            var score = 0;
            var body = emailInfo.Body.ToLower();

            // 检查垃圾邮件关键词
            var spamKeywords = new[] { "免费", "优惠", "促销", "中奖", "贷款", "减肥", "赚钱",
                "free", "offer", "winner", "loan", "weight loss", "make money" };
            
            foreach (var keyword in spamKeywords)
            {
                if (body.Contains(keyword.ToLower()))
                {
                    score += 10;
                }
            }

            // 检查全大写内容
            var uppercaseRatio = CountUppercaseRatio(body);
            if (uppercaseRatio > 0.5)
            {
                score += 20;
            }

            // 检查感叹号数量
            var exclamationCount = body.Count(c => c == '!');
            if (exclamationCount > 3)
            {
                score += 15;
            }

            return Math.Min(100, score);
        }

        private double CountUppercaseRatio(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            
            var letters = text.Where(char.IsLetter).ToList();
            if (letters.Count == 0) return 0;
            
            return (double)letters.Count(char.IsUpper) / letters.Count;
        }

        private void HandleSpamEmail(MimeMessage message, EmailMessage emailInfo, int spamScore, EmailAccount account)
        {
            NotificationService.Instance.ShowNotification(
                "垃圾邮件检测",
                $"检测到垃圾邮件: {emailInfo.Subject}",
                NotificationType.Warning
            );

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SpamEmailDetected",
                Message = "检测到垃圾邮件",
                Details = $"发件人: {emailInfo.Sender}, 主题: {emailInfo.Subject}, 垃圾分数: {spamScore}"
            });

            SaveThreatEmail(emailInfo, "Spam", $"垃圾分数: {spamScore}");
        }

        #endregion

        #region 附件扫描

        private void ScanAttachments(MimeMessage message, EmailMessage emailInfo, EmailAccount account)
        {
            foreach (var attachment in message.Attachments)
            {
                if (attachment is MimePart part)
                {
                    try
                    {
                        // 保存附件到临时文件进行扫描
                        var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                        Directory.CreateDirectory(tempPath);
                        
                        var filePath = Path.Combine(tempPath, part.FileName ?? "unknown");
                        using (var stream = File.Create(filePath))
                        {
                            part.Content.DecodeTo(stream);
                        }

                        // 扫描文件
                        var scanResult = _antivirusEngine.ScanFile(filePath);
                        
                        if (scanResult.IsInfected)
                        {
                            HandleInfectedAttachment(part.FileName ?? "unknown", emailInfo, scanResult, account);
                        }

                        // 清理临时文件
                        try { Directory.Delete(tempPath, true); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmailSecurity.cs 捕获异常", ex.Message); }
                    }
                    catch (Exception ex)
                    {
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "AttachmentScanError",
                            Message = "附件扫描失败",
                            Details = $"附件: {part.FileName}, 错误: {ex.Message}"
                        });
                    }
                }
            }
        }

        private void HandleInfectedAttachment(string fileName, EmailMessage emailInfo, ScanResult scanResult, EmailAccount account)
        {
            NotificationService.Instance.ShowNotification(
                "邮件附件威胁",
                $"发现病毒邮件附件: {fileName}",
                NotificationType.Error
            );

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "InfectedAttachmentDetected",
                Message = "发现感染病毒的邮件附件",
                Details = $"发件人: {emailInfo.Sender}, 主题: {emailInfo.Subject}, 附件: {fileName}, 威胁: {scanResult.ThreatName}"
            });

            SaveThreatEmail(emailInfo, "Malware", $"附件: {fileName}, 威胁: {scanResult.ThreatName}");
        }

        #endregion

        #region 账户管理

        public void AddAccount(EmailAccount account)
        {
            if (!_accounts.Any(a => a.Email == account.Email))
            {
                _accounts.Add(account);
                SaveAccounts();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "EmailAccountAdded",
                    Message = "邮件账户已添加",
                    Details = account.Email
                });
            }
        }

        public void RemoveAccount(string email)
        {
            var account = _accounts.FirstOrDefault(a => a.Email == email);
            if (account != null)
            {
                _accounts.Remove(account);
                SaveAccounts();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "EmailAccountRemoved",
                    Message = "邮件账户已移除",
                    Details = email
                });
            }
        }

        public void UpdateAccount(EmailAccount account)
        {
            var existing = _accounts.FirstOrDefault(a => a.Email == account.Email);
            if (existing != null)
            {
                existing.ImapServer = account.ImapServer;
                existing.ImapPort = account.ImapPort;
                existing.Username = account.Username;
                existing.Password = account.Password;
                existing.UseSsl = account.UseSsl;
                existing.IsEnabled = account.IsEnabled;
                SaveAccounts();
            }
        }

        public List<EmailAccount> GetAccounts()
        {
            return new List<EmailAccount>(_accounts);
        }

        #endregion

        #region 设置管理

        private void LoadSettings()
        {
            try
            {
                var settings = _dataManager.LoadEmailSecuritySettings();
                if (settings != null)
                {
                    _enableAttachmentScan = settings.EnableAttachmentScan;
                    _enablePhishingDetection = settings.EnablePhishingDetection;
                    _enableSpamFilter = settings.EnableSpamFilter;
                    _scanIntervalMinutes = settings.ScanIntervalMinutes;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmailSecurity.cs 捕获异常", ex.Message); }
        }

        private void SaveSettings()
        {
            try
            {
                var settings = new EmailSecuritySettings
                {
                    EnableAttachmentScan = _enableAttachmentScan,
                    EnablePhishingDetection = _enablePhishingDetection,
                    EnableSpamFilter = _enableSpamFilter,
                    ScanIntervalMinutes = _scanIntervalMinutes
                };
                _dataManager.SaveEmailSecuritySettings(settings);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmailSecurity.cs 捕获异常", ex.Message); }
        }

        private void LoadAccounts()
        {
            try
            {
                var accounts = _dataManager.LoadEmailAccounts();
                if (accounts != null)
                {
                    _accounts = accounts.Select(a => new EmailAccount
                    {
                        Email = a.Email,
                        Username = a.Username,
                        Password = a.Password,
                        ImapServer = a.ImapServer,
                        ImapPort = a.ImapPort,
                        UseSsl = a.UseSsl,
                        IsEnabled = a.IsEnabled,
                        LastScan = DateTime.TryParse(a.LastScan, out var ls) ? ls : DateTime.MinValue
                    }).ToList();
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmailSecurity.cs 捕获异常", ex.Message); }
        }

        private void SaveAccounts()
        {
            try
            {
                var accounts = _accounts.Select(a => new Data.EmailAccountData
                {
                    Email = a.Email,
                    Username = a.Username,
                    Password = a.Password,
                    ImapServer = a.ImapServer,
                    ImapPort = a.ImapPort,
                    UseSsl = a.UseSsl,
                    IsEnabled = a.IsEnabled,
                    LastScan = a.LastScan.ToString("O")
                }).ToList();
                _dataManager.SaveEmailAccounts(accounts);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmailSecurity.cs 捕获异常", ex.Message); }
        }

        private void SaveThreatEmail(EmailMessage email, string threatType, string reason)
        {
            try
            {
                var threat = new Data.ThreatEmail
                {
                    Id = Guid.NewGuid().ToString(),
                    Sender = email.Sender,
                    Subject = email.Subject,
                    ThreatType = threatType,
                    Reason = reason,
                    DetectedTime = DateTime.Now.ToString("O")
                };
                _dataManager.SaveThreatEmail(threat);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmailSecurity.cs 捕获异常", ex.Message); }
        }

        public void UpdateSettings(bool enableAttachmentScan, bool enablePhishingDetection, bool enableSpamFilter)
        {
            _enableAttachmentScan = enableAttachmentScan;
            _enablePhishingDetection = enablePhishingDetection;
            _enableSpamFilter = enableSpamFilter;
            SaveSettings();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "EmailSecuritySettingsUpdated",
                Message = "邮件安全设置已更新",
                Details = $"附件扫描: {enableAttachmentScan}, 钓鱼检测: {enablePhishingDetection}, 垃圾过滤: {enableSpamFilter}"
            });
        }

        #endregion
    }

    #region 数据模型

    public class EmailAccount
    {
        public string Email { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string ImapServer { get; set; } = "";
        public int ImapPort { get; set; } = 993;
        public bool UseSsl { get; set; } = true;
        public bool IsEnabled { get; set; } = true;
        public DateTime LastScan { get; set; }
    }

    public class PhishingResult
    {
        public bool IsPhishing { get; set; }
        public int SuspicionScore { get; set; }
        public string DetectionReason { get; set; } = "";
    }

    #endregion
}