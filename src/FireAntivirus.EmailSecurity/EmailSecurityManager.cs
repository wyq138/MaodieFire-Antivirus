using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.EmailSecurity
{
    public class EmailSecurityManager
    {
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private HashSet<string> _spamSenders;
        private HashSet<string> _maliciousDomains;
        private List<string> _suspiciousSubjects;

        public EmailSecurityManager(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _spamSenders = new HashSet<string>();
            _maliciousDomains = new HashSet<string>();
            _suspiciousSubjects = new List<string>();
            InitializeEmailSecurity();
        }

        private void InitializeEmailSecurity()
        {
            // 加载垃圾邮件发送者列表
            LoadSpamSenders();
            // 加载恶意域名列表
            LoadMaliciousDomains();
            // 加载可疑主题关键词
            LoadSuspiciousSubjects();
        }

        private void LoadSpamSenders()
        {
            // 垃圾邮件发送者列表由用户手动添加，初始为空
        }

        private void LoadMaliciousDomains()
        {
            // 恶意域名由用户手动添加，初始为空
            // 实时检查已委托给 ContainsMaliciousLinks 使用 SignatureDatabaseUpdater.IsMaliciousUrl
        }

        private void LoadSuspiciousSubjects()
        {
            // 模拟加载可疑主题关键词
            _suspiciousSubjects.Add(" urgent ");
            _suspiciousSubjects.Add(" free ");
            _suspiciousSubjects.Add(" winner ");
            _suspiciousSubjects.Add(" lottery ");
            _suspiciousSubjects.Add(" prize ");
            _suspiciousSubjects.Add(" virus ");
            _suspiciousSubjects.Add(" malware ");
        }

        public EmailSecurityResult CheckEmail(string sender, string subject, string body, List<string> attachments)
        {
            try
            {
                // 检查发送者是否为垃圾邮件发送者
                if (_spamSenders.Contains(sender))
                {
                    return new EmailSecurityResult
                    {
                        Safe = false,
                        Sender = sender,
                        Subject = subject,
                        ThreatType = "SpamSender",
                        Message = "此发送者已被标记为垃圾邮件发送者"
                    };
                }

                // 检查发送者域名是否为恶意域名
                string senderDomain = sender.Split('@')[1];
                if (_maliciousDomains.Contains(senderDomain))
                {
                    return new EmailSecurityResult
                    {
                        Safe = false,
                        Sender = sender,
                        Subject = subject,
                        ThreatType = "MaliciousDomain",
                        Message = "此发送者域名已被标记为恶意"
                    };
                }

                // 检查主题是否包含可疑关键词
                if (ContainsSuspiciousSubject(subject))
                {
                    return new EmailSecurityResult
                    {
                        Safe = false,
                        Sender = sender,
                        Subject = subject,
                        ThreatType = "SuspiciousSubject",
                        Message = "邮件主题包含可疑关键词"
                    };
                }

                // 检查邮件正文是否包含恶意链接
                if (ContainsMaliciousLinks(body))
                {
                    return new EmailSecurityResult
                    {
                        Safe = false,
                        Sender = sender,
                        Subject = subject,
                        ThreatType = "MaliciousLinks",
                        Message = "邮件正文包含恶意链接"
                    };
                }

                // 检查附件
                if (attachments != null && attachments.Count > 0)
                {
                    var attachmentResult = CheckAttachments(attachments);
                    if (!attachmentResult.Safe)
                    {
                        return attachmentResult;
                    }
                }

                return new EmailSecurityResult
                {
                    Safe = true,
                    Sender = sender,
                    Subject = subject,
                    ThreatType = "Safe",
                    Message = "邮件安全"
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "EmailSecurityError",
                    Message = "邮件安全检查错误",
                    Details = $"发送者: {sender}, 错误: {ex.Message}"
                });

                return new EmailSecurityResult
                {
                    Safe = true, // 默认安全，避免误报
                    Sender = sender,
                    Subject = subject,
                    ThreatType = "Error",
                    Message = "检查过程中发生错误"
                };
            }
        }

        private bool ContainsSuspiciousSubject(string subject)
        {
            return _suspiciousSubjects.Any(keyword => subject.ToLower().Contains(keyword));
        }

        private bool ContainsMaliciousLinks(string body)
        {
            // 从邮件正文中提取所有URL并检查是否在签名数据库中
            var urlMatches = Regex.Matches(body, @"https?://[^\s<>""']+", RegexOptions.IgnoreCase);
            foreach (Match match in urlMatches)
            {
                if (SignatureDatabaseUpdater.IsMaliciousUrl(match.Value))
                    return true;
            }
            return false;
        }

        private EmailSecurityResult CheckAttachments(List<string> attachments)
        {
            foreach (string attachment in attachments)
            {
                try
                {
                    if (File.Exists(attachment))
                    {
                        var scanResult = _antivirusEngine.ScanFile(attachment);
                        if (scanResult.IsInfected)
                        {
                            return new EmailSecurityResult
                            {
                                Safe = false,
                                ThreatType = "MaliciousAttachment",
                                Message = $"附件包含恶意内容: {scanResult.ThreatName}"
                            };
                        }

                        // 检查附件类型
                        string extension = Path.GetExtension(attachment).ToLower();
                        string[] dangerousExtensions = { ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1", ".js", ".vbs" };
                        if (dangerousExtensions.Contains(extension))
                        {
                            return new EmailSecurityResult
                            {
                                Safe = false,
                                ThreatType = "DangerousAttachment",
                                Message = "附件类型被认为是危险的"
                            };
                        }

                        // 检查附件大小
                        FileInfo fileInfo = new FileInfo(attachment);
                        if (fileInfo.Length > 10 * 1024 * 1024) // 10MB
                        {
                            return new EmailSecurityResult
                            {
                                Safe = false,
                                ThreatType = "LargeAttachment",
                                Message = "附件大小超过安全限制"
                            };
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "AttachmentCheckError",
                        Message = "附件检查错误",
                        Details = $"附件: {attachment}, 错误: {ex.Message}"
                    });
                }
            }

            return new EmailSecurityResult
            {
                Safe = true,
                ThreatType = "SafeAttachments",
                Message = "附件安全"
            };
        }

        public void AddSpamSender(string sender)
        {
            _spamSenders.Add(sender);
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SpamSenderAdded",
                Message = "发送者已被添加到垃圾邮件列表",
                Details = $"发送者: {sender}"
            });
        }

        public void RemoveSpamSender(string sender)
        {
            _spamSenders.Remove(sender);
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SpamSenderRemoved",
                Message = "发送者已从垃圾邮件列表中移除",
                Details = $"发送者: {sender}"
            });
        }

        public List<string> GetSpamSenders()
        {
            return _spamSenders.ToList();
        }

        public List<string> GetMaliciousDomains()
        {
            return _maliciousDomains.ToList();
        }

        public List<string> GetSuspiciousSubjects()
        {
            return _suspiciousSubjects;
        }

        public void UpdateSettings(bool attachmentScan, bool phishingDetection, bool spamFilter)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "EmailSecuritySettingsUpdated",
                Message = "邮件安全设置已更新",
                Details = $"附件扫描: {attachmentScan}, 钓鱼检测: {phishingDetection}, 垃圾过滤: {spamFilter}"
            });
        }
    }
}