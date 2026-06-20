// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Text.RegularExpressions;

namespace FireAntivirus.Engine.Analyzers.Protection
{
    /// <summary>
    /// 邮件防护分析器 - 分析邮件威胁
    /// </summary>
    public class EmailProtectionAnalyzer
    {
        private readonly HashSet<string> _spamDomains;
        private readonly HashSet<string> _phishingKeywords;
        private readonly HashSet<string> _maliciousExtensions;

        public EmailProtectionAnalyzer()
        {
            _spamDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _phishingKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _maliciousExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            InitializeThreatData();
        }

        private void InitializeThreatData()
        {
            // 垃圾邮件域名
            _spamDomains.UnionWith(new[]
            {
                "spam.com", "junk.com", "temp-mail.org", "guerrillamail.com",
                "10minutemail.com", "throwaway.com", "mailinator.com"
            });

            // 钓鱼关键词
            _phishingKeywords.UnionWith(new[]
            {
                "verify your account", "confirm your password", "urgent action required",
                "suspended account", "click here immediately", "update payment",
                "you have won", "lottery", "inheritance", "bank transfer",
                "密码", "验证", "紧急", "账户异常", "点击链接"
            });

            // 恶意附件扩展名
            _maliciousExtensions.UnionWith(new[]
            {
                ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".js",
                ".jar", ".msi", ".ps1", ".psm1", ".hta", ".reg", ".dll"
            });
        }

        public EmailProtectionResult AnalyzeEmail(string rawEmail)
        {
            var result = new EmailProtectionResult
            {
                Threats = new List<EmailThreat>(),
                SuspiciousLinks = new List<SuspiciousLink>(),
                SuspiciousAttachments = new List<SuspiciousAttachment>(),
                Warnings = new List<string>(),
                RiskScore = 0
            };

            try
            {
                // 解析邮件
                var mailMessage = ParseEmail(rawEmail);
                
                if (mailMessage != null)
                {
                    result.Sender = mailMessage.From?.Address ?? "";
                    result.Subject = mailMessage.Subject ?? "";
                    result.Body = mailMessage.Body ?? "";

                    // 分析发件人
                    AnalyzeSender(result.Sender, result);

                    // 分析主题
                    AnalyzeSubject(result.Subject, result);

                    // 分析正文
                    AnalyzeBody(result.Body, result);

                    // 分析链接
                    AnalyzeLinks(result.Body, result);

                    // 分析附件
                    AnalyzeAttachments(mailMessage, result);
                }

                // 计算风险等级
                result.RiskLevel = GetRiskLevel(result.RiskScore);
                result.IsSuspicious = result.RiskScore >= 30;

                if (result.IsSuspicious)
                {
                    result.Warnings.Add($"邮件风险评分: {result.RiskScore}");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"邮件分析错误: {ex.Message}");
            }

            return result;
        }

        private MailMessage ParseEmail(string rawEmail)
        {
            try
            {
                using var reader = new StringReader(rawEmail);
                var message = new MailMessage();
                
                string line;
                while ((line = reader.ReadLine()) != null && !string.IsNullOrEmpty(line))
                {
                    if (line.StartsWith("From:", StringComparison.OrdinalIgnoreCase))
                    {
                        message.From = new MailAddress(line.Substring(5).Trim());
                    }
                    else if (line.StartsWith("To:", StringComparison.OrdinalIgnoreCase))
                    {
                        message.To.Add(line.Substring(3).Trim());
                    }
                    else if (line.StartsWith("Subject:", StringComparison.OrdinalIgnoreCase))
                    {
                        message.Subject = line.Substring(8).Trim();
                    }
                }

                // 读取正文
                var bodyBuilder = new System.Text.StringBuilder();
                while ((line = reader.ReadLine()) != null)
                {
                    bodyBuilder.AppendLine(line);
                }
                message.Body = bodyBuilder.ToString();

                return message;
            }
            catch
            {
                return null;
            }
        }

        private void AnalyzeSender(string sender, EmailProtectionResult result)
        {
            if (string.IsNullOrEmpty(sender)) return;

            try
            {
                var domain = sender.Split('@').Last();
                
                if (_spamDomains.Contains(domain))
                {
                    result.Threats.Add(new EmailThreat
                    {
                        Type = "垃圾邮件发件人",
                        Value = sender,
                        Risk = "高"
                    });
                    result.RiskScore += 30;
                }

                // 检查可疑发件人格式
                if (sender.Contains("noreply", StringComparison.OrdinalIgnoreCase) ||
                    sender.Contains("donotreply", StringComparison.OrdinalIgnoreCase))
                {
                    result.RiskScore += 5;
                }
            }
            catch { }
        }

        private void AnalyzeSubject(string subject, EmailProtectionResult result)
        {
            if (string.IsNullOrEmpty(subject)) return;

            // 检查紧急性词汇
            var urgentPatterns = new[] { "urgent", "immediate", "alert", "warning", "紧急", "警告" };
            foreach (var pattern in urgentPatterns)
            {
                if (subject.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    result.RiskScore += 10;
                    result.Threats.Add(new EmailThreat
                    {
                        Type = "紧急主题",
                        Value = pattern,
                        Risk = "中"
                    });
                }
            }

            // 检查钓鱼关键词
            foreach (var keyword in _phishingKeywords)
            {
                if (subject.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    result.RiskScore += 15;
                    result.Threats.Add(new EmailThreat
                    {
                        Type = "钓鱼关键词",
                        Value = keyword,
                        Risk = "高"
                    });
                }
            }
        }

        private void AnalyzeBody(string body, EmailProtectionResult result)
        {
            if (string.IsNullOrEmpty(body)) return;

            // 检查钓鱼关键词
            foreach (var keyword in _phishingKeywords)
            {
                if (body.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    result.RiskScore += 5;
                }
            }

            // 检查可疑格式
            var suspiciousPatterns = new Dictionary<string, string>
            {
                { @"\[link\]", "链接占位符" },
                { @"\[click here\]", "点击占位符" },
                { @"dear (customer|user|member)", "泛化问候" },
                { @"<a\s+href\s*=\s*[""']http", "HTML链接" }
            };

            foreach (var pattern in suspiciousPatterns)
            {
                if (Regex.IsMatch(body, pattern.Key, RegexOptions.IgnoreCase))
                {
                    result.RiskScore += 5;
                }
            }
        }

        private void AnalyzeLinks(string body, EmailProtectionResult result)
        {
            var linkMatches = Regex.Matches(body, @"https?://[^\s<>""']+");
            
            foreach (Match match in linkMatches)
            {
                var url = match.Value;
                var linkInfo = new SuspiciousLink
                {
                    URL = url
                };

                // 检查IP地址URL
                if (Regex.IsMatch(url, @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                {
                    linkInfo.Risk = "高";
                    linkInfo.Reason = "IP地址URL";
                    result.RiskScore += 15;
                }

                // 检查短链接
                if (url.Contains("bit.ly") || url.Contains("tinyurl") || url.Contains("goo.gl"))
                {
                    linkInfo.Risk = "中";
                    linkInfo.Reason = "短链接";
                    result.RiskScore += 10;
                }

                // 检查非HTTPS
                if (url.StartsWith("http://"))
                {
                    linkInfo.Risk = "低";
                    linkInfo.Reason = "非安全连接";
                    result.RiskScore += 5;
                }

                if (!string.IsNullOrEmpty(linkInfo.Risk))
                {
                    result.SuspiciousLinks.Add(linkInfo);
                }
            }
        }

        private void AnalyzeAttachments(MailMessage message, EmailProtectionResult result)
        {
            foreach (var attachment in message.Attachments)
            {
                var fileName = attachment.Name ?? "";
                var ext = Path.GetExtension(fileName).ToLower();

                if (_maliciousExtensions.Contains(ext))
                {
                    result.SuspiciousAttachments.Add(new SuspiciousAttachment
                    {
                        FileName = fileName,
                        Extension = ext,
                        Risk = "严重",
                        Reason = "危险文件类型"
                    });
                    result.RiskScore += 30;
                }
                else if (new[] { ".zip", ".rar", ".7z", ".tar", ".gz" }.Contains(ext))
                {
                    result.SuspiciousAttachments.Add(new SuspiciousAttachment
                    {
                        FileName = fileName,
                        Extension = ext,
                        Risk = "中",
                        Reason = "压缩文件"
                    });
                    result.RiskScore += 5;
                }
                else if (new[] { ".doc", ".docx", ".xls", ".xlsx", ".pdf" }.Contains(ext))
                {
                    // 文档文件需要进一步分析
                    result.SuspiciousAttachments.Add(new SuspiciousAttachment
                    {
                        FileName = fileName,
                        Extension = ext,
                        Risk = "低",
                        Reason = "文档文件（需进一步分析）"
                    });
                }
            }
        }

        private string GetRiskLevel(int score)
        {
            return score switch
            {
                >= 60 => "严重",
                >= 40 => "高",
                >= 20 => "中",
                >= 10 => "低",
                _ => "安全"
            };
        }

        public void AddSpamDomain(string domain)
        {
            _spamDomains.Add(domain.ToLower());
        }

        public void AddPhishingKeyword(string keyword)
        {
            _phishingKeywords.Add(keyword.ToLower());
        }
    }

    public class EmailProtectionResult
    {
        public string Sender { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
        public bool IsSuspicious { get; set; }
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; }
        public List<EmailThreat> Threats { get; set; }
        public List<SuspiciousLink> SuspiciousLinks { get; set; }
        public List<SuspiciousAttachment> SuspiciousAttachments { get; set; }
        public List<string> Warnings { get; set; }
    }

    public class EmailThreat
    {
        public string Type { get; set; }
        public string Value { get; set; }
        public string Risk { get; set; }
    }

    public class SuspiciousLink
    {
        public string URL { get; set; }
        public string Risk { get; set; }
        public string Reason { get; set; }
    }

    public class SuspiciousAttachment
    {
        public string FileName { get; set; }
        public string Extension { get; set; }
        public string Risk { get; set; }
        public string Reason { get; set; }
    }
}
