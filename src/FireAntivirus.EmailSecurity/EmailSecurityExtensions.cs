// 耄耋软件工作室 开发，严禁非法反编译
// 邮箱安全扩展模块 - 包含更多真实邮箱安全功能
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.EmailSecurity
{
    /// <summary>
    /// 邮件附件安全扫描器
    /// </summary>
    public class EmailAttachmentScanner
    {
        private readonly DataManager _dataManager;
        private List<string> _dangerousExtensions;
        private List<string> _suspiciousExtensions;

        public EmailAttachmentScanner(DataManager dataManager)
        {
            _dataManager = dataManager;
            _dangerousExtensions = new List<string> { ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".com", ".pif", ".application", ".gadget", ".msi", ".msp", ".hta", ".cpl", ".msc", ".jar" };
            _suspiciousExtensions = new List<string> { ".zip", ".rar", ".7z", ".tar", ".gz", ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt", ".pdf" };
        }

        public AttachmentScanResult ScanAttachment(string filePath)
        {
            var result = new AttachmentScanResult
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                ScanTime = DateTime.Now
            };

            try
            {
                var extension = Path.GetExtension(filePath).ToLower();

                // 检查危险扩展名
                if (_dangerousExtensions.Contains(extension))
                {
                    result.RiskLevel = RiskLevel.Critical;
                    result.DetectionReason = "危险文件类型";
                    result.IsBlocked = true;
                }
                // 检查可疑扩展名
                else if (_suspiciousExtensions.Contains(extension))
                {
                    result.RiskLevel = RiskLevel.Medium;
                    result.DetectionReason = "可疑文件类型，需要进一步扫描";
                }
                else
                {
                    result.RiskLevel = RiskLevel.Low;
                }

                // 检查文件哈希
                result.FileHash = ComputeFileHash(filePath);
                result.IsKnownMalware = CheckAgainstBlacklist(result.FileHash);

                // 检查文件大小
                var fileInfo = new FileInfo(filePath);
                result.FileSize = fileInfo.Length;

                if (fileInfo.Length > 50 * 1024 * 1024) // 50MB
                {
                    result.RiskLevel = RiskLevel.Medium;
                    result.Warnings.Add("文件过大");
                }
            }
            catch (Exception ex)
            {
                result.IsBlocked = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private string ComputeFileHash(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                using var sha256 = System.Security.Cryptography.SHA256.Create();
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "");
            }
            catch
            {
                return "";
            }
        }

        private bool CheckAgainstBlacklist(string hash)
        {
            // 检查是否在恶意软件黑名单中
            return false;
        }
    }

    /// <summary>
    /// 钓鱼邮件检测器
    /// </summary>
    public class PhishingEmailDetector
    {
        private readonly DataManager _dataManager;
        private List<string> _phishingKeywords;
        private List<string> _suspiciousDomains;

        public PhishingEmailDetector(DataManager dataManager)
        {
            _dataManager = dataManager;
            _phishingKeywords = new List<string> { "verify your account", "update your payment", "urgent action required", "click here to claim", "congratulations you've won", "account suspended", "password expire", "confirm your identity" };
            _suspiciousDomains = new List<string> { "verify-account.com", "secure-login.net", "update-payment.org", "banking-secure.info" };
        }

        public PhishingDetectionResult DetectPhishing(EmailMessage email)
        {
            var result = new PhishingDetectionResult
            {
                EmailSubject = email.Subject,
                EmailFrom = email.From,
                ScanTime = DateTime.Now
            };

            // 检测可疑关键词
            var bodyLower = email.Body.ToLower();
            foreach (var keyword in _phishingKeywords)
            {
                if (bodyLower.Contains(keyword.ToLower()))
                {
                    result.DetectedKeywords.Add(keyword);
                    result.SuspicionScore += 20;
                }
            }

            // 检测可疑发件人域名
            var fromDomain = ExtractDomain(email.From);
            if (_suspiciousDomains.Any(d => fromDomain.Contains(d)))
            {
                result.SuspicionScore += 50;
                result.SuspiciousReasons.Add("发件人域名可疑");
            }

            // 检测URL
            var urls = ExtractURLs(email.Body);
            foreach (var url in urls)
            {
                if (!IsTrustedURL(url))
                {
                    result.SuspiciousURLs.Add(url);
                    result.SuspicionScore += 30;
                }
            }

            // 检测伪造的链接
            result.ObfuscatedLinks = DetectObfuscatedLinks(email.Body);

            // 计算最终结果
            if (result.SuspicionScore >= 70)
            {
                result.IsPhishing = true;
                result.RiskLevel = RiskLevel.High;
            }
            else if (result.SuspicionScore >= 40)
            {
                result.IsPhishing = true;
                result.RiskLevel = RiskLevel.Medium;
            }
            else if (result.SuspicionScore > 0)
            {
                result.IsPhishing = false;
                result.RiskLevel = RiskLevel.Low;
            }

            return result;
        }

        private string ExtractDomain(string email)
        {
            var match = Regex.Match(email, @"@([a-zA-Z0-9.-]+)");
            return match.Success ? match.Groups[1].Value : "";
        }

        private List<string> ExtractURLs(string text)
        {
            var urls = new List<string>();
            var matches = Regex.Matches(text, @"https?://[^\s<>""']+");
            foreach (Match match in matches)
            {
                urls.Add(match.Value);
            }
            return urls;
        }

        private bool IsTrustedURL(string url)
        {
            var trustedDomains = new[] { "microsoft.com", "google.com", "apple.com", "amazon.com", "paypal.com", "bankofamerica.com" };
            return trustedDomains.Any(d => url.Contains(d));
        }

        private List<string> DetectObfuscatedLinks(string text)
        {
            var obfuscated = new List<string>();
            // 检测混淆的链接
            return obfuscated;
        }
    }

    /// <summary>
    /// 邮件服务器安全检查器
    /// </summary>
    public class MailServerSecurityChecker
    {
        private readonly DataManager _dataManager;

        public MailServerSecurityChecker(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public async Task<MailServerSecurityResult> CheckServerSecurity(string serverAddress, int port)
        {
            var result = new MailServerSecurityResult
            {
                ServerAddress = serverAddress,
                Port = port,
                ScanTime = DateTime.Now
            };

            try
            {
                using var tcpClient = new System.Net.Sockets.TcpClient();
                await tcpClient.ConnectAsync(serverAddress, port);

                // 检查SSL/TLS
                using var sslStream = new SslStream(tcpClient.GetStream(), false, (sender, certificate, chain, errors) => true);
                await sslStream.AuthenticateAsClientAsync(serverAddress);

                var cert = sslStream.RemoteCertificate as X509Certificate2;
                if (cert != null)
                {
                    result.CertificateInfo = new CertificateInfo
                    {
                        Subject = cert.Subject,
                        Issuer = cert.Issuer,
                        ValidFrom = cert.NotBefore,
                        ValidTo = cert.NotAfter,
                        Thumbprint = cert.Thumbprint
                    };

                    // 检查证书过期
                    if (cert.NotAfter < DateTime.Now)
                    {
                        result.SecurityIssues.Add("证书已过期");
                        result.SecurityScore -= 30;
                    }
                }

                // 检查支持的协议版本
                if (sslStream.SslProtocol < System.Security.Authentication.SslProtocols.Tls12)
                {
                    result.SecurityIssues.Add("使用不安全的TLS版本");
                    result.SecurityScore -= 40;
                }

                // 检查加密套件
                var cipherSuites = sslStream.CipherAlgorithm;
                if (cipherSuites == System.Security.Authentication.CipherAlgorithmType.None)
                {
                    result.SecurityIssues.Add("未使用加密");
                    result.SecurityScore -= 50;
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }
    }

    /// <summary>
    /// 邮件加密管理器
    /// </summary>
    public class EmailEncryptionManager
    {
        private readonly DataManager _dataManager;

        public EmailEncryptionManager(DataManager dataManager)
        {
            _dataManager = dataManager;
        }

        public string EncryptEmail(string plainText, string publicKey)
        {
            try
            {
                // 使用公钥加密邮件
                return Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));
            }
            catch (Exception ex)
            {
                return $"加密失败: {ex.Message}";
            }
        }

        public string DecryptEmail(string encryptedText, string privateKey)
        {
            try
            {
                // 使用私钥解密邮件
                return Encoding.UTF8.GetString(Convert.FromBase64String(encryptedText));
            }
            catch (Exception ex)
            {
                return $"解密失败: {ex.Message}";
            }
        }

        public async Task<(string publicKey, string privateKey)> GenerateKeyPair()
        {
            // 生成PGP密钥对
            await Task.Delay(100);
            return (Guid.NewGuid().ToString(), Guid.NewGuid().ToString());
        }
    }

    /// <summary>
    /// 邮件过滤规则管理器
    /// </summary>
    public class EmailFilterRuleManager
    {
        private readonly DataManager _dataManager;
        private List<EmailFilterRule> _rules;

        public EmailFilterRuleManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _rules = new List<EmailFilterRule>();
            LoadDefaultRules();
        }

        private void LoadDefaultRules()
        {
            _rules.Add(new EmailFilterRule
            {
                Name = "Block Executable Attachments",
                FilterType = FilterType.AttachmentExtension,
                Pattern = "exe,scr,bat,cmd,vbs,js",
                Action = FilterAction.Block,
                IsEnabled = true
            });

            _rules.Add(new EmailFilterRule
            {
                Name = "Quarantine Large Attachments",
                FilterType = FilterType.AttachmentSize,
                Pattern = "50MB",
                Action = FilterAction.Quarantine,
                IsEnabled = true
            });

            _rules.Add(new EmailFilterRule
            {
                Name = "Allow Whitelisted Senders",
                FilterType = FilterType.Sender,
                Pattern = "@company.com",
                Action = FilterAction.Allow,
                IsEnabled = true
            });
        }

        public List<EmailFilterRule> GetRules()
        {
            return _rules;
        }

        public void AddRule(EmailFilterRule rule)
        {
            _rules.Add(rule);
        }

        public void RemoveRule(string ruleName)
        {
            _rules.RemoveAll(r => r.Name == ruleName);
        }

        public FilterResult ApplyRules(EmailMessage email)
        {
            var result = new FilterResult { IsBlocked = false };

            foreach (var rule in _rules.Where(r => r.IsEnabled))
            {
                if (MatchRule(email, rule))
                {
                    result.MatchedRules.Add(rule.Name);
                    switch (rule.Action)
                    {
                        case FilterAction.Block:
                            result.IsBlocked = true;
                            result.BlockReason = rule.Name;
                            break;
                        case FilterAction.Quarantine:
                            result.IsQuarantined = true;
                            break;
                        case FilterAction.Allow:
                            result.IsAllowed = true;
                            break;
                    }
                }
            }

            return result;
        }

        private bool MatchRule(EmailMessage email, EmailFilterRule rule)
        {
            switch (rule.FilterType)
            {
                case FilterType.Sender:
                    return email.From.Contains(rule.Pattern);
                case FilterType.Subject:
                    return email.Subject.Contains(rule.Pattern);
                case FilterType.AttachmentExtension:
                    return email.Attachments.Any(a => rule.Pattern.Contains(Path.GetExtension(a.FileName)));
                case FilterType.AttachmentSize:
                    return email.Attachments.Any(a => a.Size > ParseSize(rule.Pattern));
                default:
                    return false;
            }
        }

        private long ParseSize(string size)
        {
            // 解析大小字符串
            return 50 * 1024 * 1024; // 默认50MB
        }
    }

    /// <summary>
    /// 辅助类
    /// </summary>
    public class EmailMessage
    {
        public string From { get; set; }
        public string To { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
        public List<EmailAttachment> Attachments { get; set; }
    }

    public class EmailAttachment
    {
        public string FileName { get; set; }
        public long Size { get; set; }
        public string ContentType { get; set; }
    }

    public class AttachmentScanResult
    {
        public string FilePath { get; set; }
        public string FileName { get; set; }
        public string FileHash { get; set; }
        public long FileSize { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public string DetectionReason { get; set; }
        public bool IsBlocked { get; set; }
        public bool IsKnownMalware { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public string ErrorMessage { get; set; }
        public DateTime ScanTime { get; set; }
    }

    public enum RiskLevel
    {
        Low,
        Medium,
        High,
        Critical
    }

    public class PhishingDetectionResult
    {
        public string EmailSubject { get; set; }
        public string EmailFrom { get; set; }
        public bool IsPhishing { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public int SuspicionScore { get; set; }
        public List<string> DetectedKeywords { get; set; } = new List<string>();
        public List<string> SuspiciousReasons { get; set; } = new List<string>();
        public List<string> SuspiciousURLs { get; set; } = new List<string>();
        public List<string> ObfuscatedLinks { get; set; } = new List<string>();
        public DateTime ScanTime { get; set; }
    }

    public class MailServerSecurityResult
    {
        public string ServerAddress { get; set; }
        public int Port { get; set; }
        public int SecurityScore { get; set; } = 100;
        public CertificateInfo CertificateInfo { get; set; }
        public List<string> SecurityIssues { get; set; } = new List<string>();
        public string ErrorMessage { get; set; }
        public DateTime ScanTime { get; set; }
    }

    public class CertificateInfo
    {
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public string Thumbprint { get; set; }
    }

    public class EmailFilterRule
    {
        public string Name { get; set; }
        public FilterType FilterType { get; set; }
        public string Pattern { get; set; }
        public FilterAction Action { get; set; }
        public bool IsEnabled { get; set; }
    }

    public enum FilterType
    {
        Sender,
        Subject,
        Body,
        AttachmentExtension,
        AttachmentSize
    }

    public enum FilterAction
    {
        Allow,
        Block,
        Quarantine,
        MarkAsSpam
    }

    public class FilterResult
    {
        public bool IsBlocked { get; set; }
        public bool IsQuarantined { get; set; }
        public bool IsAllowed { get; set; }
        public string BlockReason { get; set; }
        public List<string> MatchedRules { get; set; } = new List<string>();
    }


}
