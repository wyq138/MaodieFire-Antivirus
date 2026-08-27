// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FireAntivirus.Engine.Analyzers.Security
{
    /// <summary>
    /// 证书分析器 - 分析数字证书和签名
    /// </summary>
    public class CertificateAnalyzer
    {
        private readonly HashSet<string> _trustedPublishers;
        private readonly HashSet<string> _blockedPublishers;
        private readonly Dictionary<string, DateTime> _certificateCache;

        public CertificateAnalyzer()
        {
            _trustedPublishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _blockedPublishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _certificateCache = new Dictionary<string, DateTime>();
            InitializeTrustedPublishers();
        }

        private void InitializeTrustedPublishers()
        {
            _trustedPublishers.UnionWith(new[]
            {
                "Microsoft Corporation", "Microsoft Windows", "Microsoft",
                "Google LLC", "Google Inc",
                "Apple Inc.", "Apple Inc",
                "Mozilla Corporation",
                "Adobe Inc.", "Adobe Systems Incorporated",
                "Intel Corporation",
                "NVIDIA Corporation",
                "AMD",
                "Oracle Corporation",
                "VMware, Inc.",
                "Cisco Systems, Inc.",
                "Dell Inc.",
                "HP Inc.",
                "Lenovo",
                "ASUSTeK Computer Inc.",
                "Kaspersky Lab",
                "Symantec Corporation",
                "McAfee, Inc.",
                "Trend Micro, Inc.",
                "Bitdefender",
                "ESET, spol. s r.o.",
                "360 Security Technology Inc.",
                "Tencent",
                "Huawei",
                "Baidu, Inc."
            });
        }

        public CertificateResult Analyze(string filePath)
        {
            var result = new CertificateResult
            {
                FilePath = filePath,
                IsSigned = false,
                IsValid = false,
                IsTrusted = false,
                Warnings = new List<string>()
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Warnings.Add("文件不存在");
                    return result;
                }

                // 尝试从文件读取证书
                var cert = GetCertificateFromFile(filePath);
                if (cert == null)
                {
                    result.Warnings.Add("文件未签名");
                    return result;
                }

                result.IsSigned = true;
                result.Publisher = cert.Subject;
                result.Issuer = cert.Issuer;
                result.NotBefore = cert.NotBefore;
                result.NotAfter = cert.NotAfter;
                result.Thumbprint = cert.Thumbprint;
                result.SerialNumber = cert.SerialNumber;

                // 检查证书有效期
                if (DateTime.Now < cert.NotBefore)
                {
                    result.Warnings.Add($"证书尚未生效，生效时间: {cert.NotBefore}");
                }
                else if (DateTime.Now > cert.NotAfter)
                {
                    result.Warnings.Add($"证书已过期，过期时间: {cert.NotAfter}");
                }
                else
                {
                    result.IsValid = true;
                }

                // 检查是否为可信发布者
                if (IsTrustedPublisher(cert.Subject))
                {
                    result.IsTrusted = true;
                }
                else if (IsBlockedPublisher(cert.Subject))
                {
                    result.IsBlocked = true;
                    result.Warnings.Add("发布者在黑名单中");
                }

                // 检查证书链
                var chainResult = VerifyCertificateChain(cert);
                result.ChainIsValid = chainResult.IsValid;
                if (!chainResult.IsValid)
                {
                    result.Warnings.AddRange(chainResult.Errors);
                }

                // 分析证书强度
                result.SignatureAlgorithm = cert.SignatureAlgorithm?.FriendlyName;
                result.KeySize = GetKeySize(cert);
                
                if (result.KeySize < 2048 && result.KeySize > 0)
                {
                    result.Warnings.Add($"密钥强度较弱: {result.KeySize} 位");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"分析错误: {ex.Message}");
            }

            return result;
        }

        private X509Certificate2 GetCertificateFromFile(string filePath)
        {
            try
            {
                byte[] peData = File.ReadAllBytes(filePath);
                
                if (peData.Length < 64) return null;
                if (peData[0] != 0x4D || peData[1] != 0x5A) return null;

                int peOffset = BitConverter.ToInt32(peData, 60);
                if (peOffset + 4 > peData.Length) return null;
                if (peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45) return null;

                int securityDirOffset = peOffset + 24 + 128;
                if (securityDirOffset + 8 > peData.Length) return null;

                uint rva = BitConverter.ToUInt32(peData, securityDirOffset);
                uint size = BitConverter.ToUInt32(peData, securityDirOffset + 4);

                if (rva == 0 || size == 0 || rva + size > peData.Length) return null;

                byte[] sigData = new byte[size];
                Array.Copy(peData, rva, sigData, 0, size);

                if (sigData.Length <= 8) return null;

                byte[] pkcs7 = new byte[sigData.Length - 8];
                Array.Copy(sigData, 8, pkcs7, 0, pkcs7.Length);

                return new X509Certificate2(pkcs7);
            }
            catch
            {
                return null;
            }
        }

        private bool IsTrustedPublisher(string subject)
        {
            if (string.IsNullOrEmpty(subject)) return false;
            foreach (var trusted in _trustedPublishers)
            {
                if (subject.Contains(trusted, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private bool IsBlockedPublisher(string subject)
        {
            if (string.IsNullOrEmpty(subject)) return false;
            foreach (var blocked in _blockedPublishers)
            {
                if (subject.Contains(blocked, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private ChainVerifyResult VerifyCertificateChain(X509Certificate2 cert)
        {
            var result = new ChainVerifyResult { IsValid = true, Errors = new List<string>() };

            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                if (!chain.Build(cert))
                {
                    result.IsValid = false;
                    foreach (var status in chain.ChainStatus)
                    {
                        result.Errors.Add(status.StatusInformation);
                    }
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Errors.Add($"链验证错误: {ex.Message}");
            }

            return result;
        }

        private int GetKeySize(X509Certificate2 cert)
        {
            try
            {
                var rsa = cert.GetRSAPublicKey();
                return rsa?.KeySize ?? 0;
            }
            catch
            {
                return 0;
            }
        }

        public void AddTrustedPublisher(string publisher)
        {
            _trustedPublishers.Add(publisher);
        }

        public void AddBlockedPublisher(string publisher)
        {
            _blockedPublishers.Add(publisher);
        }
    }

    public class CertificateResult
    {
        public string FilePath { get; set; }
        public bool IsSigned { get; set; }
        public bool IsValid { get; set; }
        public bool IsTrusted { get; set; }
        public bool IsBlocked { get; set; }
        public string Publisher { get; set; }
        public string Issuer { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string Thumbprint { get; set; }
        public string SerialNumber { get; set; }
        public string SignatureAlgorithm { get; set; }
        public int KeySize { get; set; }
        public bool ChainIsValid { get; set; }
        public List<string> Warnings { get; set; }
    }

    public class ChainVerifyResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; }
    }
}
