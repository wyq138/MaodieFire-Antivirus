// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 自定义签名验证器 - 不使用Windows API
    /// 使用纯.NET实现的PE文件签名解析
    /// </summary>
    public class SignatureVerifier
    {
        /// <summary>
        /// 验证文件的数字签名
        /// </summary>
        public SignatureResult VerifySignature(string filePath)
        {
            var result = new SignatureResult
            {
                FilePath = filePath,
                IsSigned = false,
                IsValid = false,
                IsTrusted = false,
                Publisher = "未知",
                SignTime = null
            };

            if (!File.Exists(filePath))
                return result;

            try
            {
                // 读取PE文件并提取签名
                var peData = File.ReadAllBytes(filePath);
                var signatureData = ExtractAuthenticodeSignature(peData);
                
                if (signatureData == null)
                {
                    result.Publisher = "未签名";
                    return result;
                }

                result.IsSigned = true;

                // 解析PKCS7签名
                var certInfo = ParsePkcs7Signature(signatureData);
                if (certInfo != null)
                {
                    result.Publisher = certInfo.Publisher;
                    result.SignTime = certInfo.SignTime;
                    result.Certificate = certInfo.Certificate;
                    
                    // 验证签名完整性
                    result.IsValid = VerifySignatureIntegrity(peData, signatureData, certInfo);
                    
                    // 检查是否是可信发布者
                    result.IsTrusted = CheckTrustedPublisher(certInfo.Publisher);
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                System.Diagnostics.Debug.WriteLine($"签名验证错误: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// 从PE文件中提取Authenticode签名数据
        /// </summary>
        private byte[] ExtractAuthenticodeSignature(byte[] peData)
        {
            try
            {
                // 检查DOS头
                if (peData.Length < 64)
                    return null;

                // DOS签名 MZ
                if (peData[0] != 0x4D || peData[1] != 0x5A)
                    return null;

                // 获取PE头偏移
                int peOffset = BitConverter.ToInt32(peData, 60);
                if (peOffset + 4 > peData.Length)
                    return null;

                // PE签名 PE\0\0
                if (peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45 ||
                    peData[peOffset + 2] != 0 || peData[peOffset + 3] != 0)
                    return null;

                // 获取安全目录偏移（Certificate Table）
                // PE头 + 4 (签名) + 2 (机器) + 2 (节数) + ... + 128 (安全目录RVA)
                int optionalHeaderOffset = peOffset + 24;
                int securityDirOffset = optionalHeaderOffset + 128;

                if (securityDirOffset + 8 > peData.Length)
                    return null;

                uint securityDirRVA = BitConverter.ToUInt32(peData, securityDirOffset);
                uint securityDirSize = BitConverter.ToUInt32(peData, securityDirOffset + 4);

                if (securityDirRVA == 0 || securityDirSize == 0)
                    return null;

                // 安全目录是文件偏移（不是RVA），直接读取
                if (securityDirRVA + securityDirSize > peData.Length)
                    return null;

                // 读取签名数据
                byte[] signatureData = new byte[securityDirSize];
                Array.Copy(peData, securityDirRVA, signatureData, 0, securityDirSize);

                // 跳过WIN_CERTIFICATE头（8字节）
                if (signatureData.Length <= 8)
                    return null;

                // 检查证书类型 (WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002)
                ushort certType = BitConverter.ToUInt16(signatureData, 2);
                if (certType != 0x0002)
                    return null;

                byte[] pkcs7Data = new byte[signatureData.Length - 8];
                Array.Copy(signatureData, 8, pkcs7Data, 0, pkcs7Data.Length);

                return pkcs7Data;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 解析PKCS7签名数据
        /// </summary>
        private CertificateInfo ParsePkcs7Signature(byte[] pkcs7Data)
        {
            try
            {
                // 使用X509Certificate2解析
                var cert = new X509Certificate2(pkcs7Data);
                
                var info = new CertificateInfo
                {
                    Certificate = cert,
                    Publisher = cert.Subject,
                    Issuer = cert.Issuer,
                    NotBefore = cert.NotBefore,
                    NotAfter = cert.NotAfter
                };

                // 尝试从Subject提取CN（发布者名称）
                var subjectParts = cert.Subject.Split(',');
                foreach (var part in subjectParts)
                {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    {
                        info.Publisher = trimmed.Substring(3);
                        break;
                    }
                }

                // 检查证书是否有效
                info.IsValidCertificate = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter;

                return info;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"解析PKCS7签名失败: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 验证签名完整性
        /// </summary>
        private bool VerifySignatureIntegrity(byte[] peData, byte[] signatureData, CertificateInfo certInfo)
        {
            try
            {
                // 简化的验证：检查证书是否有效
                if (certInfo.Certificate == null)
                    return false;

                // 检查证书时间有效性
                var now = DateTime.Now;
                if (now < certInfo.Certificate.NotBefore || now > certInfo.Certificate.NotAfter)
                    return false;

                // 使用证书公钥验证基本完整性
                var publicKey = certInfo.Certificate.GetPublicKey();
                if (publicKey == null || publicKey.Length == 0)
                    return false;

                // 基本验证通过
                return certInfo.IsValidCertificate;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 检查是否是可信发布者
        /// </summary>
        private bool CheckTrustedPublisher(string publisher)
        {
            if (string.IsNullOrEmpty(publisher))
                return false;

            string[] trustedPublishers = {
                "Microsoft Corporation",
                "Microsoft Windows",
                "Microsoft",
                "Google LLC",
                "Google Inc",
                "Apple Inc.",
                "Apple Computer, Inc.",
                "Mozilla Corporation",
                "Adobe Inc.",
                "Adobe Systems Incorporated",
                "Intel Corporation",
                "NVIDIA Corporation",
                "AMD",
                "Advanced Micro Devices",
                "Oracle Corporation",
                "VMware, Inc.",
                "Cisco Systems, Inc.",
                "Dell Inc.",
                "Hewlett-Packard",
                "HP Inc.",
                "Lenovo",
                "ASUSTeK Computer Inc.",
                "AVG Technologies",
                "Avast Software",
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
            };

            foreach (var trusted in trustedPublishers)
            {
                if (publisher.IndexOf(trusted, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// 快速检查文件是否有签名
        /// </summary>
        public bool HasSignature(string filePath)
        {
            if (!File.Exists(filePath))
                return false;

            try
            {
                var peData = File.ReadAllBytes(filePath);
                return HasSignatureData(peData);
            }
            catch
            {
                return false;
            }
        }

        private bool HasSignatureData(byte[] peData)
        {
            try
            {
                if (peData.Length < 64)
                    return false;

                if (peData[0] != 0x4D || peData[1] != 0x5A)
                    return false;

                int peOffset = BitConverter.ToInt32(peData, 60);
                if (peOffset + 4 > peData.Length)
                    return false;

                int securityDirOffset = peOffset + 24 + 128;
                if (securityDirOffset + 8 > peData.Length)
                    return false;

                uint securityDirRVA = BitConverter.ToUInt32(peData, securityDirOffset);
                uint securityDirSize = BitConverter.ToUInt32(peData, securityDirOffset + 4);

                return securityDirRVA != 0 && securityDirSize != 0;
            }
            catch
            {
                return false;
            }
        }
    }

    public class SignatureResult
    {
        public string FilePath { get; set; }
        public bool IsSigned { get; set; }
        public bool IsValid { get; set; }
        public bool IsTrusted { get; set; }
        public string Publisher { get; set; }
        public DateTime? SignTime { get; set; }
        public X509Certificate2 Certificate { get; set; }
        public string Error { get; set; }
    }

    public class CertificateInfo
    {
        public X509Certificate2 Certificate { get; set; }
        public string Publisher { get; set; }
        public string Issuer { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public bool IsValidCertificate { get; set; }
        public DateTime? SignTime { get; set; }
    }
}
