using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FireAntivirus.Kernel.CertificateSigning
{
    /// <summary>
    /// 证书管理类 - 负责生成和管理数字证书
    /// 用于内核驱动签名和绕过验证
    /// </summary>
    public sealed class CertificateManager : IDisposable
    {
        private bool _disposed = false;
        
        public CertificateManager()
        {
            InitializeCertificates();
        }
        
        /// <summary>
        /// 生成自签名根证书
        /// </summary>
        public X509Certificate2 CreateRootCertificate(string subjectName = "FireAntivirus Root CA")
        {
            using (RSA rsa = RSA.Create(2048))
            {
                CertificateRequest req = new CertificateRequest(
                    new X500DistinguishedName($