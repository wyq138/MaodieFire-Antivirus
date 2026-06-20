using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FireAntivirus.Kernel.CertTools
{
    public class CertificateGenerator
    {
        private const string RootCertName = "FireAntivirus Root CA";
        private const string CodeSignCertName = "FireAntivirus Code Signing";
        
        public static bool GenerateCertificates(string outputPath)
        {
            try
            {
                if (!Directory.Exists(outputPath))
                    Directory.CreateDirectory(outputPath);
                
                Console.WriteLine("正在生成自签名证书体系...");
                
                // 生成根证书
                var rootCert = GenerateRootCertificate();
                if (rootCert == null)
                    return false;
                
                // 生成代码签名证书
                var codeSignCert = GenerateCodeSignCertificate(rootCert);
                if (codeSignCert == null)
                    return false;
                
                // 保存证书文件
                SaveCertificate(rootCert, Path.Combine(outputPath, "FireAntivirusRoot.cer"));
                SaveCertificate(codeSignCert, Path.Combine(outputPath, "FireAntivirusCodeSign.pfx"), "FireAntivirus123!");
                
                Console.WriteLine("证书生成完成！");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"证书生成失败: {ex.Message}");
                return false;
            }
        }
        
        private static X509Certificate2 GenerateRootCertificate()
        {
            using var rsa = RSA.Create(2048);
            
            var request = new CertificateRequest(
                subjectName: new X500DistinguishedName($