// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace FireAntivirus.Engine.Analyzers.Protection
{
    /// <summary>
    /// 应用程序控制分析器 - 应用白名单/黑名单控制
    /// </summary>
    public class ApplicationControlAnalyzer
    {
        private readonly HashSet<string> _whitelistPaths;
        private readonly HashSet<string> _blacklistPaths;
        private readonly HashSet<string> _whitelistHashes;
        private readonly HashSet<string> _blacklistHashes;
        private readonly HashSet<string> _trustedPublishers;
        private readonly Dictionary<string, ApplicationInfo> _applicationCache;

        public ApplicationControlAnalyzer()
        {
            _whitelistPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _blacklistPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _whitelistHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _blacklistHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _trustedPublishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _applicationCache = new Dictionary<string, ApplicationInfo>();
            InitializeDefaultPolicies();
        }

        private void InitializeDefaultPolicies()
        {
            // 系统目录自动加入白名单
            _whitelistPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.System));
            _whitelistPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            _whitelistPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            _whitelistPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

            // 信任的系统发布者
            _trustedPublishers.UnionWith(new[]
            {
                "Microsoft Corporation", "Microsoft Windows", "Microsoft",
                "Google LLC", "Google Inc",
                "Apple Inc.", "Apple Inc",
                "Mozilla Corporation",
                "Adobe Inc."
            });
        }

        public ApplicationControlResult Analyze(string filePath)
        {
            var result = new ApplicationControlResult
            {
                FilePath = filePath,
                IsAllowed = true,
                Restrictions = new List<string>(),
                Warnings = new List<string>()
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.IsAllowed = false;
                    result.Restrictions.Add("文件不存在");
                    return result;
                }

                // 获取文件信息
                var fileInfo = GetApplicationInfo(filePath);
                result.ApplicationInfo = fileInfo;

                // 检查黑名单路径
                foreach (var blackPath in _blacklistPaths)
                {
                    if (filePath.StartsWith(blackPath, StringComparison.OrdinalIgnoreCase))
                    {
                        result.IsAllowed = false;
                        result.Restrictions.Add($"路径在黑名单中: {blackPath}");
                        return result;
                    }
                }

                // 检查黑名单哈希
                if (_blacklistHashes.Contains(fileInfo.Hash))
                {
                    result.IsAllowed = false;
                    result.Restrictions.Add("文件哈希在黑名单中");
                    return result;
                }

                // 检查白名单路径
                foreach (var whitePath in _whitelistPaths)
                {
                    if (filePath.StartsWith(whitePath, StringComparison.OrdinalIgnoreCase))
                    {
                        result.IsAllowed = true;
                        result.Restrictions.Add($"路径在白名单中: {whitePath}");
                        
                        // 检查签名
                        if (fileInfo.IsSigned && fileInfo.IsTrusted)
                        {
                            result.TrustLevel = "完全信任";
                        }
                        return result;
                    }
                }

                // 检查白名单哈希
                if (_whitelistHashes.Contains(fileInfo.Hash))
                {
                    result.IsAllowed = true;
                    result.TrustLevel = "哈希白名单";
                    return result;
                }

                // 检查签名
                if (fileInfo.IsSigned)
                {
                    if (IsTrustedPublisher(fileInfo.Publisher))
                    {
                        result.IsAllowed = true;
                        result.TrustLevel = "信任发布者";
                        return result;
                    }
                }

                // 未知应用
                result.TrustLevel = "未知";
                result.Restrictions.Add("未在白名单中，需要审核");

                // 检查可疑特征
                CheckSuspiciousFeatures(fileInfo, result);
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"分析错误: {ex.Message}");
            }

            return result;
        }

        private ApplicationInfo GetApplicationInfo(string filePath)
        {
            var info = new ApplicationInfo
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                Extension = Path.GetExtension(filePath).ToLower()
            };

            try
            {
                var fi = new FileInfo(filePath);
                info.Size = fi.Length;
                info.LastModified = fi.LastWriteTime;

                // 计算哈希
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                info.Hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();

                // 检查签名
                info.SignatureInfo = CheckSignature(filePath);
                info.IsSigned = info.SignatureInfo.IsSigned;
                info.Publisher = info.SignatureInfo.Publisher;
                info.IsTrusted = info.SignatureInfo.IsTrusted;

                // 获取版本信息
                var versionInfo = FileVersionInfo.GetVersionInfo(filePath);
                info.ProductName = versionInfo.ProductName ?? "";
                info.ProductVersion = versionInfo.ProductVersion ?? "";
                info.CompanyName = versionInfo.CompanyName ?? "";
                info.FileDescription = versionInfo.FileDescription ?? "";
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationControlAnalyzer.cs 捕获异常", ex.Message); }

            return info;
        }

        private SignatureCheckResult CheckSignature(string filePath)
        {
            var result = new SignatureCheckResult();

            try
            {
                byte[] peData = File.ReadAllBytes(filePath);
                
                if (peData.Length < 64 || peData[0] != 0x4D || peData[1] != 0x5A)
                    return result;

                int peOffset = BitConverter.ToInt32(peData, 60);
                if (peOffset + 4 > peData.Length || peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45)
                    return result;

                int securityDirOffset = peOffset + 24 + 128;
                if (securityDirOffset + 8 > peData.Length)
                    return result;

                uint rva = BitConverter.ToUInt32(peData, securityDirOffset);
                uint size = BitConverter.ToUInt32(peData, securityDirOffset + 4);

                if (rva == 0 || size == 0 || rva + size > peData.Length)
                    return result;

                result.IsSigned = true;

                byte[] sigData = new byte[size];
                Array.Copy(peData, rva, sigData, 0, size);

                if (sigData.Length > 8)
                {
                    byte[] pkcs7 = new byte[sigData.Length - 8];
                    Array.Copy(sigData, 8, pkcs7, 0, pkcs7.Length);

                    var cert = new X509Certificate2(pkcs7);
                    result.Publisher = cert.Subject;
                    result.IsValid = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter;
                    result.IsTrusted = IsTrustedPublisher(cert.Subject);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationControlAnalyzer.cs 捕获异常", ex.Message); }

            return result;
        }

        private bool IsTrustedPublisher(string publisher)
        {
            if (string.IsNullOrEmpty(publisher)) return false;
            
            foreach (var trusted in _trustedPublishers)
            {
                if (publisher.Contains(trusted, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private void CheckSuspiciousFeatures(ApplicationInfo info, ApplicationControlResult result)
        {
            // 检查可疑扩展名
            var suspiciousExtensions = new[] { ".scr", ".pif", ".com", ".bat", ".cmd", ".ps1" };
            if (suspiciousExtensions.Contains(info.Extension))
            {
                result.Restrictions.Add($"可疑扩展名: {info.Extension}");
                result.RiskLevel = "高";
            }

            // 检查临时目录
            if (info.FilePath.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                info.FilePath.Contains("\\tmp\\", StringComparison.OrdinalIgnoreCase))
            {
                result.Restrictions.Add("文件位于临时目录");
                result.RiskLevel = "中";
            }

            // 检查无签名
            if (!info.IsSigned && new[] { ".exe", ".dll" }.Contains(info.Extension))
            {
                result.Restrictions.Add("可执行文件无签名");
                result.RiskLevel = "中";
            }
        }

        public void AddToWhitelist(string path)
        {
            if (File.Exists(path))
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(path);
                var hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();
                _whitelistHashes.Add(hash);
            }
            _whitelistPaths.Add(path);
        }

        public void AddToBlacklist(string path)
        {
            if (File.Exists(path))
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(path);
                var hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();
                _blacklistHashes.Add(hash);
            }
            _blacklistPaths.Add(path);
        }

        public void AddTrustedPublisher(string publisher)
        {
            _trustedPublishers.Add(publisher);
        }

        public void BlockApplication(string filePath)
        {
            // 添加防火墙规则阻止应用
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall add rule name=\"Block {Path.GetFileNameWithoutExtension(filePath)}\" dir=out program=\"{filePath}\" action=block",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                process?.WaitForExit();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationControlAnalyzer.cs 捕获异常", ex.Message); }

            AddToBlacklist(filePath);
        }

        public List<ApplicationInfo> GetRunningApplications()
        {
            var apps = new List<ApplicationInfo>();

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    var path = process.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path) && File.Exists(path))
                    {
                        apps.Add(GetApplicationInfo(path));
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationControlAnalyzer.cs 捕获异常", ex.Message); }
            }

            return apps;
        }
    }

    public class ApplicationControlResult
    {
        public string FilePath { get; set; }
        public bool IsAllowed { get; set; }
        public string TrustLevel { get; set; }
        public string RiskLevel { get; set; }
        public List<string> Restrictions { get; set; }
        public List<string> Warnings { get; set; }
        public ApplicationInfo ApplicationInfo { get; set; }
    }

    public class ApplicationInfo
    {
        public string FilePath { get; set; }
        public string FileName { get; set; }
        public string Extension { get; set; }
        public long Size { get; set; }
        public DateTime LastModified { get; set; }
        public string Hash { get; set; }
        public bool IsSigned { get; set; }
        public bool IsTrusted { get; set; }
        public string Publisher { get; set; }
        public string ProductName { get; set; }
        public string ProductVersion { get; set; }
        public string CompanyName { get; set; }
        public string FileDescription { get; set; }
        public SignatureCheckResult SignatureInfo { get; set; }
    }

    public class SignatureCheckResult
    {
        public bool IsSigned { get; set; }
        public bool IsValid { get; set; }
        public bool IsTrusted { get; set; }
        public string Publisher { get; set; }
    }
}