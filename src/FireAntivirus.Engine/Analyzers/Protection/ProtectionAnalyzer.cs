// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FireAntivirus.Engine.Analyzers.Protection
{
    /// <summary>
    /// 高级防护分析器 - 核心防护逻辑
    /// </summary>
    public class ProtectionAnalyzer
    {
        private readonly List<string> _protectedPaths;
        private readonly Dictionary<string, FileProtectionInfo> _protectionCache;
        private readonly object _lock = new object();

        public ProtectionAnalyzer()
        {
            _protectedPaths = new List<string>();
            _protectionCache = new Dictionary<string, FileProtectionInfo>();
            InitializeProtectedPaths();
        }

        private void InitializeProtectedPaths()
        {
            _protectedPaths.AddRange(new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
            });
        }

        public ProtectionResult Analyze(string filePath)
        {
            var result = new ProtectionResult
            {
                FilePath = filePath,
                IsProtected = false,
                ProtectionLevel = ProtectionLevel.None,
                Warnings = new List<string>()
            };

            try
            {
                if (!File.Exists(filePath)) return result;

                // 检查文件是否在受保护路径
                foreach (var protectedPath in _protectedPaths)
                {
                    if (filePath.StartsWith(protectedPath, StringComparison.OrdinalIgnoreCase))
                    {
                        result.IsProtected = true;
                        result.ProtectionLevel = ProtectionLevel.System;
                        result.Warnings.Add("文件位于系统保护目录");
                        break;
                    }
                }

                // 检查文件签名
                var signatureInfo = CheckFileSignature(filePath);
                if (signatureInfo.IsSigned)
                {
                    result.HasValidSignature = signatureInfo.IsValid;
                    result.Publisher = signatureInfo.Publisher;
                    
                    if (signatureInfo.IsValid && signatureInfo.IsTrusted)
                    {
                        result.ProtectionLevel = ProtectionLevel.Trusted;
                    }
                }

                // 检查文件权限
                var permissionInfo = CheckFilePermissions(filePath);
                result.PermissionWarnings = permissionInfo.Warnings;

                // 检查文件完整性
                var integrityInfo = CheckFileIntegrity(filePath);
                result.IntegrityScore = integrityInfo.Score;
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"分析错误: {ex.Message}");
            }

            return result;
        }

        private SignatureInfo CheckFileSignature(string filePath)
        {
            var info = new SignatureInfo();
            
            try
            {
                byte[] peData = File.ReadAllBytes(filePath);
                
                // 检查DOS头
                if (peData.Length < 64 || peData[0] != 0x4D || peData[1] != 0x5A)
                    return info;

                int peOffset = BitConverter.ToInt32(peData, 60);
                if (peOffset + 4 > peData.Length) return info;
                
                // 检查PE签名
                if (peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45)
                    return info;

                // 获取签名目录
                int securityDirOffset = peOffset + 24 + 128;
                if (securityDirOffset + 8 > peData.Length) return info;

                uint rva = BitConverter.ToUInt32(peData, securityDirOffset);
                uint size = BitConverter.ToUInt32(peData, securityDirOffset + 4);

                if (rva == 0 || size == 0) return info;
                if (rva + size > peData.Length) return info;

                info.IsSigned = true;

                // 解析签名
                byte[] sigData = new byte[size];
                Array.Copy(peData, rva, sigData, 0, size);

                if (sigData.Length > 8)
                {
                    byte[] pkcs7 = new byte[sigData.Length - 8];
                    Array.Copy(sigData, 8, pkcs7, 0, pkcs7.Length);

                    var cert = new X509Certificate2(pkcs7);
                    info.Publisher = cert.Subject;
                    info.IsValid = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter;
                    info.IsTrusted = IsTrustedPublisher(cert.Subject);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionAnalyzer.cs 捕获异常", ex.Message); }

            return info;
        }

        private bool IsTrustedPublisher(string subject)
        {
            string[] trusted = {
                "Microsoft Corporation", "Microsoft Windows", "Google LLC", "Apple Inc.",
                "Intel Corporation", "NVIDIA Corporation", "Adobe Inc.", "Oracle Corporation"
            };
            return trusted.Any(t => subject.Contains(t, StringComparison.OrdinalIgnoreCase));
        }

        private PermissionInfo CheckFilePermissions(string filePath)
        {
            var info = new PermissionInfo { Warnings = new List<string>() };
            
            try
            {
                var fi = new FileInfo(filePath);
                
                // 检查是否可写
                if (!fi.IsReadOnly)
                {
                    info.Warnings.Add("文件可被修改");
                }
                
                // 检查是否可执行
                if (fi.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                    fi.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    info.IsExecutable = true;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionAnalyzer.cs 捕获异常", ex.Message); }

            return info;
        }

        private IntegrityInfo CheckFileIntegrity(string filePath)
        {
            var info = new IntegrityInfo { Score = 100 };
            
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                info.Hash = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "");
            }
            catch
            {
                info.Score = 0;
            }

            return info;
        }

        public void AddProtectedPath(string path)
        {
            lock (_lock)
            {
                if (!_protectedPaths.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    _protectedPaths.Add(path);
                }
            }
        }

        public void RemoveProtectedPath(string path)
        {
            lock (_lock)
            {
                _protectedPaths.RemoveAll(p => p.Equals(path, StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    public class ProtectionResult
    {
        public string FilePath { get; set; }
        public bool IsProtected { get; set; }
        public ProtectionLevel ProtectionLevel { get; set; }
        public bool HasValidSignature { get; set; }
        public string Publisher { get; set; }
        public List<string> Warnings { get; set; }
        public List<string> PermissionWarnings { get; set; }
        public int IntegrityScore { get; set; }
    }

    public enum ProtectionLevel { None, Basic, System, Trusted, Critical }

    public class SignatureInfo
    {
        public bool IsSigned { get; set; }
        public bool IsValid { get; set; }
        public bool IsTrusted { get; set; }
        public string Publisher { get; set; }
    }

    public class PermissionInfo
    {
        public List<string> Warnings { get; set; }
        public bool IsExecutable { get; set; }
    }

    public class IntegrityInfo
    {
        public int Score { get; set; }
        public string Hash { get; set; }
    }

    public class FileProtectionInfo
    {
        public string FilePath { get; set; }
        public string Hash { get; set; }
        public DateTime LastChecked { get; set; }
        public ProtectionLevel Level { get; set; }
    }
}