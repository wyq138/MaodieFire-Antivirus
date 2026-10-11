using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FireAntivirus.Data;
using FireAntivirus.Engine.Strings;

namespace FireAntivirus.Engine
{
    /// <summary>
    /// PE文件分析器 - 使用.NET库
    /// </summary>
    public class PEAnalyzer
    {
        public PEResult Analyze(string filePath)
        {
            var result = new PEResult
            {
                FilePath = filePath,
                IsPE = false,
                IsSigned = false,
                IsValidSignature = false,
                Publisher = "",
                Sections = new List<SectionInfo>()
            };

            if (!File.Exists(filePath))
                return result;

            try
            {
                byte[] peData = File.ReadAllBytes(filePath);
                
                // 检查DOS头
                if (peData.Length < 64) return result;
                if (peData[0] != 0x4D || peData[1] != 0x5A) return result; // MZ

                int peOffset = BitConverter.ToInt32(peData, 60);
                if (peOffset + 4 > peData.Length) return result;
                
                // 检查PE签名
                if (peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45) return result; // PE
                result.IsPE = true;

                // 提取签名
                var signatureData = ExtractSignature(peData, peOffset);
                if (signatureData != null && signatureData.Length > 0)
                {
                    result.IsSigned = true;
                    try
                    {
                        var cert = new X509Certificate2(signatureData);
                        result.Publisher = cert.Subject;
                        result.IsValidSignature = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter;
                        result.Certificate = cert;
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "Analyzers.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "Analyzers.cs 捕获异常", ex.Message); }

            return result;
        }

        private byte[] ExtractSignature(byte[] peData, int peOffset)
        {
            try
            {
                int optionalHeaderOffset = peOffset + 24;
                int securityDirOffset = optionalHeaderOffset + 128;

                if (securityDirOffset + 8 > peData.Length) return null;

                uint rva = BitConverter.ToUInt32(peData, securityDirOffset);
                uint size = BitConverter.ToUInt32(peData, securityDirOffset + 4);

                if (rva == 0 || size == 0) return null;
                if (rva + size > peData.Length) return null;

                byte[] sigData = new byte[size];
                Array.Copy(peData, rva, sigData, 0, size);

                // 跳过WIN_CERTIFICATE头
                if (sigData.Length <= 8) return null;
                ushort certType = BitConverter.ToUInt16(sigData, 2);
                if (certType != 0x0002) return null;

                byte[] pkcs7 = new byte[sigData.Length - 8];
                Array.Copy(sigData, 8, pkcs7, 0, pkcs7.Length);
                return pkcs7;
            }
            catch { return null; }
        }
    }

    public class PEResult
    {
        public string FilePath { get; set; }
        public bool IsPE { get; set; }
        public bool IsSigned { get; set; }
        public bool IsValidSignature { get; set; }
        public string Publisher { get; set; }
        public X509Certificate2 Certificate { get; set; }
        public List<SectionInfo> Sections { get; set; }
    }

    public class SectionInfo
    {
        public string Name { get; set; }
        public uint VirtualSize { get; set; }
        public uint RawSize { get; set; }
    }

    /// <summary>
    /// 简化版启发式引擎 - 减少误报
    /// </summary>
    public class HeuristicEngine
    {
        // 可信发布者列表
        private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Microsoft Windows", "Microsoft",
            "Google LLC", "Google Inc",
            "Apple Inc.", "Apple Computer, Inc.",
            "Mozilla Corporation",
            "Adobe Inc.", "Adobe Systems Incorporated",
            "Intel Corporation", "NVIDIA Corporation", "AMD", "Advanced Micro Devices",
            "Oracle Corporation", "VMware, Inc.",
            "Cisco Systems, Inc.", "Dell Inc.", "HP Inc.", "Hewlett-Packard", "Lenovo",
            "ASUSTeK Computer Inc.",
            "AVG Technologies", "Avast Software", "Kaspersky Lab",
            "Symantec Corporation", "McAfee, Inc.", "Trend Micro, Inc.",
            "Bitdefender", "ESET, spol. s r.o.",
            "360 Security Technology Inc.", "Tencent", "Huawei", "Baidu, Inc."
        };

        public ScanResult Scan(string filePath)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = false,
                Confidence = 0.0,
                DetectionTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath)) return result;

                // 检查PE签名 - 有有效签名的文件降低可疑度
                var peAnalyzer = new PEAnalyzer();
                var peResult = peAnalyzer.Analyze(filePath);
                
                if (peResult.IsSigned && peResult.IsValidSignature)
                {
                    // 检查是否为可信发布者
                    if (IsTrustedPublisher(peResult.Publisher))
                    {
                        result.Confidence = 0;
                        result.AdditionalInfo = $"已签名: {peResult.Publisher}";
                        return result;
                    }
                    result.Confidence -= 0.3; // 有签名但不在信任列表，降低可疑度
                }

                // 只对可执行文件进行深入分析
                string ext = Path.GetExtension(filePath).ToLower();
                if (ext != ".exe" && ext != ".dll" && ext != ".sys")
                {
                    return result;
                }

                // 高熵值检测（加壳/加密）
                byte[] fileBytes = File.ReadAllBytes(filePath);
                double entropy = CalculateEntropy(fileBytes);
                if (entropy > 7.5)
                {
                    result.Confidence += 0.3;
                    result.AdditionalInfo = "High entropy (possibly packed)";
                }

                // Threshold increased to 0.9 to reduce false positives
                if (result.Confidence > 0.9)
                {
                    result.IsInfected = true;
                    result.ThreatName = LocalizedStrings.SuspiciousFile;
                    result.ThreatType = "Suspicious";
                    result.Severity = "Low";
                    result.DetectionMethod = "Heuristic";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "Analyzers.cs exception", ex.Message); }

            return result;
        }

        private bool IsTrustedPublisher(string publisher)
        {
            if (string.IsNullOrEmpty(publisher)) return false;
            foreach (var trusted in TrustedPublishers)
            {
                if (publisher.Contains(trusted, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;

            var counts = new int[256];
            foreach (byte b in data) counts[b]++;

            double entropy = 0;
            int len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / len;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }
    }
}