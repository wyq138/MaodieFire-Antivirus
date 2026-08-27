using System;
using System.Collections.Generic;

namespace FireAntivirus.CloudScanner
{
    /// <summary>
    /// 云扫描结果 - 支持多引擎聚合
    /// </summary>
    public class CloudScanResult
    {
        public string FilePath { get; set; }
        public string FileName { get; set; }
        public string Url { get; set; }
        public string FileHash { get; set; }
        public bool Success { get; set; }
        public bool IsInfected { get; set; }
        public string ThreatName { get; set; }
        public double Confidence { get; set; }
        public string Message { get; set; }
        public DateTime ScanTime { get; set; }
        public string DetectionMethod { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }

        /// <summary>各引擎检测结果(引擎名->是否检测到威胁)</summary>
        public Dictionary<string, EngineDetection> EngineResults { get; set; } = new Dictionary<string, EngineDetection>();

        /// <summary>查询到的引擎总数</summary>
        public int TotalEngines { get; set; }

        /// <summary>检测到威胁的引擎数</summary>
        public int PositiveEngines { get; set; }

        public CloudScanResult() { }

        public CloudScanResult(string filePath, bool success, bool isInfected, string threatName, double confidence, string message)
        {
            FilePath = filePath;
            Success = success;
            IsInfected = isInfected;
            ThreatName = threatName;
            Confidence = confidence;
            Message = message;
            ScanTime = DateTime.Now;
        }
    }

    /// <summary>
    /// 单个引擎的检测结果
    /// </summary>
    public class EngineDetection
    {
        /// <summary>引擎名称 (如 Kaspersky, BitDefender, ESET-NOD32)</summary>
        public string EngineName { get; set; }

        /// <summary>是否检测到威胁</summary>
        public bool Detected { get; set; }

        /// <summary>该引擎报出的威胁名</summary>
        public string ThreatName { get; set; }

        /// <summary>引擎版本</summary>
        public string EngineVersion { get; set; }

        /// <summary>该引擎的检测方法 (cloud/hash/sandbox)</summary>
        public string Method { get; set; }

        public override string ToString()
        {
            return Detected
                ? $"{EngineName}: {ThreatName ?? "Malicious"}"
                : $"{EngineName}: Clean";
        }
    }
}
