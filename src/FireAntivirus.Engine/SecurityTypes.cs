using System;
using System.Collections.Generic;

namespace FireAntivirus.Engine
{
    /// <summary>
    /// 威胁级别枚举
    /// </summary>
    public enum ThreatLevel
    {
        /// <summary>
        /// 安全 - 没有检测到威胁
        /// </summary>
        Safe = 0,
        
        /// <summary>
        /// 低风险 - 可疑但可能安全
        /// </summary>
        Low = 1,
        
        /// <summary>
        /// 中风险 - 潜在的威胁
        /// </summary>
        Medium = 2,
        
        /// <summary>
        /// 高风险 - 确认的威胁
        /// </summary>
        High = 3,
        
        /// <summary>
        /// 严重风险 - 立即的威胁
        /// </summary>
        Critical = 4
    }

    /// <summary>
    /// 威胁情报数据类型
    /// </summary>
    public class ThreatIntelligenceData
    {
        public string Hash { get; set; }
        public string FilePath { get; set; }
        public ThreatLevel Level { get; set; }
        public string ThreatType { get; set; }
        public DateTime LastUpdated { get; set; }
        public string Source { get; set; }
    }

    /// <summary>
    /// 检测结果
    /// </summary>
    public class DetectionResult
    {
        public bool IsThreat { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public string ThreatName { get; set; }
        public string Description { get; set; }
        public string ScannerName { get; set; }
        public DateTime DetectionTime { get; set; }
        
        // 新增属性
        public bool IsDetected { get; set; }
        public string ThreatType { get; set; }
        public double Confidence { get; set; }
        public string Details { get; set; }
        public string AdditionalInfo { get; set; }
        public string Severity { get; set; }
        public string DetectionMethod { get; set; }
        public bool IsInfected { get; set; }
        public string FilePath { get; set; }
        public int DetectionId { get; set; }
        public string RecommendedAction { get; set; }
        public bool IsFalsePositive { get; set; }
        public bool IsQuarantined { get; set; }
    }

    /// <summary>
    /// 扫描配置
    /// </summary>
    public class ScanConfiguration
    {
        public bool EnableHeuristicScan { get; set; } = true;
        public bool EnableSignatureScan { get; set; } = true;
        public bool EnableBehaviorScan { get; set; } = true;
        public int MaxScanThreads { get; set; } = 4;
        public TimeSpan ScanTimeout { get; set; } = TimeSpan.FromMinutes(5);
        public List<string> ExcludedPaths { get; set; } = new();
    }
}