// 共享枚举和类型定义

using System;
using System.Collections.Generic;

namespace FireAntivirus.Services
{
    // 枚举定义
    public enum ThreatSeverity { Low = 1, Medium = 2, High = 3, Critical = 4 }
    
    public enum ThreatType
    {
        Unknown, Malware, Ransomware, Phishing, Trojan, Virus, Spyware, Adware,
        Rootkit, Backdoor, Exploit, SuspiciousActivity, KnownMalicious,
        BotnetCommunication, DataExfiltration, PortScan, CCCommunication,
        Warning, Quarantine, Error, Info,
        FileIntegrityViolation, PartitionTableModification, MBRModification,
        GPTModification, BootSectorModification, PopupAdvertisement
    }
    
    public enum RiskLevel { Safe = 0, Low = 1, Medium = 2, High = 3, Critical = 4, Unknown = 5 }
    
    public enum RecommendationPriority { Low, Medium, High, Critical }
    
    public enum StartupImpact { None, Low, Medium, High, Unknown }
    
    public enum ConnectionDirection { Inbound, Outbound, Unknown }

    // 签名信息
    public class SignatureInfo
    {
        public string FilePath { get; set; }
        public bool IsSigned { get; set; }
        public bool IsValid { get; set; }
        public bool IsTrusted { get; set; }
        public string Publisher { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public DateTime? SignTime { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string CertificateSubject { get; set; }
        public List<string> ChainErrors { get; set; } = new List<string>();
        public bool IsTrustedSigner { get; set; }
        public string Signer { get; set; }
        public DateTime? SigningTime { get; set; }
    }

    // 启动影响信息
    public class StartupImpactInfo
    {
        public string Name { get; set; }
        public StartupImpact Impact { get; set; }
        public int ImpactScore { get; set; }
        public int BootDelayMs { get; set; }
        public long MemoryImpactMB { get; set; }
        public bool HasNetworkDependency { get; set; }
    }

    // 优化建议
    public class OptimizationRecommendation
    {
        public RecommendationPriority Priority { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public List<object> AffectedItems { get; set; } = new List<object>();
        public string PotentialImprovement { get; set; }
        public string PotentialGain { get; set; }
        public long PotentialSavings { get; set; }
        public string Category { get; set; }
    }

    // 入侵尝试
    public class IntrusionAttempt
    {
        public string IntrusionId { get; set; }
        public string SourceIP { get; set; }
        public int SourcePort { get; set; }
        public string TargetProcess { get; set; }
        public string TargetPath { get; set; }
        public List<string> Indicators { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DateTime DetectedAt { get; set; }
    }

    // 威胁检测事件参数
    public class ThreatDetectedEventArgs : EventArgs
    {
        public string Url { get; set; }
        public string FilePath { get; set; }
        public ThreatSeverity Severity { get; set; }
        public ThreatType Type { get; set; }
        public DateTime DetectedTime { get; set; }
        public string Description { get; set; }
        public List<string> Threats { get; set; } = new List<string>();
        public RiskLevel RiskLevel { get; set; }
        public object Detection { get; set; }
    }

    // 系统信息
    public class SystemInfo
    {
        public string ComputerName { get; set; }
        public string UserName { get; set; }
        public string Domain { get; set; }
        public string OSVersion { get; set; }
        public string OSName { get; set; }
        public string OSBuild { get; set; }
        public string OSArchitecture { get; set; }
        public string Processor { get; set; }
        public string CPUName { get; set; }
        public int ProcessorCores { get; set; }
        public int ProcessorLogicalProcessors { get; set; }
        public long TotalMemory { get; set; }
        public long TotalMemoryBytes { get; set; }
        public ulong TotalPhysicalMemory { get; set; }
        public long AvailableMemory { get; set; }
        public long AvailableMemoryBytes { get; set; }
        public TimeSpan Uptime { get; set; }
        public uint CPULogicalProcessors { get; set; }
        public List<DiskInfo> Disks { get; set; } = new List<DiskInfo>();
        public List<System.IO.DriveInfo> Drives { get; set; }
        public string SystemDirectory { get; set; }
        public DateTime? InstallDate { get; set; }
        public DateTime? LastBootTime { get; set; }
        public List<string> IPAddresses { get; set; } = new List<string>();
        public string MACAddress { get; set; }
        public string Error { get; set; }
    }

    // 磁盘信息
    public class DiskInfo
    {
        public string Name { get; set; }
        public string Drive { get; set; }
        public string Label { get; set; }
        public string Format { get; set; }
        public string FileSystem { get; set; }
        public string DriveType { get; set; }
        public long TotalSize { get; set; }
        public long FreeSpace { get; set; }
        public long UsedSpace { get; set; }
        public int UsagePercent { get; set; }
        public int UsagePercentage { get; set; }
        public bool IsSSD { get; set; }
        public string SmartStatus { get; set; }
    }

    // 网络统计信息
    public class NetworkStatistics
    {
        public long BytesReceived { get; set; }
        public long BytesSent { get; set; }
        public long PacketsReceived { get; set; }
        public long PacketsSent { get; set; }
        public int TCPActiveConnections { get; set; }
        public int TCPFailedConnections { get; set; }
        public int TCPRetransmissions { get; set; }
        public int ActiveConnections { get; set; }
        public string InterfaceName { get; set; }
        public string InterfaceType { get; set; }
        public string OperationalStatus { get; set; }
        public long IncomingErrors { get; set; }
        public long OutgoingErrors { get; set; }
        public DateTime Timestamp { get; set; }
        public List<NetworkAdapterStats> Adapters { get; set; } = new List<NetworkAdapterStats>();
    }

    public class NetworkAdapterStats
    {
        public string Name { get; set; }
        public string MACAddress { get; set; }
        public long Speed { get; set; }
    }

    // 云信誉结果
    public class CloudReputationResult
    {
        public string Resource { get; set; }
        public DateTime QueryTime { get; set; }
        public bool IsQueried { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public double Confidence { get; set; }
        public string Error { get; set; }
        public bool IsMalicious { get; set; }
        public string ThreatType { get; set; }
        public List<string> Sources { get; set; } = new List<string>();
        public int Reputation { get; set; }
    }

    // 域名信息
    public class DomainInfo
    {
        public string Domain { get; set; }
        public int EstimatedAge { get; set; }
        public string Category { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public DateTime LastChecked { get; set; }
        public string[] Tags { get; set; }
    }

    // 威胁指示器
    public class ThreatIndicator
    {
        public string Url { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DateTime DetectedAt { get; set; }
        public string ThreatType { get; set; }
        public string[] Indicators { get; set; }
    }

    // 网络连接信息
    public class NetworkConnectionInfo
    {
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public string RemoteIP { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public string IdentifiedProtocol { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public int ThreatScore { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public long BytesTransferred { get; set; }
        public DateTime Timestamp { get; set; }
        public DateTime LastSeen { get; set; }
        public ThreatType ThreatType { get; set; }
        public string ThreatDescription { get; set; }
        public bool IsSuspicious { get; set; }
        public ConnectionDirection Direction { get; set; }
    }

    // 漏洞信息
    public class VulnerabilityInfo
    {
        public string Id { get; set; }
        public string Category { get; set; }
        public string Name { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public string Location { get; set; }
        public bool CanAutoFix { get; set; }
        public string FixAction { get; set; }
        public string CveId { get; set; }
        public string CVEId { get; set; }
        public double CVSSScore { get; set; }
        public string[] AffectedProducts { get; set; }
        public string Remediation { get; set; }
        public string[] Remediations { get; set; }
        public DateTime Published { get; set; }
        public List<string> References { get; set; } = new List<string>();
        public DateTime DetectedAt { get; set; }
        public bool IsFixed { get; set; }
    }

    // 安全建议
    public class SecurityRecommendation
    {
        public int Priority { get; set; }
        public string Category { get; set; }
        public string Item { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public RecommendationPriority PriorityLevel { get; set; }
        public string Action { get; set; }
        public int CurrentScore { get; set; }
        public int MaxScore { get; set; }
        public string Status { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public string PotentialGain { get; set; }
        public long PotentialSavings { get; set; }
    }

    // 网络告警
    public class NetworkAlert
    {
        public string AlertId { get; set; }
        public string AlertType { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public DateTime Timestamp { get; set; }
        public string Status { get; set; }
        public string Source { get; set; }
    }

    // 网络报告
    public class NetworkReport
    {
        public string ReportId { get; set; }
        public DateTime Timestamp { get; set; }
        public int ConnectionCount { get; set; }
        public int InterfaceCount { get; set; }
        public int AlertCount { get; set; }
        public List<NetworkConnection> Connections { get; set; }
        public List<NetworkStatistics> Statistics { get; set; }
        public List<NetworkAlert> Alerts { get; set; }
    }
}

