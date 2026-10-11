// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;

namespace FireAntivirus.Sandbox
{
    /// <summary>
    /// 沙箱会话状态枚举。
    /// </summary>
    public enum SandboxStatus
    {
        Ready,
        Initializing,
        Running,
        Analyzing,
        Completed,
        Failed,
        Timeout
    }

    /// <summary>
    /// 风险评估等级。
    /// </summary>
    public enum RiskLevel
    {
        Clean,
        Low,
        Medium,
        High,
        Critical
    }

    /// <summary>
    /// 文件系统行为记录：记录沙箱执行期间发生的文件创建/修改/删除/重命名事件。
    /// </summary>
    public class FileChangeRecord
    {
        public string FilePath { get; set; }
        public string ChangeType { get; set; }
        public DateTime Timestamp { get; set; }
        public long FileSize { get; set; }
        public string FileExtension { get; set; }
        public bool IsSystemDirectory { get; set; }
        public bool IsRansomwareIndicator { get; set; }
    }

    /// <summary>
    /// 注册表行为记录：记录沙箱执行期间监控到的注册表项变更。
    /// </summary>
    public class RegistryChangeRecord
    {
        public string Hive { get; set; }
        public string KeyPath { get; set; }
        public string ChangeType { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsAutorunLocation { get; set; }
    }

    /// <summary>
    /// 网络行为记录：记录沙箱执行期间进程发起的对外 TCP 连接。
    /// </summary>
    public class NetworkConnectionRecord
    {
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsSuspicious { get; set; }
        public string SuspicionReason { get; set; }
    }

    /// <summary>
    /// 进程树节点：记录沙箱主进程及其衍生的子进程。
    /// </summary>
    public class ProcessNode
    {
        public int ProcessId { get; set; }
        public int ParentProcessId { get; set; }
        public string ProcessName { get; set; }
        public string CommandLine { get; set; }
        public string ExecutablePath { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public int ExitCode { get; set; }
        public bool IsInjectionIndicator { get; set; }
        public List<ProcessNode> Children { get; set; } = new List<ProcessNode>();
    }

    /// <summary>
    /// 行为分析综合报告，在沙箱执行完成后生成。
    /// </summary>
    public class BehaviorReport
    {
        public string SessionId { get; set; }
        public string AnalyzedFile { get; set; }
        public string FileHash { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public long ExecutionDurationMs { get; set; }
        public int ExitCode { get; set; }
        public List<FileChangeRecord> FileChanges { get; set; } = new List<FileChangeRecord>();
        public List<RegistryChangeRecord> RegistryChanges { get; set; } = new List<RegistryChangeRecord>();
        public List<NetworkConnectionRecord> NetworkConnections { get; set; } = new List<NetworkConnectionRecord>();
        public List<ProcessNode> ChildProcesses { get; set; } = new List<ProcessNode>();
        public int RiskScore { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public List<string> RiskFactors { get; set; } = new List<string>();
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
        public string Summary { get; set; }
    }

    /// <summary>
    /// 沙箱会话：承载一次分析的全部状态与行为数据。
    /// </summary>
    public class SandboxSession
    {
        public string SessionId { get; set; }
        public string SessionPath { get; set; }
        public DateTime CreatedTime { get; set; }
        public DateTime? StartTime { get; set; }
        public DateTime? CompletedTime { get; set; }
        public SandboxStatus Status { get; set; }
        public int ExitCode { get; set; }
        public string ErrorMessage { get; set; }

        // 被分析目标信息
        public string AnalyzedFilePath { get; set; }
        public string FileHash { get; set; }
        public string CommandLine { get; set; }
        public int MainProcessId { get; set; }
        public long ExecutionDurationMs { get; set; }

        // 行为数据（执行期间实时填充）
        public List<FileChangeRecord> FileChanges { get; } = new List<FileChangeRecord>();
        public List<RegistryChangeRecord> RegistryChanges { get; } = new List<RegistryChangeRecord>();
        public List<NetworkConnectionRecord> NetworkConnections { get; } = new List<NetworkConnectionRecord>();
        public List<ProcessNode> ChildProcesses { get; } = new List<ProcessNode>();

        // 标准输出/错误（API 调用追踪）
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }

        // 风险评估结果
        public int RiskScore { get; set; }
        public RiskLevel RiskLevel { get; set; }
        public List<string> RiskFactors { get; set; } = new List<string>();

        // 最终报告
        public string AnalysisReport { get; set; }
        public string ReportPath { get; set; }

        public SandboxSession() { }

        public SandboxSession(string sessionId, string sessionPath)
        {
            SessionId = sessionId;
            SessionPath = sessionPath;
            CreatedTime = DateTime.Now;
            Status = SandboxStatus.Ready;
        }
    }
}
