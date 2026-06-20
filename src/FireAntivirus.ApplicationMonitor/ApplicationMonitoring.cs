using System;
using System.Collections.Generic;

namespace FireAntivirus.ApplicationMonitor
{
    public enum AlertSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    public class MonitoredApplication
    {
        public string Id { get; set; }
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string MainWindowTitle { get; set; }
        public DateTime StartTime { get; set; }
        public float CpuUsage { get; set; }
        public long MemoryUsage { get; set; }
        public string Status { get; set; }

        public MonitoredApplication() { }

        public MonitoredApplication(string processName, int processId, string mainWindowTitle)
        {
            Id = Guid.NewGuid().ToString();
            ProcessName = processName;
            ProcessId = processId;
            MainWindowTitle = mainWindowTitle;
            StartTime = DateTime.Now;
            Status = "Running";
        }
    }

    public class ApplicationAlert
    {
        public string Id { get; set; }
        public string AlertType { get; set; }
        public AlertSeverity Severity { get; set; }
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string Message { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }

        public ApplicationAlert() { }

        public ApplicationAlert(string alertType, AlertSeverity severity, string processName, int processId, string message)
        {
            Id = Guid.NewGuid().ToString();
            AlertType = alertType;
            Severity = severity;
            ProcessName = processName;
            ProcessId = processId;
            Message = message;
            Timestamp = DateTime.Now;
        }
    }

    public class ProcessResourceUsage
    {
        public string ProcessName { get; set; }
        public float CpuUsage { get; set; }
        public long MemoryUsage { get; set; }

        public ProcessResourceUsage() { }

        public ProcessResourceUsage(string processName, float cpuUsage, long memoryUsage)
        {
            ProcessName = processName;
            CpuUsage = cpuUsage;
            MemoryUsage = memoryUsage;
        }
    }

    public class ApplicationActivityReport
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public int TotalProcesses { get; set; }
        public int ActiveProcesses { get; set; }
        public List<ApplicationAlert> Alerts { get; set; } = new List<ApplicationAlert>();
        public List<ProcessResourceUsage> TopCpuProcesses { get; set; } = new List<ProcessResourceUsage>();
        public List<ProcessResourceUsage> TopMemoryProcesses { get; set; } = new List<ProcessResourceUsage>();

        public ApplicationActivityReport() { }

        public ApplicationActivityReport(DateTime startTime, DateTime endTime)
        {
            StartTime = startTime;
            EndTime = endTime;
        }
    }
}