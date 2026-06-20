using System;
using System.Collections.Generic;

namespace FireAntivirus.NetworkTrafficAnalyzer
{
    public enum AlertSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    public class NetworkConnection
    {
        public string Id { get; set; }
        public string ProcessName { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string Protocol { get; set; }
        public string State { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public DateTime StartTime { get; set; }

        public NetworkConnection() { }

        public NetworkConnection(string processName, string localAddress, int localPort, string remoteAddress, int remotePort, string protocol)
        {
            Id = Guid.NewGuid().ToString();
            ProcessName = processName;
            LocalAddress = localAddress;
            LocalPort = localPort;
            RemoteAddress = remoteAddress;
            RemotePort = remotePort;
            Protocol = protocol;
            StartTime = DateTime.Now;
        }
    }

    public class NetworkAlert
    {
        public string Id { get; set; }
        public string AlertType { get; set; }
        public AlertSeverity Severity { get; set; }
        public string Message { get; set; }
        public string Details { get; set; }
        public DateTime Timestamp { get; set; }

        public NetworkAlert() { }

        public NetworkAlert(string alertType, AlertSeverity severity, string message, string details)
        {
            Id = Guid.NewGuid().ToString();
            AlertType = alertType;
            Severity = severity;
            Message = message;
            Details = details;
            Timestamp = DateTime.Now;
        }
    }

    public class ProcessNetworkUsage
    {
        public string ProcessName { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public int ConnectionCount { get; set; }

        public ProcessNetworkUsage() { }

        public ProcessNetworkUsage(string processName, long bytesSent, long bytesReceived, int connectionCount)
        {
            ProcessName = processName;
            BytesSent = bytesSent;
            BytesReceived = bytesReceived;
            ConnectionCount = connectionCount;
        }
    }

    public class DestinationNetworkUsage
    {
        public string Address { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public int ConnectionCount { get; set; }

        public DestinationNetworkUsage() { }

        public DestinationNetworkUsage(string address, long bytesSent, long bytesReceived, int connectionCount)
        {
            Address = address;
            BytesSent = bytesSent;
            BytesReceived = bytesReceived;
            ConnectionCount = connectionCount;
        }
    }

    public class NetworkTrafficReport
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public long TotalBytesSent { get; set; }
        public long TotalBytesReceived { get; set; }
        public int TotalConnections { get; set; }
        public List<ProcessNetworkUsage> TopProcesses { get; set; } = new List<ProcessNetworkUsage>();
        public List<DestinationNetworkUsage> TopDestinations { get; set; } = new List<DestinationNetworkUsage>();
        public List<NetworkAlert> Alerts { get; set; } = new List<NetworkAlert>();

        public NetworkTrafficReport() { }

        public NetworkTrafficReport(DateTime startTime, DateTime endTime)
        {
            StartTime = startTime;
            EndTime = endTime;
        }
    }
}