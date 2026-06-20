using System;

namespace FireAntivirus.NetworkFirewall
{
    public enum FirewallAction
    {
        Allow,
        Block
    }

    public enum FirewallProtocol
    {
        TCP,
        UDP,
        ICMP,
        All
    }

    public enum FirewallDirection
    {
        Inbound,
        Outbound,
        Both
    }

    public class FirewallRule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public FirewallAction Action { get; set; }
        public FirewallProtocol Protocol { get; set; }
        public string LocalPort { get; set; }
        public string RemotePort { get; set; }
        public string LocalAddress { get; set; } = "0.0.0.0";
        public string RemoteAddress { get; set; } = "0.0.0.0";
        public FirewallDirection Direction { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;

        public FirewallRule() { }

        public FirewallRule(string name, string description, FirewallAction action, FirewallProtocol protocol, string localPort, string remotePort, FirewallDirection direction)
        {
            Id = Guid.NewGuid().ToString();
            Name = name;
            Description = description;
            Action = action;
            Protocol = protocol;
            LocalPort = localPort;
            RemotePort = remotePort;
            Direction = direction;
            Enabled = true;
        }
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
        public DateTime CreatedAt { get; set; }

        public NetworkConnection() { }
    }

    public class FirewallRuleResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public FirewallRule Rule { get; set; }
        public DateTime OperationTime { get; set; } = DateTime.Now;

        public FirewallRuleResult() { }

        public FirewallRuleResult(bool success, string message, FirewallRule rule = null)
        {
            Success = success;
            Message = message;
            Rule = rule;
        }
    }
}