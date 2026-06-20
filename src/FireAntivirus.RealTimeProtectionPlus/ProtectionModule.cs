using System;

namespace FireAntivirus.RealTimeProtectionPlus
{
    public enum ProtectionType
    {
        Process,
        File,
        Registry,
        Network,
        Behavior
    }

    public enum ProtectionAction
    {
        Allow,
        Block,
        Quarantine,
        Alert
    }

    public class ProtectionModule
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public ProtectionType Type { get; set; }
        public bool Enabled { get; set; }
        public DateTime LastUpdated { get; set; } = DateTime.Now;

        public ProtectionModule() { }

        public ProtectionModule(string name, string description, ProtectionType type, bool enabled)
        {
            Name = name;
            Description = description;
            Type = type;
            Enabled = enabled;
        }
    }

    public class ProtectionEvent
    {
        public string EventId { get; set; }
        public ProtectionType ProtectionType { get; set; }
        public string EventType { get; set; }
        public string Details { get; set; }
        public string ProcessName { get; set; }
        public string FilePath { get; set; }
        public string RegistryPath { get; set; }
        public string NetworkAddress { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;

        public ProtectionEvent() { }

        public ProtectionEvent(ProtectionType protectionType, string eventType, string details)
        {
            EventId = Guid.NewGuid().ToString();
            ProtectionType = protectionType;
            EventType = eventType;
            Details = details;
        }
    }

    public class ProtectionEventResult
    {
        public string EventId { get; set; }
        public ProtectionAction Action { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }

        public ProtectionEventResult() { }

        public ProtectionEventResult(string eventId, ProtectionAction action, string message)
        {
            EventId = eventId;
            Action = action;
            Message = message;
            Timestamp = DateTime.Now;
        }
    }
}