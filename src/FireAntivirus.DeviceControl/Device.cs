using System;

namespace FireAntivirus.DeviceControl
{
    public enum DeviceType
    {
        USB,
        HardDrive,
        OpticalDrive,
        Printer,
        NetworkAdapter,
        Bluetooth,
        Other
    }

    public enum DeviceStatus
    {
        Connected,
        Disconnected,
        Blocked
    }

    public enum DeviceAccessType
    {
        Allow,
        Block,
        ReadOnly
    }

    public class Device
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public DeviceType Type { get; set; }
        public string Manufacturer { get; set; }
        public string Model { get; set; }
        public string SerialNumber { get; set; }
        public DeviceStatus Status { get; set; }
        public DateTime? ConnectedAt { get; set; }
        public DateTime? DisconnectedAt { get; set; }

        public Device() { }

        public Device(string name, DeviceType type, string manufacturer, string model, string serialNumber)
        {
            Id = Guid.NewGuid().ToString();
            Name = name;
            Type = type;
            Manufacturer = manufacturer;
            Model = model;
            SerialNumber = serialNumber;
            Status = DeviceStatus.Disconnected;
        }
    }

    public class DevicePolicy
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public DeviceType DeviceType { get; set; }
        public DeviceAccessType AccessType { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;

        public DevicePolicy() { }

        public DevicePolicy(string name, string description, DeviceType deviceType, DeviceAccessType accessType)
        {
            Id = Guid.NewGuid().ToString();
            Name = name;
            Description = description;
            DeviceType = deviceType;
            AccessType = accessType;
            Enabled = true;
        }
    }

    public class DevicePolicyResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public DevicePolicy Policy { get; set; }
        public DateTime OperationTime { get; set; } = DateTime.Now;

        public DevicePolicyResult() { }

        public DevicePolicyResult(bool success, string message, DevicePolicy policy = null)
        {
            Success = success;
            Message = message;
            Policy = policy;
        }
    }
}