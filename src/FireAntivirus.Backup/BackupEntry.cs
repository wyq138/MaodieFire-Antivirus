using System;

namespace FireAntivirus.Backup
{
    public enum BackupType
    {
        Full,
        Incremental,
        Differential,
        Custom
    }

    public class BackupEntry
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Path { get; set; }
        public long Size { get; set; }
        public DateTime CreatedAt { get; set; }
        public BackupType Type { get; set; }

        public BackupEntry() { }

        public BackupEntry(string name, string description, string path, long size, BackupType type)
        {
            Id = Guid.NewGuid().ToString();
            Name = name;
            Description = description;
            Path = path;
            Size = size;
            CreatedAt = DateTime.Now;
            Type = type;
        }
    }

    public class BackupResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public BackupEntry BackupEntry { get; set; }
        public DateTime OperationTime { get; set; } = DateTime.Now;

        public BackupResult() { }

        public BackupResult(bool success, string message, BackupEntry backupEntry = null)
        {
            Success = success;
            Message = message;
            BackupEntry = backupEntry;
        }
    }
}