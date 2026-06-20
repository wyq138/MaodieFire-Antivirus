using System;
using System.Collections.Generic;

namespace FireAntivirus.Services
{
    public class BackupOptions
    {
        public string Description { get; set; } = string.Empty;
        public bool IncludeConfiguration { get; set; } = true;
        public bool IncludeDefinitions { get; set; } = true;
        public bool IncludeLogs { get; set; } = true;
        public bool IncludeQuarantine { get; set; } = true;
        public bool IncludeSystemSettings { get; set; } = true;
        public bool IncludeDocuments { get; set; } = false;
        public bool IncludePictures { get; set; } = false;
        public bool IncludeVideos { get; set; } = false;
        public bool IncludeDesktop { get; set; } = false;
        public bool IncludeFavorites { get; set; } = false;
        public List<string> CustomFolders { get; set; } = new List<string>();
        public bool EnableEncryption { get; set; } = false;
        public string EncryptionPassword { get; set; } = string.Empty;
    }

    public class RestoreOptions
    {
        public bool RestoreConfiguration { get; set; } = true;
        public bool RestoreDefinitions { get; set; } = true;
        public bool RestoreLogs { get; set; } = true;
        public bool RestoreQuarantine { get; set; } = true;
        public bool RestoreSystemSettings { get; set; } = true;
    }

    public class BackupInfoResult
    {
        public string BackupId { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public long BackupSize { get; set; }
        public BackupMetadata Metadata { get; set; } = new BackupMetadata();
        public bool ContainsConfiguration { get; set; }
        public bool ContainsDefinitions { get; set; }
        public bool ContainsLogs { get; set; }
        public bool ContainsQuarantine { get; set; }
        public bool ContainsSystemSettings { get; set; }
    }

    public class DeleteBackupResult
    {
        public string BackupId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
    }

    public class BackupValidationResult
    {
        public string BackupId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public List<string> RestoredItems { get; set; } = new List<string>();
        public List<string> MissingFiles { get; set; } = new List<string>();
    }

    public class BackupMetadata
    {
        public string BackupId { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime CreationTime { get; set; }
        public BackupOptions Options { get; set; } = new BackupOptions();
        public bool IncludeConfiguration { get; set; }
        public bool IncludeDefinitions { get; set; }
        public bool IncludeLogs { get; set; }
        public bool IncludeQuarantine { get; set; }
        public bool IncludeSystemSettings { get; set; }
        public long BackupSize { get; set; }
        public TimeSpan Duration { get; set; }
    }

    public class BackupResult
    {
        public string BackupId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public string BackupPath { get; set; } = string.Empty;
        public long BackupSize { get; set; }
        public DateTime BackupDate { get; set; } = DateTime.Now;
        public BackupOptions Options { get; set; } = new BackupOptions();
        public BackupMetadata Metadata { get; set; } = new BackupMetadata();
        public List<string> BackupItems { get; set; } = new List<string>();
        public List<string> Warnings { get; set; } = new List<string>();
    }

    public class RestoreResult
    {
        public string BackupId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public DateTime BackupDate { get; set; }
        public DateTime RestoreDate { get; set; } = DateTime.Now;
        public RestoreOptions Options { get; set; } = new RestoreOptions();
        public BackupMetadata BackupMetadata { get; set; } = new BackupMetadata();
        public List<string> RestoredItems { get; set; } = new List<string>();
        public List<string> RestoredFolders { get; set; } = new List<string>();
        public List<string> Warnings { get; set; } = new List<string>();
    }

    public class BackupInfo
    {
        public string BackupPath { get; set; } = string.Empty;
        public string BackupId { get; set; } = string.Empty;
        public long BackupSize { get; set; }
        public DateTime BackupDate { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime CreationDate { get; set; }
        public bool IsEncrypted { get; set; } = false;
        public bool ContainsConfiguration { get; set; }
        public bool ContainsDefinitions { get; set; }
        public bool ContainsLogs { get; set; }
        public bool ContainsQuarantine { get; set; }
        public bool ContainsSystemSettings { get; set; }
        public string Description { get; set; } = string.Empty;
    }
}
