using System;
using System.Collections.Generic;
using System.IO;

namespace FireAntivirus.SystemOptimizer
{
    public class SystemOptimizationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public bool TempFilesCleaned { get; set; }
        public bool SystemLogsCleaned { get; set; }
        public bool BrowserCacheCleaned { get; set; }
        public bool StartupItemsOptimized { get; set; }
        public bool SystemServicesOptimized { get; set; }
        public bool DiskSpaceAnalyzed { get; set; }
        public DateTime OptimizationTime { get; set; } = DateTime.Now;

        public SystemOptimizationResult() { }

        public SystemOptimizationResult(bool success, string message)
        {
            Success = success;
            Message = message;
        }
    }

    public class SystemInfo
    {
        public string OperatingSystem { get; set; }
        public string MachineName { get; set; }
        public string UserName { get; set; }
        public int ProcessorCount { get; set; }
        public long WorkingSet { get; set; }
        public List<DriveInfo> Drives { get; set; }

        public SystemInfo() { }
    }
}