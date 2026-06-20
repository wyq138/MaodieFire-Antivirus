using System;
using System.Collections.Generic;

namespace FireAntivirus.RansomwareProtection
{
    public enum RansomwareDetectionType
    {
        FileEncryption,
        MassFileModification,
        SuspiciousProcess,
        UnauthorizedAccess,
        NetworkCommunication,
        ShadowCopyDeletion,
        MassFileRename
    }

    public class ProtectedFile
    {
        public string FilePath { get; set; }
        public DateTime LastModified { get; set; }
        public long FileSize { get; set; }
        public string FileHash { get; set; }

        public ProtectedFile() { }

        public ProtectedFile(string filePath, DateTime lastModified, long fileSize)
        {
            FilePath = filePath;
            LastModified = lastModified;
            FileSize = fileSize;
        }
    }

    public class RansomwareDetection
    {
        public string Id { get; set; }
        public RansomwareDetectionType DetectionType { get; set; }
        public string ProcessName { get; set; }
        public string AffectedFile { get; set; }
        public DateTime Timestamp { get; set; }
        public string Details { get; set; }

        public RansomwareDetection() { }

        public RansomwareDetection(RansomwareDetectionType detectionType, string processName, string affectedFile)
        {
            Id = Guid.NewGuid().ToString();
            DetectionType = detectionType;
            ProcessName = processName;
            AffectedFile = affectedFile;
            Timestamp = DateTime.Now;
        }
    }

    public class RansomwareDetectionResult
    {
        public DateTime Timestamp { get; set; }
        public bool IsRansomwareDetected { get; set; }
        public string Message { get; set; }
        public List<RansomwareDetection> Detections { get; set; } = new List<RansomwareDetection>();

        public RansomwareDetectionResult() { }

        public RansomwareDetectionResult(bool isRansomwareDetected, string message)
        {
            Timestamp = DateTime.Now;
            IsRansomwareDetected = isRansomwareDetected;
            Message = message;
        }
    }
}