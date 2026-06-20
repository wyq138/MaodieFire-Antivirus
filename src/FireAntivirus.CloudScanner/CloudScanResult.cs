using System;

namespace FireAntivirus.CloudScanner
{
    public class CloudScanResult
    {
        public string FilePath { get; set; }
        public string Url { get; set; }
        public string FileHash { get; set; }
        public bool Success { get; set; }
        public bool IsInfected { get; set; }
        public string ThreatName { get; set; }
        public double Confidence { get; set; }
        public string Message { get; set; }
        public DateTime ScanTime { get; set; }
        public string DetectionMethod { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }

        public CloudScanResult() { }

        public CloudScanResult(string filePath, bool success, bool isInfected, string threatName, double confidence, string message)
        {
            FilePath = filePath;
            Success = success;
            IsInfected = isInfected;
            ThreatName = threatName;
            Confidence = confidence;
            Message = message;
            ScanTime = DateTime.Now;
        }
    }
}