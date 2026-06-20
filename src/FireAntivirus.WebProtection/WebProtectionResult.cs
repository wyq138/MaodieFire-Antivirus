using System;

namespace FireAntivirus.WebProtection
{
    public class WebProtectionResult
    {
        public bool Safe { get; set; }
        public string Url { get; set; }
        public string ThreatType { get; set; }
        public string Message { get; set; }
        public DateTime CheckTime { get; set; } = DateTime.Now;

        public WebProtectionResult() { }

        public WebProtectionResult(bool safe, string url, string threatType, string message)
        {
            Safe = safe;
            Url = url;
            ThreatType = threatType;
            Message = message;
        }
    }
}