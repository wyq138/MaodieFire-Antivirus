using System;

namespace FireAntivirus.SecureBrowser
{
    public class SecureBrowserResult
    {
        public string Url { get; set; }
        public bool Safe { get; set; }
        public bool HasTracking { get; set; }
        public string ThreatType { get; set; }
        public string Message { get; set; }
        public DateTime CheckTime { get; set; }

        public SecureBrowserResult() { }

        public SecureBrowserResult(string url, bool safe, string message)
        {
            Url = url;
            Safe = safe;
            Message = message;
            CheckTime = DateTime.Now;
        }
    }
}