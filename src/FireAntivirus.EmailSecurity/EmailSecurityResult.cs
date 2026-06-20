using System;

namespace FireAntivirus.EmailSecurity
{
    public class EmailSecurityResult
    {
        public bool Safe { get; set; }
        public string Sender { get; set; }
        public string Subject { get; set; }
        public string ThreatType { get; set; }
        public string Message { get; set; }
        public DateTime CheckTime { get; set; } = DateTime.Now;

        public EmailSecurityResult() { }

        public EmailSecurityResult(bool safe, string sender, string subject, string threatType, string message)
        {
            Safe = safe;
            Sender = sender;
            Subject = subject;
            ThreatType = threatType;
            Message = message;
        }
    }
}