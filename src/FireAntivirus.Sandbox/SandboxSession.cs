using System;

namespace FireAntivirus.Sandbox
{
    public enum SandboxStatus
    {
        Ready,
        Running,
        Completed,
        Failed
    }

    public class SandboxSession
    {
        public string SessionId { get; set; }
        public string SessionPath { get; set; }
        public DateTime CreatedTime { get; set; }
        public DateTime? CompletedTime { get; set; }
        public SandboxStatus Status { get; set; }
        public int ExitCode { get; set; }
        public string ErrorMessage { get; set; }

        public SandboxSession() { }

        public SandboxSession(string sessionId, string sessionPath)
        {
            SessionId = sessionId;
            SessionPath = sessionPath;
            CreatedTime = DateTime.Now;
            Status = SandboxStatus.Ready;
        }
    }
}