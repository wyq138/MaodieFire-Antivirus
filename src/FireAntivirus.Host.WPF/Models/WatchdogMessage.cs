using System;

namespace FireAntivirus.Host.Models
{
    /// <summary>
    /// 看门狗IPC消息模型
    /// </summary>
    public class WatchdogMessage
    {
        /// <summary>
        /// 进程类型: "Main" 或 "Guardian"
        /// </summary>
        public string ProcessType { get; set; } = "Main";
        
        /// <summary>
        /// 进程ID
        /// </summary>
        public int ProcessId { get; set; }
        
        /// <summary>
        /// 消息时间戳
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.Now;
        
        /// <summary>
        /// 动作类型: "Heartbeat", "Exit", "Restart", "Register"
        /// </summary>
        public string Action { get; set; } = "Heartbeat";
        
        /// <summary>
        /// 主进程可执行文件路径(用于重启)
        /// </summary>
        public string? MainProcessPath { get; set; }
        
        /// <summary>
        /// 附加数据
        /// </summary>
        public string? Data { get; set; }
    }
}
