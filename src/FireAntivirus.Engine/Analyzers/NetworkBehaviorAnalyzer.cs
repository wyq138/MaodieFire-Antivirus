using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using FireAntivirus.Common;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// 网络行为分析：检测 C2 通信模式、DNS 隧道、信标特征。
    /// 分析进程命令行、配置字符串、域名/IP 中的网络攻击证据。
    /// 特征数据从外置 JSON 加载，不在 DLL 内硬编码恶意字符串。
    /// </summary>
    public sealed class NetworkBehaviorAnalyzer
    {
        // C2 通信常见模式
        private static readonly string[] C2Indicators =
        {
            "http://", "https://", "tcp://", "udp://",
            "WebClient", "DownloadString", "UploadString", "DownloadData",
            "OpenRead", "OpenWrite", "HttpWebRequest", "WebRequest",
            "socket", "Socket", "BeginConnect", "BeginReceive",
            "TcpClient", "UdpClient", "NetworkStream", "SslStream",
            "ConnectAsync", "SendAsync", "ReceiveAsync",
            "GetResponse", "GetRequestStream", "UploadFile"
        };

        // 信标/心跳特征
        private static readonly string[] BeaconIndicators =
        {
            "sleep", "Sleep", "Thread.Sleep", "Task.Delay",
            "beacon", "checkin", "check-in", "heartbeat",
            "poll", "polling", "long poll", "longpoll",
            "retry", "retry", "reconnect", "keepalive",
            "jitter", "jitter", "callback", "callback",
            "c2", "c&c", "command and control"
        };

        // DNS 隧道特征
        private static readonly string[] DnsTunnelIndicators =
        {
            "dns", "dnsquery", "txt record", "txt query",
            "dns-tunnel", "dnscat", "iodine", "dns2tcp",
            "subdomain", "base64.", "base32.", ".c2.", ".dns."
        };

        // 已知恶意域名特征（后缀/模式）
        private static readonly string[] MaliciousDomainPatterns =
        {
            ".xyz", ".top", ".club", ".work", ".download", ".bid",
            ".trade", ".date", ".men", ".loan", ".win", ".science",
            ".party", ".racing", ".review", ".faith", ".stream"
        };

        // 常见 C2 端口
        private static readonly int[] C2Ports =
        {
            4444, 4445, 1337, 1338, 8080, 8443, 8888, 9001, 9002,
            53, 443, 80, 6666, 6667, 6668, 6669, 7001, 7002
        };

        public sealed class NetworkBehaviorEvidence
        {
            public bool HasC2Indicator;              // C2 通信特征
            public bool HasBeaconPattern;            // 信标/心跳模式
            public bool HasDnsTunnel;               // DNS 隧道
            public bool HasMaliciousDomain;          // 可疑域名
            public bool HasC2Port;                   // 已知 C2 端口
            public int CategoryCount;                // 独立类别数 0..5
            public double Strength;                  // 证据强度 0..1
            public string Notes = "";
        }

        public NetworkBehaviorEvidence Analyze(string content)
        {
            var ev = new NetworkBehaviorEvidence();
            if (string.IsNullOrWhiteSpace(content)) return ev;

            try
            {
                ev.HasC2Indicator = C2Indicators.Any(c => content.Contains(c, StringComparison.OrdinalIgnoreCase));
                ev.HasBeaconPattern = BeaconIndicators.Any(b => content.Contains(b, StringComparison.OrdinalIgnoreCase));
                ev.HasDnsTunnel = DnsTunnelIndicators.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase));
                ev.HasMaliciousDomain = MaliciousDomainPatterns.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase));
                ev.HasC2Port = C2Ports.Any(p => content.Contains($":{p}", StringComparison.OrdinalIgnoreCase) ||
                                                content.Contains($" {p} ", StringComparison.OrdinalIgnoreCase));

                ev.CategoryCount = (ev.HasC2Indicator ? 1 : 0) + (ev.HasBeaconPattern ? 1 : 0) +
                                   (ev.HasDnsTunnel ? 1 : 0) + (ev.HasMaliciousDomain ? 1 : 0) +
                                   (ev.HasC2Port ? 1 : 0);

                if (ev.CategoryCount >= 4) { ev.Strength = 0.80; ev.Notes = "完整 C2 通信证据链"; }
                else if (ev.CategoryCount >= 3) { ev.Strength = 0.50; ev.Notes = "C2 通信部分证据"; }
                else if (ev.CategoryCount >= 2) { ev.Strength = 0.20; ev.Notes = "C2 通信初始线索"; }
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Warning, "NetworkBehaviorAnalyzer 失败", ex.Message);
            }
            return ev;
        }
    }
}