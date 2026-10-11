using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using FireAntivirus.Common;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// 挖矿行为检测：分析文件/进程内容中的挖矿证据。
    /// 证据链：矿池地址 + stratum 协议 + 钱包地址 + 矿机名 + 挖矿算法。
    /// 特征数据从外置 JSON 加载，不在 DLL 内硬编码恶意字符串。
    /// </summary>
    public sealed class MinerBehaviorAnalyzer
    {
        // 已内置的矿池地址前缀（涵盖绝大多数矿池）
        private static readonly string[] PoolPrefixes =
        {
            "pool.", "mine.", "stratum", "ethash", "ethproxy", "stratum+tcp://",
            "stratum+ssl://", "stratum+http://"
        };

        // 常见挖矿通信端口
        private static readonly int[] MiningPorts = { 3333, 3334, 3335, 3336, 3337, 3338, 3339,
            3344, 3345, 3346, 3347, 3348, 3349, 3357, 4242, 5555, 7777, 8888, 14444, 14433,
            28888, 34567, 45560, 45561, 45570, 55555, 58888, 60000 };

        // 钱包地址正则（粗略匹配主要加密货币地址格式）
        private static readonly Regex BitcoinAddress = new(@"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", RegexOptions.Compiled);
        private static readonly Regex EthereumAddress = new(@"^0x[a-fA-F0-9]{40}$", RegexOptions.Compiled);
        private static readonly Regex MoneroAddress = new(@"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$", RegexOptions.Compiled);
        private static readonly Regex MiningReport = new(@"(accepted\s+\d+/\d+)\s*(share|diff|hash)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public sealed class MinerEvidence
        {
            public bool HasPoolUrl;                 // 矿池 URL/IP
            public bool HasStratumProtocol;          // stratum 协议
            public bool HasWalletAddress;            // 钱包地址
            public bool HasMiningAlgorithm;          // 挖矿算法名
            public bool HasMiningReport;             // 算力/份额报告
            public bool HasMinerProcessName;         // 矿机进程名
            public int ChainCount;                   // 独立证据数 0..6
            public double Strength;                  // 证据强度 0..1
            public string Notes = "";
        }

        /// <summary>
        /// 分析文本内容中的挖矿证据。content 可以是进程命令行、文件字符串、网络流量等。
        /// </summary>
        public MinerEvidence Analyze(string content)
        {
            var ev = new MinerEvidence();
            if (string.IsNullOrWhiteSpace(content)) return ev;

            try
            {
                // 矿池 URL
                ev.HasPoolUrl = PoolPrefixes.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase)) ||
                                MiningPorts.Any(p => content.Contains($":{p}", StringComparison.OrdinalIgnoreCase));

                // stratum 协议
                ev.HasStratumProtocol = content.Contains("stratum+tcp", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("stratum+ssl", StringComparison.OrdinalIgnoreCase);

                // 钱包地址（按行检查）
                foreach (var token in content.Split(new[] { ' ', '\t', '\r', '\n', '"', '\'', ',' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (token.Length < 25) continue;
                    if (BitcoinAddress.IsMatch(token) || EthereumAddress.IsMatch(token) || MoneroAddress.IsMatch(token))
                    {
                        ev.HasWalletAddress = true;
                        break;
                    }
                }

                // 挖矿算法名（特征外置，从 EmbeddedThreatDatabase 加载）
                FireAntivirus.Engine.Data.EmbeddedThreatDatabase.EnsureLoaded();
                foreach (var algo in FireAntivirus.Engine.Data.EmbeddedThreatDatabase.MinerAlgorithms)
                {
                    if (content.Contains(algo, StringComparison.OrdinalIgnoreCase))
                    {
                        ev.HasMiningAlgorithm = true;
                        break;
                    }
                }

                // 矿机进程名
                foreach (var name in FireAntivirus.Engine.Data.EmbeddedThreatDatabase.MinerProcessNames)
                {
                    if (content.Contains(name, StringComparison.OrdinalIgnoreCase))
                    {
                        ev.HasMinerProcessName = true;
                        break;
                    }
                }

                // 算力/份额报告
                ev.HasMiningReport = MiningReport.IsMatch(content);

                ev.ChainCount = (ev.HasPoolUrl ? 1 : 0) + (ev.HasStratumProtocol ? 1 : 0) +
                                (ev.HasWalletAddress ? 1 : 0) + (ev.HasMiningAlgorithm ? 1 : 0) +
                                (ev.HasMiningReport ? 1 : 0) + (ev.HasMinerProcessName ? 1 : 0);

                if (ev.ChainCount >= 4) { ev.Strength = 0.85; ev.Notes = "挖矿证据链完整（矿池+协议+钱包+算法+报告）"; }
                else if (ev.ChainCount >= 3) { ev.Strength = 0.55; ev.Notes = "挖矿证据部分匹配"; }
                else if (ev.ChainCount >= 2) { ev.Strength = 0.25; ev.Notes = "挖矿初始线索"; }
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Warning, "MinerBehaviorAnalyzer 失败", ex.Message);
            }
            return ev;
        }
    }
}