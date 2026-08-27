// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Common;

namespace FireAntivirus.RealTimeProtectionPlus
{
    /// <summary>单项自检结果。</summary>
    public class SelfTestItem
    {
        public string Name { get; set; }
        public string Category { get; set; }
        public bool Passed { get; set; }
        public string Detail { get; set; }
    }

    /// <summary>
    /// 无杀伤力自检：不使用真实病毒样本，只使用 EICAR 测试样本与合法测试数据，
    /// 验证【引擎查杀】【特征库更新解析】【实时防护】【不误杀不删除】等核心功能达标。
    /// 所有测试都在 %TEMP% 下创建临时文件，结束后即时清理，绝不影响用户数据。
    /// </summary>
    public static class FeatureSelfTest
    {
        // 标准 EICAR 测试样本的固定 SHA256（供在内存中校验内置特征，无需把 EICAR 落盘，
        // 因为写入磁盘会被本机实时防病毒拦截读取，导致文件无法被引擎打开——详见根因分析等注解）。
        private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        /// <summary>运行全部自检，返回逐项结果。</summary>
        public static async Task<List<SelfTestItem>> RunAllAsync(DataManager dataManager, AntivirusEngine engine, RealTimeProtectionPlusManager rtp)
        {
            var results = new List<SelfTestItem>();
            var tempDir = Path.Combine(Path.GetTempPath(), "FireAntivirus_SelfTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            try
            {
                // ---------- 1. 特征库更新解析（离线确定性，不发网络） ----------
                // 每次使用随机生成的唯一样本，避免与反复运行持久化后的特征库冲突，保证可重复达标
                results.Add(Run("特征库-解析恶意哈希", "特征库", () =>
                {
                    string h = NewRandomHex64();
                    int added = SignatureDatabaseUpdater.AddHashesFromText(h + "\n");
                    bool found = SignatureDatabaseUpdater.TryGetHashThreat(h, out _);
                    SignatureDatabaseUpdater.RemoveTestHash(h);
                    return Check(found, found ? $"解析成功(added={added}), 命中特征库" : "解析失败: 哈希未被提取");
                }));

                results.Add(Run("特征库-解析恶意URL", "特征库", () =>
                {
                    string url = NewRandomUrl();
                    int added = SignatureDatabaseUpdater.AddUrlsFromText($"2026082621,\"{url}\",dump|payload,,online\n");
                    bool hit = SignatureDatabaseUpdater.IsMaliciousUrl(url);
                    return Check(hit, hit ? $"解析成功(added={added}), 命中URL" : "解析失败: URL未被提取");
                }));

                results.Add(Run("特征库-解析恶意IP", "特征库", () =>
                {
                    string ip = NewRandomIp();
                    int added = SignatureDatabaseUpdater.AddIpsFromText($"2026-08-26,\"{ip}\",443,online\n");
                    bool hit = SignatureDatabaseUpdater.IsMaliciousIp(ip);
                    return Check(hit, hit ? $"解析成功(added={added}), 命中IP" : "解析失败: IP未被提取");
                }));

                // ---------- 2. 引擎查杀（签名库高置信命中 + 内置EICAR特征在位 + 正常文件不误报） ----------
                // 注意：标准 EICAR 样本一旦写入磁盘，会被本机实时防病毒（如 Windows Defender）拦截读取
                // （IOException: 文件包含病毒或潜在的垃圾软件），导致引擎无法打开文件、检测链断开。
                // 因此检测链改用"无害良性文件 + 内存注册其哈希为恶意"来验证，仍走真实"文件→SHA256→特征库"判定，
                // 全程不写盘、可逆、不依赖外部杀软状态。
                string detectPath = Path.Combine(tempDir, "detect_test.exe");
                File.WriteAllBytes(detectPath, Encoding.UTF8.GetBytes(
                    "harmless deterministic self-test payload " + Guid.NewGuid().ToString("N")));

                results.Add(Run("引擎-检出高置信威胁(经签名库)", "引擎", () =>
                {
                    if (!TryGetSha256(detectPath, out string hash))
                        return Check(false, "无法计算样本哈希");
                    SignatureDatabaseUpdater.RegisterTestHash(hash, "SelfTest.Threat");
                    try
                    {
                        var scan = engine.ScanFile(detectPath);
                        bool ok = scan != null && scan.IsInfected && scan.Confidence >= 0.8;
                        return Check(ok, scan == null
                            ? "扫描无结果"
                            : $"风险名={scan.ThreatName}, 置信度={scan.Confidence:F2}, 方法={scan.DetectionMethod}");
                    }
                    finally
                    {
                        SignatureDatabaseUpdater.RemoveTestHash(hash);
                    }
                }));

                results.Add(Run("引擎-内置EICAR特征已加载", "引擎", () =>
                {
                    bool inDb = SignatureDatabaseUpdater.TryGetHashThreat(EicarSha256, out var t);
                    return Check(inDb, inDb ? $"内置EICAR特征在位: {t}" : "内置EICAR特征未加载");
                }));

                results.Add(Run("引擎-正常文件不误报", "引擎", () =>
                {
                    string benignPath = Path.Combine(tempDir, "benign_test.exe");
                    File.WriteAllBytes(benignPath, Encoding.UTF8.GetBytes(
                        "This is a fully benign application that performs ordinary tasks. " +
                        "It contains no malicious behavior whatsoever and is safe to run."));

                    var scan = engine.ScanFile(benignPath);
                    bool ok = scan != null && !scan.IsInfected;
                    return Check(ok, scan == null ? "扫描无结果" : "正常文件判定为安全，无误报");
                }));

                // ---------- 3. 实时防护（高置信阻断 + 正常放行 + 绝不删除原文件） ----------
                string rtpPath = Path.Combine(tempDir, "rtp_detect.exe");
                File.WriteAllBytes(rtpPath, Encoding.UTF8.GetBytes(
                    "harmless deterministic self-test payload " + Guid.NewGuid().ToString("N")));

                results.Add(Run("实时防护-高置信文件阻断", "实时防护", () =>
                {
                    if (!TryGetSha256(rtpPath, out string hash))
                        return Check(false, "无法计算样本哈希");
                    SignatureDatabaseUpdater.RegisterTestHash(hash, "SelfTest.Threat");
                    try
                    {
                        var evt = new ProtectionEvent
                        {
                            EventId = Guid.NewGuid().ToString(),
                            EventType = "FileCreated",
                            ProtectionType = ProtectionType.File,
                            Timestamp = DateTime.Now,
                            FilePath = rtpPath,
                            Details = $"FilePath={rtpPath}"
                        };

                        var outcome = rtp.OnProtectionEvent(evt);

                        // 关键安全保证：无论阻断与否，绝不删除原文件（只做可逆隔离/告警）
                        bool notDeleted = File.Exists(rtpPath);
                        return Check(outcome.Action == ProtectionAction.Block && notDeleted,
                            $"动作={outcome.Action}, 文件未被删除={notDeleted}, {outcome.Message}");
                    }
                    finally
                    {
                        SignatureDatabaseUpdater.RemoveTestHash(hash);
                    }
                }));

                results.Add(Run("实时防护-正常文件放行", "实时防护", () =>
                {
                    string benignRtp = Path.Combine(tempDir, "rtp_benign.exe");
                    File.WriteAllBytes(benignRtp, Encoding.UTF8.GetBytes(
                        "This is a benign file used for the real-time protection self test. Normal content."));

                    var evt = new ProtectionEvent
                    {
                        EventId = Guid.NewGuid().ToString(),
                        EventType = "FileCreated",
                        ProtectionType = ProtectionType.File,
                        Timestamp = DateTime.Now,
                        FilePath = benignRtp,
                        Details = $"FilePath={benignRtp}"
                    };

                    var outcome = rtp.OnProtectionEvent(evt);
                    bool stillExists = File.Exists(benignRtp);
                    return Check(outcome.Action != ProtectionAction.Block && stillExists,
                        $"动作={outcome.Action}, 文件未被删除={stillExists}, {outcome.Message}");
                }));

                // ---------- 4. 网页/网络拦截（URL + C2 IP，特征库实时命中） ----------
                results.Add(Run("实时防护-拦截恶意网址(URL特征库)", "网页拦截", () =>
                {
                    string url = $"https://{NewRandomHex64().Substring(0,12)}.evil.example.net/load";
                    SignatureDatabaseUpdater.RegisterTestUrl(url);
                    try
                    {
                        var evt = new ProtectionEvent
                        {
                            EventId = Guid.NewGuid().ToString(),
                            ProtectionType = ProtectionType.Network,
                            EventType = "UrlVisited",
                            Timestamp = DateTime.Now,
                            NetworkAddress = url,
                            Details = $"BlockedUrl={url}"
                        };
                        var outcome = rtp.OnProtectionEvent(evt);
                        return Check(outcome.Action == ProtectionAction.Block,
                            $"动作={outcome.Action}, {outcome.Message}");
                    }
                    finally
                    {
                        SignatureDatabaseUpdater.RemoveTestUrl(url);
                    }
                }));

                results.Add(Run("实时防护-拦截恶意C2连接(IP特征库)", "网页拦截", () =>
                {
                    string ip = NewRandomIp();
                    SignatureDatabaseUpdater.RegisterTestIp(ip);
                    try
                    {
                        var evt = new ProtectionEvent
                        {
                            EventId = Guid.NewGuid().ToString(),
                            ProtectionType = ProtectionType.Network,
                            EventType = "SuspiciousConnection",
                            Timestamp = DateTime.Now,
                            NetworkAddress = ip,
                            Details = $"RemoteIP={ip}:4444"
                        };
                        var outcome = rtp.OnProtectionEvent(evt);
                        return Check(outcome.Action == ProtectionAction.Block,
                            $"动作={outcome.Action}, {outcome.Message}");
                    }
                    finally
                    {
                        SignatureDatabaseUpdater.RemoveTestIp(ip);
                    }
                }));

                results.Add(Run("实时防护-正常网页放行", "网页拦截", () =>
                {
                    var evt = new ProtectionEvent
                    {
                        EventId = Guid.NewGuid().ToString(),
                        ProtectionType = ProtectionType.Network,
                        EventType = "UrlVisited",
                        Timestamp = DateTime.Now,
                        NetworkAddress = "https://portal.example.com",
                        Details = "BlockedUrl=https://portal.example.com/index"
                    };
                    var outcome = rtp.OnProtectionEvent(evt);
                    return Check(outcome.Action != ProtectionAction.Block,
                        $"动作={outcome.Action}, {outcome.Message}");
                }));

                // ---------- 5. 进程 / 行为 实时防护 ----------
                results.Add(Run("实时防护-可疑进程阻断", "实时防护", () =>
                {
                    string suspect = rtp.SuspiciousProcessNames.Count > 0
                        ? new System.Collections.Generic.List<string>(rtp.SuspiciousProcessNames)[0]
                        : "cryptomining.exe";
                    if (string.IsNullOrEmpty(suspect)) return Check(false, "无可疑进程名集合");
                    var evt = new ProtectionEvent
                    {
                        EventId = Guid.NewGuid().ToString(),
                        ProtectionType = ProtectionType.Process,
                        EventType = "ProcessCreated",
                        Timestamp = DateTime.Now,
                        ProcessName = suspect,
                        Details = $"ProcessName={suspect}"
                    };
                    var outcome = rtp.OnProtectionEvent(evt);
                    return Check(outcome.Action == ProtectionAction.Block,
                        $"动作={outcome.Action}, {outcome.Message}");
                }));

                results.Add(Run("实时防护-高风险行为阻断", "实时防护", () =>
                {
                    var evt = new ProtectionEvent
                    {
                        EventId = Guid.NewGuid().ToString(),
                        ProtectionType = ProtectionType.Behavior,
                        EventType = "SuspiciousBehavior",
                        Timestamp = DateTime.Now,
                        ProcessName = "powershell.exe",
                        Details = "Invoke-WebRequest -UseBasicParsing downloadstring -EncodedCommand"
                    };
                    var outcome = rtp.OnProtectionEvent(evt);
                    return Check(outcome.Action == ProtectionAction.Block,
                        $"动作={outcome.Action}, {outcome.Message}");
                }));
            }
            finally
            {
                // 清理临时目录
                try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "FeatureSelfTest.cs 捕获异常", ex.Message); }
            }

            // 写入日志便于 UI/自检可见
            try
            {
                foreach (var r in results)
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = r.Passed ? "SelfTestPassed" : "SelfTestFailed",
                        Message = $"功能自检{(r.Passed ? "通过" : "失败")}: {r.Name}",
                        Details = r.Detail
                    });
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "FeatureSelfTest.cs 捕获异常", ex.Message); }

            return results;
        }

        private static SelfTestItem Run(string name, string category, Func<SelfTestReport> action)
        {
            try
            {
                var report = action();
                return new SelfTestItem { Name = name, Category = category, Passed = report.Ok, Detail = report.Detail };
            }
            catch (Exception ex)
            {
                return new SelfTestItem { Name = name, Category = category, Passed = false, Detail = "异常: " + ex.Message };
            }
        }

        private static SelfTestReport Check(bool ok, string detail) => new SelfTestReport(ok, detail);

        private static bool TryGetSha256(string path, out string hash)
        {
            hash = null;
            try
            {
                using var sha = SHA256.Create();
                using var fs = File.OpenRead(path);
                hash = ToHex(sha.ComputeHash(fs));
                return true;
            }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "计算文件哈希失败", ex.Message); return false; }
        }

        private static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        // ---- 自检样本生成：每轮生成随机唯一值，保证测试可重复运行且不与持久化特征库冲突 ----
        private static string NewRandomHex64()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            return ToHex(bytes);
        }

        private static string NewRandomUrl() =>
            $"https://host{NewRandomHex64().Substring(0, 16)}.example.net/load/{NewRandomHex64().Substring(0, 16)}";

        private static string NewRandomIp() =>
            $"{_rand.Next(1, 230)}.{_rand.Next(0, 255)}.{_rand.Next(0, 255)}.{_rand.Next(1, 254)}";

        private static readonly System.Random _rand = new System.Random();

        private sealed class SelfTestReport
        {
            public bool Ok { get; }
            public string Detail { get; }
            public SelfTestReport(bool ok, string detail) { Ok = ok; Detail = detail; }
        }
    }
}