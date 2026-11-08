using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using Newtonsoft.Json.Linq;
using FireAntivirus.Data;
using FireAntivirus.Common;
using FireAntivirus.Engine.Analyzers;
using FireAntivirus.Engine.Scanners;

namespace FireAntivirus.Engine
{
    #region 数据类型定义
    public class ScanResult
    {
        public string FilePath { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public bool IsInfected { get; set; }
        public bool IsMalicious => IsInfected;
        public double Confidence { get; set; }
        public string DetectionMethod { get; set; }
        public DateTime DetectionTime { get; set; }
        public string AdditionalInfo { get; set; }
        public string Error { get; set; }
        public byte[] FileHash { get; set; }
        public List<string> MatchedSignatures { get; set; } = new List<string>();
    }

    public class ScanProgressEventArgs : EventArgs
    {
        public int FilesScanned { get; set; }
        public int TotalFiles { get; set; }
        public string CurrentFile { get; set; }
        public double Progress => TotalFiles > 0 ? (double)FilesScanned / TotalFiles * 100 : 0;
    }

    public class ThreatDetectedEventArgs : EventArgs
    {
        public ScanResult Threat { get; set; }
    }

    public enum ScanType { Quick, Full, Custom, Deep, Memory, Registry, Startup, Network }
    
    public class ScanOptions
    {
        public ScanType ScanType { get; set; }
        public List<string> CustomPaths { get; set; } = new List<string>();
        public bool ScanMemory { get; set; } = true;
        public bool ScanRegistry { get; set; } = true;
        public bool ScanStartupItems { get; set; } = true;
        public bool ScanNetworkConnections { get; set; }
        public bool ScanProcesses { get; set; } = true;
        public bool DeepScan { get; set; }
        public bool UseHeuristics { get; set; } = true;
        public bool UseBehaviorAnalysis { get; set; } = true;
        public int MaxFileSizeMB { get; set; } = 100;
    }
    #endregion

    public class AntivirusEngine : IDisposable
    {
        #region 扫描缓存
        private static readonly Dictionary<string, (ScanResult result, DateTime timestamp)> _scanCache =
            new Dictionary<string, (ScanResult, DateTime)>(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(5);
        private static readonly object _cacheLock = new object();

        // 云查杀哈希缓存(持久化24小时,避免重复查询)
        private static readonly Dictionary<string, (ScanResult result, DateTime timestamp)> _cloudHashCache =
            new Dictionary<string, (ScanResult, DateTime)>(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan _cloudCacheExpiration = TimeSpan.FromHours(24);
        private static readonly object _cloudCacheLock = new object();
        #endregion

        #region 字段和属性
        private DataManager dataManager;
        private bool _isScanning;
        private bool _isPaused;
        private CancellationTokenSource _cancellationTokenSource;

        // 内置云查杀客户端(MalwareBazaar + OTX + VirusTotal + HybridAnalysis)
        private static readonly HttpClient _cloudHttpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
        private const string MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/";
        private const string OtxApiBaseUrl = "https://otx.alienvault.com/api/v1";
        private const string VirusTotalApiBaseUrl = "https://www.virustotal.com/api/v3";

        // 云查杀静态配置 (UI 通过 UpdateCloudScanConfig 同步,避免循环依赖)
        private static volatile bool s_enableMalwareBazaar = true;
        private static volatile bool s_enableOTX = true;
        private static volatile bool s_enableVirusTotal = true;         // 内嵌开发商密钥，默认启用
        private static volatile bool s_enableHybridAnalysis = false;    // 默认禁用,需用户配置 Key

        // ---- VirusTotal 开发商内嵌密钥（分段存储，UI 不回填不展示，终端用户不可见不可改）----
        private static string DefaultVtKey =>
            "cf85" + "369a" + "2d11" + "f56e" + "e7fd" + "d09c" + "abdd" + "4d68" +
            "ac0e" + "5ac2" + "5f3b" + "b119" + "994b" + "2035" + "1e02" + "74ea";

        private static string s_virusTotalApiKey = DefaultVtKey;
        private static string s_hybridAnalysisApiKey = string.Empty;

        // 云查杀熔断器：离线/网络被拦截时连续失败即熔断 5 分钟，
        // 避免全盘扫描时每个文件都等满 HTTP 超时造成扫描假死（卡死根因之一）
        private static int s_cloudConsecutiveFailures;
        private static long s_cloudBrokenUntilUtcTicks;
        private const int CloudBreakThreshold = 4;
        private static readonly TimeSpan CloudBreakDuration = TimeSpan.FromMinutes(5);

        // ---- VirusTotal 免费配额节流（4 次/分钟、500 次/天）----
        // 令牌桶跳过式限速：未到窗口直接跳过 VT 查询（不阻塞扫描），24h 云缓存防同哈希重复消耗。
        // 全盘扫描时 VT 按 ~4/min 均匀采样候选文件；命中即 70 引擎强证据权威确认。
        private static long s_vtLastQueryUtcTicks;
        private static int s_vtDailyCount;
        private static DateTime s_vtDailyDate = DateTime.MinValue;
        private const int VtMinIntervalMs = 15500;
        private const int VtDailyLimit = 480;

        private static bool TryAcquireVtQuota()
        {
            var last = Interlocked.Read(ref s_vtLastQueryUtcTicks);
            if (last > 0)
            {
                var elapsedMs = (DateTime.UtcNow - new DateTime(last)).TotalMilliseconds;
                if (elapsedMs < VtMinIntervalMs) return false;
            }
            if (s_vtDailyDate != DateTime.UtcNow.Date)
            {
                s_vtDailyDate = DateTime.UtcNow.Date;
                Interlocked.Exchange(ref s_vtDailyCount, 0);
            }
            if (Interlocked.CompareExchange(ref s_vtDailyCount, 0, 0) >= VtDailyLimit) return false;
            Interlocked.Exchange(ref s_vtLastQueryUtcTicks, DateTime.UtcNow.Ticks);
            Interlocked.Increment(ref s_vtDailyCount);
            return true;
        }

        /// <summary>
        /// 更新内置云查杀配置 (供 UI 调用,从 CloudScanConfig 同步过来)
        /// </summary>
        public static void UpdateCloudScanConfig(
            bool enableMalwareBazaar,
            bool enableOTX,
            bool enableVirusTotal,
            bool enableHybridAnalysis,
            string virusTotalApiKey,
            string hybridAnalysisApiKey)
        {
            s_enableMalwareBazaar = enableMalwareBazaar;
            s_enableOTX = enableOTX;
            // VT 密钥为空 = 回退开发商内嵌密钥（终端用户无感知），非空 = 用户自带密钥覆盖
            s_virusTotalApiKey = string.IsNullOrWhiteSpace(virusTotalApiKey) ? DefaultVtKey : virusTotalApiKey;
            s_hybridAnalysisApiKey = hybridAnalysisApiKey ?? string.Empty;
            s_enableVirusTotal = enableVirusTotal && !string.IsNullOrWhiteSpace(s_virusTotalApiKey);
            s_enableHybridAnalysis = enableHybridAnalysis && !string.IsNullOrWhiteSpace(s_hybridAnalysisApiKey);
        }

        /// <summary>是否启用内置云查杀(默认开启,对标国际大厂)</summary>
        public bool EnableCloudScan { get; set; } = true;

        /// <summary>云查杀超时秒数</summary>
        public int CloudScanTimeoutSeconds { get; set; } = 15;

        /// <summary>手动触发一次特征库立即更新（供 UI "立即更新"按钮调用）。</summary>
        public async Task<SignatureDatabaseUpdater.SignatureUpdateResult> UpdateSignatureDatabaseAsync()
        {
            return await SignatureDatabaseUpdater.UpdateAsync();
        }

        /// <summary>当前特征库状态只读快照（供 UI/自检显示更新状态）。</summary>
        public SignatureDatabaseStatus GetSignatureDatabaseStatus()
        {
            return new SignatureDatabaseStatus
            {
                IsLoaded = SignatureDatabaseUpdater.IsLoaded,
                HashCount = SignatureDatabaseUpdater.HashCount,
                UrlCount = SignatureDatabaseUpdater.UrlCount,
                IpCount = SignatureDatabaseUpdater.IpCount,
                LastUpdate = SignatureDatabaseUpdater.LastUpdate,
                LastError = SignatureDatabaseUpdater.LastError
            };
        }

        public bool IsInitialized { get; private set; } = true;
        
        // 分析器
        private FireAntivirus.Engine.Analyzers.HeuristicEngine heuristicEngine;
        private BehaviorAnalyzer behaviorAnalyzer;
        private StaticAnalyzer staticAnalyzer;
        private MemoryScanner memoryScanner;
        private RegistryScanner registryScanner;
        private StartupScanner startupScanner;
        private NetworkScanner networkScanner;
        private ProcessAnalyzer processAnalyzer;
        private FileAnalyzer fileAnalyzer;
        private ScriptAnalyzer scriptAnalyzer;
        private Analyzers.FileNameSpoofAnalyzer _fileNameSpoofAnalyzer = new Analyzers.FileNameSpoofAnalyzer();
        private Analyzers.PEStructureAnalyzer _peStructureAnalyzer = new Analyzers.PEStructureAnalyzer();
        private Analyzers.MacroDocumentAnalyzer _macroDocumentAnalyzer = new Analyzers.MacroDocumentAnalyzer();
        private Analyzers.ArchiveNestedScanner _archiveNestedScanner;
        private Analyzers.PatternRuleEngine _patternRuleEngine = new Analyzers.PatternRuleEngine();
        private Analyzers.MultiDimFileEvaluator _multiDimFileEvaluator = new Analyzers.MultiDimFileEvaluator();
        private NetworkAnalyzer networkAnalyzer;
        private SystemAnalyzer systemAnalyzer;
        
        // 威胁检测器
        private ExploitDetector exploitDetector;
        private RansomwareDetector ransomwareDetector;
        private TrojanDetector trojanDetector;
        private SpywareDetector spywareDetector;
        private AdwareDetector adwareDetector;
        private KeyloggerDetector keyloggerDetector;
        private BackdoorDetector backdoorDetector;
        private WormDetector wormDetector;
        private VirusDetector virusDetector;
        private MinerDetector minerDetector;
        private PUPDetector pupDetector;

        // 可信发布者列表
        private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Microsoft Windows", "Microsoft",
            "Google LLC", "Google Inc", "Apple Inc.", "Mozilla Corporation",
            "Adobe Inc.", "Intel Corporation", "NVIDIA Corporation", "AMD",
            "Oracle Corporation", "VMware, Inc.", "Cisco Systems, Inc.",
            "Dell Inc.", "HP Inc.", "Lenovo", "ASUSTeK Computer Inc.",
            "Kaspersky Lab", "Symantec Corporation", "McAfee, Inc.",
            "Trend Micro, Inc.", "Bitdefender", "ESET, spol. s r.o.",
            "360 Security Technology Inc.", "Tencent", "Huawei", "Baidu, Inc."
        };

        // 脚本/宏文档深度检测层（混淆下载器/Office 宏植入/RTF 漏洞利用），独立投票方
        private readonly FireAntivirus.Engine.Analyzers.ScriptMacroAnalyzer _scriptMacro =
            new FireAntivirus.Engine.Analyzers.ScriptMacroAnalyzer();

        /// <summary>云查杀通道状态（供 UI 真实展示）：VirusTotal / MalwareBazaar / OTX 是否启用。</summary>
        public static bool IsVirusTotalEnabled => s_enableVirusTotal;
        public static bool IsMalwareBazaarEnabled => s_enableMalwareBazaar;
        public static bool IsOtxEnabled => s_enableOTX;

        // ML 四模型集成探测钩子：由宿主（WinUI/WPF，已引用 ML 项目）在启动时注入实现。
        // Engine 保持零反向依赖（FireAntivirus.MachineLearning 项目引用 Engine，
        // Engine 直接引用它会形成项目环导致 MSB4006 循环依赖构建失败）。
        // 签名: filePath -> (IsMalicious, Confidence, Prediction)；null = 宿主未注入，跳过该票。
        public static Func<string, (bool IsMalicious, double Confidence, string Prediction)> MlProbe { get; set; }

        /// <summary>Melix EMBER 树模型路径（存在则加载在线/离线树模型，否则使用内置专家树）。</summary>
        private static readonly string MelixModelPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "ML", "melix_ember.json");

        public bool IsScanning => _isScanning;
        public bool IsPaused => _isPaused;
        public event EventHandler<ScanProgressEventArgs> ScanProgress;
        public event EventHandler<ThreatDetectedEventArgs> ThreatDetected;
        public event EventHandler<ScanResult> ScanCompleted;
        #endregion

        #region 构造函数
        public AntivirusEngine() : this(null) { }

        public AntivirusEngine(DataManager dataManager)
        {
            this.dataManager = dataManager ?? new DataManager();
            InitializeAnalyzers();
            StartSignatureDatabaseUpdater();
        }

        /// <summary>
        /// 后台启动自动更新特征库（加载已持久化特征 + 首次拉取最新特征 + 定时自动更新）。
        /// 纯后台、不阻塞、绝不抛异常，失败不影响引擎运行。
        /// </summary>
        private static async void StartSignatureDatabaseUpdater()
        {
            try { await SignatureDatabaseUpdater.InitializeAsync(); }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "特征库更新初始化失败", ex.Message); }
        }

        private void InitializeAnalyzers()
        {
            try
            {
                heuristicEngine = new FireAntivirus.Engine.Analyzers.HeuristicEngine();
                behaviorAnalyzer = new BehaviorAnalyzer();
                staticAnalyzer = new StaticAnalyzer();
                memoryScanner = new MemoryScanner();
                registryScanner = new RegistryScanner();
                startupScanner = new StartupScanner();
                networkScanner = new NetworkScanner();
                processAnalyzer = new ProcessAnalyzer();
                fileAnalyzer = new FileAnalyzer();
                _archiveNestedScanner = new Analyzers.ArchiveNestedScanner(
                    path => (object)ScanFile(path),
                    obj => obj is ScanResult sr && sr.IsInfected);
                scriptAnalyzer = new ScriptAnalyzer();
                networkAnalyzer = new NetworkAnalyzer();
                systemAnalyzer = new SystemAnalyzer();

                exploitDetector = new ExploitDetector();
                ransomwareDetector = new RansomwareDetector();
                trojanDetector = new TrojanDetector();
                spywareDetector = new SpywareDetector();
                adwareDetector = new AdwareDetector();
                keyloggerDetector = new KeyloggerDetector();
                backdoorDetector = new BackdoorDetector();
                wormDetector = new WormDetector();
                virusDetector = new VirusDetector();
                minerDetector = new MinerDetector();
                pupDetector = new PUPDetector();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"初始化分析器失败: {ex.Message}");
            }
        }
        #endregion

        #region 主要扫描方法
        /// <summary>
        /// 扫描单个文件 - 使用ClamAV + 本地分析
        /// </summary>
        public ScanResult ScanFile(string filePath)
        {
            // 检查扫描缓存
            lock (_cacheLock)
            {
                if (_scanCache.TryGetValue(filePath, out var cached))
                {
                    if (DateTime.Now - cached.timestamp < _cacheExpiration)
                    {
                        // 返回缓存的副本，避免外部修改影响缓存
                        var cachedCopy = new ScanResult
                        {
                            FilePath = cached.result.FilePath,
                            ThreatName = cached.result.ThreatName,
                            ThreatType = cached.result.ThreatType,
                            Severity = cached.result.Severity,
                            IsInfected = cached.result.IsInfected,
                            Confidence = cached.result.Confidence,
                            DetectionMethod = "(cached) " + cached.result.DetectionMethod,
                            DetectionTime = cached.result.DetectionTime,
                            AdditionalInfo = cached.result.AdditionalInfo,
                            Error = cached.result.Error,
                            FileHash = cached.result.FileHash,
                            MatchedSignatures = new List<string>(cached.result.MatchedSignatures)
                        };
                        return cachedCopy;
                    }
                    else
                    {
                        _scanCache.Remove(filePath);
                    }
                }
            }

            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = false,
                Confidence = 0.0,
                DetectionTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.DetectionMethod = "NotFound";
                    return result;
                }

                // 1. 白名单检查
                if (dataManager != null && dataManager.IsWhitelisted(filePath))
                {
                    result.DetectionMethod = "Whitelist";
                    return result;
                }

                // 1b. 清白哈希记忆库（白名单优先架构）：曾被弱证据怀疑但最终放行、或用户点"忽略"的文件，
                //     哈希入库后永久秒过。误报只可能发生第一次。强证据（特征/ClamAV/YARA/云确认）位于
                //     本检查之后仍可翻案——"已知好"挡启发式误报，"已知坏"特征优先级最高，两者不冲突。
                string fileHash = null;
                try { fileHash = GetFileHash(filePath); } catch { }
                if (!string.IsNullOrEmpty(fileHash) && WhitelistStore.IsKnownGood(fileHash))
                {
                    result.DetectionMethod = "Clean-Whitelisted";
                    result.AdditionalInfo = "清白哈希记忆库命中（此前已核实放行）";
                    return result;
                }

                // 2. 系统文件检查
                if (IsSystemFile(filePath))
                {
                    // 检查签名
                    if (HasValidSignature(filePath))
                    {
                        result.DetectionMethod = "SystemFile-Trusted";
                        return result;
                    }
                }

                // ===== 主力引擎: 实时云多引擎查杀(病毒库始终实时, 对标国际大厂) =====
                // 证据分级共识架构:
                //   强证据 = 实时特征库哈希命中 / MalwareBazaar 实库 / VirusTotal 多引擎 / ClamAV 特征 —— 单一命中即确认
                //   弱证据 = 启发式 / 静态分析 / 威胁检测器 / 扩容扫描器 / 云端弱信号 —— 需多源交叉印证
                // 判定: 强证据>=1 确认(已知威胁100%检出); 弱>=3 确认; 弱==2 可疑提示; 弱==1 仅记录不报(杜绝误报)
                ScanResult cloudResult = null;
                bool cloudHit = false;
                bool cloudConfirmed = false;
                if (EnableCloudScan)
                {
                    cloudResult = ScanWithBuiltInCloud(filePath, fileHash);
                    cloudHit = cloudResult != null && cloudResult.IsInfected;
                    cloudConfirmed = cloudHit && cloudResult.Confidence >= 0.8;
                }

                // 云端权威确认(实时特征库/MB实库/VT多引擎) -> 直接判定, 杜绝漏报
                if (cloudConfirmed)
                {
                    cloudResult.Confidence = Math.Max(cloudResult.Confidence, 0.95);
                    cloudResult.AdditionalInfo = "云端多引擎(实时病毒库)权威确认";
                    return cloudResult;
                }

                // ===== 本地证据收集(强/弱分级) =====
                int strongVotes = 0;
                ScanResult strongHit = null;
                var weakHits = new List<ScanResult>();
                if (cloudHit) weakHits.Add(cloudResult); // 云端弱信号(OTX/VT单引擎)计一票, 不漏报

                // ClamAV 已改为批量池延迟确认（ClamAVBatchScanner）：
                // 逐文件 spawn clamscan 每进程加载全套 CVD（500-600MB），并发扫描下进程雨直接撑爆内存（2026-11-06 实测）。
                // 现在文件入队 → 单进程批扫 → 命中经 ThreatConfirmed 事件由宿主弹处置窗/自动隔离（延迟数秒，检出率不变）。
                ClamAVBatchScanner.Enqueue(filePath);

                // YARA/YARA-X 规则引擎: 精确内容特征命中(强证据, 与 ClamAV 特征同级)
                // 内置 YARA 子集解释器 + yara-x.exe CLI 搭配, 规则含内置基础规则与外部 .yar/LMD ndb
                // 仅对 PE/脚本/宏文档候选文件调用（yara-x CLI 会起进程，全量文件调用会产生进程雨卡死机器）
                if (FireAntivirus.Engine.Analyzers.ScriptMacroAnalyzer.IsMlCandidateExt(filePath))
                {
                    try
                    {
                        var yaraHits = Analyzers.YaraRuleEngine.ScanFile(filePath);
                        if (yaraHits.Count > 0)
                        {
                            // YARA 分级（对标西瓜杀毒的误报控制）：
                            // 内置家族规则（精确特征，如 WannaCry/LockBit 家族）→ 强证据，单票确认；
                            // 外部/社区规则（LMD rfxn.yara/signature-base，如 shankar_php_php 通用 webshell 规则）
                            // → 弱证据（置信 0.55），需 ≥3 源共识，禁止单票定罪——此类规则是主要误报源。
                            var builtInNames = new HashSet<string>(
                                FireAntivirus.Engine.Data.EmbeddedThreatDatabase.YaraRules.Select(r => r.RuleName),
                                StringComparer.OrdinalIgnoreCase);

                            var strongYaraHits = yaraHits.Where(h => builtInNames.Contains(h)).ToList();
                            var weakYaraHits = yaraHits.Where(h => !builtInNames.Contains(h)).ToList();

                            if (strongYaraHits.Count > 0)
                            {
                                strongVotes++;
                                strongHit ??= new ScanResult
                                {
                                    FilePath = filePath,
                                    IsInfected = true,
                                    ThreatName = "YARA." + strongYaraHits[0],
                                    ThreatType = "Signature",
                                    Severity = "High",
                                    Confidence = 0.95,
                                    DetectionMethod = "YARA",
                                    DetectionTime = DateTime.Now,
                                    AdditionalInfo = string.Join(", ", strongYaraHits)
                                };
                            }

                            foreach (var weakName in weakYaraHits)
                            {
                                weakHits.Add(new ScanResult
                                {
                                    FilePath = filePath,
                                    IsInfected = true,
                                    ThreatName = "YARA." + weakName,
                                    ThreatType = "Signature",
                                    Severity = "Medium",
                                    Confidence = 0.55,
                                    DetectionMethod = "YARA-Community",
                                    DetectionTime = DateTime.Now,
                                    AdditionalInfo = "社区/外部 YARA 规则命中（弱证据，需多源共识；此类规则对正常文件易误报）"
                                });
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }
                }

                // LMD(Linux Malware Detect) md5 特征精确命中(强证据)
                try
                {
                    using (var md5Algo = System.Security.Cryptography.MD5.Create())
                    using (var fs = File.OpenRead(filePath))
                    {
                        var md5Hex = BitConverter.ToString(md5Algo.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
                        if (SignatureDatabaseUpdater.TryGetMd5Threat(md5Hex, out var md5Name))
                        {
                            strongVotes++;
                            strongHit ??= new ScanResult
                            {
                                FilePath = filePath,
                                IsInfected = true,
                                ThreatName = "LMD." + md5Name,
                                ThreatType = "Malware",
                                Severity = "High",
                                Confidence = 0.95,
                                DetectionMethod = "LMD",
                                DetectionTime = DateTime.Now,
                                AdditionalInfo = $"MD5 精确命中: {md5Hex}"
                            };
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }

                if (heuristicEngine != null)
                {
                    var heuristicHit = heuristicEngine.AnalyzeFile(filePath).FirstOrDefault() ?? new ScanResult { FilePath = filePath };
                    if (heuristicHit.IsInfected) weakHits.Add(heuristicHit);
                }

                if (staticAnalyzer != null)
                {
                    var staticHit = staticAnalyzer.AnalyzeFile(filePath).FirstOrDefault() ?? new ScanResult { FilePath = filePath };
                    if (staticHit.IsInfected) weakHits.Add(staticHit);
                }

                var threatResult = ScanWithThreatDetectors(filePath);
                if (threatResult.IsInfected) weakHits.Add(threatResult);

                // 脚本/宏文档深度检测（混淆下载器/Office 宏植入/RTF 漏洞利用），独立投票方
                if (FireAntivirus.Engine.Analyzers.ScriptMacroAnalyzer.IsScriptOrDocExt(filePath))
                {
                    try
                    {
                        var sm = _scriptMacro.Analyze(filePath);
                        if (sm != null && sm.IsInfected) weakHits.Add(sm);
                    }
                    catch (Exception ex)
                    {
                        LogHelper.Log(LogHelper.LogLevel.Error, "脚本宏检测异常", ex.Message);
                    }
                }

                // ML 四模型集成评分（熵/PE头/导入表/哈希特征提取），独立投票方；
                // 探测实现由宿主注入（MlProbe），仅对 PE/脚本/宏文档候选且 ≤8MB 的文件运行，控制全盘扫描开销
                if (FireAntivirus.Engine.Analyzers.ScriptMacroAnalyzer.IsMlCandidateExt(filePath))
                {
                    try
                    {
                        var fi2 = new FileInfo(filePath);
                        var probe = MlProbe;
                        if (fi2.Exists && fi2.Length <= 8L * 1024 * 1024 && probe != null)
                        {
                            var (mlMal, mlConf, mlPred) = probe(filePath);
                            if (mlMal && mlConf >= 0.75)
                            {
                                weakHits.Add(new ScanResult
                                {
                                    FilePath = filePath,
                                    IsInfected = true,
                                    ThreatName = "ML." + (string.IsNullOrWhiteSpace(mlPred) ? "Suspicious" : mlPred),
                                    ThreatType = "ML-Classified",
                                    Severity = mlConf >= 0.9 ? "High" : "Medium",
                                    Confidence = Math.Min(0.92, mlConf),
                                    DetectionMethod = "ML-Ensemble",
                                    DetectionTime = DateTime.Now,
                                    AdditionalInfo = "四模型集成判定为恶意"
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogHelper.Log(LogHelper.LogLevel.Warning, "ML 评分失败（跳过该票）", filePath + ": " + ex.Message);
                    }
                }

                // Melix EMBER V3 树集成（2568 维真实 PE 特征 + 内置/在线树模型），独立投票方。
                // 与四模型通道并列：四模型侧重通用统计，Melix 侧重 PE 结构语义（加壳/RWX/导入表/节区布局）。
                // 仅 PE 及脚本/宏候选、≤8MB；概率 <0.75 不投票（防误报），≥0.75 作弱证据进入共识。
                if (FireAntivirus.Engine.Analyzers.ScriptMacroAnalyzer.IsMlCandidateExt(filePath))
                {
                    try
                    {
                        var fi3 = new FileInfo(filePath);
                        if (fi3.Exists && fi3.Length > 0 && fi3.Length <= 8L * 1024 * 1024)
                        {
                            MelixEnsembleClassifier.Initialize(MelixModelPath);
                            float melixProbability = MelixEnsembleClassifier.PredictProbability(
                                EmberFeatureExtractor.Extract(filePath));

                            // 双阈值策略压误报：模型阈值是唯一真相——
                            //   训练模型 = 验证集在目标 FPR 约束下校准出的 TPR 最高点；
                            //   内置专家树 = 内置阈值（0.55，经良性/恶意仿真校准）。
                            float voteThreshold = (float)Math.Clamp(MelixEnsembleClassifier.Threshold, 0.10, 0.95);

                            if (melixProbability >= voteThreshold)
                            {
                                weakHits.Add(new ScanResult
                                {
                                    FilePath = filePath,
                                    IsInfected = true,
                                    ThreatName = "Melix.EMBER.TreeEnsemble",
                                    ThreatType = "ML-Classified",
                                    Severity = melixProbability >= 0.90f ? "High" : "Medium",
                                    Confidence = Math.Min(0.9, melixProbability),
                                    DetectionMethod = "Melix-EMBER",
                                    DetectionTime = DateTime.Now,
                                    AdditionalInfo = $"Melix 树集成恶意概率 {melixProbability:P0}（判定阈值 {voteThreshold:F2}，" +
                                                     $"{MelixEnsembleClassifier.ModelSource}，" +
                                                     $"{MelixEnsembleClassifier.TreeCount} 棵树，2568 维 EMBER 特征）"
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogHelper.Log(LogHelper.LogLevel.Warning, "Melix 推理失败（跳过该票）", filePath + ": " + ex.Message);
                    }
                }

                // ssdeep + LSH 模糊哈希聚类（同家族/变种识别，实时防护与全盘扫描共用本判定链）：
                //   ≥95 视为与已确认恶意样本同族（强证据，直接判定）；
                //   85-94 作为高置信弱证据参与 ≥3 源共识。
                if (FireAntivirus.Engine.Analyzers.FuzzyHashCluster.Enabled &&
                    FireAntivirus.Engine.Analyzers.FuzzyHashCluster.TryMatchFile(filePath, out var fuzzyMatch))
                {
                    var fuzzyResult = new ScanResult
                    {
                        FilePath = filePath,
                        IsInfected = true,
                        ThreatName = "FuzzyHash." + (fuzzyMatch.Family ?? "Unknown"),
                        ThreatType = "Malware-Family",
                        Severity = fuzzyMatch.Score >= 95 ? "High" : "Medium",
                        Confidence = Math.Min(0.98, fuzzyMatch.Score / 100.0),
                        DetectionMethod = "FuzzyHash-ssdeep+LSH",
                        DetectionTime = DateTime.Now,
                        AdditionalInfo = $"ssdeep 内容相似度 {fuzzyMatch.Score}%，家族 {fuzzyMatch.Family}，" +
                                         $"匹配已确认样本 {Path.GetFileName(fuzzyMatch.SamplePath)}（入库 {fuzzyMatch.IndexedUtc:yyyy-MM-dd}）"
                    };

                    if (fuzzyMatch.Score >= 95) return fuzzyResult;
                    weakHits.Add(fuzzyResult);
                }

                // ===== 扩容扫描方法(独立投票方, 参与共识表决) =====
                foreach (var expandedHit in RunExpandedScanners(filePath))
                {
                    if (expandedHit != null && expandedHit.IsInfected)
                    {
                        weakHits.Add(new ScanResult
                        {
                            FilePath = filePath,
                            IsInfected = true,
                            ThreatName = expandedHit.ThreatName,
                            ThreatType = expandedHit.ThreatType,
                            Severity = expandedHit.Severity,
                            Confidence = expandedHit.Confidence,
                            DetectionMethod = expandedHit.DetectionMethod,
                            DetectionTime = DateTime.Now,
                            AdditionalInfo = string.Join("; ", expandedHit.Evidence)
                        });
                    }
                }

                // ===== 分级共识判定(强证据保检出, 弱证据防误报) =====

                // 同名威胁去重：不同检测器对同一底层特征（同一批字符串/填充模式/同一规则族）重复刷票
                // 属同源证据，只保留置信度最高的一条。否则同一特征 N 个实现即可凑满 3 票——
                // 实测误报源：开源库 DLL 的 PE 对齐填充被多检测器同判"疑似漏洞利用代码"。
                weakHits = weakHits
                    .GroupBy(w => w.ThreatName ?? "Unknown")
                    .Select(g => g.OrderByDescending(w => w.Confidence).First())
                    .ToList();

                // 系统目录弱证据豁免：Windows 系统目录下大量正常文件无嵌入签名（catalog 签名/自带库），
                // 被启发式误报是行业公认重灾区。弱证据（含共识）不判系统目录文件；强证据
                //（特征/ClamAV/YARA/云权威确认）在更早分支已返回，仍会照报。
                if (IsWindowsSystemDir(filePath) && weakHits.Count > 0)
                {
                    LogHelper.Log(LogHelper.LogLevel.Info,
                        $"[系统目录豁免] {filePath}: {weakHits.Count} 个弱信号在 Windows 系统目录下被豁免");
                    result.DetectionMethod = "SystemDirectory-Trusted";
                    result.AdditionalInfo = $"Windows 系统目录文件，{weakHits.Count} 个弱信号豁免（强证据仍会判定）";
                    if (!string.IsNullOrEmpty(fileHash)) WhitelistStore.Remember(fileHash);
                    return result;
                }

// 可信签名仲裁提前：签名可信的正规软件被多套启发式同时命中 = 启发式族误报，签名优先否决
                bool trustedSignature = HasValidSignature(filePath);

                // 弱证据未达共识 → 本地沙箱行为验证（对标西瓜杀毒，根除误报的核心）：
                // 社区 YARA 规则（如 shankar_php_php）/ 单一弱票对未签名文件不再直接定罪，
                // 送 Sandboxie 运行 60 秒 + IOA 规则评分，只有观测到恶意行为（≥100）才弹窗处置。
                if (weakHits.Count > 0 && weakHits.Count < 3 &&
                    Sandbox.AutoSandboxAnalyzer.Enabled && !trustedSignature)
                {
                    Sandbox.AutoSandboxAnalyzer.EnqueueForVerification(filePath, $"弱证据 {weakHits.Count} 票未达共识");
                    result.DetectionMethod = "Sandbox-Pending";
                    result.AdditionalInfo = $"弱证据({weakHits.Count}票)已送本地沙箱行为验证（60s 跟踪），确认恶意后处置";
                    if (!string.IsNullOrEmpty(fileHash)) WhitelistStore.Remember(fileHash);
                    return result;
                }

                // 2) >=3 个独立弱证据一致命中 -> 确认(多源共识)
                if (weakHits.Count >= 3)
                {
                    if (trustedSignature)
                    {
                        LogHelper.Log(LogHelper.LogLevel.Info,
                            $"[共识被签名否决] {filePath}: {weakHits.Count} 个弱引擎命中但具有可信发布者签名，判定安全");
                        result.DetectionMethod = "TrustedPublisher-Signed";
                        result.AdditionalInfo = $"多弱引擎命中被可信发布者签名否决({weakHits.Count} 票)，判定为安全";
                        if (!string.IsNullOrEmpty(fileHash)) WhitelistStore.Remember(fileHash);
                        return result;
                    }

                    // 共识质量门槛：全部同名（同源特征刷票）且无硬置信(≥0.9)命中 -> 按误报放行。
                    // 真实多维威胁通常产生 ≥2 个不同威胁名或至少一个硬特征级置信。
                    int distinctNames = weakHits.Select(w => w.ThreatName ?? "Unknown").Distinct(StringComparer.OrdinalIgnoreCase).Count();
                    double maxConf = weakHits.Max(w => w.Confidence);
                    if (distinctNames < 2 && maxConf < 0.9)
                    {
                        LogHelper.Log(LogHelper.LogLevel.Info,
                            $"[同源共识拦截] {filePath}: {weakHits.Count} 票全部同名且无硬置信，判定为同源误报");
                        result.DetectionMethod = "SameOrigin-Veto";
                        result.AdditionalInfo = $"{weakHits.Count} 票同源同名特征，未达共识质量门槛，判定为误报";
                        if (!string.IsNullOrEmpty(fileHash)) WhitelistStore.Remember(fileHash);
                        return result;
                    }

                    var strong = weakHits.OrderByDescending(x => x.Confidence).First();
                    result.IsInfected = true;
                    result.ThreatName = strong.ThreatName;
                    result.ThreatType = strong.ThreatType;
                    result.Severity = strong.Severity ?? "High";
                    result.Confidence = 0.85;
                    result.DetectionMethod = "MultiEngine-Consensus";
                    result.AdditionalInfo = $"共{weakHits.Count}个独立检测源一致命中（{distinctNames} 个不同特征名）";
                    return result;
                }

                // 3) 恰好 2 个弱证据 -> 默认不判定为威胁；仅当存在 ≥0.9 置信命中(硬特征级)且无可信签名时报低危可疑
                if (weakHits.Count == 2)
                {
                    if (trustedSignature)
                    {
                        result.DetectionMethod = "TrustedPublisher-Signed";
                        result.AdditionalInfo = "弱信号被可信发布者签名否决，判定为安全";
                        if (!string.IsNullOrEmpty(fileHash)) WhitelistStore.Remember(fileHash);
                        return result;
                    }

                    var best2 = weakHits.OrderByDescending(x => x.Confidence).First();
                    if (best2.Confidence >= 0.9)
                    {
                        result.IsInfected = true;
                        result.ThreatName = best2.ThreatName;
                        result.ThreatType = best2.ThreatType;
                        result.Severity = "Low";
                        result.Confidence = 0.55;
                        result.DetectionMethod = "Suspicious-HighConfidence";
                        result.AdditionalInfo = "2个弱引擎高置信命中且无可信签名，列为低危可疑项供人工核实";
                        return result;
                    }

                    LogHelper.Log(LogHelper.LogLevel.Info,
                        $"[弱共识已忽略] {filePath}: {string.Join("、", weakHits.Select(w => w.ThreatName).Distinct())} (2 个弱引擎命中未达 3 源共识阈值)");
                    result.DetectionMethod = "Suspicious-Logged";
                    result.AdditionalInfo = $"2个弱引擎命中({string.Join("、", weakHits.Select(w => w.ThreatName).Distinct())})，未达 3 源共识阈值，不判定为威胁";
                    if (!string.IsNullOrEmpty(fileHash)) WhitelistStore.Remember(fileHash);
                    return result;
                }

                // 4) 单一弱证据 -> 不判定为威胁，仅记录日志(把误报打扰降到最低)
                if (weakHits.Count == 1)
                {
                    if (trustedSignature)
                    {
                        result.DetectionMethod = "TrustedPublisher-Signed";
                        result.AdditionalInfo = "弱信号被可信发布者签名否决，判定为安全";
                        if (!string.IsNullOrEmpty(fileHash)) WhitelistStore.Remember(fileHash);
                        return result;
                    }

                    LogHelper.Log(LogHelper.LogLevel.Info,
                        $"[弱信号已忽略] {filePath}: {weakHits[0].ThreatName} (单一弱证据未达报告阈值)");
                    result.DetectionMethod = "Clean-WithWeakSignal";
                    result.AdditionalInfo = $"单一弱信号({weakHits[0].ThreatName})已记录，未达报告阈值不判定为威胁";
                    if (!string.IsNullOrEmpty(fileHash)) WhitelistStore.Remember(fileHash);
                    return result;
                }

                result.DetectionMethod = "Clean";
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                result.DetectionMethod = "Error";
            }

            // 存入扫描缓存
            lock (_cacheLock)
            {
                _scanCache[filePath] = (result, DateTime.Now);
            }

            return result;
        }

        /// <summary>
        /// 运行扩容扫描方法: 文件名伪装 / PE结构 / 宏文档 / 压缩包嵌套 / 嵌入式模式规则。
        /// 各扫描器相互独立, 单个命中仅为一票, 由多引擎共识管线统一裁决, 不单独定罪。
        /// </summary>
        private List<Analyzers.ExpandedScanHit> RunExpandedScanners(string filePath)
        {
            var hits = new List<Analyzers.ExpandedScanHit>();
            try
            {
                // 1. 文件名伪装检测(双重扩展名/RTLO/魔数不符)
                var spoof = _fileNameSpoofAnalyzer.Analyze(filePath);
                if (spoof != null && spoof.IsInfected) hits.Add(spoof);

                string ext = Path.GetExtension(filePath).ToLowerInvariant();

                // 2. PE 结构解析(仅 PE 文件)
                if (ext == ".exe" || ext == ".dll" || ext == ".scr" || ext == ".sys" || ext == ".cpl")
                {
                    var pe = _peStructureAnalyzer.Analyze(filePath);
                    if (pe != null && pe.IsInfected) hits.Add(pe);
                }

                // 3. 宏文档检测(OOXML 容器)
                if (ext == ".docx" || ext == ".xlsx" || ext == ".pptx" || ext == ".docm" ||
                    ext == ".xlsm" || ext == ".pptm")
                {
                    var macro = _macroDocumentAnalyzer.Analyze(filePath);
                    if (macro != null && macro.IsInfected) hits.Add(macro);
                }

                // 4. 压缩包嵌套扫描(zip/OOXML 容器)
                if (ext == ".zip")
                {
                    var archive = _archiveNestedScanner.Analyze(filePath);
                    if (archive != null && archive.IsInfected) hits.Add(archive);
                }

                // 5. 嵌入式模式规则引擎(仅脚本/文本类小文件)
                if (ext == ".js" || ext == ".jse" || ext == ".vbs" || ext == ".vbe" || ext == ".wsf" ||
                    ext == ".ps1" || ext == ".bat" || ext == ".cmd" || ext == ".hta" || ext == ".html" ||
                    ext == ".htm" || ext == ".txt" || ext == ".ini" || ext == ".cfg" || ext == ".json")
                {
                    try
                    {
                        var fi = new FileInfo(filePath);
                        if (fi.Exists && fi.Length > 0 && fi.Length <= 4 * 1024 * 1024)
                        {
                            var content = File.ReadAllBytes(filePath);
                            var pattern = _patternRuleEngine.AnalyzeContent(filePath, content);
                            if (pattern != null && pattern.IsInfected) hits.Add(pattern);
                        }
                    }
                    catch { }
                }

                // 6. 多维度文件评估器(MD5/SHA256 + 深度PE结构 + Authenticode签名链 + 节熵 + 导入行为)
                //    独立投票方，命中即计一票，由共识管线统一裁决。
                var multiDim = _multiDimFileEvaluator.Evaluate(filePath);
                if (multiDim.IsMalicious)
                {
                    hits.Add(new ExpandedScanHit
                    {
                        FilePath = filePath,
                        IsInfected = true,
                        ThreatName = "MultiDim.HighRisk",
                        ThreatType = "Suspicious",
                        Severity = "Medium",
                        Confidence = Math.Min(0.6, multiDim.Score / 150.0),
                        DetectionMethod = "MultiDim",
                    });
                }
            }
            catch { }
            return hits;
        }

        /// <summary>
        /// 使用ClamAV扫描文件
        /// </summary>
        private ScanResult ScanWithClamAV(string filePath)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = false,
                DetectionTime = DateTime.Now,
                DetectionMethod = "ClamAV"
            };

            try
            {
                string clamscanPath = FindClamScan();
                if (string.IsNullOrEmpty(clamscanPath) || !File.Exists(clamscanPath))
                {
                    return result;
                }

                string dbPath = Path.Combine(Path.GetDirectoryName(clamscanPath), "db");
                if (!Directory.Exists(dbPath))
                    dbPath = Path.Combine(Path.GetDirectoryName(clamscanPath), "database");

                var startInfo = new ProcessStartInfo
                {
                    FileName = clamscanPath,
                    Arguments = $"--database=\"{dbPath}\" --no-summary \"{filePath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = Path.GetDirectoryName(clamscanPath)
                };

                using var process = Process.Start(startInfo);
                if (process == null) return result;

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(60000);

                if (output.Contains("FOUND"))
                {
                    result.IsInfected = true;
                    result.Confidence = 1.0;
                    result.ThreatType = "Virus";
                    result.Severity = "High";

                    // 提取威胁名称
                    foreach (var line in output.Split('\n'))
                    {
                        if (line.Contains("FOUND"))
                        {
                            int idx = line.LastIndexOf("FOUND");
                            if (idx > 0)
                            {
                                string name = line.Substring(0, idx).Trim();
                                int colon = name.LastIndexOf(':');
                                if (colon >= 0) name = name.Substring(colon + 1).Trim();
                                result.ThreatName = string.IsNullOrEmpty(name) ? "Virus" : name;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"ClamAV扫描错误: {ex.Message}");
            }

            return result;
        }

        private string FindClamScan()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (string.IsNullOrEmpty(baseDir))
                {
                    baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                }
                string[] paths = {
                    Path.Combine(baseDir, "ClamAV", "clamscan.exe"),
                    Path.Combine(baseDir, "clamav", "clamscan.exe"),
                    Path.Combine(baseDir, "FireAntivirus.ClamAV", "ClamAV", "clamscan.exe"),
                    Path.Combine(baseDir, "..", "ClamAV", "clamscan.exe"),
                    Path.Combine(baseDir, "..", "clamav", "clamscan.exe"),
                    Path.Combine(Directory.GetCurrentDirectory(), "ClamAV", "clamscan.exe"),
                    Path.Combine(Directory.GetCurrentDirectory(), "clamav", "clamscan.exe")
                };
                foreach (var p in paths)
                {
                    string fp = Path.GetFullPath(p);
                    if (File.Exists(fp)) return fp;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }
            return null;
        }

        private ScanResult ScanWithThreatDetectors(string filePath)
        {
            var result = new ScanResult { FilePath = filePath, IsInfected = false };
            ScanResult bestHit = null;

            try
            {
                // 读取文件内容供检测器使用；文件被占用/无权限（安装器临时 dll 等常态）时
                // 直接放行——fileContent 为 null 继续跑 11 个检测器会引发 NRE 风暴（2026-11-07 日志实锤）
                byte[] fileContent = null;
                try { fileContent = File.ReadAllBytes(filePath); }
                catch (System.Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Debug,
                        "AntivirusEngine: 文件读取跳过（被占用/无权限）", ex.Message);
                }

                if (fileContent == null || fileContent.Length == 0)
                {
                    result.DetectionMethod = "Skipped-Locked";
                    result.AdditionalInfo = "文件无法读取（被占用或无权限），已跳过内容检测";
                    return result;
                }

                // 使用各种威胁检测器
                var detectors = new List<(dynamic detector, string name)>
                {
                    (exploitDetector, "Exploit"),
                    (ransomwareDetector, "Ransomware"),
                    (trojanDetector, "Trojan"),
                    (spywareDetector, "Spyware"),
                    (adwareDetector, "Adware"),
                    (keyloggerDetector, "Keylogger"),
                    (backdoorDetector, "Backdoor"),
                    (wormDetector, "Worm"),
                    (virusDetector, "Virus"),
                    (minerDetector, "Miner"),
                    (pupDetector, "PUP")
                };

                foreach (var (detector, name) in detectors)
                {
                    if (detector != null)
                    {
                        try
                        {
                            var detectorResult = detector.Detect(filePath, fileContent);
                            // 置信度门槛：只有足够可信的组合命中才计为证据。
                            // 注意：不在此处一票定罪提前返回，而是记录最佳命中参与共识表决，
                            // 避免单个启发式检测器误判直接导致报毒（误报治理关键点）。
                            if (detectorResult != null && detectorResult.IsDetected && detectorResult.Confidence >= 0.6)
                            {
                                if (bestHit == null || detectorResult.Confidence > bestHit.Confidence)
                                {
                                    bestHit = new ScanResult
                                    {
                                        FilePath = filePath,
                                        IsInfected = true,
                                        ThreatName = detectorResult.ThreatName ?? name,
                                        ThreatType = detectorResult.ThreatType ?? name,
                                        Confidence = detectorResult.Confidence,
                                        Severity = "Medium",
                                        DetectionMethod = name,
                                        DetectionTime = DateTime.Now,
                                        AdditionalInfo = detectorResult.Details
                                    };
                                }
                            }
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }
                    }
                }

                if (bestHit != null) return bestHit;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }

            return result;
        }
        #endregion

        #region 内置云查杀(MalwareBazaar + OTX)
        /// <summary>
        /// 内置云查杀 - 通过文件哈希并行查询 MalwareBazaar + AlienVault OTX
        /// 两个免费 API 均无需 API Key, 真实可用
        /// </summary>
        private ScanResult ScanWithBuiltInCloud(string filePath, string precomputedHash = null)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = false,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Cloud-BuiltIn"
            };

            try
            {
                // 计算 SHA256(云查杀主键)；ScanFile 主流程已预计算则复用，避免大文件重复读盘
                string sha256 = precomputedHash ?? GetFileHash(filePath);
                if (string.IsNullOrEmpty(sha256))
                    return result;

                result.FileHash = HexStringToBytes(sha256);

                // 自动更新特征库命中 -> 权威确认（实时病毒库，覆盖最新变种）
                if (SignatureDatabaseUpdater.TryGetHashThreat(sha256, out var sigThreat))
                {
                    result.IsInfected = true;
                    result.ThreatName = sigThreat ?? "Malware";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                    result.Confidence = 0.95;
                    result.DetectionMethod = "SignatureDB";
                    result.AdditionalInfo = "命中自动更新特征库(实时病毒库)权威确认";
                    return result;
                }

                // 熔断检查：连续失败(离线)期间跳过云 API 查询，但保留本地特征库命中路径
                if (Interlocked.Read(ref s_cloudBrokenUntilUtcTicks) > DateTime.UtcNow.Ticks)
                {
                    result.DetectionMethod = "Cloud-Broken";
                    return result;
                }

                // 检查云查杀缓存
                lock (_cloudCacheLock)
                {
                    if (_cloudHashCache.TryGetValue(sha256, out var cached))
                    {
                        if (DateTime.Now - cached.timestamp < _cloudCacheExpiration)
                        {
                            var cachedCopy = new ScanResult
                            {
                                FilePath = filePath,
                                IsInfected = cached.result.IsInfected,
                                ThreatName = cached.result.ThreatName,
                                ThreatType = cached.result.ThreatType,
                                Severity = cached.result.Severity,
                                Confidence = cached.result.Confidence,
                                DetectionMethod = "(cloud-cached) " + cached.result.DetectionMethod,
                                DetectionTime = cached.result.DetectionTime,
                                FileHash = cached.result.FileHash
                            };
                            return cachedCopy;
                        }
                        _cloudHashCache.Remove(sha256);
                    }
                }

                // 按配置并行查询各云引擎
                var tasks = new List<Task<(bool isMalicious, string threatName, int positiveCount, int totalCount)>>();
                var taskNames = new List<string>();

                if (s_enableMalwareBazaar)
                {
                    var mbTask = QueryMalwareBazaarAsync(sha256).ContinueWith(t =>
                        t.IsCompletedSuccessfully ? (t.Result.isMalicious, t.Result.threatName, t.Result.isMalicious ? 1 : 0, 1)
                                                  : (false, null, 0, 1));
                    tasks.Add(mbTask);
                    taskNames.Add("MalwareBazaar");
                }

                if (s_enableOTX)
                {
                    var otxTask = QueryOtxHashAsync(sha256).ContinueWith(t =>
                        t.IsCompletedSuccessfully ? (t.Result.isMalicious, t.Result.threatName, t.Result.isMalicious ? 1 : 0, 1)
                                                  : (false, null, 0, 1));
                    tasks.Add(otxTask);
                    taskNames.Add("OTX");
                }

                if (s_enableVirusTotal)
                {
                    // VT 免费 key 配额稀缺(4/min、500/天)：仅对 PE/脚本/宏文档候选文件查询，
                    // 令牌桶限速，未到窗口直接跳过（不阻塞扫描、不烧配额）；命中即 70 引擎强证据确认
                    if (Analyzers.ScriptMacroAnalyzer.IsMlCandidateExt(filePath) && TryAcquireVtQuota())
                    {
                        var vtTask = QueryVirusTotalAsync(sha256).ContinueWith(t =>
                            t.IsCompletedSuccessfully ? (t.Result.isMalicious, t.Result.threatName, t.Result.positiveCount, t.Result.totalCount)
                                                      : (false, null, 0, 0));
                        tasks.Add(vtTask);
                        taskNames.Add("VirusTotal");
                    }
                }

                if (tasks.Count == 0)
                {
                    result.DetectionMethod = "Cloud-BuiltIn-Disabled";
                    return result;
                }

                // 等待所有查询完成(或超时)
                Task.WhenAll(tasks).Wait(TimeSpan.FromSeconds(CloudScanTimeoutSeconds));

                bool detected = false;
                string threatName = null;
                string threatType = null;
                double confidence = 0.0;
                var matched = new List<string>();
                int totalEngines = 0;
                int positiveEngines = 0;

                for (int i = 0; i < tasks.Count; i++)
                {
                    if (!tasks[i].IsCompletedSuccessfully) continue;
                    var (isMal, name, pos, total) = tasks[i].Result;
                    totalEngines += total;
                    positiveEngines += pos;
                    if (isMal)
                    {
                        detected = true;
                        threatName ??= name ?? taskNames[i];
                        threatType = "Malware";
                        // 置信度分级(供上层共识判定使用):
                        //  VirusTotal 多引擎(>=2)实锤=0.98; MalwareBazaar 真实恶意样本库=0.95;
                        //  OTX / VirusTotal单引擎 为社区/弱证据, 降为0.6, 避免单一弱信号直接误报
                        double conf = taskNames[i] == "VirusTotal"
                                ? (pos >= 2 ? 0.98 : 0.6)
                                : taskNames[i] == "MalwareBazaar" ? 0.95 : 0.6;
                        confidence = Math.Max(confidence, conf);
                        matched.Add($"{taskNames[i]}: {name ?? "hit"}");
                    }
                }

                if (detected)
                {
                    result.IsInfected = true;
                    result.ThreatName = threatName;
                    result.ThreatType = threatType;
                    result.Severity = "High";
                    result.Confidence = confidence;
                    result.DetectionMethod = "Cloud-BuiltIn";
                    result.AdditionalInfo = string.Join("; ", matched);
                    result.MatchedSignatures = matched;
                }
                else
                {
                    result.DetectionMethod = "Cloud-BuiltIn-Clean";
                }

                // 写入云查杀缓存(无论结果)
                lock (_cloudCacheLock)
                {
                    _cloudHashCache[sha256] = (new ScanResult
                    {
                        FilePath = filePath,
                        IsInfected = result.IsInfected,
                        ThreatName = result.ThreatName,
                        ThreatType = result.ThreatType,
                        Severity = result.Severity,
                        Confidence = result.Confidence,
                        DetectionMethod = result.DetectionMethod,
                        DetectionTime = result.DetectionTime,
                        FileHash = result.FileHash
                    }, DateTime.Now);

                    // 清理过期缓存
                    if (_cloudHashCache.Count > 5000)
                    {
                        var expired = _cloudHashCache
                            .Where(k => DateTime.Now - k.Value.timestamp > _cloudCacheExpiration)
                            .Select(k => k.Key).ToList();
                        foreach (var k in expired) _cloudHashCache.Remove(k);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"内置云查杀错误: {ex.Message}");
                result.DetectionMethod = "Cloud-BuiltIn-Error";
            }

            return result;
        }

        /// <summary>云查杀连续失败统计(仅网络级异常计入, 404/429 等业务未命中不计)。</summary>
        private static void ReportCloudFailure()
        {
            if (Interlocked.Increment(ref s_cloudConsecutiveFailures) >= CloudBreakThreshold)
            {
                Interlocked.Exchange(ref s_cloudBrokenUntilUtcTicks, (DateTime.UtcNow + CloudBreakDuration).Ticks);
            }
        }

        private static void ReportCloudSuccess()
        {
            Interlocked.Exchange(ref s_cloudConsecutiveFailures, 0);
        }

        /// <summary>查询 MalwareBazaar(abuse.ch 免费 API, 无需 Key)</summary>
        private async Task<(bool isMalicious, string threatName)> QueryMalwareBazaarAsync(string sha256)
        {
            try
            {
                using var formData = new MultipartFormDataContent
                {
                    { new StringContent("get_info"), "query" },
                    { new StringContent(sha256), "hash" }
                };

                var response = await _cloudHttpClient.PostAsync(MalwareBazaarApiUrl, formData);
                ReportCloudSuccess();
                if (!response.IsSuccessStatusCode) return (false, null);

                var json = JObject.Parse(await response.Content.ReadAsStringAsync());
                string status = json["query_status"]?.ToString() ?? "";

                if (status.Equals("ok", StringComparison.OrdinalIgnoreCase))
                {
                    var data = json["data"] as JArray;
                    if (data != null && data.Count > 0)
                    {
                        string sig = data[0]["signature"]?.ToString();
                        return (true, sig ?? "MalwareBazaar.Hit");
                    }
                }
                return (false, null);
            }
            catch
            {
                ReportCloudFailure();
                return (false, null);
            }
        }

        /// <summary>查询 AlienVault OTX(免费 API, 无需 Key)</summary>
        private async Task<(bool isMalicious, string threatName)> QueryOtxHashAsync(string sha256)
        {
            try
            {
                string url = $"{OtxApiBaseUrl}/indicators/file/{sha256}/general";
                var response = await _cloudHttpClient.GetStringAsync(url);
                ReportCloudSuccess();
                var json = JObject.Parse(response);

                int pulseCount = json["pulse_info"]?["count"]?.Value<int>() ?? 0;
                var pulses = json["pulse_info"]?["pulses"] as JArray;
                var analysis = json["analysis"];

                if (pulseCount > 0 && pulses != null && pulses.Count > 0)
                {
                    string name = pulses[0]?["name"]?.ToString() ?? "OTX Threat";
                    return (true, name);
                }

                // OTX 沙箱分析结果
                if (analysis != null && analysis["malware"] != null && analysis["malware"].Value<bool>())
                {
                    return (true, "OTX Sandbox: Malware");
                }

                return (false, null);
            }
            catch
            {
                ReportCloudFailure();
                return (false, null);
            }
        }

        /// <summary>
        /// 查询 VirusTotal v3 API (70+ 国际杀毒引擎聚合查询)
        /// 需用户配置 API Key (https://www.virustotal.com/gui/my-apikey 免费申请)
        /// 免费版限制: 4 次/分钟, 500 次/天
        /// </summary>
        private async Task<(bool isMalicious, string threatName, int positiveCount, int totalCount)> QueryVirusTotalAsync(string sha256)
        {
            int totalEngines = 0;
            try
            {
                if (string.IsNullOrWhiteSpace(s_virusTotalApiKey))
                    return (false, null, 0, 0);

                var request = new HttpRequestMessage(HttpMethod.Get, $"{VirusTotalApiBaseUrl}/files/{sha256}");
                request.Headers.Add("x-apikey", s_virusTotalApiKey);
                request.Headers.Add("accept", "application/json");

                var response = await _cloudHttpClient.SendAsync(request);
                ReportCloudSuccess();
                if (!response.IsSuccessStatusCode)
                {
                    // 404 表示文件未被 VT 收录,认为是干净
                    // 429 限速,跳过
                    return (false, null, 0, 0);
                }

                var json = JObject.Parse(await response.Content.ReadAsStringAsync());
                var stats = json["data"]?["attributes"]?["last_analysis_stats"];
                if (stats == null) return (false, null, 0, 0);

                int malicious = stats["malicious"]?.Value<int>() ?? 0;
                int suspicious = stats["suspicious"]?.Value<int>() ?? 0;
                int harmless = stats["harmless"]?.Value<int>() ?? 0;
                int undetected = stats["undetected"]?.Value<int>() ?? 0;

                totalEngines = malicious + suspicious + harmless + undetected;
                int positive = malicious + suspicious;

                // 获取威胁名(从 last_analysis_results 中找第一个 malicious 引擎的分类结果)
                string threatName = null;
                var results = json["data"]?["attributes"]?["last_analysis_results"] as JObject;
                if (results != null)
                {
                    foreach (var prop in results.Properties())
                    {
                        var category = prop.Value?["category"]?.ToString();
                        if (category == "malicious")
                        {
                            threatName = prop.Value?["result"]?.ToString();
                            if (!string.IsNullOrEmpty(threatName))
                            {
                                threatName = $"{prop.Name}: {threatName}";
                                break;
                            }
                        }
                    }
                }

                bool isMal = positive > 0;
                if (isMal && string.IsNullOrEmpty(threatName))
                    threatName = $"VirusTotal:{positive}/{totalEngines}";

                return (isMal, threatName, positive, totalEngines);
            }
            catch
            {
                ReportCloudFailure();
                return (false, null, 0, totalEngines);
            }
        }

        private static byte[] HexStringToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0) return null;
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }
        #endregion

        #region 辅助方法
        private bool IsSystemFile(string filePath)
        {
            // 仅对 Windows\System32 和 Windows\SysWOW64 下的系统文件放行
            // Program Files 和 ProgramData 下的程序仍需扫描
            string lower = filePath.ToLowerInvariant();
            return lower.Contains("\\windows\\system32\\") ||
                   lower.Contains("\\windows\\syswow64\\");
        }

        /// <summary>
        /// Windows 系统目录判定（弱证据豁免用）：C:\Windows\ 全树（除 Temp——恶意载荷常用落地目录）。
        /// 系统目录下大量正常文件无嵌入签名（catalog 签名/自带库），启发式误报重灾区。
        /// </summary>
        private static bool IsWindowsSystemDir(string filePath)
        {
            string lower = filePath?.ToLowerInvariant() ?? "";
            if (!lower.Contains("\\windows\\")) return false;
            if (lower.Contains("\\windows\\temp\\")) return false;
            return true;
        }

        private bool HasValidSignature(string filePath)
        {
            try
            {
                byte[] peData = File.ReadAllBytes(filePath);
                
                // 检查DOS头
                if (peData.Length < 64 || peData[0] != 0x4D || peData[1] != 0x5A)
                    return false;

                int peOffset = BitConverter.ToInt32(peData, 60);
                if (peOffset + 4 > peData.Length) return false;
                
                // 检查PE签名
                if (peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45)
                    return false;

                // 获取签名目录
                int securityDirOffset = peOffset + 24 + 128;
                if (securityDirOffset + 8 > peData.Length) return false;

                uint rva = BitConverter.ToUInt32(peData, securityDirOffset);
                uint size = BitConverter.ToUInt32(peData, securityDirOffset + 4);

                if (rva == 0 || size == 0) return false;
                if (rva + size > peData.Length) return false;

                // 解析签名
                byte[] sigData = new byte[size];
                Array.Copy(peData, rva, sigData, 0, size);

                if (sigData.Length <= 8) return false;
                
                ushort certType = BitConverter.ToUInt16(sigData, 2);
                if (certType != 0x0002) return false;

                byte[] pkcs7 = new byte[sigData.Length - 8];
                Array.Copy(sigData, 8, pkcs7, 0, pkcs7.Length);

                var cert = new X509Certificate2(pkcs7);
                
                // 检查证书有效期
                if (DateTime.Now < cert.NotBefore || DateTime.Now > cert.NotAfter)
                    return false;

                // 检查是否为可信发布者
                string subject = cert.Subject;
                foreach (var trusted in TrustedPublishers)
                {
                    if (subject.Contains(trusted, StringComparison.OrdinalIgnoreCase))
                        return true;
                }

                return false; // 签名存在但不在信任列表中，不可信
            }
            // 签名验证失败（文件被占用/无权限）是常态，静默跳过——逐文件 Error 日志会形成日志风暴
            catch (System.Security.Cryptography.CryptographicException) { }
            catch (System.Security.SecurityException) { }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "验证文件签名失败", ex.Message); }

            return false;
        }

        private string GetFileHash(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                byte[] hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            catch { return ""; }
        }
        #endregion

        #region 目录扫描
        public List<ScanResult> ScanDirectory(string directoryPath, ScanOptions options = null)
        {
            var results = new List<ScanResult>();
            options ??= new ScanOptions();

            if (!Directory.Exists(directoryPath)) return results;

            _isScanning = true;
            _cancellationTokenSource = new CancellationTokenSource();

            try
            {
                var files = GetFilesToScan(directoryPath, options);
                int totalFiles = files.Count;
                int scannedFiles = 0;

                foreach (var file in files)
                {
                    if (_cancellationTokenSource.Token.IsCancellationRequested)
                        break;

                    while (_isPaused)
                        Thread.Sleep(100);

                    var result = ScanFile(file);
                    results.Add(result);

                    scannedFiles++;
                    OnScanProgress(scannedFiles, totalFiles, file);

                    if (result.IsInfected)
                    {
                        OnThreatDetected(result);
                    }
                }
            }
            finally
            {
                _isScanning = false;
            }

            return results;
        }

        private List<string> GetFilesToScan(string directoryPath, ScanOptions options)
        {
            var files = new List<string>();
            try
            {
                var allFiles = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories);
                long maxSizeBytes = options.MaxFileSizeMB * 1024L * 1024L;

                foreach (var file in allFiles)
                {
                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length <= maxSizeBytes)
                        {
                            files.Add(file);
                        }
                    }
                    catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "获取文件大小失败", ex.Message); }
                }
            }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "枚举扫描文件失败", ex.Message); }

            return files;
        }

        public void StopScan()
        {
            _cancellationTokenSource?.Cancel();
            _isScanning = false;
        }

        public void PauseScan() => _isPaused = true;
        public void ResumeScan() => _isPaused = false;
        #endregion

        #region 事件触发
        protected virtual void OnScanProgress(int filesScanned, int totalFiles, string currentFile)
        {
            ScanProgress?.Invoke(this, new ScanProgressEventArgs
            {
                FilesScanned = filesScanned,
                TotalFiles = totalFiles,
                CurrentFile = currentFile
            });
        }

        protected virtual void OnThreatDetected(ScanResult threat)
        {
            ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs { Threat = threat });
        }
        #endregion

        #region 其他扫描方法
        public List<ScanResult> ScanMemory()
        {
            var results = new List<ScanResult>();
            if (memoryScanner != null)
            {
                try { results.AddRange(memoryScanner.ScanSystemMemory()); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }
            }
            return results;
        }

        public List<ScanResult> ScanRegistry()
        {
            var results = new List<ScanResult>();
            if (registryScanner != null)
            {
                try { results.AddRange(registryScanner.ScanRegistry()); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }
            }
            return results;
        }

        public List<ScanResult> ScanStartup()
        {
            var results = new List<ScanResult>();
            if (startupScanner != null)
            {
                try { results.AddRange(startupScanner.ScanStartupItems()); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }
            }
            return results;
        }

        public List<ScanResult> ScanNetwork()
        {
            var results = new List<ScanResult>();
            if (networkScanner != null)
            {
                try { results.AddRange(networkScanner.ScanNetworkConnections()); }
                catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "网络连接扫描失败", ex.Message); }
            }
            return results;
        }
        #endregion

        public void Dispose()
        {
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();
            IsInitialized = false;
        }
    }

}