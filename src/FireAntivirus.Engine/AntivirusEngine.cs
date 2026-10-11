// 耄耋软件工作室 开发，严禁非法反编译
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
        private static volatile bool s_enableVirusTotal = false;        // 默认禁用,需用户配置 Key
        private static volatile bool s_enableHybridAnalysis = false;    // 默认禁用,需用户配置 Key
        private static string s_virusTotalApiKey = string.Empty;
        private static string s_hybridAnalysisApiKey = string.Empty;

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
            s_enableVirusTotal = enableVirusTotal && !string.IsNullOrWhiteSpace(virusTotalApiKey);
            s_enableHybridAnalysis = enableHybridAnalysis && !string.IsNullOrWhiteSpace(hybridAnalysisApiKey);
            s_virusTotalApiKey = virusTotalApiKey ?? string.Empty;
            s_hybridAnalysisApiKey = hybridAnalysisApiKey ?? string.Empty;
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
                // MalwareBazaar(真实恶意样本库) / VirusTotal(70+引擎聚合) / OTX(社区情报)
                // 命中且置信度高(>=0.8)即权威确认; 置信度低(<0.8)则作为一票参与下方共识表决
                ScanResult cloudResult = null;
                bool cloudHit = false;
                bool cloudConfirmed = false;
                if (EnableCloudScan)
                {
                    cloudResult = ScanWithBuiltInCloud(filePath);
                    cloudHit = cloudResult != null && cloudResult.IsInfected;
                    cloudConfirmed = cloudHit && cloudResult.Confidence >= 0.8;
                }

                // 云端权威确认(MB实库 / VT多引擎) -> 直接判定, 杜绝漏报
                if (cloudConfirmed)
                {
                    cloudResult.Confidence = Math.Max(cloudResult.Confidence, 0.95);
                    cloudResult.AdditionalInfo = "云端多引擎(实时病毒库)权威确认";
                    return cloudResult;
                }

                // ===== 本地多引擎并行收集证据 =====
                // ClamAV特征 + 启发式 + 静态 + 威胁检测器, 全部参与计数, 互相印证
                var localHits = new List<ScanResult>();
                if (cloudHit) localHits.Add(cloudResult); // 云端弱信号也计入一票, 不漏报

                var clamavResult = ScanWithClamAV(filePath);
                if (clamavResult.IsInfected) localHits.Add(clamavResult);

                if (heuristicEngine != null)
                {
                    var heuristicHit = heuristicEngine.AnalyzeFile(filePath).FirstOrDefault() ?? new ScanResult { FilePath = filePath };
                    if (heuristicHit.IsInfected) localHits.Add(heuristicHit);
                }

                if (staticAnalyzer != null)
                {
                    var staticHit = staticAnalyzer.AnalyzeFile(filePath).FirstOrDefault() ?? new ScanResult { FilePath = filePath };
                    if (staticHit.IsInfected) localHits.Add(staticHit);
                }

                var threatResult = ScanWithThreatDetectors(filePath);
                if (threatResult.IsInfected) localHits.Add(threatResult);

                // ===== 扩容扫描方法(独立投票方, 参与共识表决) =====
                foreach (var expandedHit in RunExpandedScanners(filePath))
                {
                    if (expandedHit != null && expandedHit.IsInfected)
                    {
                        localHits.Add(new ScanResult
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

                int localVotes = localHits.Count;

                // ===== 多引擎共识判定(杜绝误报) =====
                // ≥2个独立引擎一致命中 -> 确认感染
                if (localVotes >= 2)
                {
                    var strong = localHits.OrderByDescending(x => x.Confidence).First();
                    result.IsInfected = true;
                    result.ThreatName = strong.ThreatName;
                    result.ThreatType = strong.ThreatType;
                    result.Severity = strong.Severity ?? "High";
                    result.Confidence = 0.9;
                    result.DetectionMethod = "MultiEngine-Consensus";
                    result.AdditionalInfo = $"本地/云端共{localVotes}个检测引擎一致命中, 云端未权威确认或未收录";
                    return result;
                }

                // 单一引擎命中,云端未权威确认 -> 报为"可疑/低置信"
                // 保留上报(不漏报), 同时低置信并提示可能存在误报(杜绝对误报误杀)
                if (localVotes == 1)
                {
                    var s = localHits[0];
                    result.IsInfected = true;
                    result.ThreatName = s.ThreatName;
                    result.ThreatType = s.ThreatType;
                    result.Severity = "Low";
                    result.Confidence = Math.Min(Math.Max(s.Confidence, 0.35), 0.5);
                    result.DetectionMethod = "Suspicious-Single";
                    result.AdditionalInfo = "仅单一引擎命中且云端未权威确认, 可能存在误报, 请人工核实后再处理";
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

            try
            {
                // 读取文件内容供检测器使用
                byte[] fileContent = null;
                try { fileContent = File.ReadAllBytes(filePath); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }

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
                            // 置信度门槛：只有足够可信的组合命中才计为证据，弱信号不计票，避免正常程序被乱报
                            if (detectorResult != null && detectorResult.IsDetected && detectorResult.Confidence >= 0.6)
                            {
                                return new ScanResult
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
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AntivirusEngine.cs 捕获异常", ex.Message); }
                    }
                }
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
        private ScanResult ScanWithBuiltInCloud(string filePath)
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
                // 计算 SHA256(云查杀主键)
                string sha256 = GetFileHash(filePath);
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
                    var vtTask = QueryVirusTotalAsync(sha256);
                    tasks.Add(vtTask);
                    taskNames.Add("VirusTotal");
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