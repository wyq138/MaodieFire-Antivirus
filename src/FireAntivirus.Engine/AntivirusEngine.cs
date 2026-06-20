// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
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
        #endregion

        #region 字段和属性
        private DataManager dataManager;
        private bool _isScanning;
        private bool _isPaused;
        private CancellationTokenSource _cancellationTokenSource;
        
        public bool IsInitialized { get; private set; } = true;
        
        // 分析器
        private HeuristicEngine heuristicEngine;
        private BehaviorAnalyzer behaviorAnalyzer;
        private StaticAnalyzer staticAnalyzer;
        private MemoryScanner memoryScanner;
        private RegistryScanner registryScanner;
        private StartupScanner startupScanner;
        private NetworkScanner networkScanner;
        private ProcessAnalyzer processAnalyzer;
        private FileAnalyzer fileAnalyzer;
        private ScriptAnalyzer scriptAnalyzer;
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
        }

        private void InitializeAnalyzers()
        {
            try
            {
                heuristicEngine = new HeuristicEngine();
                behaviorAnalyzer = new BehaviorAnalyzer();
                staticAnalyzer = new StaticAnalyzer();
                memoryScanner = new MemoryScanner();
                registryScanner = new RegistryScanner();
                startupScanner = new StartupScanner();
                networkScanner = new NetworkScanner();
                processAnalyzer = new ProcessAnalyzer();
                fileAnalyzer = new FileAnalyzer();
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

                // 3. ClamAV病毒扫描
                var clamavResult = ScanWithClamAV(filePath);
                if (clamavResult.IsInfected)
                {
                    return clamavResult;
                }

                // 4. 启发式分析
                if (heuristicEngine != null)
                {
                    var heuristicResult = heuristicEngine.Scan(filePath);
                    if (heuristicResult.IsInfected && heuristicResult.Confidence > 0.9)
                    {
                        return heuristicResult;
                    }
                }

                // 5. 静态分析
                if (staticAnalyzer != null)
                {
                    var staticResult = staticAnalyzer.AnalyzeFile(filePath).FirstOrDefault() ?? new ScanResult { FilePath = filePath };
                    if (staticResult.IsInfected)
                    {
                        result = staticResult;
                    }
                }

                // 6. 威胁检测器分析
                var threatResult = ScanWithThreatDetectors(filePath);
                if (threatResult.IsInfected)
                {
                    return threatResult;
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
            catch { }
            return null;
        }

        private ScanResult ScanWithThreatDetectors(string filePath)
        {
            var result = new ScanResult { FilePath = filePath, IsInfected = false };

            try
            {
                // 读取文件内容供检测器使用
                byte[] fileContent = null;
                try { fileContent = File.ReadAllBytes(filePath); } catch { }

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
                            if (detectorResult != null && detectorResult.IsDetected)
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
                        catch { }
                    }
                }
            }
            catch { }

            return result;
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
            catch { }

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
                    catch { }
                }
            }
            catch { }

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
                try { results.AddRange(memoryScanner.ScanSystemMemory()); } catch { }
            }
            return results;
        }

        public List<ScanResult> ScanRegistry()
        {
            var results = new List<ScanResult>();
            if (registryScanner != null)
            {
                try { results.AddRange(registryScanner.ScanRegistry()); } catch { }
            }
            return results;
        }

        public List<ScanResult> ScanStartup()
        {
            var results = new List<ScanResult>();
            if (startupScanner != null)
            {
                try { results.AddRange(startupScanner.ScanStartupItems()); } catch { }
            }
            return results;
        }

        public List<ScanResult> ScanNetwork()
        {
            var results = new List<ScanResult>();
            if (networkScanner != null)
            {
                try { results.AddRange(networkScanner.ScanNetworkConnections()); } catch { }
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
