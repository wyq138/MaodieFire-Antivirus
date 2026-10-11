using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using FireAntivirus.Data;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    /// <summary>
    /// Windows Defender 后台扫描服务 - 通过命令行调用 Windows Defender 进行后台扫描
    /// </summary>
    public class DefenderScanService : IMonitor, IDisposable
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private bool _isScanning;
        private bool _stopRequested;
        private DefenderScanProgress _currentProgress;
        private List<DefenderThreatInfo> _detectedThreats;
        private CancellationTokenSource _cts;
        private System.Timers.Timer _progressTimer;
        private Process _scanProcess;
        
        public bool IsRunning => _isRunning;
        public bool IsScanning => _isScanning;
        public DefenderScanProgress CurrentProgress => _currentProgress;
        public int ThreatsCount => _detectedThreats?.Count ?? 0;

        // Windows Defender 路径
        private static readonly string MpCmdRunPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Windows Defender", "MpCmdRun.exe"
        );
        
        private static readonly string MpCmdRunPath64 = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender", "MpCmdRun.exe"
        );

        public DefenderScanService(DataManager dataManager)
        {
            _dataManager = dataManager;
            _detectedThreats = new List<DefenderThreatInfo>();
            _currentProgress = new DefenderScanProgress();
        }

        public void Start()
        {
            if (_isRunning) return;
            
            _isRunning = true;
            _cts = new CancellationTokenSource();
            
            _monitorThread = new Thread(() => MonitorLoop(_cts.Token));
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DefenderScanServiceStarted",
                Message = "Defender后台扫描服务已启动"
            });
        }

        public void Stop()
        {
            if (!_isRunning) return;
            
            _isRunning = false;
            _stopRequested = true;
            _cts?.Cancel();
            _monitorThread?.Join(2000);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DefenderScanServiceStopped",
                Message = "Defender后台扫描服务已停止"
            });
        }

        #region 扫描方法

        /// <summary>
        /// 快速扫描 - 扫描常见威胁位置
        /// </summary>
        public async Task<DefenderScanResult> QuickScanAsync()
        {
            return await StartDefenderScanAsync(DefenderScanType.Quick, null);
        }

        /// <summary>
        /// 全盘扫描
        /// </summary>
        public async Task<DefenderScanResult> FullScanAsync()
        {
            return await StartDefenderScanAsync(DefenderScanType.Full, null);
        }

        /// <summary>
        /// 自定义路径扫描
        /// </summary>
        public async Task<DefenderScanResult> CustomScanAsync(string path)
        {
            return await StartDefenderScanAsync(DefenderScanType.Custom, path);
        }

        /// <summary>
        /// USB设备扫描
        /// </summary>
        public async Task<DefenderScanResult> ScanUsbAsync(string driveLetter)
        {
            return await StartDefenderScanAsync(DefenderScanType.Usb, driveLetter);
        }

        /// <summary>
        /// 停止当前扫描
        /// </summary>
        public void StopScan()
        {
            _stopRequested = true;
            try
            {
                // 使用 MpCmdRun 取消扫描
                var mpCmdRun = GetMpCmdRunPath();
                if (!string.IsNullOrEmpty(mpCmdRun))
                {
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = mpCmdRun,
                            Arguments = "-CancelAllCustomScans",
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            WindowStyle = ProcessWindowStyle.Hidden
                        }
                    };
                    process.Start();
                    process.WaitForExit(5000);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
        }

        private async Task<DefenderScanResult> StartDefenderScanAsync(DefenderScanType scanType, string customPath)
        {
            if (_isScanning)
            {
                return new DefenderScanResult
                {
                    Success = false,
                    ErrorMessage = "已有扫描任务正在运行"
                };
            }

            _isScanning = true;
            _stopRequested = false;
            _detectedThreats.Clear();
            
            var result = new DefenderScanResult
            {
                Type = scanType,
                StartTime = DateTime.Now
            };

            try
            {
                var mpCmdRun = GetMpCmdRunPath();
                if (string.IsNullOrEmpty(mpCmdRun) || !File.Exists(mpCmdRun))
                {
                    result.Success = false;
                    result.ErrorMessage = "无法找到 Windows Defender (MpCmdRun.exe)";
                    return result;
                }

                // 构建扫描参数
                var arguments = BuildScanArguments(scanType, customPath);
                
                _currentProgress = new DefenderScanProgress
                {
                    Type = scanType,
                    Status = DefenderScanStatus.Running,
                    StartTime = DateTime.Now
                };

                // 启动后台扫描进程
                using var process = new Process();
                process.StartInfo = new ProcessStartInfo
                {
                    FileName = mpCmdRun,
                    Arguments = arguments,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                process.OutputDataReceived += (sender, e) => ProcessScanOutput(e.Data);
                process.ErrorDataReceived += (sender, e) => ProcessScanError(e.Data);

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                
                _scanProcess = process;

                // 使用 Timer 定期更新进度（避免阻塞）
                _progressTimer = new System.Timers.Timer(300); // 300ms 更新一次
                _progressTimer.Elapsed += (s, e) => UpdateProgress();
                _progressTimer.Start();

                // 立即发送开始扫描的进度更新
                UpdateProgress();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DefenderScanStarted",
                    Message = $"Defender后台扫描已开始",
                    Details = $"类型: {scanType}, 路径: {customPath ?? "默认"}"
                });

                // 异步等待扫描完成
                while (!process.HasExited && !_stopRequested)
                {
                    await Task.Delay(500).ConfigureAwait(false); // 异步等待，不阻塞线程
                }

                _progressTimer?.Stop();
                _progressTimer?.Dispose();

                if (_stopRequested)
                {
                    process.Kill();
                    result.Success = false;
                    result.ErrorMessage = "扫描已取消";
                    _currentProgress.Status = DefenderScanStatus.Cancelled;
                }
                else
                {
                    process.WaitForExit();
                    result.ExitCode = process.ExitCode;
                    result.Success = process.ExitCode == 0 || process.ExitCode == 2; // 0=无威胁, 2=有威胁已处理
                }

                result.EndTime = DateTime.Now;
                result.Duration = result.EndTime - result.StartTime;
                result.Threats = new List<DefenderThreatInfo>(_detectedThreats);
                result.ThreatsFound = _detectedThreats.Count;

                _currentProgress.Status = _stopRequested ? DefenderScanStatus.Cancelled : DefenderScanStatus.Completed;
                _currentProgress.EndTime = result.EndTime;
                _currentProgress.ElapsedTime = result.Duration;
                
                // 发送最终进度更新
                UpdateProgress();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DefenderScanCompleted",
                    Message = "Defender后台扫描已完成",
                    Details = $"类型: {scanType}, 发现威胁: {result.ThreatsFound}, 耗时: {result.Duration.TotalSeconds:F1}秒"
                });
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                _currentProgress.Status = DefenderScanStatus.Error;
                
                // 发送错误进度更新
                UpdateProgress();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DefenderScanError",
                    Message = "Defender扫描出错",
                    Details = ex.Message
                });
            }
            finally
            {
                _isScanning = false;
            }

            return result;
        }

        private string BuildScanArguments(DefenderScanType scanType, string customPath)
        {
            return scanType switch
            {
                DefenderScanType.Quick => "-Scan -ScanType 1", // 快速扫描
                DefenderScanType.Full => "-Scan -ScanType 2",  // 全盘扫描
                DefenderScanType.Deep => "-Scan -ScanType 2",  // 深度扫描（使用全盘扫描）
                DefenderScanType.Custom => $"-Scan -ScanType 3 -File \"{customPath}\"", // 自定义扫描
                DefenderScanType.Usb => $"-Scan -ScanType 3 -File \"{customPath}\"", // USB扫描
                _ => "-Scan -ScanType 1"
            };
        }

        private string GetMpCmdRunPath()
        {
            if (File.Exists(MpCmdRunPath)) return MpCmdRunPath;
            if (File.Exists(MpCmdRunPath64)) return MpCmdRunPath64;
            
            // Windows 10/11: MpCmdRun.exe in ProgramData platform directory
            try
            {
                string platformDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Microsoft", "Windows Defender", "platform");
                if (Directory.Exists(platformDir))
                {
                    var latestDir = Directory.GetDirectories(platformDir)
                        .OrderByDescending(d => d)
                        .FirstOrDefault();
                    if (latestDir != null)
                    {
                        string mpPath = Path.Combine(latestDir, "MpCmdRun.exe");
                        if (File.Exists(mpPath)) return mpPath;
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
            
            // 尝试查找其他可能的位置
            var possiblePaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "MpCmdRun.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64", "MpCmdRun.exe")
            };
            
            foreach (var path in possiblePaths)
            {
                if (File.Exists(path)) return path;
            }
            
            return null;
        }

        #endregion

        #region 进度处理

        private void ProcessScanOutput(string output)
        {
            if (string.IsNullOrEmpty(output)) return;

            // MpCmdRun 的实际输出格式多样，常见的有：
            // "Threat  : [威胁名] 文件路径: [路径]"
            // "Threat  detected: [威胁名] in file: [路径]"
            // "[结果] [路径]->[威胁名]"
            bool isThreat = false;

            // 先检查是否包含威胁相关关键字
            if (output.Contains("Threat", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Virus", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Malware", StringComparison.OrdinalIgnoreCase))
            {
                isThreat = true;
            }

            if (isThreat)
            {
                var threat = ParseThreat(output);
                if (threat != null)
                {
                    _detectedThreats.Add(threat);
                    _currentProgress.ThreatsFound = _detectedThreats.Count;

                    NotificationService.Instance.ShowNotification(
                        "发现威胁",
                        $"检测到威胁: {threat.Name}",
                        NotificationType.Error
                    );
                }
            }

            // 更新进度
            if (output.Contains("Scanning", StringComparison.OrdinalIgnoreCase))
            {
                _currentProgress.FilesScanned++;
                _currentProgress.CurrentPath = ExtractCurrentScanPath(output);
            }
        }

        /// <summary>
        /// 从扫描输出中提取当前正在扫描的文件路径
        /// </summary>
        private string ExtractCurrentScanPath(string output)
        {
            // MpCmdRun 通常输出 "Scanning [路径]" 格式
            var scanIndex = output.IndexOf("Scanning", StringComparison.OrdinalIgnoreCase);
            if (scanIndex >= 0)
            {
                var pathStart = scanIndex + "Scanning".Length;
                var remaining = output.Substring(pathStart).Trim();
                // 去掉开头的冒号、空格等
                remaining = remaining.TrimStart(':', ' ', '\t');
                if (remaining.Length > 0 && remaining.Contains(":\\"))
                {
                    return remaining;
                }
            }
            return null;
        }

        private void ProcessScanError(string error)
        {
            if (string.IsNullOrEmpty(error)) return;
            
            // 记录错误但不中断扫描
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "DefenderScanWarning",
                Message = "扫描警告",
                Details = error
            });
        }

        private void UpdateProgress()
        {
            try
            {
                // 更新进度时间
                _currentProgress.ElapsedTime = DateTime.Now - _currentProgress.StartTime;

                // 通知进度更新（可通过事件或回调）
                OnProgressChanged?.Invoke(_currentProgress);
            }
            catch
            {
                // 忽略跨线程异常，不影响扫描主流程
            }
        }

        private DefenderThreatInfo ParseThreat(string output)
        {
            try
            {
                // 简单解析威胁信息
                return new DefenderThreatInfo
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = ExtractThreatName(output),
                    Path = ExtractFilePath(output),
                    Severity = DetermineSeverity(output),
                    DetectedTime = DateTime.Now
                };
            }
            catch { return null; }
        }

        private string ExtractThreatName(string output)
        {
            // MpCmdRun 真实输出格式多样，优先匹配更精确的模式：
            // 格式1: "Threat  : [威胁名]"
            // 格式2: "Threat detected: [威胁名] in file: [路径]"
            // 格式3: "[结果] [路径]->[威胁名]"

            // 尝试匹配 "Threat  : [威胁名]" 或 "Threat:[威胁名]"
            var threatMatch = System.Text.RegularExpressions.Regex.Match(
                output, @"Threat\s*[:：]\s*(.+?)(?:\s+文件路径|\s+in file|\s*$)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (threatMatch.Success && !string.IsNullOrWhiteSpace(threatMatch.Groups[1].Value))
            {
                return threatMatch.Groups[1].Value.Trim();
            }

            // 尝试匹配 "->[威胁名]" 格式
            var arrowMatch = System.Text.RegularExpressions.Regex.Match(
                output, @"->\s*(.+?)$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (arrowMatch.Success && !string.IsNullOrWhiteSpace(arrowMatch.Groups[1].Value))
            {
                return arrowMatch.Groups[1].Value.Trim();
            }

            // 回退到原有简单关键字匹配
            var keywords = new[] { "Threat:", "Virus:", "Malware:", "Trojan:", "PUP:" };
            foreach (var keyword in keywords)
            {
                var index = output.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
                if (index >= 0)
                {
                    var start = index + keyword.Length;
                    var end = output.IndexOfAny(new[] { '\r', '\n', '\t' }, start);
                    if (end < 0) end = output.Length;
                    return output.Substring(start, end - start).Trim();
                }
            }
            return "未知威胁";
        }

        private string ExtractFilePath(string output)
        {
            // 尝试提取文件路径
            if (output.Contains(":\\"))
            {
                var start = output.IndexOf(":\\") - 1;
                if (start >= 0)
                {
                    var end = output.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }, start);
                    if (end < 0) end = output.Length;
                    return output.Substring(start, end - start);
                }
            }
            return "";
        }

        private DefenderThreatSeverity DetermineSeverity(string output)
        {
            var lower = output.ToLower();
            if (lower.Contains("critical") || lower.Contains("severe")) return DefenderThreatSeverity.Critical;
            if (lower.Contains("high")) return DefenderThreatSeverity.High;
            if (lower.Contains("medium")) return DefenderThreatSeverity.Medium;
            return DefenderThreatSeverity.Low;
        }

        #endregion

        #region 威胁处理

        /// <summary>
        /// 隔离威胁
        /// </summary>
        public bool QuarantineThreat(string threatId)
        {
            var threat = _detectedThreats.FirstOrDefault(t => t.Id == threatId);
            if (threat == null) return false;

            try
            {
                var mpCmdRun = GetMpCmdRunPath();
                if (string.IsNullOrEmpty(mpCmdRun)) return false;

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = mpCmdRun,
                        Arguments = $"-RemoveThreat -ID {threatId}",
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden
                    }
                };

                process.Start();
                process.WaitForExit(30000);

                threat.Status = DefenderThreatStatus.Quarantined;
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ThreatQuarantined",
                    Message = "威胁已隔离",
                    Details = $"威胁: {threat.Name}, 路径: {threat.Path}"
                });

                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// 删除威胁文件
        /// </summary>
        public bool DeleteThreat(string threatId)
        {
            var threat = _detectedThreats.FirstOrDefault(t => t.Id == threatId);
            if (threat == null || string.IsNullOrEmpty(threat.Path)) return false;

            try
            {
                if (File.Exists(threat.Path))
                {
                    File.Delete(threat.Path);
                }

                threat.Status = DefenderThreatStatus.Removed;
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ThreatDeleted",
                    Message = "威胁文件已删除",
                    Details = $"威胁: {threat.Name}, 路径: {threat.Path}"
                });

                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// 恢复误报文件
        /// </summary>
        public bool RestoreThreat(string threatId)
        {
            var threat = _detectedThreats.FirstOrDefault(t => t.Id == threatId);
            if (threat == null) return false;

            try
            {
                var mpCmdRun = GetMpCmdRunPath();
                if (string.IsNullOrEmpty(mpCmdRun)) return false;

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = mpCmdRun,
                        Arguments = $"-Restore -Name \"{threat.Name}\"",
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden
                    }
                };

                process.Start();
                process.WaitForExit(30000);

                threat.Status = DefenderThreatStatus.Allowed;

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ThreatRestored",
                    Message = "威胁已恢复/允许",
                    Details = $"威胁: {threat.Name}"
                });

                return true;
            }
            catch { return false; }
        }

        #endregion

        #region 监控循环

        private void MonitorLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    // 定期检查 Windows Defender 状态
                    CheckDefenderStatus();
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }

                Thread.Sleep(60000); // 每分钟检查一次
            }
        }

        private void CheckDefenderStatus()
        {
            try
            {
                var mpCmdRun = GetMpCmdRunPath();
                if (string.IsNullOrEmpty(mpCmdRun)) return;

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = mpCmdRun,
                        Arguments = "-GetFiles",
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(5000);

                // 检查实时保护状态
                if (output.Contains("Real-time protection", StringComparison.OrdinalIgnoreCase))
                {
                    var isEnabled = output.Contains("enabled", StringComparison.OrdinalIgnoreCase);
                    _currentProgress.RealTimeProtectionEnabled = isEnabled;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region 事件和属性

        public event Action<DefenderScanProgress> OnProgressChanged;

        public List<DefenderThreatInfo> GetThreats()
        {
            return new List<DefenderThreatInfo>(_detectedThreats);
        }

        public bool IsDefenderAvailable()
        {
            return !string.IsNullOrEmpty(GetMpCmdRunPath());
        }

        /// <summary>
        /// 通过 MpCmdRun 获取 Windows Defender 状态信息
        /// </summary>
        public DefenderStatusInfo GetDefenderStatus()
        {
            var status = new DefenderStatusInfo();
            try
            {
                var mpCmdRun = GetMpCmdRunPath();
                if (string.IsNullOrEmpty(mpCmdRun)) return status;

                // 使用 WMI 查询 Defender 状态
                // 某些系统上命名空间可能不同，添加备用查询路径
                System.Management.ManagementObjectCollection collection = null;
                try
                {
                    using (var searcher = new System.Management.ManagementObjectSearcher(
                        @"Root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus"))
                    {
                        collection = searcher.Get();
                    }
                }
                catch
                {
                    // 备用命名空间（某些版本的 Windows 可能使用不同的命名空间）
                    try
                    {
                        using (var searcher = new System.Management.ManagementObjectSearcher(
                            @"Root\Microsoft\SecurityClient", "SELECT * FROM AntimalwareHealthStatus"))
                        {
                            collection = searcher.Get();
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
                }

                if (collection != null)
                {
                    foreach (var obj in collection)
                    {
                        // 使用 try-catch 包装每个属性读取，防止单个属性失败导致整个查询失败
                        try { status.AntivirusEnabled = Convert.ToBoolean(obj["AntivirusEnabled"]); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
                        try { status.RealTimeProtectionEnabled = Convert.ToBoolean(obj["RealTimeProtectionEnabled"]); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
                        try { status.AntispywareEnabled = Convert.ToBoolean(obj["AntispywareEnabled"]); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
                        try { status.NISEnabled = Convert.ToBoolean(obj["NISEnabled"]); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
                        try
                        {
                            status.DefenderSignaturesUpToDate = Convert.ToBoolean(obj["AntivirusSignatureAge"] != null &&
                                Convert.ToUInt32(obj["AntivirusSignatureAge"]) <= 1);
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
                        try { status.QuickScanEndTime = obj["QuickScanEndTime"]?.ToString(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
                        try { status.FullScanEndTime = obj["FullScanEndTime"]?.ToString(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
                        try { status.AntivirusSignatureLastUpdated = obj["AntivirusSignatureLastUpdated"]?.ToString(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
                        break;
                    }
                    collection.Dispose();
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "DefenderScanService.cs 捕获异常", ex.Message); }
            return status;
        }

        /// <summary>
        /// 打开 Windows 安全中心
        /// </summary>
        public void OpenWindowsSecurityCenter()
        {
            // Windows 11 上使用 windowsdefender:// 协议更可靠
            // 按优先级尝试多个打开方式
            var openMethods = new (string description, Action openAction)[]
            {
                ("windowsdefender:// 协议", () =>
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "windowsdefender:",
                        UseShellExecute = true
                    });
                }),
                ("ms-settings:windowsdefender 协议", () =>
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "ms-settings:windowsdefender",
                        UseShellExecute = true
                    });
                }),
                ("SecurityHealthSystray.exe", () =>
                {
                    var systrayPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                        "System32", "SecurityHealthSystray.exe");
                    if (File.Exists(systrayPath))
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = systrayPath,
                            UseShellExecute = true
                        });
                    }
                }),
                ("explorer.exe shell:AppsFolder 启动 SecHealthUI", () =>
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        Arguments = "shell:AppsFolder\\Microsoft.SecHealthUI_8wekyb3d8bbwe!SecHealthUI",
                        UseShellExecute = true
                    });
                })
            };

            foreach (var (description, openAction) in openMethods)
            {
                try
                {
                    openAction();
                    _dataManager?.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "OpenWindowsSecurityCenter",
                        Message = "已打开 Windows 安全中心",
                        Details = $"使用方式: {description}"
                    });
                    return;
                }
                catch (Exception ex)
                {
                    _dataManager?.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "OpenWindowsSecurityCenterError",
                        Message = "打开 Windows 安全中心失败",
                        Details = $"方式: {description}, 错误: {ex.Message}"
                    });
                }
            }
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _progressTimer?.Stop();
            _progressTimer?.Dispose();
            _scanProcess?.Dispose();
            _cts?.Dispose();
        }

        #endregion
    }

    #region 数据模型

    public enum DefenderScanType
    {
        Quick,
        Full,
        Custom,
        Usb,
        Deep
    }

    public enum DefenderScanStatus
    {
        Idle,
        Running,
        Completed,
        Cancelled,
        Error
    }

    public enum DefenderThreatSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    public enum DefenderThreatStatus
    {
        Detected,
        Quarantined,
        Removed,
        Allowed
    }

    public class DefenderScanProgress
    {
        public DefenderScanType Type { get; set; }
        public DefenderScanStatus Status { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        public TimeSpan ElapsedTime { get; set; }
        public long FilesScanned { get; set; }
        public int ThreatsFound { get; set; }
        public bool RealTimeProtectionEnabled { get; set; }
        public string CurrentPath { get; set; }
    }

    public class DefenderScanResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public DefenderScanType Type { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public int ThreatsFound { get; set; }
        public List<DefenderThreatInfo> Threats { get; set; }
        public int ExitCode { get; set; }
    }

    public class DefenderThreatInfo
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public DefenderThreatSeverity Severity { get; set; }
        public DefenderThreatStatus Status { get; set; }
        public DateTime DetectedTime { get; set; }
        public string Description { get; set; }
    }

    public class DefenderStatusInfo
    {
        public bool AntivirusEnabled { get; set; }
        public bool RealTimeProtectionEnabled { get; set; }
        public bool AntispywareEnabled { get; set; }
        public bool NISEnabled { get; set; }
        public bool DefenderSignaturesUpToDate { get; set; }
        public string QuickScanEndTime { get; set; }
        public string FullScanEndTime { get; set; }
        public string AntivirusSignatureLastUpdated { get; set; }
    }

    #endregion
}
