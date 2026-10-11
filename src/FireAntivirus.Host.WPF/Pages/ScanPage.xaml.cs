using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using FireAntivirus.ClamAV;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Engine.Analyzers;
// 使用别名解决命名冲突
using EngineScanResult = FireAntivirus.Engine.ScanResult;
using System.Threading.Tasks;
using System.Threading;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class ScanPage : Page, IThemed, FireAntivirus.Host.WPF.IPageWithLifecycle
    {
        private Theme _currentTheme = Theme.Light;
        private DispatcherTimer _progressTimer;
        private string _selectedScanType = "Quick";
        private string _customScanPath;
        private DateTime _scanStartTime;
        private ObservableCollection<ThreatDisplayItem> _threatsList;
        private System.Threading.CancellationTokenSource _cts = new();
        
        // 专业杀毒引擎组件
        private ClamAVManager _clamAVManager;
        private AntivirusEngine _antivirusEngine;
        private DataManager _dataManager;
        
        // 扫描统计
        private int _scannedFiles = 0;
        private int _totalFiles = 0;
        private int _threatsFound = 0;
        private long _totalBytesScanned = 0;
        
        // 引擎加载状态
        private bool _areEnginesLoaded = false;
        private bool _isLoadingEngines = false;
        private SemaphoreSlim _engineLoadingSemaphore = new SemaphoreSlim(1, 1);

        public ScanPage()
        {
            InitializeComponent();
            _threatsList = new ObservableCollection<ThreatDisplayItem>();
            ScanResultsList.ItemsSource = _threatsList;
            StatusLabel.Text = "就绪 - 点击扫描按钮启动引擎";
            
            _progressTimer = new DispatcherTimer();
            _progressTimer.Interval = TimeSpan.FromMilliseconds(500);
            _progressTimer.Tick += Timer_Tick;
            
            // 延迟加载引擎，只有在需要时初始化
            Loaded += (s, e) => PreloadEnginesAsync();
            
            Unloaded += (s, e) =>
            {
                _cts?.Cancel();
                _progressTimer?.Stop();
                _clamAVManager?.Dispose();
                _antivirusEngine?.Dispose();
            };
        }

        private async Task PreloadEnginesAsync()
        {
            if (_areEnginesLoaded || _isLoadingEngines)
                return;

            await _engineLoadingSemaphore.WaitAsync();
            try
            {
                if (_areEnginesLoaded) return;
                
                _isLoadingEngines = true;
                
                // 显示引擎加载状态
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    StartScanBtn.Content = "初始化引擎中...";
                    StartScanBtn.IsEnabled = false;
                    StatusLabel.Text = "正在初始化扫描引擎...";
                }));

                // 并行初始化各个引擎组件
                var tasks = new List<Task>
                {
                    // DataManager 初始化
                    Task.Run(async () =>
                    {
                        System.Diagnostics.Debug.WriteLine($"{DateTime.Now:HH:mm:ss.fff} - 开始初始化数据管理器");
                        _dataManager = new DataManager();
                        System.Diagnostics.Debug.WriteLine($"{DateTime.Now:HH:mm:ss.fff} - 数据管理器初始化完成");
                        await Task.CompletedTask;
                    }),

                    // AntivirusEngine 初始化
                    Task.Run(async () =>
                    {
                        System.Diagnostics.Debug.WriteLine($"{DateTime.Now:HH:mm:ss.fff} - 开始初始化反病毒引擎");
                        _antivirusEngine = new AntivirusEngine(_dataManager);
                        System.Diagnostics.Debug.WriteLine($"{DateTime.Now:HH:mm:ss.fff} - 反病毒引擎初始化完成");
                        await Task.CompletedTask;
                    }),

                    // ClamAVManager 初始化
                    Task.Run(async () =>
                    {
                        System.Diagnostics.Debug.WriteLine($"{DateTime.Now:HH:mm:ss.fff} - 开始初始化 ClamAV 引擎");
                        _clamAVManager = new ClamAVManager(_dataManager);
                        System.Diagnostics.Debug.WriteLine($"{DateTime.Now:HH:mm:ss.fff} - ClamAV 引擎初始化完成");
                        await Task.CompletedTask;
                    })
                };

                // 等待所有引擎并行初始化完成
                await Task.WhenAll(tasks);
                
                // 设置事件订阅
                _antivirusEngine.ThreatDetected += (s, threat) =>
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        AddThreat(threat.Threat);

                        // 右下角风险处理弹窗（带 隔离/删除/信任/忽略 处理选项，而不是屏幕中央的默认弹窗）
                        var threatCopy = threat.Threat;
                        var payload = new FireAntivirus.Common.Notification.RiskNotificationPayload
                        {
                            FilePath = threatCopy?.FilePath,
                            ThreatName = threatCopy?.ThreatName ?? "未知威胁",
                            Severity = threatCopy?.Severity ?? "High",
                            SuggestedAction = "建议先隔离",
                            Actions = new System.Collections.Generic.List<FireAntivirus.Common.Notification.RiskAction>
                            {
                                new FireAntivirus.Common.Notification.RiskAction
                                {
                                    Text = "隔离",
                                    Handler = path => { if (!string.IsNullOrEmpty(path)) QuarantineFileByPath(path); }
                                },
                                new FireAntivirus.Common.Notification.RiskAction
                                {
                                    Text = "删除",
                                    Handler = path => { if (!string.IsNullOrEmpty(path)) DeleteFileByPath(path); }
                                },
                                new FireAntivirus.Common.Notification.RiskAction
                                {
                                    Text = "信任",
                                    Handler = path => { if (!string.IsNullOrEmpty(path)) TrustFileByPath(path); }
                                },
                                new FireAntivirus.Common.Notification.RiskAction
                                {
                                    Text = "忽略",
                                    Handler = _ => { /* 仅关闭弹窗 */ }
                                }
                            }
                        };
                        FireAntivirus.Common.Notification.NotificationService.Instance.ShowRisk(payload);
                    }));
                };
                
                _antivirusEngine.ScanProgress += (s, progress) =>
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        UpdateScanProgress(progress);
                    }));
                };

                // 启动ClamAV自动更新
                _clamAVManager.AutoUpdateIntervalHours = 4;
                _clamAVManager.StartAutoUpdate();
                
                _clamAVManager.OnUpdateProgress += (msg) =>
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        StatusLabel.Text = $"病毒库更新: {msg}";
                    }));
                };
                
                _clamAVManager.OnUpdateComplete += (success, msg) =>
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        if (success)
                        {
                            StatusLabel.Text = $"病毒库版本: {_clamAVManager.GetVirusDatabaseVersion()} | 专业杀毒引擎就绪";
                        }
                    }));
                };

                _areEnginesLoaded = true;
                _isLoadingEngines = false;

                // 更新UI状态
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    StartScanBtn.Content = "开始扫描";
                    StartScanBtn.IsEnabled = true;
                    StatusLabel.Text = "扫描引擎准备就绪";
                    System.Diagnostics.Debug.WriteLine($"{DateTime.Now:HH:mm:ss.fff} - 所有扫描引擎初始化完成");
                }));
            }
            catch (Exception ex)
            {
                _isLoadingEngines = false;
                System.Diagnostics.Debug.WriteLine($"引擎初始化失败: {ex}");
                
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    StatusLabel.Text = $"引擎初始化失败: {ex.Message}";
                    StatusLabel.Foreground = Brushes.Red;
                }));
            }
            finally
            {
                _engineLoadingSemaphore.Release();
            }
        }

        private async Task EnsureEnginesLoadedAsync()
        {
            if (!_areEnginesLoaded)
            {
                await PreloadEnginesAsync();
            }
        }

        /// <summary>
        /// 按需获取数据管理器实例（支持延迟加载）
        /// </summary>
        public async Task<DataManager> GetDataManagerAsync()
        {
            await EnsureEnginesLoadedAsync();
            return _dataManager;
        }

        /// <summary>
        /// 按需获取反病毒引擎实例（支持延迟加载）
        /// </summary>
        public async Task<AntivirusEngine> GetAntivirusEngineAsync()
        {
            await EnsureEnginesLoadedAsync();
            return _antivirusEngine;
        }

        /// <summary>
        /// 按需获取ClamAV管理器实例（支持延迟加载）
        /// </summary>
        public async Task<ClamAVManager> GetClamAVManagerAsync()
        {
            await EnsureEnginesLoadedAsync();
            return _clamAVManager;
        }

        /// <summary>
        /// 检查引擎健康状态
        /// </summary>
        public async Task<bool> CheckEngineHealthAsync()
        {
            try
            {
                await EnsureEnginesLoadedAsync();
                
                var checks = new List<bool>
                {
                    _dataManager != null,
                    _antivirusEngine != null && _antivirusEngine.IsInitialized,
                    _clamAVManager != null && _clamAVManager.IsInitialized
                };
                
                return checks.All(check => check);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 卸载并重新加载引擎（异常恢复机制）
        /// </summary>
        public async Task ReinitializeEnginesAsync()
        {
            try
            {
                // 清理现有资源
                _clamAVManager?.Dispose();
                _antivirusEngine?.Dispose();
                _dataManager?.Dispose();
                
                // 重置状态
                _areEnginesLoaded = false;
                _isLoadingEngines = false;
                
                // 重新加载
                await PreloadEnginesAsync();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"引擎重初始化失败: {ex}");
                throw;
            }
        }

        [Obsolete("InitializeEngines方法已废弃，请使用异步延迟加载机制")]
        private void InitializeEngines()
        {
            // 保持兼容性但不执行任何操作
            // 实际初始化已移动到PreloadEnginesAsync方法中
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            var elapsed = DateTime.Now - _scanStartTime;
            var speed = _scannedFiles > 0 ? _scannedFiles / elapsed.TotalSeconds : 0;
            var mbScanned = _totalBytesScanned / (1024.0 * 1024.0);
            
            ProgressLabel.Text = $"耗时: {elapsed:hh\\:mm\\:ss} | 已扫描: {_scannedFiles:N0} 文件 | {mbScanned:F1} MB | {speed:F1} 文件/秒 | 威胁: {_threatsFound}";
        }

        private void ScanTypeButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag != null)
            {
                _selectedScanType = btn.Tag.ToString();
                string desc = _selectedScanType switch
                {
                    "Quick" => "快速扫描 - 扫描用户目录、内存、启动项和关键系统区域",
                    "Full" => "全盘扫描 - 完整扫描所有磁盘、内存、注册表、启动项和网络连接",
                    "Custom" => "自定义扫描 - 扫描指定目录",
                    _ => _selectedScanType
                };
                StatusLabel.Text = desc;
                
                if (_selectedScanType == "Custom")
                {
                    var dialog = new System.Windows.Forms.FolderBrowserDialog
                    {
                        Description = "选择要扫描的目录",
                        ShowNewFolderButton = false
                    };
                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    {
                        _customScanPath = dialog.SelectedPath;
                        StatusLabel.Text = $"自定义扫描 - 已选择: {_customScanPath}";
                    }
                }
            }
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            StartScanBtn.IsEnabled = false;
            StopScanBtn.IsEnabled = true;
            _threatsList.Clear();
            _scannedFiles = 0;
            _totalFiles = 0;
            _threatsFound = 0;
            _totalBytesScanned = 0;
            _scanStartTime = DateTime.Now;
            _progressTimer.Start();
            _cts = new System.Threading.CancellationTokenSource();
            
            ScanProgressBar.IsIndeterminate = true;
            StatusLabel.Text = "正在初始化专业杀毒引擎...";

            // 确保引擎已加载
            await EnsureEnginesLoadedAsync();

            await System.Threading.Tasks.Task.Run(async () =>
            {
                try
                {
                    // 确保病毒库可用
                    if (_clamAVManager != null && !_clamAVManager.HasDatabaseFiles())
                    {
                        Dispatcher.BeginInvoke(new Action(() => 
                        {
                            StatusLabel.Text = "正在下载病毒库...";
                        }));
                        await _clamAVManager.UpdateDatabaseAsync();
                    }

                    var scanOptions = new ScanOptions
                    {
                        ScanType = _selectedScanType switch
                        {
                            "Quick" => ScanType.Quick,
                            "Full" => ScanType.Full,
                            "Custom" => ScanType.Custom,
                            _ => ScanType.Quick
                        },
                        CustomPaths = !string.IsNullOrEmpty(_customScanPath) 
                            ? new List<string> { _customScanPath } 
                            : new List<string>(),
                        ScanMemory = true,
                        ScanRegistry = _selectedScanType == "Full",
                        ScanStartupItems = true,
                        ScanNetworkConnections = _selectedScanType == "Full",
                        ScanProcesses = true,
                        DeepScan = _selectedScanType == "Full",
                        UseHeuristics = true,
                        UseBehaviorAnalysis = true,
                        MaxFileSizeMB = 256
                    };

                    // 开始专业级扫描
                    await PerformProfessionalScan(scanOptions);
                }
                catch (OperationCanceledException)
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        StatusLabel.Text = "扫描已取消";
                        FinishScan();
                    }));
                }
                catch (Exception ex)
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        StatusLabel.Text = $"扫描错误: {ex.Message}";
                        FinishScan();
                    }));
                }
            }, _cts.Token);
        }

        private async System.Threading.Tasks.Task PerformProfessionalScan(ScanOptions options)
        {
            var allThreats = new List<EngineScanResult>();
            
            try
            {
                // ===== 第一阶段：文件系统扫描 =====
                Dispatcher.BeginInvoke(new Action(() => 
                {
                    ScanProgressBar.IsIndeterminate = false;
                    StatusLabel.Text = "第一阶段：病毒特征扫描...";
                }));

                var scanPaths = GetScanPaths(options);
                _totalFiles = CountTotalFiles(scanPaths);
                
                foreach (var path in scanPaths)
                {
                    if (_cts.Token.IsCancellationRequested) break;
                    
                    if (Directory.Exists(path))
                    {
                        var results = await ScanDirectoryProfessional(path, options);
                        allThreats.AddRange(results.Where(r => r.IsInfected));
                    }
                }

                // ===== 第二阶段：内存扫描 =====
                if (options.ScanMemory && !_cts.Token.IsCancellationRequested)
                {
                    Dispatcher.BeginInvoke(new Action(() => 
                    {
                        StatusLabel.Text = "第二阶段：内存扫描...";
                        ScanProgressBar.Value = 50;
                    }));
                    
                    var memoryThreats = _antivirusEngine.ScanMemory();
                    foreach (var threat in memoryThreats.Where(t => t.IsInfected))
                    {
                        allThreats.Add(threat);
                        Dispatcher.BeginInvoke(new Action(() => AddThreat(threat)));
                    }
                }

                // ===== 第三阶段：启动项扫描 =====
                if (options.ScanStartupItems && !_cts.Token.IsCancellationRequested)
                {
                    Dispatcher.BeginInvoke(new Action(() => 
                    {
                        StatusLabel.Text = "第三阶段：启动项扫描...";
                        ScanProgressBar.Value = 65;
                    }));
                    
                    var startupThreats = _antivirusEngine.ScanStartup();
                    foreach (var threat in startupThreats.Where(t => t.IsInfected))
                    {
                        allThreats.Add(threat);
                        Dispatcher.BeginInvoke(new Action(() => AddThreat(threat)));
                    }
                }

                // ===== 第四阶段：注册表扫描 =====
                if (options.ScanRegistry && !_cts.Token.IsCancellationRequested)
                {
                    Dispatcher.BeginInvoke(new Action(() => 
                    {
                        StatusLabel.Text = "第四阶段：注册表扫描...";
                        ScanProgressBar.Value = 75;
                    }));
                    
                    var registryThreats = _antivirusEngine.ScanRegistry();
                    foreach (var threat in registryThreats.Where(t => t.IsInfected))
                    {
                        allThreats.Add(threat);
                        Dispatcher.BeginInvoke(new Action(() => AddThreat(threat)));
                    }
                }

                // ===== 第五阶段：网络扫描 =====
                if (options.ScanNetworkConnections && !_cts.Token.IsCancellationRequested)
                {
                    Dispatcher.BeginInvoke(new Action(() => 
                    {
                        StatusLabel.Text = "第五阶段：网络连接扫描...";
                        ScanProgressBar.Value = 85;
                    }));
                    
                    var networkThreats = _antivirusEngine.ScanNetwork();
                    foreach (var threat in networkThreats.Where(t => t.IsInfected))
                    {
                        allThreats.Add(threat);
                        Dispatcher.BeginInvoke(new Action(() => AddThreat(threat)));
                    }
                }

                // 完成扫描
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    ScanProgressBar.Value = 100;
                    
                    if (_threatsFound > 0)
                    {
                        StatusLabel.Text = $"扫描完成 - 发现 {_threatsFound} 个威胁 | 扫描文件: {_scannedFiles:N0}";
                        MessageBox.Show(
                            $"专业扫描完成！\n\n" +
                            $"扫描文件: {_scannedFiles:N0}\n" +
                            $"发现威胁: {_threatsFound}\n" +
                            $"扫描耗时: {(DateTime.Now - _scanStartTime):hh\\:mm\\:ss}\n\n" +
                            $"请查看威胁列表并进行处理。", 
                            "扫描结果", 
                            MessageBoxButton.OK, 
                            MessageBoxImage.Warning);
                    }
                    else
                    {
                        StatusLabel.Text = $"扫描完成 - 系统安全 | 扫描文件: {_scannedFiles:N0}";
                        MessageBox.Show(
                            $"专业扫描完成！\n\n" +
                            $"扫描文件: {_scannedFiles:N0}\n" +
                            $"发现威胁: 0\n" +
                            $"扫描耗时: {(DateTime.Now - _scanStartTime):hh\\:mm\\:ss}\n\n" +
                            $"系统安全，未发现威胁。", 
                            "扫描结果", 
                            MessageBoxButton.OK, 
                            MessageBoxImage.Information);
                    }
                    FinishScan();
                }));
            }
            catch (Exception ex)
            {
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    StatusLabel.Text = $"扫描异常: {ex.Message}";
                    FinishScan();
                }));
            }
        }

        private List<string> GetScanPaths(ScanOptions options)
        {
            var paths = new List<string>();
            
            if (options.ScanType == ScanType.Custom && options.CustomPaths.Count > 0)
            {
                paths.AddRange(options.CustomPaths);
            }
            else if (options.ScanType == ScanType.Full)
            {
                // 全盘扫描 - 扫描所有驱动器
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        paths.Add(drive.RootDirectory.FullName);
                    }
                }
            }
            else
            {
                // 快速扫描 - 关键位置
                paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
                paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
                paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
                paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
                paths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"));
                paths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"));
            }
            
            return paths.Where(p => Directory.Exists(p)).ToList();
        }

        private int CountTotalFiles(List<string> paths)
        {
            int count = 0;
            foreach (var path in paths)
            {
                try
                {
                    count += Directory.GetFiles(path, "*.*", SearchOption.AllDirectories).Length;
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ScanPage.xaml.cs 捕获异常", ex.Message); }
            }
            return count;
        }

        private async System.Threading.Tasks.Task<List<EngineScanResult>> ScanDirectoryProfessional(string directoryPath, ScanOptions options)
        {
            var threats = new List<EngineScanResult>();
            
            try
            {
                var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
                    ".js", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".msi", ".msp",
                    ".scr", ".pif", ".jar", ".class", ".swf", ".flv", ".pdf",
                    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".xlsm", ".docm",
                    ".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".iso",
                    ".lnk", ".url", ".reg", ".inf", ".ini", ".cfg"
                };

                var files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories)
                    .Where(f => extensions.Contains(Path.GetExtension(f)) || options.DeepScan)
                    .ToList();

                long maxSize = options.MaxFileSizeMB * 1024L * 1024L;

                foreach (var file in files)
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    try
                    {
                        var fileInfo = new FileInfo(file);
                        
                        // 跳过超大文件
                        if (fileInfo.Length > maxSize) continue;

                        _scannedFiles++;
                        _totalBytesScanned += fileInfo.Length;

                        // 更新进度
                        if (_scannedFiles % 10 == 0)
                        {
                            Dispatcher.BeginInvoke(new Action(() =>
                            {
                                var progress = _totalFiles > 0 ? (double)_scannedFiles / _totalFiles * 50 : 0;
                                ScanProgressBar.Value = Math.Min(50, progress);
                                StatusLabel.Text = $"正在扫描: {Path.GetFileName(file)}";
                            }));
                        }

                        // 使用AntivirusEngine进行专业扫描
                        var result = _antivirusEngine.ScanFile(file);
                        
                        if (result.IsInfected)
                        {
                            threats.Add(result);
                            Dispatcher.BeginInvoke(new Action(() => AddThreat(result)));
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"扫描文件失败 {file}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"扫描目录失败 {directoryPath}: {ex.Message}");
            }

            return threats;
        }

        private void AddThreat(EngineScanResult threat)
        {
            _threatsFound++;
            _threatsList.Add(new ThreatDisplayItem
            {
                FileName = Path.GetFileName(threat.FilePath),
                ThreatName = threat.ThreatName ?? "未知威胁",
                FilePath = threat.FilePath,
                ThreatType = threat.ThreatType ?? "恶意软件",
                Severity = GetSeverityText(threat.Severity ?? "High"),
                Confidence = threat.Confidence,
                DetectionMethod = threat.DetectionMethod ?? "启发式分析",
                FileSize = new FileInfo(threat.FilePath).Length
            });
        }

        private string GetSeverityText(string severity)
        {
            return severity?.ToLower() switch
            {
                "critical" => "严重",
                "high" => "高",
                "medium" => "中",
                "low" => "低",
                _ => "高"
            };
        }

        private void UpdateScanProgress(ScanProgressEventArgs progress)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                ScanProgressBar.Value = progress.Progress;
                StatusLabel.Text = $"正在扫描: {progress.CurrentFile}";
                _scannedFiles = progress.FilesScanned;
                _totalFiles = progress.TotalFiles;
            }));
        }

        private void FinishScan()
        {
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 100;
            StartScanBtn.IsEnabled = true;
            StopScanBtn.IsEnabled = false;
            _progressTimer.Stop();
        }

        private void StopScan_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            _antivirusEngine?.StopScan();
            StatusLabel.Text = "正在停止扫描...";
        }

        private void PauseScan_Click(object sender, RoutedEventArgs e)
        {
            if (_antivirusEngine != null)
            {
                if (_antivirusEngine.IsPaused)
                {
                    _antivirusEngine.ResumeScan();
                    StatusLabel.Text = "扫描已恢复";
                }
                else
                {
                    _antivirusEngine.PauseScan();
                    StatusLabel.Text = "扫描已暂停";
                }
            }
        }

        private void DeleteThreat_Click(object sender, RoutedEventArgs e)
        {
            if (ScanResultsList.SelectedItem is ThreatDisplayItem item)
            {
                var result = MessageBox.Show(
                    $"确定要删除此威胁文件吗？\n\n文件: {item.FileName}\n路径: {item.FilePath}",
                    "确认删除", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                
                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        if (File.Exists(item.FilePath))
                        {
                            File.Delete(item.FilePath);
                            _threatsList.Remove(item);
                            StatusLabel.Text = $"已删除: {item.FileName}";
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"删除失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private void QuarantineThreat_Click(object sender, RoutedEventArgs e)
        {
            if (ScanResultsList.SelectedItem is ThreatDisplayItem item)
            {
                try
                {
                    var quarantineDir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "FireAntivirus", "Quarantine");
                    
                    if (!Directory.Exists(quarantineDir))
                        Directory.CreateDirectory(quarantineDir);
                    
                    var destFile = Path.Combine(quarantineDir, 
                        $"{DateTime.Now:yyyyMMdd_HHmmss}_{item.FileName}.quar");
                    
                    File.Move(item.FilePath, destFile);
                    _threatsList.Remove(item);
                    StatusLabel.Text = $"已隔离: {item.FileName}";
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"隔离失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void TrustThreat_Click(object sender, RoutedEventArgs e)
        {
            if (ScanResultsList.SelectedItem is ThreatDisplayItem item)
            {
                var result = MessageBox.Show(
                    $"确定将此文件添加到信任列表吗？\n\n文件: {item.FileName}\n路径: {item.FilePath}\n\n此操作将不再扫描此文件。",
                    "添加到信任列表", MessageBoxButton.YesNo, MessageBoxImage.Question);
                
                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        _dataManager?.AddToWhitelist(item.FilePath);
                        _threatsList.Remove(item);
                        StatusLabel.Text = $"已添加到信任列表: {item.FileName}";
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"添加失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        // ---- 右下角风险弹窗处理动作（隔离/删除/信任/忽略）----
        private void QuarantineFileByPath(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return;
            try
            {
                var quarantineDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Quarantine");
                if (!Directory.Exists(quarantineDir)) Directory.CreateDirectory(quarantineDir);

                var destFile = Path.Combine(quarantineDir,
                    $"{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(filePath)}.quar");
                File.Move(filePath, destFile);
                System.Diagnostics.Debug.WriteLine($"已隔离: {filePath}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"隔离失败: {ex.Message}");
            }
        }

        private void DeleteFileByPath(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return;
            try
            {
                File.Delete(filePath);
                System.Diagnostics.Debug.WriteLine($"已删除: {filePath}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"删除失败: {ex.Message}");
            }
        }

        private void TrustFileByPath(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return;
            try
            {
                _dataManager?.AddToWhitelist(filePath);
                System.Diagnostics.Debug.WriteLine($"已加入信任: {filePath}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"加入信任失败: {ex.Message}");
            }
        }

        public void ApplyTheme(Theme theme)
        {
            _currentTheme = theme;
            MainGrid.Background = theme == Theme.Dark 
                ? new SolidColorBrush(Color.FromRgb(30, 30, 30))
                : Brushes.White;
        }

        // IPageWithLifecycle 实现
        private DateTime _lastAccessTime;
        private float _memoryUsageEstimate = 0f;

        public void OnPageCached()
        {
            _lastAccessTime = DateTime.Now;
            _memoryUsageEstimate = EstimateMemoryUsage();
            System.Diagnostics.Debug.WriteLine($"ScanPage被缓存，内存估算: {_memoryUsageEstimate:F2}MB");
        }

        public void OnPageActivated()
        {
            _lastAccessTime = DateTime.Now;
            System.Diagnostics.Debug.WriteLine($"ScanPage被激活，引擎状态: {_areEnginesLoaded}");
        }

        public void OnPageUnloaded()
        {
            // 在页面从缓存中卸载时，可以考虑卸载非必要的引擎资源
            if (_clamAVManager != null)
            {
                System.Diagnostics.Debug.WriteLine("ScanPage卸载，清理ClamAV引擎资源");
                // 保留基本的引擎实例，但停止不必要的活动
                _clamAVManager.StopAutoUpdate();
            }
            _memoryUsageEstimate = 0f;
        }

        public DateTime GetLastAccessTime()
        {
            return _lastAccessTime;
        }

        public float GetMemoryUsage()
        {
            return _memoryUsageEstimate;
        }

        /// <summary>
        /// 估算当前页面的内存使用量
        /// </summary>
        private float EstimateMemoryUsage()
        {
            float usage = 0f;
            
            // 页面基础结构：约 0.5MB
            usage += 0.5f;
            
            // 引擎占用内存（如果已加载）
            if (_areEnginesLoaded)
            {
                usage += 2.0f; // 基础引擎约2MB
                usage += 3.5f; // 病毒库和算法组件
            }
            
            // UI控件和数据绑定
            usage += 1.5f;
            
            return usage;
        }
    }

    /// <summary>
    /// 威胁显示项 - 专业版
    /// </summary>
    public class ThreatDisplayItem
    {
        public string FileName { get; set; }
        public string ThreatName { get; set; }
        public string FilePath { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public double Confidence { get; set; }
        public string DetectionMethod { get; set; }
        public long FileSize { get; set; }
        
        public string ConfidencePercent => $"{Confidence * 100:F1}%";
        public string FileSizeText => FormatFileSize(FileSize);
        
        private static string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            int order = 0;
            double size = bytes;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }
            return $"{size:F2} {sizes[order]}";
        }
    }
}