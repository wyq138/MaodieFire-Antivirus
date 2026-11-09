using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class ThreatRow
    {
        public string ThreatName { get; set; }
        public string FilePath { get; set; }
        public string Severity { get; set; }
        public string Confidence { get; set; }
    }

    public sealed partial class ScanPage : Page
    {
        public ObservableCollection<ThreatRow> Threats { get; } = new();
        private CancellationTokenSource _cts;
        // 扫描任务序号：旧任务用序号比对判断自己是否已被新扫描取代，避免旧回调回写 UI
        private int _seq;
        // 闸门：同一时刻只允许一个扫描任务真正执行（引擎/缓存非并发安全层）
        private static readonly SemaphoreSlim ScanGate = new(1, 1);
        // 引擎单例：构造含签名库加载与 30+ 分析器，禁止每次扫描重复构造
        private static FireAntivirus.Engine.AntivirusEngine _engine;
        private static FireAntivirus.Engine.AntivirusEngine SharedEngine =>
            _engine ??= new FireAntivirus.Engine.AntivirusEngine();

        private int _scanned;
        private int _threats;
        private long _lastUiTick;

        private static readonly HashSet<string> QuickExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".scr", ".ps1", ".bat",
            ".com", ".pif", ".cpl", ".hta", ".jse", ".vbe", ".wsf",
            ".jar", ".lnk", ".docm", ".xlsm", ".pptm", ".rtf"
        };

        private static readonly HashSet<string> FullExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".scr", ".ps1", ".bat",
            ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta",
            ".msi", ".cpl", ".ocx", ".sys", ".jar", ".docm", ".dotm", ".xlsm", ".xlam",
            ".pptm", ".lnk", ".reg", ".doc", ".xls", ".ppt", ".rtf"
        };

        /// <summary>快速扫描 = 全部高危落地目录（下载/桌面/临时/启动/程序目录/ProgramData/AppData）。</summary>
        private static string[] QuickRoots()
        {
            var roots = new List<string>();
            void Add(string p) { try { if (!string.IsNullOrEmpty(p) && Directory.Exists(p)) roots.Add(Path.GetFullPath(p)); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); } }

            Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"));
            Add(Path.GetTempPath());
            Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));   // ProgramData
            Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));    // AppData\Local
            Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));

            // 去重 + 剔除互相包含的父集（Temp 已被 UserProfile 覆盖时保留两者，扫描器按根循环无碍）
            return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        /// <summary>完整扫描 = 全盘（所有固定驱动器根目录递归）。</summary>
        private static string[] FullRoots()
        {
            try
            {
                return DriveInfo.GetDrives()
                    .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
                    .Select(d => d.RootDirectory.FullName)
                    .ToArray();
            }
            catch
            {
                return new[] { @"C:\" };
            }
        }

        private const long MaxScanFileBytes = 300L * 1024 * 1024;

        public ScanPage()
        {
            InitializeComponent();
            ThreatList.ItemsSource = Threats;
        }

        protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            if (e.Parameter is string mode)
            {
                AutoStart(mode);
            }
        }

        /// <summary>托管导航模式下的外部启动入口（首页"快速/完整扫描"按钮调用）。</summary>
        public void AutoStart(string mode)
        {
            // 延迟到页面渲染完成后再自动启动，避免与渲染抢占 UI 线程
            DispatcherQueue.TryEnqueue(() =>
            {
                if (mode == "quick") Quick_Click(null, null);
                else if (mode == "full") Full_Click(null, null);
            });
        }

        private void Quick_Click(object sender, RoutedEventArgs e) => StartScan("快速扫描", QuickRoots(), QuickExtensions);

        private void Full_Click(object sender, RoutedEventArgs e) => StartScan("完整扫描", FullRoots(), FullExtensions);

        private void Custom_Click(object sender, RoutedEventArgs e)
        {
            var path = PathBox.Text?.Trim();
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
                ScanState.Text = "请输入有效的扫描路径";
                return;
            }
            StartScan("自定义扫描", new[] { path }, FullExtensions);
        }

        private void Stop_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            StopBtn.IsEnabled = false;
            ScanState.Text = "正在停止扫描（等待当前文件结束）...";
        }

        private void SetScanningUi(bool scanning, string stateText)
        {
            QuickBtn.IsEnabled = !scanning;
            FullBtn.IsEnabled = !scanning;
            CustomBtn.IsEnabled = !scanning;
            StopBtn.IsEnabled = scanning;
            if (!string.IsNullOrEmpty(stateText)) ScanState.Text = stateText;
        }

        private void StartScan(string name, string[] roots, HashSet<string> extensions)
        {
            int seq = Interlocked.Increment(ref _seq);
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            var skipQuarantine = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "FireAntivirus", "Quarantine");

            Threats.Clear();
            Progress.Value = 0;
            _scanned = 0;
            _threats = 0;
            _lastUiTick = 0;
            SetScanningUi(true, $"{name}：正在枚举待扫描文件...");
            ScanStats.Text = "";

            _ = Task.Run(async () =>
            {
                bool gateTaken = false;
                try
                {
                    // 等待上一个扫描任务真正退出后再执行，避免两个扫描并发回写同一 UI
                    await ScanGate.WaitAsync(token);
                    gateTaken = true;
                    if (seq != Volatile.Read(ref _seq)) return;

                    var engine = SharedEngine;

                    // 枚举阶段：IgnoreInaccessible 让无权限目录被跳过而不是中止整个枚举。
                    // 旧实现 SearchOption.AllDirectories 一遇受限目录即抛异常终止，
                    // 导致完整扫描文件列表近乎为空、瞬间"扫完"。
                    var enumOptions = new EnumerationOptions
                    {
                        IgnoreInaccessible = true,
                        RecurseSubdirectories = true,
                        AttributesToSkip = FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReparsePoint
                    };

                    var files = new List<string>();
                    foreach (var root in roots)
                    {
                        try
                        {
                            foreach (var f in Directory.EnumerateFiles(root, "*", enumOptions))
                            {
                                token.ThrowIfCancellationRequested();
                                if (!extensions.Contains(Path.GetExtension(f))) continue;
                                if (SettingsStore.IsExcluded(f)) continue; // 用户配置的扫描排除目录
                                if (f.StartsWith(skipQuarantine, StringComparison.OrdinalIgnoreCase)) continue;
                                files.Add(f);

                                var now = Environment.TickCount64;
                                if (now - Interlocked.Read(ref _lastUiTick) > 200)
                                {
                                    Interlocked.Exchange(ref _lastUiTick, now);
                                    var found = files.Count;
                                    DispatcherQueue.TryEnqueue(() =>
                                    {
                                        if (seq != Volatile.Read(ref _seq)) return;
                                        ScanStats.Text = $"枚举中：已发现 {found} 个待扫描文件";
                                    });
                                }
                            }
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception ex)
                        {
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, $"WinUI 枚举目录失败 {root}: {ex.Message}");
                        }
                    }

                    if (seq != Volatile.Read(ref _seq)) return;
                    int total = files.Count;

                    var pendingOverlays = new ConcurrentQueue<FireAntivirus.Engine.ScanResult>();

                    var parallelOptions = new ParallelOptions
                    {
                        CancellationToken = token,
                        MaxDegreeOfParallelism = SettingsStore.EffectiveConcurrency
                    };

                    try
                    {
                        Parallel.ForEach(files, parallelOptions, file =>
                        {
                            try
                            {
                                try
                                {
                                    if (new FileInfo(file).Length > MaxScanFileBytes) return;
                                }
                                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

                                var r = engine.ScanFile(file);

                                // 压缩包深度扫描：解开 zip/tar/gz（原生）与 rar/7z（7-Zip）后对每个内部文件真实查杀。
                                // 压缩包本身无 PE 特征，只扫外层会漏掉全部载荷；有则可疑才展开，控制全盘扫描开销。
                                if (r != null && !r.IsInfected && FireAntivirus.Engine.Analyzers.ArchiveScanner.Enabled
                                    && FireAntivirus.Engine.Analyzers.ArchiveScanner.IsArchiveExt(file))
                                {
                                    try
                                    {
                                        var archiveResult = FireAntivirus.Engine.Analyzers.ArchiveScanner.Scan(file, engine.ScanFile);
                                        var badEntry = archiveResult.Files.FirstOrDefault(x => x.IsMalicious);
                                        if (badEntry != null)
                                        {
                                            r = new FireAntivirus.Engine.ScanResult
                                            {
                                                FilePath = file,
                                                IsInfected = true,
                                                ThreatName = badEntry.ThreatName ?? "Archive.MaliciousContent",
                                                ThreatType = "Trojan",
                                                Severity = "High",
                                                Confidence = 0.9,
                                                DetectionMethod = "ArchiveScan",
                                                DetectionTime = DateTime.Now,
                                                AdditionalInfo = $"压缩包内文件 {badEntry.InnerPath} 命中威胁" +
                                                                 $"（共展开 {archiveResult.Files.Count} 个内部文件）"
                                            };
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                            $"压缩包展开失败 {file}: {ex.Message}");
                                    }
                                }

                                Interlocked.Increment(ref _scanned);

                                if (r != null && r.IsInfected)
                                {
                                    Interlocked.Increment(ref _threats);
                                    pendingOverlays.Enqueue(r);
                                    var captured = r;
                                    DispatcherQueue.TryEnqueue(() =>
                                    {
                                        if (seq != Volatile.Read(ref _seq)) return;
                                        Threats.Add(new ThreatRow
                                        {
                                            ThreatName = captured.ThreatName,
                                            FilePath = captured.FilePath,
                                            Severity = captured.Severity,
                                            Confidence = captured.Confidence.ToString("P0")
                                        });
                                    });
                                }
                            }
                            catch (OperationCanceledException) { throw; }
                            catch (Exception ex)
                            {
                                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, $"WinUI 扫描失败 {file}: {ex.Message}");
                            }

                            var tick = Environment.TickCount64;
                            var prev = Interlocked.Read(ref _lastUiTick);
                            if (tick - prev > 200 && Interlocked.CompareExchange(ref _lastUiTick, tick, prev) == prev)
                            {
                                int s = Volatile.Read(ref _scanned);
                                int t = Volatile.Read(ref _threats);
                                DispatcherQueue.TryEnqueue(() =>
                                {
                                    if (seq != Volatile.Read(ref _seq)) return;
                                    Progress.Value = total > 0 ? (double)s / total * 100 : 100;
                                    ScanStats.Text = $"{s}/{total} 文件 · {t} 威胁";
                                });
                            }
                        });
                    }
                    catch (OperationCanceledException) { }

                    if (seq != Volatile.Read(ref _seq)) return;
                    int finalThreats = Volatile.Read(ref _threats);
                    int finalScanned = Volatile.Read(ref _scanned);
                    var firstOverlay = pendingOverlays.FirstOrDefault();
                    bool cancelled = token.IsCancellationRequested;

                    DispatcherQueue.TryEnqueue(() =>
                    {
                        if (seq != Volatile.Read(ref _seq)) return;
                        Progress.Value = 100;
                        ScanState.Text = cancelled
                            ? "扫描已停止"
                            : finalThreats > 0 ? $"扫描完成：发现 {finalThreats} 个威胁" : "扫描完成：未发现威胁";
                        ScanStats.Text = $"{finalScanned}/{total} 文件 · {finalThreats} 威胁";
                        SetScanningUi(false, null);
                        // 汇总式提示：扫描中只入列表不逐个弹浮层（防止大量威胁时浮层风暴冻结 UI），完成时弹一次
                        if (!cancelled && firstOverlay != null) ShowThreatOverlay(firstOverlay);
                    });
                }
                catch (OperationCanceledException)
                {
                    if (seq != Volatile.Read(ref _seq)) return;
                    DispatcherQueue.TryEnqueue(() =>
                    {
                        if (seq != Volatile.Read(ref _seq)) return;
                        ScanState.Text = "扫描已停止";
                        SetScanningUi(false, null);
                    });
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 扫描任务异常: " + ex.Message);
                    if (seq != Volatile.Read(ref _seq)) return;
                    DispatcherQueue.TryEnqueue(() =>
                    {
                        if (seq != Volatile.Read(ref _seq)) return;
                        ScanState.Text = $"扫描失败: {ex.Message}";
                        SetScanningUi(false, null);
                    });
                }
                finally
                {
                    if (gateTaken) ScanGate.Release();
                }
            }, CancellationToken.None);
        }

        private void ShowThreatOverlay(FireAntivirus.Engine.ScanResult r)
        {
            try
            {
                // 扫描确认威胁：独立处置窗口（隔离/忽略/打开位置，真实按钮）
                ThreatDealWindow.Show(
                    r.FilePath,
                    r.ThreatName,
                    r.Severity,
                    canQuarantine: true);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 扫描威胁弹窗失败: " + ex.Message);
            }
        }

        // 真实处理：隔离 = 移入隔离目录；删除 = 彻底删除文件
        private async void Handle_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button btn || btn.Tag is not string path) return;

            var menu = new MenuFlyout();
            var quarantineItem = new MenuFlyoutItem { Text = "隔离到隔离区", Tag = "quarantine" };
            var deleteItem = new MenuFlyoutItem { Text = "彻底删除", Tag = "delete" };
            quarantineItem.Click += async (_, _) => await DoAction(path, "quarantine");
            deleteItem.Click += async (_, _) => await DoAction(path, "delete");
            menu.Items.Add(quarantineItem);
            menu.Items.Add(deleteItem);
            menu.ShowAt(btn);
        }

        private async System.Threading.Tasks.Task DoAction(string path, string action)
        {
            try
            {
                bool ok; string err;
                if (action == "delete") ok = QuarantineStore.Delete(path, out err);
                else ok = QuarantineStore.Quarantine(path, "手动处理", "Medium", out err);

                var row = Threats.FirstOrDefault(t => string.Equals(t.FilePath, path, StringComparison.OrdinalIgnoreCase));
                if (ok && row != null) Threats.Remove(row);

                if (XamlRoot == null)
                {
                    ScanState.Text = ok
                        ? $"{(action == "delete" ? "已彻底删除" : "已隔离")}: {path}"
                        : $"处理失败: {err}";
                    return;
                }

                var dialog = new ContentDialog
                {
                    Title = ok ? "处理成功" : "处理失败",
                    Content = ok
                        ? $"{path}\n\n已{(action == "delete" ? "彻底删除" : "移入隔离区")}，可在隔离区查看。"
                        : $"{path}\n\n失败原因：{err}",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 威胁处理失败: " + ex.Message);
            }
        }
    }
}
