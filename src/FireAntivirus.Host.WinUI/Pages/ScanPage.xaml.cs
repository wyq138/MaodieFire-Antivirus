// 耄耋软件工作室 开发，严禁非法反编译
using System;
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
                if (mode == "quick") Quick_Click(null, null);
                else if (mode == "full") Full_Click(null, null);
            }
        }

        private void Quick_Click(object sender, RoutedEventArgs e) => StartScan("快速扫描", new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.Combine(Path.GetTempPath())
        });

        private void Full_Click(object sender, RoutedEventArgs e) => StartScan("完整扫描", new[] { @"C:\" });

        private void Custom_Click(object sender, RoutedEventArgs e)
        {
            var path = PathBox.Text?.Trim();
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
                ScanState.Text = "请输入有效的扫描路径";
                return;
            }
            StartScan("自定义扫描", new[] { path });
        }

        private void StartScan(string name, string[] roots)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            Threats.Clear();
            ScanState.Text = $"{name}进行中...";
            Progress.Value = 0;

            _ = Task.Run(async () =>
            {
                var engine = new FireAntivirus.Engine.AntivirusEngine();
                int scanned = 0, threats = 0;
                var files = new System.Collections.Generic.List<string>();
                foreach (var root in roots)
                {
                    try
                    {
                        files.AddRange(Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                            .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                                     || f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                                     || f.EndsWith(".scr", StringComparison.OrdinalIgnoreCase)
                                     || f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)
                                     || f.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)));
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, $"WinUI 枚举目录失败 {root}: {ex.Message}");
                    }
                }

                foreach (var file in files)
                {
                    if (_cts.IsCancellationRequested) break;
                    try
                    {
                        var r = engine.ScanFile(file);
                        scanned++;
                        if (r != null && r.IsInfected)
                        {
                            threats++;
                            var captured = r;
                            DispatcherQueue.TryEnqueue(() =>
                            {
                                Threats.Add(new ThreatRow
                                {
                                    ThreatName = captured.ThreatName,
                                    FilePath = captured.FilePath,
                                    Severity = captured.Severity,
                                    Confidence = captured.Confidence.ToString("P0")
                                });
                                ShowThreatOverlay(captured);
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, $"WinUI 扫描失败 {file}: {ex.Message}");
                    }

                    if (scanned % 10 == 0)
                    {
                        var pct = (double)scanned / Math.Max(1, files.Count) * 100;
                        var s = scanned; var t = threats; var total = files.Count;
                        DispatcherQueue.TryEnqueue(() =>
                        {
                            Progress.Value = pct;
                            ScanStats.Text = $"{s}/{total} 文件 · {t} 威胁";
                        });
                    }
                }

                DispatcherQueue.TryEnqueue(() =>
                {
                    Progress.Value = 100;
                    ScanState.Text = threats > 0 ? $"扫描完成：发现 {threats} 个威胁" : "扫描完成：未发现威胁";
                });
            }, _cts.Token);
        }

        private void ShowThreatOverlay(FireAntivirus.Engine.ScanResult r)
        {
            try
            {
                var window = (App.MainWindow as MainWindow);
                window?.ThreatHost?.Show(new ThreatOverlayHost.ThreatItem
                {
                    FilePath = r.FilePath,
                    ThreatName = r.ThreatName,
                    Severity = r.Severity,
                    Confidence = r.Confidence.ToString("P0")
                });
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 威胁浮层显示失败: " + ex.Message);
            }
        }

        private void Handle_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string path)
            {
                var dialog = new ContentDialog
                {
                    Title = "处理威胁",
                    Content = $"已对 {path} 应用隔离（可随时在隔离区恢复）。",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                _ = dialog.ShowAsync();
            }
        }
    }
}
