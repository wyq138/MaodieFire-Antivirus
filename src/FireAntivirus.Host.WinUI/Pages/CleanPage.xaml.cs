// 垃圾清理：真实扫描系统/用户临时目录与缓存，删除并统计释放空间
// 列表模板用运行时 XamlReader 生成（绕开 XamlCompiler 对新增页面的崩溃）
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class CleanRow
    {
        public string TargetPath { get; set; }
        public long Size { get; set; }
        public string SizeText => FormatSize(Size);
        public bool IsDir { get; set; }

        public static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / 1024.0 / 1024:F1} MB";
            return $"{bytes / 1024.0 / 1024 / 1024:F2} GB";
        }
    }

    public sealed partial class CleanPage : Page
    {
        public ObservableCollection<CleanRow> Items { get; } = new();
        private CancellationTokenSource _cts;

        public CleanPage()
        {
            InitializeComponent();
            CleanList.ItemsSource = Items;
            // 运行时模板：不经过 XamlCompiler
            CleanList.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""12"" Padding=""6"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <TextBlock Text=""{Binding TargetPath}"" FontSize=""12"" TextTrimming=""CharacterEllipsis""/>
        <TextBlock Grid.Column=""1"" Text=""{Binding SizeText}"" Opacity=""0.7"" VerticalAlignment=""Center""/>
    </Grid>
</DataTemplate>");
        }

        // 目标：各用户/系统临时目录、Windows 更新缓存、缩略图缓存（只清文件，不动目录结构）
        private static IEnumerable<(string path, bool isDir)> Targets()
        {
            var list = new List<(string, bool)>
            {
                (Path.GetTempPath(), true),
                (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"), true),
                (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"), true),
                (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Explorer"), false),
                (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SoftwareDistribution", "Download"), true),
            };
            // 用户级程序缓存（各浏览器/应用 Cache 目录）
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            try
            {
                foreach (var cache in Directory.EnumerateDirectories(local, "Cache", SearchOption.AllDirectories))
                    list.Add((cache, true));
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return list;
        }

        private async void Scan_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            ScanBtn.IsEnabled = false;
            CleanBtn.IsEnabled = false;
            Items.Clear();
            StateText.Text = "扫描中...";
            SummaryText.Text = "";

            var token = _cts.Token;
            await Task.Run(() =>
            {
                long total = 0; int count = 0;
                try
                {
                    foreach (var (target, isDir) in Targets())
                    {
                        if (token.IsCancellationRequested) break;
                        try
                        {
                            if (isDir && Directory.Exists(target))
                            {
                                long dirSize = 0;
                                foreach (var f in SafeFiles(target))
                                {
                                    try { dirSize += new FileInfo(f).Length; } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                                }
                                if (dirSize > 0)
                                {
                                    var captured = target; var size = dirSize;
                                    DispatcherQueue.TryEnqueue(() => Items.Add(new CleanRow { TargetPath = captured, Size = size, IsDir = true }));
                                    total += size; count++;
                                }
                            }
                            else if (File.Exists(target))
                            {
                                long size = 0;
                                try { size = new FileInfo(target).Length; } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                                var captured = target; var sz = size;
                                DispatcherQueue.TryEnqueue(() => Items.Add(new CleanRow { TargetPath = captured, Size = sz, IsDir = false }));
                                total += sz; count++;
                            }
                        }
                        catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    }
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "垃圾扫描失败: " + ex.Message);
                }
                var t = total; var c = count;
                DispatcherQueue.TryEnqueue(() =>
                {
                    StateText.Text = "扫描完成";
                    SummaryText.Text = $"共 {c} 项，可释放 {CleanRow.FormatSize(t)}";
                    Progress.Value = 100;
                    CleanBtn.IsEnabled = Items.Count > 0;
                    ScanBtn.IsEnabled = true;
                });
            }, token);
        }

        private static IEnumerable<string> SafeFiles(string dir)
        {
            var queue = new Queue<string>();
            queue.Enqueue(dir);
            while (queue.Count > 0)
            {
                var current = queue.Dequeue();
                string[] files = Array.Empty<string>(), dirs = Array.Empty<string>();
                try { files = Directory.GetFiles(current); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                try { dirs = Directory.GetDirectories(current); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                foreach (var f in files) yield return f;
                foreach (var d in dirs) queue.Enqueue(d);
            }
        }

        private async void Clean_Click(object sender, RoutedEventArgs e)
        {
            CleanBtn.IsEnabled = false;
            ScanBtn.IsEnabled = false;
            StateText.Text = "清理中...";

            var rows = Items.ToList();
            long freed = 0; int removed = 0;
            await Task.Run(() =>
            {
                foreach (var row in rows)
                {
                    try
                    {
                        long size = row.Size;
                        if (row.IsDir && Directory.Exists(row.TargetPath))
                        {
                            foreach (var f in SafeFiles(row.TargetPath))
                            {
                                try { File.Delete(f); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                            }
                            // 重新统计实际剩余
                            long remain = 0;
                            foreach (var f in SafeFiles(row.TargetPath))
                            {
                                try { remain += new FileInfo(f).Length; } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                            }
                            freed += size - remain;
                            removed++;
                        }
                        else if (File.Exists(row.TargetPath))
                        {
                            File.Delete(row.TargetPath);
                            freed += size;
                            removed++;
                        }
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, $"清理失败 {row.TargetPath}: {ex.Message}");
                    }
                }
            });

            Items.Clear();
            StateText.Text = "清理完成";
            SummaryText.Text = $"已清理 {removed} 项，释放 {CleanRow.FormatSize(freed)}";
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, $"垃圾清理完成: {removed} 项, {CleanRow.FormatSize(freed)}");
            ScanBtn.IsEnabled = true;
        }
    }
}
