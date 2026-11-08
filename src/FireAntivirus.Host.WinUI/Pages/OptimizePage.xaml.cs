// 系统优化：真实调用 SystemOptimization 服务（临时文件/浏览器缓存/回收站清理），
// 每项清理统计真实释放空间。UI 采用运行时模板。
using System;
using System.Linq;
using System.Threading.Tasks;
using FireAntivirus.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class OptimizePage : Page
    {
        private SystemOptimization _optimizer;
        private SystemOptimization Optimizer => _optimizer ??= new SystemOptimization();
        private TextBlock _state;
        private TextBlock _summary;
        private ProgressBar _progress;

        public OptimizePage()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[页面诊断] OptimizePage 构造开始");
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"[页面诊断] OptimizePage 构造完成 {sw.ElapsedMilliseconds}ms");
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("系统优化", ex);
            }
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 12 };

            root.Children.Add(new TextBlock
            {
                Text = "系统优化",
                FontSize = 22,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            });

            _state = new TextBlock { Text = "选择要执行的清理项，全部为真实系统清理操作", Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_state);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            btnRow.Children.Add(MakeButton("清理临时文件", () => new SystemCleanupOptions
            {
                CleanTempFiles = true, CleanLogFiles = false, CleanBrowserCache = false,
                CleanRecycleBin = false, CleanTemporaryInternetFiles = false
            }));
            btnRow.Children.Add(MakeButton("清理浏览器缓存", () => new SystemCleanupOptions
            {
                CleanTempFiles = false, CleanLogFiles = false, CleanBrowserCache = true,
                CleanRecycleBin = false, CleanTemporaryInternetFiles = false
            }));
            btnRow.Children.Add(MakeButton("清空回收站", () => new SystemCleanupOptions
            {
                CleanTempFiles = false, CleanLogFiles = false, CleanBrowserCache = false,
                CleanRecycleBin = true, CleanTemporaryInternetFiles = false
            }));
            btnRow.Children.Add(MakeButton("全部清理", () => new SystemCleanupOptions
            {
                CleanTempFiles = true, CleanLogFiles = true, CleanBrowserCache = true,
                CleanRecycleBin = true, CleanTemporaryInternetFiles = true
            }));
            root.Children.Add(btnRow);

            _progress = new ProgressBar { Minimum = 0, Maximum = 100, IsIndeterminate = false, Height = 4 };
            root.Children.Add(_progress);

            _summary = new TextBlock { FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_summary);

            root.Children.Add(new TextBlock
            {
                Text = "说明：回收站清理通过系统 Shell API 真实清空；浏览器缓存覆盖本机各用户缓存目录；清理结果按实际删除文件统计。",
                Opacity = 0.55,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap
            });

            return root;
        }

        private Button MakeButton(string text, Func<SystemCleanupOptions> optionsFactory)
        {
            var btn = new Button { Content = text, MinWidth = 130 };
            btn.Click += async (_, _) => await RunCleanup(optionsFactory());
            return btn;
        }

        private async Task RunCleanup(SystemCleanupOptions options)
        {
            _progress.IsIndeterminate = true;
            _summary.Text = "";

            try
            {
                // 服务层的 CleanupXxxAsync 是假异步（async 签名但内部零 await，CS1998），
                // 递归删临时文件/清空回收站/删浏览器缓存若不包 Task.Run 会全部跑在 UI 线程冻结整窗
                // （Task.Run 对返回 Task 的 lambda 自动解包，清理逻辑整体落在线程池线程）
                var result = await Task.Run(() => Optimizer.CleanupSystemAsync(options));

                if (result.Success)
                {
                    long freed = result.FreedSpaceBytes;
                    _summary.Text = result.CleanedItems.Count > 0
                        ? $"清理完成：{result.CleanedItems.Count} 个目标，释放 {FormatSize(freed)}"
                        : "清理完成：当前没有可清理的内容";
                }
                else
                {
                    _summary.Text = $"清理未完全成功: {result.ErrorMessage}";
                }
                _state.Text = $"上次操作: {DateTime.Now:HH:mm:ss}";
            }
            catch (Exception ex)
            {
                _summary.Text = $"清理失败: {ex.Message}";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 系统清理失败: " + ex.Message);
            }
            finally
            {
                _progress.IsIndeterminate = false;
                _progress.Value = 100;
            }
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / 1024.0 / 1024:F1} MB";
            return $"{bytes / 1024.0 / 1024 / 1024:F2} GB";
        }
    }
}