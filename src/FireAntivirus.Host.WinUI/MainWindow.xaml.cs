using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Host.WinUI.Pages;

namespace FireAntivirus.Host.WinUI
{
    public sealed partial class MainWindow : Window
    {
        // ============================================================
        // 页面实例托管（替代 Frame.Navigate）——六页卡死根因的根除方案：
        // 六个卡死页面（优化/漏洞/防火墙/密码库/报告/备份）是"纯代码 Page"（无 .xaml 文件，
        // 未在 XamlTypeInfo 注册）；Frame.Navigate(Type) 对未注册类型走反射路径直接挂起
        // （埋点实锤：导航开始后无任何后续、页面构造未执行）。
        // 对比法验证：有 .xaml 的 11 个页面全部正常，无 .xaml 的 6 个页面全部卡死。
        // 方案：反射直接构造页面（构造本身毫秒级），由 Grid 容器托管；XAML 页 InitializeComponent
        // 与纯代码页 Content=BuildLayout 均正常；Required 缓存语义由 _pages 字典实现。
        // ============================================================
        private readonly Dictionary<Type, Page> _pages = new Dictionary<Type, Page>();
        private Page _currentPage;

        public MainWindow()
        {
            InitializeComponent();
            Title = "耄耋安全";

            // 窗口/任务栏图标：猫脸图标（与 exe 内嵌图标一致，勿用旧版 app.ico 覆盖）
            try { AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "app_cat.ico")); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            // 毛玻璃：优先 DesktopAcrylic，失败则回退 Mica，再失败保持默认
            try { SystemBackdrop = new Microsoft.UI.Xaml.Media.DesktopAcrylicBackdrop(); }
            catch { try { SystemBackdrop = new Microsoft.UI.Xaml.Media.MicaBackdrop(); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); } }
            ShowPage(typeof(HomePage));
            // 同步首页导航项选中态（触发 SelectionChanged → ShowPage 提前返回）
            if (Nav.MenuItems.Count > 0) Nav.SelectedItem = Nav.MenuItems[0];
            Nav.IsPaneOpen = true;

        }

        /// <summary>
        /// 托管页面：反射构造（首次）+ 容器切换。取代 Frame.Navigate，绕开未注册类型的挂起路径。
        /// </summary>
        public Page ShowPage(Type pageType)
        {
            if (_currentPage != null && _currentPage.GetType() == pageType) return _currentPage;

            if (!_pages.TryGetValue(pageType, out var page))
            {
                page = (Page)Activator.CreateInstance(pageType);
                _pages[pageType] = page;
            }

            PageHost.Children.Clear();
            PageHost.Children.Add(page);
            _currentPage = page;
            return page;
        }

        /// <summary>代码内跳转（如首页扫描按钮）：托管切换 + 同步左侧导航选中态。</summary>
        public Page NavigateTo(Type pageType)
        {
            var page = ShowPage(pageType);
            foreach (var obj in Nav.MenuItems)
            {
                if (obj is NavigationViewItem nvi && TagToType(nvi.Tag?.ToString()) == pageType)
                {
                    Nav.SelectedItem = nvi; // 触发 SelectionChanged → ShowPage 提前返回
                    break;
                }
            }
            return page;
        }

        private static Type TagToType(string tag) => tag switch
        {
            "scan" => typeof(ScanPage),
            "protect" => typeof(ProtectPage),
            "quarantine-center" => typeof(QuarantineCenterPage),
            "security-center" => typeof(SecurityCenterPage),
            "vul" => typeof(VulnerabilityPage),
            "netstat" => typeof(NetstatPage),
            "firewall" => typeof(FirewallPage),
            "web-security" => typeof(WebSecurityPage),
            "device-privacy" => typeof(DevicePrivacyPage),

            "password" => typeof(PasswordVaultPage),
            "backup" => typeof(BackupPage),
            "system-monitor" => typeof(SystemMonitorPage),
            "system-tools" => typeof(SystemToolsPage),
            "logs" => typeof(LogsPage),
            "settings" => typeof(SettingsPage),
            "about" => typeof(AboutPage),
            _ => typeof(HomePage)
        };

        /// <summary>
        /// 页面诊断模式（--pagediag 启动参数触发）：自动依次打开六个曾报卡死的页面，
        /// 每页停留 4 秒——配合页面级埋点日志毫秒级定位卡点，无需人工操作。
        /// </summary>
        public async System.Threading.Tasks.Task RunPageDiagnosticsAsync()
        {
            var pages = new (string tag, Type type)[]
            {
                ("optimize", typeof(OptimizePage)),
                ("vul", typeof(VulnerabilityPage)),
                ("firewall", typeof(FirewallPage)),
                ("password", typeof(PasswordVaultPage)),
                ("report", typeof(ReportPage)),
                ("backup", typeof(BackupPage)),
            };

            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                "[页面诊断] ===== 自动遍历开始 =====");

            foreach (var (tag, type) in pages)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"[页面诊断] >>> 自动导航 {tag}");
                var sw = System.Diagnostics.Stopwatch.StartNew();
                try
                {
                    ShowPage(type);
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        $"[页面诊断] <<< 自动导航 {tag} 完成 {sw.ElapsedMilliseconds}ms");
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                        $"[页面诊断] 导航 {tag} 异常: {ex}");
                }
                await System.Threading.Tasks.Task.Delay(4000);
            }

            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                "[页面诊断] ===== 自动遍历结束 =====");
        }

        /// <summary>
        /// 首次导航回调：首页已在构造时托管加载完成，直接回调（保留签名供 App 调用）。
        /// </summary>
        public void RunAfterFirstNavigation(Action action)
        {
            try { action(); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
        }

        private async void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItem is not NavigationViewItem item) return;
            var tag = item.Tag?.ToString();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, $"[页面诊断] 导航到 {tag} 开始");
            var page = TagToType(tag);

            if (_currentPage != null && _currentPage.GetType() == page) return;

            try
            {
                ShowPage(page);
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"[页面诊断] 导航到 {tag} 完成 {sw.ElapsedMilliseconds}ms");
            }
            catch (Exception ex)
            {
                // 页面初始化失败时如实提示，不闪退
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    $"页面加载失败 [{tag}]: {ex}");
                try
                {
                    await new ContentDialog
                    {
                        Title = "页面加载失败",
                        Content = $"功能: {item.Content}\n\n原因: {ex.Message}\n\n详细信息已写入日志。",
                        CloseButtonText = "确定",
                        XamlRoot = Content.XamlRoot
                    }.ShowAsync();
                }
                catch (Exception ex2) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex2.Message); }
            }
        }
    }
}