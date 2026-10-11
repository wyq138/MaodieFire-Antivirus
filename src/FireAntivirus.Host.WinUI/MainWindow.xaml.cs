// 耄耋软件工作室 开发，严禁非法反编译
using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Host.WinUI.Pages;

namespace FireAntivirus.Host.WinUI
{
    public sealed partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            Title = "耄耋安全";
            ContentFrame.Navigate(typeof(HomePage));
            Nav.IsPaneOpen = true;
        }

        private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItem is not NavigationViewItem item) return;
            var tag = item.Tag?.ToString();
            var page = tag switch
            {
                "home" => typeof(HomePage),
                "scan" => typeof(ScanPage),
                "protect" => typeof(ProtectPage),
                "quarantine" => typeof(QuarantinePage),
                "report" => typeof(ReportPage),
                "tools" => typeof(ToolsPage),
                "about" => typeof(AboutPage),
                // 网络防护
                "firewall" => typeof(NetworkFirewallPage),
                "network" => typeof(NetworkPage),
                "traffic" => typeof(NetworkTrafficAnalyzerPage),
                "web" => typeof(WebProtectionPage),
                // 检测与隔离
                "cloud" => typeof(CloudScannerPage),
                "vuln" => typeof(VulnerabilityScannerPage),
                "behavior" => typeof(BehaviorAnalysisPage),
                "score" => typeof(SecurityScorePage),
                "trust" => typeof(TrustZonePage),
                // 防护中心
                "ransom" => typeof(RansomwareProtectionPage),
                "privacy" => typeof(PrivacyProtectionPage),
                "popup" => typeof(PopupBlockerPage),
                "password" => typeof(PasswordManagerPage),
                "parental" => typeof(ParentalControlPage),
                "mobile" => typeof(MobileSecurityPage),
                "email" => typeof(EmailSecurityPage),
                "device" => typeof(DeviceControlPage),
                // 系统工具
                "optimizer" => typeof(SystemOptimizerPage),
                "sysinfo" => typeof(SystemInfoPage),
                "startup" => typeof(StartupManagerPage),
                "perf" => typeof(PerformanceDiagnosticsPage),
                "backup" => typeof(BackupPage),
                "appmonitor" => typeof(ApplicationMonitorPage),
                "browser" => typeof(SecureBrowserPage),
                // 其他
                "logs" => typeof(LogsPage),
                "settings" => typeof(SettingsPage),
                "donation" => typeof(DonationPage),
                _ => typeof(HomePage)
            };

            if (ContentFrame.CurrentSourcePageType != page)
                ContentFrame.Navigate(page, null, args.RecommendedNavigationTransitionInfo);
        }
    }
}