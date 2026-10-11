// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class HomePage : Page
    {
        private readonly FireAntivirus.Engine.AntivirusEngine _engine;

        public HomePage()
        {
            InitializeComponent();
            try
            {
                _engine = new FireAntivirus.Engine.AntivirusEngine();
                LoadStatus();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 首页初始化失败: " + ex.Message);
            }
        }

        private void LoadStatus()
        {
            try
            {
                // 内嵌特征库自检：确认 YARA/PE/文件名/白名单数据全部加载
                var (ok, yara, pe, kf, pub, err) = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.SelfCheck();
                DbVersion.Text = ok ? $"内嵌 {yara + pe + kf} 条" : "特征库异常";
                if (!ok)
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "内嵌特征库自检失败: " + err);

                StatusText.Text = ok ? "你的设备受保护" : "防护组件部分异常";
                RealTimeToggle.IsOn = true;
                WebToggle.IsOn = true;
                RansomToggle.IsOn = true;
                BehaviorToggle.IsOn = true;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 首页状态加载失败: " + ex.Message);
            }
        }

        private void QuickScan_Click(object sender, RoutedEventArgs e) => NavigateToScan("quick");
        private void FullScan_Click(object sender, RoutedEventArgs e) => NavigateToScan("full");

        private void NavigateToScan(string mode)
        {
            try
            {
                if (Frame?.Content is null && Frame != null) { }
                Frame?.Navigate(typeof(ScanPage), mode);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 跳转扫描页失败: " + ex.Message);
            }
        }

        private async void UpdateDb_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var btn = (Button)sender;
                btn.IsEnabled = false;
                btn.Content = "更新中...";
                var result = await FireAntivirus.Engine.SignatureDatabaseUpdater.UpdateAsync();
                DbVersion.Text = result.Succeeded ? "已更新" : "更新失败（检查网络）";
                btn.Content = "更新病毒库";
                btn.IsEnabled = true;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 病毒库更新失败: " + ex.Message);
            }
        }

        private void RealTimeToggle_Toggled(object sender, RoutedEventArgs e) => LogToggle("实时防护", RealTimeToggle.IsOn);
        private void WebToggle_Toggled(object sender, RoutedEventArgs e) => LogToggle("网页防护", WebToggle.IsOn);
        private void RansomToggle_Toggled(object sender, RoutedEventArgs e) => LogToggle("勒索防护", RansomToggle.IsOn);
        private void BehaviorToggle_Toggled(object sender, RoutedEventArgs e) => LogToggle("行为分析", BehaviorToggle.IsOn);

        private void LogToggle(string name, bool on)
        {
            try
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, $"WinUI {name} 切换为 {(on ? "开启" : "关闭")}");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 记录开关失败: " + ex.Message);
            }
        }
    }
}
