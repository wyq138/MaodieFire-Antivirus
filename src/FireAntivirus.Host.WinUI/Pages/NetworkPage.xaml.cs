// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Linq;
using System.Net.NetworkInformation;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Engine;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class NetworkPage : Page
    {
        public NetworkPage()
        {
            InitializeComponent();
            Refresh_Click(null, null);
        }

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                bool connected = NetworkInterface.GetIsNetworkAvailable();
                int upCount = 0, conns = 0;
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up) upCount++;
                }
                try { conns = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Length; } catch { }
                NetStateText.Text = connected ? "网络已连接" : "网络未连接";
                NetStateText.Foreground = connected
                    ? (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SafeBrush"]
                    : (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
                NetDetailText.Text = $"活动接口 {upCount} 个，活动 TCP 连接 {conns} 条。检测引擎：本地特征库（abuse.ch 每小时自动更新）。";
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "网络状态检测失败: " + ex.Message);
                NetStateText.Text = "网络状态检测失败";
            }
        }
    }
}