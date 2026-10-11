// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class MobileSecurityPage : Page
    {
        public MobileSecurityPage()
        {
            InitializeComponent();
            DetectDevices();
        }

        private void Detect_Click(object sender, RoutedEventArgs e) => DetectDevices();

        private void DetectDevices()
        {
            int removable = 0;
            try
            {
                foreach (var d in DriveInfo.GetDrives())
                {
                    if (d.DriveType == DriveType.Removable && d.IsReady) removable++;
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "检测移动设备失败: " + ex.Message);
            }
            DeviceStatus.Text = removable > 0
                ? $"检测到 {removable} 个可移动设备，已启用接入扫描"
                : "未检测到可移动设备连接";
        }
    }
}