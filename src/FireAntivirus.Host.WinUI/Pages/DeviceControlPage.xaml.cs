// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class DeviceControlPage : Page
    {
        public DeviceControlPage()
        {
            InitializeComponent();
            Detect();
        }

        private void Detect_Click(object sender, RoutedEventArgs e) => Detect();

        private void Detect()
        {
            int removable = 0, other = 0;
            try
            {
                foreach (var d in DriveInfo.GetDrives())
                {
                    if (d.DriveType == DriveType.Removable && d.IsReady) removable++;
                    else if (d.DriveType == DriveType.Removable || d.DriveType == DriveType.CDRom) other++;
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "检测外设失败: " + ex.Message);
            }
            StatusText.Text = $"检测到可移动存储 {removable} 个，光盘/其他外设 {other} 个";
        }
    }
}