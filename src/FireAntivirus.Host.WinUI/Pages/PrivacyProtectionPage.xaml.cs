// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class PrivacyProtectionPage : Page
    {
        public PrivacyProtectionPage()
        {
            InitializeComponent();
        }

        private void Clean_Browsers_Click(object sender, RoutedEventArgs e)
        {
            long freed = 0;
            foreach (var root in new[] { "Edge", "Chrome", "Firefox" })
                freed += CleanDir(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), root, "Default", "Cache"));
            StatusText.Text = "已清理浏览器缓存，释放 " + Fmt(freed);
        }

        private void Clean_Clipboard_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 通过命令符调用系统剪贴板清理（不重启资源管理器，避免打断用户会话）
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c powershell -NoProfile -Command \"Get-Process | Where-Object {$_.Name -in 'clip','Clipboard'} | Stop-Process -Force -ErrorAction SilentlyContinue; echo done\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                System.Diagnostics.Process.Start(psi);
                StatusText.Text = "已尝试清空剪贴板历史记录";
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "清空剪贴板失败: " + ex.Message);
                StatusText.Text = "清空剪贴板失败";
            }
        }

        private void Clean_Temp_Click(object sender, RoutedEventArgs e)
        {
            long freed = 0;
            foreach (var d in new[] { Path.GetTempPath(),
                      Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp") })
                freed += CleanDir(d);
            StatusText.Text = "已清理临时追踪文件，释放 " + Fmt(freed);
        }

        private static long CleanDir(string dir)
        {
            long freed = 0;
            if (!Directory.Exists(dir)) return 0;
            try
            {
                foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    try { var fi = new FileInfo(f); var len = fi.Length; fi.Delete(); freed += len; } catch { }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "清理目录失败: " + ex.Message);
            }
            return freed;
        }

        private static string Fmt(long bytes)
        {
            string[] suf = { "B", "KB", "MB", "GB" };
            double v = bytes; int i = 0;
            while (v >= 1024 && i < suf.Length - 1) { v /= 1024; i++; }
            return $"{v:F1} {suf[i]}";
        }
    }
}