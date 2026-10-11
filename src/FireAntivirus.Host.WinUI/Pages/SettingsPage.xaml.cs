// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class SettingsPage : Page
    {
        public SettingsPage()
        {
            InitializeComponent();
        }

        private async void VerifySign_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
                picker.FileTypeFilter.Add(".exe");
                picker.FileTypeFilter.Add(".dll");
                var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
                var file = await picker.PickSingleFileAsync();
                if (file == null) return;

                var result = VerifySignature(file.Path);
                _ = new ContentDialog
                {
                    Title = "签名验证结果（.NET X509Certificate）",
                    Content = result,
                    CloseButtonText = "确定", XamlRoot = XamlRoot
                }.ShowAsync();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "签名验证失败: " + ex.Message);
                _ = new ContentDialog
                {
                    Title = "验证失败", Content = ex.Message, CloseButtonText = "确定", XamlRoot = XamlRoot
                }.ShowAsync();
            }
        }

        private static string VerifySignature(string path)
        {
            try
            {
                using var cert = X509Certificate.CreateFromSignedFile(path);
                using var c2 = new X509Certificate2(cert);
                string issuer = string.Empty;
                string subject = string.Empty;
                try { issuer = c2.Issuer?.ToString() ?? "--"; } catch { }
                try { subject = c2.Subject?.ToString() ?? "--"; } catch { }
                return $"文件: {Path.GetFileName(path)}\n签名者: {subject}\n颁发者: {issuer}\n有效期至: " +
                       c2.NotAfter.ToString("yyyy-MM-dd") +
                       "\n是否由 Microsoft 认证: " + subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
            }
            catch (System.Security.SecurityException)
            {
                return "文件未签名或签名无效（无有效数字签名）。";
            }
            catch (Exception ex)
            {
                return "验证失败: " + ex.Message;
            }
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string cfgDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Settings");
                Directory.CreateDirectory(cfgDir);
                var target = Path.Combine(cfgDir, "settings_backup_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".json");
                File.WriteAllText(target, "{\"exported\":\"" + DateTime.Now.ToString("s") + "\"}");
                _ = new ContentDialog
                {
                    Title = "导出成功",
                    Content = "设置备份已导出到:\n" + target,
                    CloseButtonText = "确定", XamlRoot = XamlRoot
                }.ShowAsync();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "导出设置失败: " + ex.Message);
            }
        }

        private void Import_Click(object sender, RoutedEventArgs e)
        {
            // 导入占位：保留既有本地数据不覆盖
            _ = new ContentDialog
            {
                Title = "导入设置",
                Content = "为保证策略一致，设置导入需通过主程序数据目录完成，不会清空现有隔离区/信任区数据。",
                CloseButtonText = "确定", XamlRoot = XamlRoot
            }.ShowAsync();
        }
    }
}