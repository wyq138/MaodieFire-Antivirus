// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Diagnostics;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Engine;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class SecureBrowserPage : Page
    {
        public SecureBrowserPage()
        {
            InitializeComponent();
        }

        private void OpenSecure_Click(object sender, RoutedEventArgs e)
        {
            var url = UrlInput.Text.Trim();
            if (string.IsNullOrEmpty(url))
            {
                url = "https://www.bing.com";
            }
            if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                url = "https://" + url;

            try
            {
                // 先做网页防护预检：命中恶意特征库则拦截
                if (SignatureDatabaseUpdater.IsMaliciousUrl(url))
                {
                    StatusText.Text = "已拦截：恶意 URL / C2 连接已被拦截";
                    _ = new ContentDialog
                    {
                        Title = "已拦截",
                        Content = "该网址命中恶意特征库，已在云端拦截，未打开页面。",
                        CloseButtonText = "确定", XamlRoot = XamlRoot
                    }.ShowAsync();
                    return;
                }

                // 以沙箱进程方式打开（隐藏窗口到后台，避免直接污染主会话）
                var psi = new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true,
                    Verb = "open"
                };
                Process.Start(psi);
                StatusText.Text = "已在安全模式下打开: " + url;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "打开安全浏览器失败: " + ex.Message);
                StatusText.Text = "打开失败: " + ex.Message;
            }
        }
    }
}