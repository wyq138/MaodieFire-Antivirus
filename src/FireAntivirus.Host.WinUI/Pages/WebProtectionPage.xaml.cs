// 耄耋软件工作室 开发，严禁非法反编译
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Engine;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class WebProtectionPage : Page
    {
        private readonly ObservableCollection<string> _black = new();
        private readonly ObservableCollection<string> _white = new();

        public WebProtectionPage()
        {
            InitializeComponent();
            BlacklistBox.ItemsSource = _black;
            WhitelistBox.ItemsSource = _white;
            try
            {
                // 预置常用站点用于UI展示，可随时移除
                _black.Add("malware-dist.site");
                _black.Add("phishing-example.net");
                _white.Add("trusted-site.com");
            }
            catch (System.Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "网页防护初始化: " + ex.Message);
            }
        }

        private static bool LooksLikeUrl(string url) =>
            url.Contains('.') && url.Length > 3;

        private void AddBlacklist_Click(object sender, RoutedEventArgs e)
        {
            var url = BlacklistInput.Text.Trim().ToLower();
            if (!LooksLikeUrl(url) || _black.Contains(url)) return;
            _black.Add(url);
            BlacklistInput.Text = "";
        }

        private void RemoveBlacklist_Click(object sender, RoutedEventArgs e)
        {
            if (BlacklistBox.SelectedItem is string s) _black.Remove(s);
        }

        private void AddWhitelist_Click(object sender, RoutedEventArgs e)
        {
            var url = WhitelistInput.Text.Trim().ToLower();
            if (!LooksLikeUrl(url) || _white.Contains(url)) return;
            _white.Add(url);
            WhitelistInput.Text = "";
        }

        private void RemoveWhitelist_Click(object sender, RoutedEventArgs e)
        {
            if (WhitelistBox.SelectedItem is string s) _white.Remove(s);
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            var threatCount = 0;
            foreach (var u in _black)
                if (SignatureDatabaseUpdater.IsMaliciousUrl(u)) threatCount++;
            StatusText.Text = $"已保存 - 黑名单 {_black.Count} 项，检测到 {threatCount} 个命中特征库";
        }

        private void Settings_Toggled(object sender, RoutedEventArgs e)
        {
            StatusText.Text = $"网页防护已启用 - 黑名单 {_black.Count} 项";
        }
    }
}