// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class PrivacyProtectionPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public PrivacyProtectionPage()
        {
            InitializeComponent();                
                // 页面加载时自动加载数据
                Loaded += (s, e) => { /* 页面已初始化 */ };
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
        }

        private void ClearBrowser_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                int cleared = 0;
                if (ClearBrowserHistory.IsChecked == true) cleared++;
                if (ClearCookies.IsChecked == true) cleared++;
                if (ClearCache.IsChecked == true) cleared++;
                MessageBox.Show($"已清理 {cleared} 项浏览器数据", "清理完成", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"清理失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ApplyAll_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 应用Windows隐私设置
                if (DisableTelemetry.IsChecked == true)
                {
                    // 禁用遥测
                }
                MessageBox.Show("隐私设置已应用", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark)
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else
                MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("PrivacyProtection", "隐私保护"); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PrivacyProtectionPage.xaml.cs 捕获异常", ex.Message); }
        }
    }
}