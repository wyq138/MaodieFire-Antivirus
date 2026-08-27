// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 关于页面 - 从WinForms转换
    /// </summary>
    public partial class AboutPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public AboutPage()
        {
            try
            {
                InitializeComponent();
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing AboutPage: {ex.Message}");
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("AboutTitle");
                VersionLabel.Text = _languageManager.GetString("Version", "1.0.3");
                DeveloperLabel.Text = _languageManager.GetString("Developer");
                PhoneLabel.Text = _languageManager.GetString("Phone");
                EmailLabel.Text = _languageManager.GetString("Email");
                DescriptionLabel.Text = _languageManager.GetString("Description");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "AboutPage.xaml.cs 捕获异常", ex.Message); }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            if (currentTheme == Theme.Dark)
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Colors.White);
            }
        }
    }
}