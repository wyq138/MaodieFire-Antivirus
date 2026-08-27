// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class MobileSecurityPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private MobileSecurityService mobileSecurity;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public MobileSecurityPage()
        {
            InitializeComponent();                
            // 延迟加载：将数据加载逻辑移到Loaded事件中
            Loaded += (s, e) => InitializeService();
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
        }

        private void InitializeService()
        {
            try { mobileSecurity = new MobileSecurityService(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MobileSecurityPage.xaml.cs 捕获异常", ex.Message); }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark) MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("MobileSecurity", "移动安全"); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MobileSecurityPage.xaml.cs 捕获异常", ex.Message); }
        }
    }
}