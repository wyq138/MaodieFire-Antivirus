// 抖音用户 耙耋杀毒软件 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class SecureBrowserPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private SecureBrowserService secureBrowser;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public SecureBrowserPage()
        {
            InitializeComponent();                
            // 延迟加载：将数据加载逻辑移到Loaded事件中
            Loaded += (s, e) => InitializeService();
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
        }

        private void InitializeService()
        {
            try { secureBrowser = new SecureBrowserService(); } catch { }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark) MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("SecureBrowser", "安全浏览器"); } catch { }
        }
    }
}
