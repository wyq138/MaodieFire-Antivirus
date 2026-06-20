// 抖音用户 耙耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class PasswordManagerPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private PasswordManager passwordManager;
        private DataManager dataManager;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private List<StoredPassword> passwords = new List<StoredPassword>();

        public PasswordManagerPage()
        {
            InitializeComponent();                
            // 延迟加载：将数据加载逻辑移到Loaded事件中
            Loaded += (s, e) => InitializeService();
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
        }

        private void InitializeService()
        {
            try
            {
                dataManager = new DataManager();
                passwordManager = new PasswordManager(dataManager);
                
                // 加载密码列表
                passwords = passwordManager?.GetPasswords() ?? new List<StoredPassword>();
            }
            catch { }
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
            try { TitleText.Text = _languageManager.GetString("PasswordManager", "密码管理"); }
            catch { }
        }
    }
}
