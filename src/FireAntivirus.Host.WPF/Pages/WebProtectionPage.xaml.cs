// 抖音用户 耙耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Threading.Tasks;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class WebProtectionPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private WebProtection webProtection;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private LanguageManager _languageManager = LanguageManager.Instance;
        
        private ObservableCollection<string> blacklist = new ObservableCollection<string>();
        private ObservableCollection<string> whitelist = new ObservableCollection<string>();
        private bool _isInitialized = false;

        public WebProtectionPage()
        {
            InitializeComponent();
                    
                    // 页面卸载时停止后台任务
                    Unloaded += (s, e) =>
                    {
                        _isLoaded = false;
                        _cts?.Cancel();
                    };
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            
            // 先设置默认数据，避免UI空白
            BlacklistListBox.ItemsSource = blacklist;
            WhitelistListBox.ItemsSource = whitelist;
            
            // 异步初始化
            Loaded += async (s, e) =>
            {
                if (_isInitialized) return;
                _isInitialized = true;
                await Task.Run(() => InitializeService());
            };
        }

        private void InitializeService()
        {
            try
            {
                dataManager = new DataManager();
                antivirusEngine = new AntivirusEngine();
                webProtection = new WebProtection(dataManager, antivirusEngine);
                
                // 加载列表 - 使用Dispatcher更新UI集合
                var blockedSites = webProtection.GetBlockedWebsites().ToList();
                var allowedSites = webProtection.GetAllowedWebsites().ToList();
                
                Dispatcher.Invoke(() =>
                {
                    foreach (var site in blockedSites)
                        blacklist.Add(site);
                    foreach (var site in allowedSites)
                        whitelist.Add(site);
                    
                    SetupEventHandlers();
                });
            }
            catch 
            {
                // 使用默认数据
                Dispatcher.Invoke(() =>
                {
                    blacklist.Add("malware-site.com");
                    blacklist.Add("phishing-example.net");
                    whitelist.Add("trusted-site.com");
                    SetupEventHandlers();
                });
            }
        }

        private void SetupEventHandlers()
        {
            AddBlacklistBtn.Click += AddBlacklist_Click;
            RemoveBlacklistBtn.Click += RemoveBlacklist_Click;
            AddWhitelistBtn.Click += AddWhitelist_Click;
            RemoveWhitelistBtn.Click += RemoveWhitelist_Click;
            
            BlockPhishing.Checked += (s, e) => UpdateSettings();
            BlockPhishing.Unchecked += (s, e) => UpdateSettings();
            BlockMalware.Checked += (s, e) => UpdateSettings();
            BlockMalware.Unchecked += (s, e) => UpdateSettings();
            BlockAds.Checked += (s, e) => UpdateSettings();
            BlockAds.Unchecked += (s, e) => UpdateSettings();
            BlockTrackers.Checked += (s, e) => UpdateSettings();
            BlockTrackers.Unchecked += (s, e) => UpdateSettings();
            BlockPopups.Checked += (s, e) => UpdateSettings();
            BlockPopups.Unchecked += (s, e) => UpdateSettings();
        }

        private void AddBlacklist_Click(object sender, RoutedEventArgs e)
        {
            var url = BlacklistTextBox.Text.Trim();
            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show("请输入网站地址", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            
            if (!blacklist.Contains(url))
            {
                blacklist.Add(url);
                webProtection?.BlockWebsite(url);
                BlacklistTextBox.Text = "";
                UpdateStatusText();
            }
        }

        private void RemoveBlacklist_Click(object sender, RoutedEventArgs e)
        {
            if (BlacklistListBox.SelectedItem is string selected)
            {
                blacklist.Remove(selected);
                webProtection?.UnblockWebsite(selected);
            }
        }

        private void AddWhitelist_Click(object sender, RoutedEventArgs e)
        {
            var url = WhitelistTextBox.Text.Trim();
            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show("请输入网站地址", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            
            if (!whitelist.Contains(url))
            {
                whitelist.Add(url);
                webProtection?.AddAllowedWebsite(url);
                WhitelistTextBox.Text = "";
                UpdateStatusText();
            }
        }

        private void RemoveWhitelist_Click(object sender, RoutedEventArgs e)
        {
            if (WhitelistListBox.SelectedItem is string selected)
            {
                whitelist.Remove(selected);
                webProtection?.RemoveAllowedWebsite(selected);
            }
        }

        private void UpdateSettings()
        {
            webProtection?.UpdateSettings(
                BlockPhishing.IsChecked == true,
                BlockMalware.IsChecked == true,
                BlockAds.IsChecked == true,
                blacklist.ToList(),
                new System.Collections.Generic.List<string>(),
                whitelist.ToList()
            );
            
            UpdateStatusText();
        }

        private void UpdateStatusText()
        {
            bool anyEnabled = BlockPhishing.IsChecked == true ||
                              BlockMalware.IsChecked == true ||
                              BlockAds.IsChecked == true ||
                              BlockTrackers.IsChecked == true ||
                              BlockPopups.IsChecked == true;
            
            StatusText.Text = anyEnabled ? $"网页防护已启用 - 已阻止 {blacklist.Count} 个网站" : "网页防护已禁用";
            StatusText.Foreground = anyEnabled ? Brushes.Green : Brushes.Red;
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
            try { TitleText.Text = _languageManager.GetString("WebProtection", "网页防护"); }
            catch { }
        }
    }
}
