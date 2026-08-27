// 耄耋软件工作室 开发，严禁非法反编译
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
using FireAntivirus.EmailSecurity;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class EmailSecurityPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private EmailSecurityManager emailSecurity;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private LanguageManager _languageManager = LanguageManager.Instance;
        
        private ObservableCollection<ScannedEmail> scannedEmails = new ObservableCollection<ScannedEmail>();
        private bool _isInitialized = false;

        public EmailSecurityPage()
        {
            InitializeComponent();
                    
                    // 页面卸载时停止后台任务
                    Unloaded += (s, e) =>
                    {
                        _isLoaded = false;
                        _cts?.Cancel();
                    };
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            ScannedEmailsGrid.ItemsSource = scannedEmails;
            
            // 异步初始化
            Loaded += async (s, e) =>
            {
                if (_isInitialized) return;
                _isInitialized = true;
                await Task.Run(() => InitializeService());
                SetupEventHandlers();
            };
        }

        private void InitializeService()
        {
            try
            {
                dataManager = new DataManager();
                antivirusEngine = new AntivirusEngine();
                emailSecurity = new EmailSecurityManager(dataManager, antivirusEngine);
                Dispatcher.Invoke(() => LoadScannedEmails());
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmailSecurityPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void SetupEventHandlers()
        {
            SaveSettingsBtn.Click += SaveSettings_Click;
            AttachmentScanCheck.Checked += (s, e) => UpdateStatus();
            AttachmentScanCheck.Unchecked += (s, e) => UpdateStatus();
            PhishingDetectionCheck.Checked += (s, e) => UpdateStatus();
            PhishingDetectionCheck.Unchecked += (s, e) => UpdateStatus();
            SpamFilterCheck.Checked += (s, e) => UpdateStatus();
            SpamFilterCheck.Unchecked += (s, e) => UpdateStatus();
            LinkProtectionCheck.Checked += (s, e) => UpdateStatus();
            LinkProtectionCheck.Unchecked += (s, e) => UpdateStatus();
        }

        private void LoadScannedEmails()
        {
            try
            {
                scannedEmails.Clear();
                ScannedEmailsGrid.ItemsSource = scannedEmails;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmailSecurityPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void UpdateStatus()
        {
            bool anyEnabled = AttachmentScanCheck.IsChecked == true ||
                              PhishingDetectionCheck.IsChecked == true ||
                              SpamFilterCheck.IsChecked == true ||
                              LinkProtectionCheck.IsChecked == true;
            
            StatusText.Text = anyEnabled ? "邮件防护已启用" : "邮件防护已禁用";
            StatusText.Foreground = anyEnabled ? Brushes.Green : Brushes.Red;
        }

        private void SaveSettings_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                emailSecurity?.UpdateSettings(
                    AttachmentScanCheck.IsChecked == true,
                    PhishingDetectionCheck.IsChecked == true,
                    SpamFilterCheck.IsChecked == true
                );
                
                MessageBox.Show("设置已保存", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
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
            try { TitleText.Text = _languageManager.GetString("EmailSecurity", "邮件安全"); }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "EmailSecurityPage.xaml.cs 捕获异常", ex.Message); }
        }
    }

    // 已扫描邮件模型
    public class ScannedEmail
    {
        public string Sender { get; set; }
        public string Subject { get; set; }
        public DateTime ScanTime { get; set; }
        public string Status { get; set; }
    }
}