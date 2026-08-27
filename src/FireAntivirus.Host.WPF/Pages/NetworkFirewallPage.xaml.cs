// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Threading.Tasks;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class NetworkFirewallPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private FirewallManager firewallManager;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private LanguageManager _languageManager = LanguageManager.Instance;
        
        private ObservableCollection<string> firewallRules = new ObservableCollection<string>();
        private ObservableCollection<ConnectionInfo> activeConnections = new ObservableCollection<ConnectionInfo>();
        
        private bool isFirewallEnabled = true;
        private int todayBlocked = 0;
        private int weekBlocked = 0;
        private int totalBlocked = 0;
        private bool _isInitialized = false;

        public NetworkFirewallPage()
        {
            InitializeComponent();
                    
                    // 页面卸载时停止后台任务
                    Unloaded += (s, e) =>
                    {
                        _isLoaded = false;
                        _cts?.Cancel();
                    };
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            
            // 先设置ItemsSource
            ActiveConnectionsGrid.ItemsSource = activeConnections;
            RulesListBox.ItemsSource = firewallRules;
            
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
                firewallManager = new FirewallManager(dataManager, antivirusEngine);
                
                Dispatcher.Invoke(() => UpdateStatistics());
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkFirewallPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void SetupEventHandlers()
        {
            FirewallToggle.Click += FirewallToggle_Click;
            RefreshConnectionsBtn.Click += RefreshConnections_Click;
            AddRuleBtn.Click += AddRule_Click;
            RemoveRuleBtn.Click += RemoveRule_Click;
        }

        private void FirewallToggle_Click(object sender, RoutedEventArgs e)
        {
            isFirewallEnabled = !isFirewallEnabled;
            
            FirewallStatusText.Text = isFirewallEnabled ? "已启用" : "已禁用";
            FirewallStatusText.Foreground = isFirewallEnabled ? Brushes.Green : Brushes.Red;
            FirewallToggle.Content = isFirewallEnabled ? "关闭" : "启用";
            
            MessageBox.Show(
                isFirewallEnabled ? "防火墙已启用" : "防火墙已禁用",
                "防火墙状态",
                MessageBoxButton.OK,
                MessageBoxImage.Information
            );
        }

        private void RefreshConnections_Click(object sender, RoutedEventArgs e)
        {
            LoadActiveConnections();
        }

        private void LoadActiveConnections()
        {
            try
            {
                activeConnections.Clear();
                
                // 添加一些示例连接
                activeConnections.Add(new ConnectionInfo
                {
                    ProcessName = "chrome.exe",
                    LocalAddress = "192.168.1.100",
                    RemoteAddress = "142.250.80.46",
                    Port = 443,
                    Protocol = "TCP",
                    Status = "已建立"
                });
                
                UpdateStatistics();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkFirewallPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void AddRule_Click(object sender, RoutedEventArgs e)
        {
            var input = Microsoft.VisualBasic.Interaction.InputBox("请输入规则名称:", "添加规则", "");
            if (!string.IsNullOrEmpty(input))
            {
                firewallRules.Add(input);
            }
        }

        private void RemoveRule_Click(object sender, RoutedEventArgs e)
        {
            if (RulesListBox.SelectedItem is string selected)
            {
                firewallRules.Remove(selected);
            }
            else
            {
                MessageBox.Show("请先选择要移除的规则", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void UpdateStatistics()
        {
            try
            {
                var stats = firewallManager?.GetStatistics();
                if (stats != null)
                {
                    todayBlocked = (int)stats.ConnectionsBlocked;
                }
                
                TodayBlockedText.Text = todayBlocked.ToString();
                WeekBlockedText.Text = weekBlocked.ToString();
                TotalBlockedText.Text = totalBlocked.ToString();
                PortScanCountText.Text = "0 次";
                DDoSCountText.Text = "0 次";
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkFirewallPage.xaml.cs 捕获异常", ex.Message); }
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
            try { TitleText.Text = _languageManager.GetString("NetworkFirewall", "网络防火墙"); }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkFirewallPage.xaml.cs 捕获异常", ex.Message); }
        }
    }

    // 连接信息模型
    public class ConnectionInfo
    {
        public string ProcessName { get; set; }
        public string LocalAddress { get; set; }
        public string RemoteAddress { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; }
        public string Status { get; set; }
    }
}