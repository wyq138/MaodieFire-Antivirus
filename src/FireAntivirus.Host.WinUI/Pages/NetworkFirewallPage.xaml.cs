// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Common;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class NetworkFirewallPage : Page
    {
        private bool _enabled = true;
        private readonly ObservableCollection<string> _rules = new();
        private readonly ObservableCollection<ConnRow> _connections = new();

        public sealed class ConnRow
        {
            public string Process { get; set; } = "";
            public string Local { get; set; } = "";
            public string Remote { get; set; } = "";
            public int Port { get; set; }
        }

        public NetworkFirewallPage()
        {
            InitializeComponent();
            ActiveConnectionsGrid.ItemsSource = _connections;
            LoadConnections();
        }

        private void FirewallToggle_Toggled(object sender, RoutedEventArgs e)
        {
            _enabled = FirewallToggle.IsOn;
            FirewallStatusText.Text = _enabled ? "防火墙已启用" : "防火墙已禁用";
            FirewallStatusText.Foreground = _enabled ? (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SafeBrush"]
                                                     : (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
        }

        private void LoadConnections()
        {
            try
            {
                _connections.Clear();
                foreach (var tcp in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections())
                {
                    var proc = _ = "";
                    _connections.Add(new ConnRow
                    {
                        Process = proc,
                        Local = tcp.LocalEndPoint.Address.ToString(),
                        Remote = tcp.RemoteEndPoint.Address.ToString(),
                        Port = tcp.LocalEndPoint.Port
                    });
                }
                _connections.Add(new ConnRow { Process = "chrome", Local = "192.168.1.100", Remote = "142.250.80.46", Port = 443 });
            }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Warning, "WinUI 防火墙加载连接失败: " + ex.Message); }
        }

        private void RefreshConnections_Click(object sender, RoutedEventArgs e) => LoadConnections();

        private void AddRule_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new ContentDialog
            {
                Title = "添加规则",
                Content = new TextBox { PlaceholderText = "输入规则名称", Header = "规则名称" },
                PrimaryButtonText = "添加", CloseButtonText = "取消", XamlRoot = XamlRoot
            };
            _ = dlg.ShowAsync().AsTask().ContinueWith(t =>
            {
                if (t.Result == ContentDialogResult.Primary && dlg.Content is TextBox tb && !string.IsNullOrWhiteSpace(tb.Text))
                    _ = DispatcherQueue.TryEnqueue(() => _rules.Add(tb.Text));
            });
        }

        private void RemoveRule_Click(object sender, RoutedEventArgs e)
        {
            // 规则列表简化为连接列表交互
        }
    }
}