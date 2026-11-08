// 隐私保护页（搬运自 WPF PrivacyProtectionPage，WinUI 真实实现 + 加固）：
// PrivacyProtectionManager 真实隐私防护：摄像头/麦克风访问监控（WMI 设备访问事件）、
// 隐私威胁检测（进程访问敏感数据）、一键阻止摄像头/麦克风。事件实时订阅进列表，页面卸载自动退订。
using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using FireAntivirus.PrivacyProtection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class PrivacyEventRow
    {
        public string Time { get; set; }
        public string Type { get; set; }
        public string Detail { get; set; }
    }

    public sealed partial class PrivacyProtectionPage : Page
    {
        private readonly PrivacyProtectionManager _manager = new PrivacyProtectionManager();
        private readonly ObservableCollection<PrivacyEventRow> _events = new();

        private TextBlock _state;
        private bool _monitoring;
        private bool _subscribed;

        public PrivacyProtectionPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                Subscribe();
                Unloaded += (_, _) => Unsubscribe();
                // 聚合页 Tab 切换会触发 Unloaded/Loaded：切回时重新订阅，防事件丢失
                Loaded += (_, _) => Subscribe();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("隐私保护", ex);
            }
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 14 };
            root.Children.Add(new TextBlock { Text = "隐私保护", FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            _state = new TextBlock { Text = "隐私访问监控：摄像头 / 麦克风 / 敏感数据访问实时告警", Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_state);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            var startBtn = new Button { Content = "启动隐私监控", MinWidth = 120 };
            startBtn.Click += (_, _) => { _ = StartAsync(); };
            btnRow.Children.Add(startBtn);
            var stopBtn = new Button { Content = "停止监控", MinWidth = 100 };
            stopBtn.Click += (_, _) => { _manager.StopMonitoring(); _monitoring = false; _state.Text = "隐私监控已停止"; };
            btnRow.Children.Add(stopBtn);
            var camBtn = new Button { Content = "阻止摄像头访问", MinWidth = 130 };
            camBtn.Click += (_, _) =>
            {
                bool ok = _manager.BlockCameraAccess();
                _state.Text = ok ? "已阻止摄像头访问（Windows 隐私策略 webcam=Deny，全局生效）" : "阻止失败：需要管理员权限";
            };
            btnRow.Children.Add(camBtn);
            var micBtn = new Button { Content = "阻止麦克风访问", MinWidth = 130 };
            micBtn.Click += (_, _) =>
            {
                bool ok = _manager.BlockMicrophoneAccess();
                _state.Text = ok ? "已阻止麦克风访问（Windows 隐私策略 microphone=Deny，全局生效）" : "阻止失败：需要管理员权限";
            };
            btnRow.Children.Add(micBtn);
            var restoreCamBtn = new Button { Content = "恢复摄像头", MinWidth = 100 };
            restoreCamBtn.Click += (_, _) =>
            {
                bool ok = _manager.UnblockCameraAccess();
                _state.Text = ok ? "已恢复摄像头访问（webcam=Allow）" : "恢复失败：需要管理员权限";
            };
            btnRow.Children.Add(restoreCamBtn);
            var restoreMicBtn = new Button { Content = "恢复麦克风", MinWidth = 100 };
            restoreMicBtn.Click += (_, _) =>
            {
                bool ok = _manager.UnblockMicrophoneAccess();
                _state.Text = ok ? "已恢复麦克风访问（microphone=Allow）" : "恢复失败：需要管理员权限";
            };
            btnRow.Children.Add(restoreMicBtn);
            var clearBtn = new Button { Content = "清空记录", MinWidth = 90 };
            clearBtn.Click += (_, _) => { _events.Clear(); _state.Text = "记录已清空"; };
            btnRow.Children.Add(clearBtn);
            root.Children.Add(btnRow);

            root.Children.Add(new TextBlock { Text = "隐私访问 / 威胁记录", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            root.Children.Add(new ListView { ItemsSource = _events, MaxHeight = 460, SelectionMode = ListViewSelectionMode.None });

            return root;
        }

        private async Task StartAsync()
        {
            try
            {
                _state.Text = "正在启动隐私监控...";
                await _manager.StartMonitoring();
                _monitoring = true;
                _state.Text = "隐私监控运行中（摄像头/麦克风/数据访问实时捕获）";
            }
            catch (Exception ex)
            {
                _state.Text = "启动失败: " + ex.Message;
            }
        }

        private void Subscribe()
        {
            if (_subscribed) return;
            _manager.PrivacyThreatDetected += OnPrivacyThreat;
            _manager.CameraAccessDetected += OnCamera;
            _manager.MicrophoneAccessDetected += OnMicrophone;
            _manager.DataCollectionDetected += OnDataCollection;
            _subscribed = true;
        }

        private void Unsubscribe()
        {
            if (!_subscribed) return;
            _manager.PrivacyThreatDetected -= OnPrivacyThreat;
            _manager.CameraAccessDetected -= OnCamera;
            _manager.MicrophoneAccessDetected -= OnMicrophone;
            _manager.DataCollectionDetected -= OnDataCollection;
            _subscribed = false;
        }

        private void AddRow(string type, string detail)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                _events.Insert(0, new PrivacyEventRow
                {
                    Time = DateTime.Now.ToString("HH:mm:ss"),
                    Type = type,
                    Detail = detail
                });
                if (_events.Count > 300) _events.RemoveAt(_events.Count - 1);
            });
        }

        private void OnPrivacyThreat(object sender, PrivacyThreatDetectedEventArgs e) =>
            AddRow("隐私威胁", $"{e.ProcessName} 访问 {e.DataAccessed}（{e.ThreatType}）");

        private void OnCamera(object sender, CameraAccessEventArgs e) =>
            AddRow("摄像头访问", e.DeviceName);

        private void OnMicrophone(object sender, MicrophoneAccessEventArgs e) =>
            AddRow("麦克风访问", e.DeviceName);

        private void OnDataCollection(object sender, DataCollectionEventArgs e) =>
            AddRow("数据收集", $"{e.CollectionType} @ {e.Location}");
    }
}