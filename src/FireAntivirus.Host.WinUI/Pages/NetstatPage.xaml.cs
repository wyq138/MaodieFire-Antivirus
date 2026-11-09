// 网络连接：真实解析 netstat -ano 输出，关联进程名，支持筛选
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class NetstatRow
    {
        public string Proto { get; set; }
        public string Local { get; set; }
        public string Remote { get; set; }
        public string State { get; set; }
        public string Process { get; set; }
    }

    public sealed partial class NetstatPage : Page
    {
        public ObservableCollection<NetstatRow> Items { get; } = new();
        private List<NetstatRow> _all = new();

        public NetstatPage()
        {
            InitializeComponent();
            ConnList.ItemsSource = Items;
            // 运行时模板：不经过 XamlCompiler
            ConnList.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""12"" Padding=""6"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""52""/>
            <ColumnDefinition Width=""2*""/>
            <ColumnDefinition Width=""2*""/>
            <ColumnDefinition Width=""110""/>
            <ColumnDefinition Width=""*""/>
        </Grid.ColumnDefinitions>
        <TextBlock Text=""{Binding Proto}"" FontWeight=""SemiBold""/>
        <TextBlock Grid.Column=""1"" Text=""{Binding Local}"" FontSize=""12"" TextTrimming=""CharacterEllipsis""/>
        <TextBlock Grid.Column=""2"" Text=""{Binding Remote}"" FontSize=""12"" TextTrimming=""CharacterEllipsis""/>
        <TextBlock Grid.Column=""3"" Text=""{Binding State}"" FontSize=""12"" Opacity=""0.7""/>
        <TextBlock Grid.Column=""4"" Text=""{Binding Process}"" FontSize=""12"" Opacity=""0.85"" TextTrimming=""CharacterEllipsis""/>
    </Grid>
</DataTemplate>");
            LoadConnections();
            LoadTrafficAlerts();
        }

        private bool _loading;

        private async Task LoadConnectionsAsync()
        {
            if (_loading) return;
            _loading = true;
            try
            {
                CountText.Text = "正在加载网络连接（可能需要数秒）...";
                var rows = await Task.Run(() =>
                {
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "netstat.exe",
                            Arguments = "-ano",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true
                        };
                        using var p = Process.Start(psi);
                        if (p == null) return new List<NetstatRow>();
                        string output = p.StandardOutput.ReadToEnd();
                        p.WaitForExit(15000);

                        // PID -> 进程名缓存
                        var pidNames = new Dictionary<int, string>();
                        foreach (var proc in Process.GetProcesses())
                        {
                            try { pidNames[proc.Id] = proc.ProcessName; } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                        }

                        var result = new List<NetstatRow>();
                        foreach (var raw in output.Split('\n'))
                        {
                            var line = raw.Trim();
                            if (!line.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                                !line.StartsWith("UDP", StringComparison.OrdinalIgnoreCase)) continue;
                            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            // TCP: 协议 本地 远程 状态 PID；UDP: 协议 本地 PID
                            if (parts.Length < 4) continue;
                            string proto = parts[0].ToUpperInvariant();
                            string local = parts[1], remote = "-", state = "-";
                            int pid;
                            if (proto == "TCP")
                            {
                                if (parts.Length < 5) continue;
                                remote = parts[2];
                                state = parts[3];
                                if (!int.TryParse(parts[4], out pid)) continue;
                            }
                            else
                            {
                                if (!int.TryParse(parts[3], out pid)) continue;
                            }
                            pidNames.TryGetValue(pid, out var name);
                            result.Add(new NetstatRow
                            {
                                Proto = proto,
                                Local = local,
                                Remote = remote,
                                State = state,
                                Process = name != null ? $"{name} ({pid})" : pid.ToString()
                            });
                        }
                        return result;
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 加载网络连接失败: " + ex.Message);
                        return new List<NetstatRow>();
                    }
                });

                _all = rows;
                ApplyFilter(FilterBox.Text);
            }
            finally
            {
                _loading = false;
            }
        }

        private void LoadConnections() => _ = LoadConnectionsAsync();

        private void Refresh_Click(object sender, RoutedEventArgs e) => _ = LoadConnectionsAsync();

        private void ApplyFilter(string keyword)
        {
            Items.Clear();
            IEnumerable<NetstatRow> query = _all;
            if (!string.IsNullOrWhiteSpace(keyword))
            {
                keyword = keyword.Trim();
                query = query.Where(r =>
                    (r.Process?.Contains(keyword, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (r.Local?.Contains(keyword, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (r.Remote?.Contains(keyword, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    (r.State?.Contains(keyword, StringComparison.OrdinalIgnoreCase) ?? false));
            }
            foreach (var r in query) Items.Add(r);
            CountText.Text = $"共 {Items.Count} 条连接";
        }

        private void Filter_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter(FilterBox.Text);

        // ---- 流量监控（原独立"网络流量"页能力整合进网络连接页，避免重复入口）----
        private FireAntivirus.NetworkTrafficAnalyzer.NetworkTrafficAnalyzerManager _traffic;
        private FireAntivirus.NetworkTrafficAnalyzer.NetworkTrafficAnalyzerManager Traffic =>
            _traffic ??= new FireAntivirus.NetworkTrafficAnalyzer.NetworkTrafficAnalyzerManager(
                FireAntivirus.Data.DataManager.SharedInstance);
        private bool _trafficRunning;

        private void TrafficStart_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Traffic.StartMonitoring();
                _trafficRunning = true;
                TrafficState.Text = "流量监控运行中（可疑连接实时告警）";
                LoadTrafficAlerts();
            }
            catch (Exception ex)
            {
                TrafficState.Text = "启动失败: " + ex.Message;
            }
        }

        private void TrafficStop_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Traffic.StopMonitoring();
                _trafficRunning = false;
                TrafficState.Text = "流量监控已停止";
            }
            catch (Exception ex)
            {
                TrafficState.Text = "停止失败: " + ex.Message;
            }
        }

        private void TrafficAnalyze_Click(object sender, RoutedEventArgs e)
        {
            _ = Task.Run(() =>
            {
                try { Traffic.AnalyzeTraffic(); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                LoadTrafficAlerts();
            });
        }

        /// <summary>刷新可疑连接告警（真实 NetworkAlert 数据，最多展示 5 条）。</summary>
        private void LoadTrafficAlerts()
        {
            _ = Task.Run(() =>
            {
                System.Collections.Generic.List<FireAntivirus.NetworkTrafficAnalyzer.NetworkAlert> alerts = null;
                try { alerts = Traffic.GetAlerts(); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

                DispatcherQueue.TryEnqueue(() =>
                {
                    if (alerts == null || alerts.Count == 0)
                    {
                        TrafficAlertText.Text = "无可疑连接告警";
                        return;
                    }
                    TrafficAlertText.Text = string.Join("\n", alerts.Take(5)
                        .Select(a => $"[{a.Timestamp:HH:mm:ss}] {a.Severity} · {a.Message}"));
                    if (!_trafficRunning) TrafficState.Text = $"历史告警 {alerts.Count} 条";
                });
            });
        }
    }
}
