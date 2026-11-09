// 防火墙：真实调用 NetworkFirewallManager（Enable/Disable/AddRule/DeleteRule/GetConnections），
// 所有操作落到 Windows 防火墙与规则存储。UI 采用运行时模板（与 CleanPage/StartupPage 同模式）。
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using FireAntivirus.Data;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class FirewallRuleRow
    {
        public string Name { get; set; }
        public string Detail { get; set; }
        public string RuleId { get; set; }
    }

    public sealed class FirewallConnRow
    {
        public string Process { get; set; }
        public string Local { get; set; }
        public string Remote { get; set; }
        public string Protocol { get; set; }
        public string State { get; set; }
    }

    public sealed class BlockedIpRow
    {
        public string Ip { get; set; }
    }

    public sealed partial class FirewallPage : Page
    {
        public ObservableCollection<FirewallRuleRow> Rules { get; } = new();
        public ObservableCollection<FirewallConnRow> Connections { get; } = new();
        // IP 封禁（原独立"网络防护"页能力并入防火墙页，避免重复入口）
        public ObservableCollection<BlockedIpRow> BlockedIps { get; } = new();

        private DataManager _data => App.Data;
        private FireAntivirus.NetworkFirewall.NetworkFirewallManager _firewall;
        private FireAntivirus.NetworkFirewall.NetworkFirewallManager Firewall =>
            _firewall ??= new FireAntivirus.NetworkFirewall.NetworkFirewallManager(_data);
        private ToggleSwitch _fwToggle;
        private TextBlock _state;
        private TextBox _ipBox;

        public FirewallPage()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[页面诊断] FirewallPage 构造开始");
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                LoadAll();
                LoadBlockedIps();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("网络防火墙", ex);
            }
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"[页面诊断] FirewallPage 构造完成 {sw.ElapsedMilliseconds}ms");
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 12 };

            root.Children.Add(new TextBlock
            {
                Text = "网络防火墙",
                FontSize = 22,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            });

            // 防火墙总开关
            var togglePanel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
            _fwToggle = new ToggleSwitch { OnContent = "已启用", OffContent = "已关闭" };
            _fwToggle.Toggled += FwToggle_Toggled;
            togglePanel.Children.Add(_fwToggle);
            _state = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Opacity = 0.7 };
            togglePanel.Children.Add(_state);
            root.Children.Add(togglePanel);

            // 规则区
            var ruleHeader = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            ruleHeader.Children.Add(new TextBlock
            {
                Text = "防火墙规则",
                FontSize = 16,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            var addBtn = new Button { Content = "添加拦截规则" };
            addBtn.Click += async (_, _) => await AddRuleDialog();
            ruleHeader.Children.Add(addBtn);
            root.Children.Add(ruleHeader);

            var ruleList = new ListView { MaxHeight = 240, SelectionMode = ListViewSelectionMode.None };
            ruleList.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""12"" Padding=""6"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <StackPanel>
            <TextBlock Text=""{Binding Name}"" FontWeight=""SemiBold""/>
            <TextBlock Text=""{Binding Detail}"" Opacity=""0.6"" FontSize=""12"" TextTrimming=""CharacterEllipsis""/>
        </StackPanel>
        <Button Grid.Column=""1"" Content=""删除"" Tag=""{Binding RuleId}"" VerticalAlignment=""Center""/>
    </Grid>
</DataTemplate>");
            ruleList.ContainerContentChanging += (s, args) =>
            {
                if (args.Item is FirewallRuleRow row && args.ItemContainer.ContentTemplateRoot is Grid grid)
                {
                    var del = grid.Children.OfType<Button>().FirstOrDefault();
                    if (del != null) del.Click += (_, _) => DeleteRule(row.RuleId);
                }
            };
            ruleList.ItemsSource = Rules;
            root.Children.Add(ruleList);

            // 连接区
            var connHeader = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            connHeader.Children.Add(new TextBlock
            {
                Text = "当前活动连接",
                FontSize = 16,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            var refreshBtn = new Button { Content = "刷新" };
            refreshBtn.Click += (_, _) => LoadConnections();
            connHeader.Children.Add(refreshBtn);
            root.Children.Add(connHeader);

            var connList = new ListView { MaxHeight = 260, SelectionMode = ListViewSelectionMode.None };
            connList.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""12"" Padding=""4"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""140""/>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""48""/>
            <ColumnDefinition Width=""90""/>
        </Grid.ColumnDefinitions>
        <TextBlock Text=""{Binding Process}"" FontSize=""12"" TextTrimming=""CharacterEllipsis""/>
        <TextBlock Grid.Column=""1"" Text=""{Binding Local}"" FontSize=""12"" Opacity=""0.8"" TextTrimming=""CharacterEllipsis""/>
        <TextBlock Grid.Column=""2"" Text=""{Binding Remote}"" FontSize=""12"" Opacity=""0.8"" TextTrimming=""CharacterEllipsis""/>
        <TextBlock Grid.Column=""3"" Text=""{Binding Protocol}"" FontSize=""12"" Opacity=""0.6""/>
        <TextBlock Grid.Column=""4"" Text=""{Binding State}"" FontSize=""12"" Opacity=""0.6""/>
    </Grid>
</DataTemplate>");
            connList.ItemsSource = Connections;
            root.Children.Add(connList);

            // ---- IP 封禁区（原"网络防护"页能力整合）----
            var ipHeader = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            ipHeader.Children.Add(new TextBlock
            {
                Text = "IP 黑名单封禁",
                FontSize = 16,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            _ipBox = new TextBox { Width = 240, PlaceholderText = "输入要封禁的 IP 地址" };
            ipHeader.Children.Add(_ipBox);
            var blockBtn = new Button { Content = "封禁 IP" };
            blockBtn.Click += (_, _) => BlockIp();
            ipHeader.Children.Add(blockBtn);
            var refreshIpsBtn = new Button { Content = "刷新" };
            refreshIpsBtn.Click += (_, _) => LoadBlockedIps();
            ipHeader.Children.Add(refreshIpsBtn);
            root.Children.Add(ipHeader);

            var ipList = new ListView { ItemsSource = BlockedIps, MaxHeight = 160, SelectionMode = ListViewSelectionMode.None };
            ipList.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""8"" Padding=""2"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <TextBlock Text=""{Binding Ip}"" FontFamily=""Consolas"" FontSize=""12"" VerticalAlignment=""Center""/>
        <Button Grid.Column=""1"" Content=""解除封禁"" Tag=""{Binding}"" MinWidth=""84""/>
    </Grid>
</DataTemplate>");
            ipList.ContainerContentChanging += (_, args) =>
            {
                if (args.ItemContainer.ContentTemplateRoot is Grid g
                    && g.Children.OfType<Button>().LastOrDefault() is Button b)
                {
                    b.Click -= OnUnblockIpClick;
                    b.Click += OnUnblockIpClick;
                }
            };
            root.Children.Add(ipList);

            return root;
        }

        /// <summary>真实封禁 IP（NetworkSecurityManager → 防火墙规则下发）。</summary>
        private void BlockIp()
        {
            var text = _ipBox.Text?.Trim();
            if (!IPAddress.TryParse(text, out var ip))
            {
                _state.Text = "IP 地址格式无效";
                return;
            }
            try
            {
                NetSecurity.BlockIP(ip);
                _state.Text = "已封禁: " + ip;
                _ipBox.Text = "";
                LoadBlockedIps();
            }
            catch (Exception ex)
            {
                _state.Text = "封禁失败: " + ex.Message;
            }
        }

        /// <summary>真实解除封禁（删除对应防火墙入站+出站规则）。</summary>
        private void OnUnblockIpClick(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.Tag is BlockedIpRow row && IPAddress.TryParse(row.Ip, out var ip))
            {
                try
                {
                    NetSecurity.UnblockIP(ip);
                    _state.Text = "已解除封禁: " + ip;
                    LoadBlockedIps();
                }
                catch (Exception ex)
                {
                    _state.Text = "解除封禁失败: " + ex.Message;
                }
            }
        }

        /// <summary>加载已封禁 IP（后台）。</summary>
        private void LoadBlockedIps()
        {
            _ = Task.Run(() =>
            {
                System.Collections.Generic.List<IPAddress> list = null;
                try { list = NetSecurity.GetBlockedIPs(); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

                DispatcherQueue.TryEnqueue(() =>
                {
                    BlockedIps.Clear();
                    foreach (var ip in list ?? new System.Collections.Generic.List<IPAddress>())
                        BlockedIps.Add(new BlockedIpRow { Ip = ip.ToString() });
                });
            });
        }

        private FireAntivirus.NetworkSecurity.NetworkSecurityManager _netSec;
        private FireAntivirus.NetworkSecurity.NetworkSecurityManager NetSecurity =>
            _netSec ??= new FireAntivirus.NetworkSecurity.NetworkSecurityManager();

        // 全部走 LoadAllAsync（后台线程）：构造同步调 LoadAll 会在 UI 线程触发
        // Firewall.IsFirewallEnabled()（netsh 进程调用）导致页面打开冻结——多页面卡死成员之一
        private void LoadAll() => _ = LoadAllAsync();

        private bool _loadAllBusy;

        private async Task LoadAllAsync()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[页面诊断] FirewallPage LoadAllAsync 开始");
            if (_loadAllBusy) return;
            _loadAllBusy = true;
            try
            {
                // 防火墙开关状态检查（netsh 进程调用）、规则 API 与连接表枚举都在后台线程
                var (fwOn, rules, conns) = await Task.Run(() =>
                {
                    bool on = false;
                    try { on = Firewall.IsFirewallEnabled(); } catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 查询防火墙状态失败: " + ex.Message);
                    }

                    var r = new System.Collections.Generic.List<FirewallRuleRow>();
                    var c = new System.Collections.Generic.List<FirewallConnRow>();
                    try
                    {
                        foreach (var item in Firewall.GetRules())
                            r.Add(new FirewallRuleRow
                            {
                                Name = item.Name,
                                Detail = $"{item.Action} · {item.Protocol} · 本地端口 {item.LocalPort} · 远程 {item.RemoteAddress}:{item.RemotePort} · {item.Direction}" + (item.Enabled ? "" : "（已停用）"),
                                RuleId = item.Id
                            });
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 加载防火墙规则失败: " + ex.Message);
                    }
                    try
                    {
                        foreach (var item in Firewall.GetConnections().Take(100))
                            c.Add(new FirewallConnRow
                            {
                                Process = item.ProcessName,
                                Local = $"{item.LocalAddress}:{item.LocalPort}",
                                Remote = $"{item.RemoteAddress}:{item.RemotePort}",
                                Protocol = item.Protocol,
                                State = item.State
                            });
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 加载防火墙连接失败: " + ex.Message);
                    }
                    return (on, r, c);
                });

                _fwToggle.Toggled -= FwToggle_Toggled;
                _fwToggle.IsOn = fwOn;
                _fwToggle.Toggled += FwToggle_Toggled;
                _state.Text = _fwToggle.IsOn ? "防火墙运行中，出入站规则生效" : "防火墙已关闭，系统处于无规则防护状态";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"[页面诊断] FirewallPage LoadAllAsync 完成 {sw.ElapsedMilliseconds}ms（规则 {Rules.Count} / 连接 {Connections.Count}）");

                Rules.Clear();
                foreach (var row in rules) Rules.Add(row);
                Connections.Clear();
                foreach (var row in conns) Connections.Add(row);
            }
            finally
            {
                _loadAllBusy = false;
            }
        }

        private void LoadRules() => _ = LoadAllAsync();

        private void LoadConnections() => _ = LoadAllAsync();

        private async void FwToggle_Toggled(object sender, RoutedEventArgs e)
        {
            try
            {
                bool on = _fwToggle.IsOn;
                _state.Text = "正在应用防火墙策略（netsh）...";
                // netsh 进程调用秒级，放后台防开关切换冻结
                await Task.Run(() =>
                {
                    if (on) Firewall.EnableFirewall();
                    else Firewall.DisableFirewall();
                });

                _state.Text = on ? "防火墙运行中，出入站规则生效" : "防火墙已关闭，系统处于无规则防护状态";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"防火墙切换为 {(on ? "开启" : "关闭")}");
            }
            catch (Exception ex)
            {
                _state.Text = $"操作失败: {ex.Message}";
            }
        }

        private async Task AddRuleDialog()
        {
            var nameBox = new TextBox { PlaceholderText = "规则名称，例如：拦截恶意端口 4444" };
            var portBox = new TextBox { PlaceholderText = "本地端口，例如：4444" };
            var addressBox = new TextBox { PlaceholderText = "远程地址（留空为任意 0.0.0.0）" };
            var protocolCombo = new ComboBox { PlaceholderText = "协议" };
            foreach (var p in new[] { "TCP", "UDP", "All" }) protocolCombo.Items.Add(p);
            protocolCombo.SelectedIndex = 0;
            var directionCombo = new ComboBox { PlaceholderText = "方向" };
            foreach (var d in new[] { "Outbound（出站拦截）", "Inbound（入站拦截）", "Both（双向）" }) directionCombo.Items.Add(d);
            directionCombo.SelectedIndex = 0;

            var panel = new StackPanel { Spacing = 10, MinWidth = 360 };
            panel.Children.Add(nameBox);
            panel.Children.Add(portBox);
            panel.Children.Add(addressBox);
            panel.Children.Add(protocolCombo);
            panel.Children.Add(directionCombo);

            var dialog = new ContentDialog
            {
                Title = "添加拦截规则",
                Content = panel,
                PrimaryButtonText = "添加",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot
            };
            var result = await dialog.ShowAsync();
            if (result != ContentDialogResult.Primary) return;

            if (string.IsNullOrWhiteSpace(nameBox.Text) || string.IsNullOrWhiteSpace(portBox.Text))
            {
                await ShowMessage("名称与端口不能为空");
                return;
            }

            var direction = directionCombo.SelectedIndex switch
            {
                1 => FireAntivirus.NetworkFirewall.FirewallDirection.Inbound,
                2 => FireAntivirus.NetworkFirewall.FirewallDirection.Both,
                _ => FireAntivirus.NetworkFirewall.FirewallDirection.Outbound
            };

            var protocol = protocolCombo.SelectedIndex switch
            {
                1 => FireAntivirus.NetworkFirewall.FirewallProtocol.UDP,
                2 => FireAntivirus.NetworkFirewall.FirewallProtocol.All,
                _ => FireAntivirus.NetworkFirewall.FirewallProtocol.TCP
            };

            var rule = new FireAntivirus.NetworkFirewall.FirewallRule(
                nameBox.Text.Trim(),
                "由 WinUI 客户端添加",
                FireAntivirus.NetworkFirewall.FirewallAction.Block,
                protocol,
                portBox.Text.Trim(),
                "",
                direction)
            {
                RemoteAddress = string.IsNullOrWhiteSpace(addressBox.Text) ? "0.0.0.0" : addressBox.Text.Trim()
            };

            var addResult = Firewall.AddRule(rule);
            await ShowMessage($"{(addResult.Success ? "规则已添加并生效" : "添加失败")}: {addResult.Message}");
            LoadRules();
        }

        private async void DeleteRule(string ruleId)
        {
            var result = Firewall.DeleteRule(ruleId);
            await ShowMessage($"{(result.Success ? "规则已删除" : "删除失败")}: {result.Message}");
            LoadRules();
        }

        private async Task ShowMessage(string message)
        {
            await new ContentDialog
            {
                Title = "防火墙",
                Content = message,
                CloseButtonText = "确定",
                XamlRoot = XamlRoot
            }.ShowAsync();
        }
    }
}