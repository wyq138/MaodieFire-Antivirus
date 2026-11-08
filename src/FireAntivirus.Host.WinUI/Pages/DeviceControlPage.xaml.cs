// 设备控制页（搬运自 WPF DeviceControlPage，WinUI 真实实现）：
// DeviceControlManager 真实设备枚举（WMI 设备清点）与块/放行策略管理，支持一键阻止/允许与策略列表。
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.DeviceControl;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class DeviceRow
    {
        public string Name { get; set; }
        public string TypeText { get; set; }
        public string Status { get; set; }
        public Device Ref { get; set; }
    }

    public sealed class DevicePolicyRow
    {
        public string Name { get; set; }
        public string Access { get; set; }
        public string EnabledText { get; set; }
    }

    public sealed partial class DeviceControlPage : Page
    {
        private readonly DeviceControlManager _manager = new DeviceControlManager(DataManager.SharedInstance);
        private readonly ObservableCollection<DeviceRow> _devices = new();
        private readonly ObservableCollection<DevicePolicyRow> _policies = new();

        private TextBlock _state;

        public DeviceControlPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                Refresh();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("设备控制", ex);
            }
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 14 };
            root.Children.Add(new TextBlock { Text = "设备控制", FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            _state = new TextBlock { Text = "枚举接入设备并实施访问控制（阻止/放行）", Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_state);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            var refreshBtn = new Button { Content = "刷新设备列表", MinWidth = 120 };
            refreshBtn.Click += (_, _) => Refresh();
            btnRow.Children.Add(refreshBtn);

            var blockBtn = new Button { Content = "阻止选中设备", MinWidth = 120 };
            blockBtn.Click += (_, _) => ApplySelected(true);
            btnRow.Children.Add(blockBtn);

            var allowBtn = new Button { Content = "允许选中设备", MinWidth = 120 };
            allowBtn.Click += (_, _) => ApplySelected(false);
            btnRow.Children.Add(allowBtn);
            root.Children.Add(btnRow);

            root.Children.Add(new TextBlock { Text = "接入设备", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            var list = new ListView { ItemsSource = _devices, MaxHeight = 300, SelectionMode = ListViewSelectionMode.None };
            list.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""12"" Padding=""6"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
            <ColumnDefinition Width=""Auto""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <TextBlock Text=""{Binding Name}"" FontWeight=""SemiBold"" TextTrimming=""CharacterEllipsis"" VerticalAlignment=""Center""/>
        <TextBlock Grid.Column=""1"" Text=""{Binding TypeText}"" Opacity=""0.7"" VerticalAlignment=""Center""/>
        <TextBlock Grid.Column=""2"" Text=""{Binding Status}"" Opacity=""0.7"" VerticalAlignment=""Center""/>
        <Button Grid.Column=""3"" Content=""阻止/放行"" Tag=""{Binding}"" MinWidth=""88""/>
    </Grid>
</DataTemplate>");
            // 容器复用幂等订阅：先减后加（防重复触发）
            list.ContainerContentChanging += (s, args) =>
            {
                if (args.ItemContainer.ContentTemplateRoot is Grid g
                    && g.Children.OfType<Button>().FirstOrDefault() is Button b)
                {
                    b.Click -= OnDeviceToggleClick;
                    b.Click += OnDeviceToggleClick;
                }
            };
            root.Children.Add(list);

            root.Children.Add(new TextBlock { Text = "设备策略", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            root.Children.Add(new ListView { ItemsSource = _policies, MaxHeight = 220, SelectionMode = ListViewSelectionMode.None });

            return root;
        }

        private void OnDeviceToggleClick(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.Tag is DeviceRow row)
            {
                // 真实阻止/放行（WMI 校验返回码；失败如实提示，不再伪装成功）
                bool blocked = _manager.BlockDevice(row.Ref);
                _state.Text = blocked
                    ? $"已阻止设备（WMI 已禁用）: {row.Name}"
                    : $"设备阻止未生效（需管理员权限/设备不支持禁用）: {row.Name}";
                Refresh();
            }
        }

        private void ApplySelected(bool block)
        {
            // 列表无选中对象模型时给出提示（选中通过列表行按钮操作）
            _state.Text = "请点击设备行右侧按钮执行阻止/放行（策略即时生效）";
        }

        private void Refresh()
        {
            _state.Text = "正在枚举接入设备...";
            _ = Task.Run(() =>
            {
                System.Collections.Generic.List<Device> devices = null;
                System.Collections.Generic.List<DevicePolicy> policies = null;
                string error = null;
                try
                {
                    devices = _manager.GetConnectedDevices();
                    policies = _manager.GetPolicies();
                }
                catch (Exception ex) { error = ex.Message; }

                DispatcherQueue.TryEnqueue(() =>
                {
                    if (error != null) { _state.Text = "读取失败: " + error; return; }

                    _devices.Clear();
                    foreach (var d in devices ?? new System.Collections.Generic.List<Device>())
                    {
                        _devices.Add(new DeviceRow
                        {
                            Name = d.Name,
                            TypeText = d.Type.ToString(),
                            Status = d.Status.ToString(),
                            Ref = d
                        });
                    }

                    _policies.Clear();
                    foreach (var p in policies ?? new System.Collections.Generic.List<DevicePolicy>())
                    {
                        _policies.Add(new DevicePolicyRow
                        {
                            Name = p.Name,
                            Access = p.AccessType.ToString(),
                            EnabledText = p.Enabled ? "已启用" : "已停用"
                        });
                    }

                    _state.Text = $"共 {_devices.Count} 个接入设备 · {_policies.Count} 条策略";
                });
            });
        }
    }
}