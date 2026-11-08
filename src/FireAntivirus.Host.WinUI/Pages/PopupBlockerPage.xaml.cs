// 弹窗拦截页（WPF PopupBlockerPage 迁移 + 真实化升级）：
// PopupBlockerService 真实窗口拦截（EnumWindows + WM_CLOSE），规则增删/启停/立即扫描/拦截日志，
// 默认零规则零动作，系统外壳窗口与关键进程永不拦截。
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using FireAntivirus.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class PopupRuleRow
    {
        public string AppName { get; set; }
        public string Rule { get; set; }
        public string CountText { get; set; }
        public string EnabledText { get; set; }
        public PopupRule Ref { get; set; }
    }

    public sealed class PopupLogRow
    {
        public string Time { get; set; }
        public string AppName { get; set; }
        public string WindowTitle { get; set; }
    }

    public sealed partial class PopupBlockerPage : Page
    {
        private readonly PopupBlockerService _service = PopupBlockerService.Instance;
        private readonly ObservableCollection<PopupRuleRow> _rules = new();
        private readonly ObservableCollection<PopupLogRow> _logs = new();

        private TextBox _appBox;
        private TextBox _titleBox;
        private TextBlock _state;

        public PopupBlockerPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                LoadAll();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("弹窗拦截", ex);
            }
            // 注意：聚合页 Tab 切换会触发 Unloaded，但弹窗拦截是持续防护，
// 页面实例由聚合页持有不销毁——切走 Tab 不停止拦截（服务定时器继续工作），
// 只由页面按钮显式停止。
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 12 };
            root.Children.Add(new TextBlock { Text = "弹窗拦截", FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            _state = new TextBlock { Text = "按应用名 / 窗口标题关键字拦截垃圾弹窗（默认零规则，系统窗口永不拦截）", Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_state);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            var startBtn = new Button { Content = "开启拦截", MinWidth = 100 };
            startBtn.Click += (_, _) => { _service.Start(); _state.Text = "弹窗拦截运行中（每 3 秒扫描一次）"; LoadAll(); };
            btnRow.Children.Add(startBtn);
            var stopBtn = new Button { Content = "停止拦截", MinWidth = 100 };
            stopBtn.Click += (_, _) => { _service.Stop(); _state.Text = "弹窗拦截已停止"; LoadAll(); };
            btnRow.Children.Add(stopBtn);
            var scanBtn = new Button { Content = "立即扫描一次", MinWidth = 120 };
            scanBtn.Click += (_, _) =>
            {
                _ = Task.Run(() =>
                {
                    int closed = _service.ScanOnce();
                    DispatcherQueue.TryEnqueue(() =>
                    {
                        _state.Text = closed > 0 ? $"本次关闭 {closed} 个弹窗" : "本次未发现匹配弹窗";
                        LoadAll();
                    });
                });
            };
            btnRow.Children.Add(scanBtn);
            var clearBtn = new Button { Content = "清空日志", MinWidth = 90 };
            clearBtn.Click += (_, _) => { _service.ClearLogs(); LoadAll(); };
            btnRow.Children.Add(clearBtn);
            root.Children.Add(btnRow);

            // 添加规则
            var addRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            _appBox = new TextBox { Width = 220, PlaceholderText = "应用名（如 myapp 或 myapp.exe）" };
            addRow.Children.Add(_appBox);
            _titleBox = new TextBox { Width = 260, PlaceholderText = "窗口标题关键字（如 广告）" };
            addRow.Children.Add(_titleBox);
            var addBtn = new Button { Content = "添加规则", MinWidth = 100 };
            addBtn.Click += (_, _) => AddRule();
            addRow.Children.Add(addBtn);
            root.Children.Add(addRow);

            root.Children.Add(new TextBlock { Text = "拦截规则", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            var ruleList = new ListView { ItemsSource = _rules, MaxHeight = 220, SelectionMode = ListViewSelectionMode.None };
            ruleList.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""10"" Padding=""6"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
            <ColumnDefinition Width=""Auto""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <StackPanel>
            <TextBlock Text=""{Binding AppName}"" FontWeight=""SemiBold""/>
            <TextBlock Text=""{Binding Rule}"" Opacity=""0.6"" FontSize=""12""/>
        </StackPanel>
        <TextBlock Grid.Column=""1"" Text=""{Binding CountText}"" Opacity=""0.7"" VerticalAlignment=""Center""/>
        <TextBlock Grid.Column=""2"" Text=""{Binding EnabledText}"" Opacity=""0.7"" VerticalAlignment=""Center""/>
        <Button Grid.Column=""3"" Content=""删除"" Tag=""{Binding}"" MinWidth=""70""/>
    </Grid>
</DataTemplate>");
            ruleList.ContainerContentChanging += (s, args) =>
            {
                if (args.ItemContainer.ContentTemplateRoot is Grid g
                    && g.Children.OfType<Button>().LastOrDefault() is Button b)
                {
                    b.Click -= OnDeleteRuleClick;
                    b.Click += OnDeleteRuleClick;
                }
            };
            root.Children.Add(ruleList);

            root.Children.Add(new TextBlock { Text = "拦截日志", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            root.Children.Add(new ListView { ItemsSource = _logs, MaxHeight = 240, SelectionMode = ListViewSelectionMode.None });

            return root;
        }

        private void AddRule()
        {
            var rule = new PopupRule
            {
                AppName = _appBox.Text?.Trim(),
                Rule = _titleBox.Text?.Trim(),
                Enabled = true
            };

            if (_service.AddRule(rule, out var error))
            {
                _state.Text = "已添加拦截规则";
                _appBox.Text = "";
                _titleBox.Text = "";
                LoadAll();
            }
            else
            {
                _state.Text = "添加失败: " + error;
            }
        }

        private void OnDeleteRuleClick(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.Tag is PopupRuleRow row && row.Ref != null)
            {
                _service.RemoveRule(row.Ref.Id);
                _state.Text = "已删除规则";
                LoadAll();
            }
        }

        private void LoadAll()
        {
            var rules = _service.GetRules();
            var logs = _service.GetLogs();
            var stats = _service.GetStatistics();

            _rules.Clear();
            foreach (var r in rules)
            {
                _rules.Add(new PopupRuleRow
                {
                    AppName = string.IsNullOrEmpty(r.AppName) ? "（任意应用）" : r.AppName,
                    Rule = string.IsNullOrEmpty(r.Rule) ? "（任意窗口）" : "标题含: " + r.Rule,
                    CountText = $"拦截 {r.BlockedCount}",
                    EnabledText = r.Enabled ? "启用" : "停用",
                    Ref = r
                });
            }

            _logs.Clear();
            foreach (var l in logs.Take(200))
            {
                _logs.Add(new PopupLogRow
                {
                    Time = l.Time.ToString("HH:mm:ss"),
                    AppName = l.AppName,
                    WindowTitle = l.WindowTitle
                });
            }

            _state.Text = $"{(stats.Running ? "拦截运行中" : "拦截未启动")} · {stats.RuleCount} 条规则 · 累计拦截 {stats.TotalBlocked} 次";
        }
    }
}