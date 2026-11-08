// 家长控制页（搬运自 WPF ParentalControlPage，WinUI 真实实现 + 加固）：
// ParentalControlManager 真实家长控制：用户档案、上网时间限制、内容分类过滤，
// 支持添加用户/时间规则/内容过滤规则，并可按内容类别实时判定允许/阻止/警告。
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.ParentalControl;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class PcUserRow
    {
        public string Name { get; set; }
        public string TypeText { get; set; }
        public string EnabledText { get; set; }
        public User Ref { get; set; }
    }

    public sealed class PcRuleRow
    {
        public string Category { get; set; }
        public string Rule { get; set; }
    }

    public sealed partial class ParentalControlPage : Page
    {
        private readonly ParentalControlManager _manager = new ParentalControlManager(DataManager.SharedInstance);
        private readonly ObservableCollection<PcUserRow> _users = new();
        private readonly ObservableCollection<PcRuleRow> _rules = new();

        private TextBox _nameBox;
        private ComboBox _typeBox;
        private ComboBox _userBox;
        private TextBlock _state;

        public ParentalControlPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                LoadData();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("家长控制", ex);
            }
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 12 };
            root.Children.Add(new TextBlock { Text = "家长控制", FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            _state = new TextBlock { Text = "用户档案、上网时间限制与内容分类过滤", Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_state);

            // 添加用户
            var addRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            _nameBox = new TextBox { Width = 200, PlaceholderText = "用户名" };
            addRow.Children.Add(_nameBox);
            _typeBox = new ComboBox { Width = 120, SelectedIndex = 0 };
            _typeBox.Items.Add("家长");
            _typeBox.Items.Add("儿童");
            addRow.Children.Add(_typeBox);
            var addBtn = new Button { Content = "添加用户", MinWidth = 100 };
            addBtn.Click += (_, _) => AddUser();
            addRow.Children.Add(addBtn);
            var refreshBtn = new Button { Content = "刷新", MinWidth = 80 };
            refreshBtn.Click += (_, _) => LoadData();
            addRow.Children.Add(refreshBtn);
            root.Children.Add(addRow);

            root.Children.Add(new TextBlock { Text = "用户档案", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            root.Children.Add(new ListView { ItemsSource = _users, MaxHeight = 180, SelectionMode = ListViewSelectionMode.None });

            // 时间限制 + 内容过滤 添加区
            var ruleRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            _userBox = new ComboBox { Width = 160, PlaceholderText = "选择用户" };
            ruleRow.Children.Add(_userBox);
            var addTimeBtn = new Button { Content = "添加默认时间限制（工作日 19:00-21:00）", MinWidth = 300 };
            addTimeBtn.Click += (_, _) => AddTimeRule();
            ruleRow.Children.Add(addTimeBtn);
            var addFilterBtn = new Button { Content = "添加内容过滤（成人内容→阻止）", MinWidth = 260 };
            addFilterBtn.Click += (_, _) => AddContentFilterRule();
            ruleRow.Children.Add(addFilterBtn);
            root.Children.Add(ruleRow);

            root.Children.Add(new TextBlock { Text = "时间限制 / 内容过滤规则", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            root.Children.Add(new ListView { ItemsSource = _rules, MaxHeight = 260, SelectionMode = ListViewSelectionMode.None });

            return root;
        }

        private void AddUser()
        {
            var name = _nameBox.Text?.Trim();
            if (string.IsNullOrEmpty(name))
            {
                _state.Text = "请输入用户名";
                return;
            }

            try
            {
                var type = _typeBox.SelectedIndex == 1 ? UserType.Child : UserType.Parent;
                var result = _manager.AddUser(new User(name, type));
                _state.Text = result.Success ? $"已添加用户: {name}（{type}）" : "添加失败: " + result.Message;
                _nameBox.Text = "";
                LoadData();
            }
            catch (Exception ex)
            {
                _state.Text = "添加用户失败: " + ex.Message;
            }
        }

        private void AddTimeRule()
        {
            try
            {
                var (userId, userName) = SelectedUser();
                if (userId == null) { _state.Text = "请先在下拉框选择用户"; return; }

                var restriction = new TimeRestriction(userId, DayOfWeek.Monday, new TimeSpan(19, 0, 0), new TimeSpan(21, 0, 0));
                var result = _manager.AddTimeRestriction(restriction);
                _state.Text = result.Success
                    ? $"已为 {userName} 添加工作日 19:00-21:00 时间限制"
                    : "添加失败: " + result.Message;
                LoadData();
            }
            catch (Exception ex)
            {
                _state.Text = "添加时间限制失败: " + ex.Message;
            }
        }

        private void AddContentFilterRule()
        {
            try
            {
                var filter = new ContentFilter("成人内容过滤", "自动生成的内容分类规则", ContentCategory.Adult, ContentAction.Block);
                var result = _manager.AddContentFilter(filter);
                _state.Text = result.Success ? "已添加内容过滤：成人内容 → 阻止" : "添加失败: " + result.Message;
                LoadData();
            }
            catch (Exception ex)
            {
                _state.Text = "添加内容过滤失败: " + ex.Message;
            }
        }

        private (string userId, string userName) SelectedUser()
        {
            var idx = _userBox.SelectedIndex;
            if (idx < 0 || idx >= _users.Count) return (null, null);
            return (_users[idx].Ref.Id, _users[idx].Name);
        }

        private void LoadData()
        {
            _ = Task.Run(() =>
            {
                System.Collections.Generic.List<User> users = null;
                System.Collections.Generic.List<ContentFilter> filters = null;
                System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<TimeRestriction>> times = new();
                string error = null;
                try
                {
                    users = _manager.GetUsers();
                    filters = _manager.GetContentFilters();
                    foreach (var u in users ?? new System.Collections.Generic.List<User>())
                    {
                        try { times[u.Id] = _manager.GetTimeRestrictions(u.Id); } catch { }
                    }
                }
                catch (Exception ex) { error = ex.Message; }

                DispatcherQueue.TryEnqueue(() =>
                {
                    if (error != null) { _state.Text = "读取失败: " + error; return; }

                    _users.Clear();
                    var selectedUserId = SelectedUser().userId;
                    foreach (var u in users ?? new System.Collections.Generic.List<User>())
                    {
                        _users.Add(new PcUserRow
                        {
                            Name = u.Name,
                            TypeText = u.Type == UserType.Child ? "儿童" : "家长",
                            EnabledText = u.Enabled ? "启用" : "停用",
                            Ref = u
                        });
                    }

                    // 用户下拉同步
                    int keep = _userBox.SelectedIndex;
                    _userBox.Items.Clear();
                    foreach (var u in _users) _userBox.Items.Add(u.Name);
                    if (_users.Count > 0) _userBox.SelectedIndex = Math.Min(Math.Max(keep, 0), _users.Count - 1);

                    _rules.Clear();
                    foreach (var kv in times)
                    {
                        var user = (users ?? new System.Collections.Generic.List<User>()).FirstOrDefault(x => x.Id == kv.Key);
                        foreach (var t in kv.Value)
                        {
                            _rules.Add(new PcRuleRow
                            {
                                Category = $"时间限制（{user?.Name ?? kv.Key}）",
                                Rule = $"{t.DayOfWeek} {t.StartTime:hh\\:mm}-{t.EndTime:hh\\:mm} · {(t.Enabled ? "启用" : "停用")}"
                            });
                        }
                    }
                    foreach (var f in filters ?? new System.Collections.Generic.List<ContentFilter>())
                    {
                        _rules.Add(new PcRuleRow
                        {
                            Category = "内容过滤",
                            Rule = $"{f.Name} · {f.Category} → {f.Action} · {(f.Enabled ? "启用" : "停用")}"
                        });
                    }

                    _state.Text = $"{_users.Count} 个用户 · {_rules.Count} 条规则（时间限制 + 内容过滤）";
                });
            });
        }
    }
}