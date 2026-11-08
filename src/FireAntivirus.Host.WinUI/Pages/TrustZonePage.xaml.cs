// 信任区页（搬运自 WPF TrustZonePage，WinUI 真实实现 + 加固）：
// DataManager 真实信任列表（trustlist.json 持久化）：添加/删除信任项，
// 信任项参与引擎白名单判定（DataManager.IsWhitelisted）。支持路径/哈希/发布者三类。
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using FireAntivirus.Data;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class TrustRow
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public string Type { get; set; }
        public string AddTime { get; set; }
        public string Description { get; set; }
        public TrustItem Ref { get; set; }
    }

    public sealed partial class TrustZonePage : Page
    {
        private readonly ObservableCollection<TrustRow> _items = new();

        private TextBox _pathBox;
        private ComboBox _typeBox;
        private TextBlock _state;

        public TrustZonePage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                LoadList();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("信任区", ex);
            }
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 12 };
            root.Children.Add(new TextBlock { Text = "信任区", FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            _state = new TextBlock { Text = "受信任的文件/目录不会被引擎判定为威胁（参与白名单仲裁）", Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_state);

            var addRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            _pathBox = new TextBox { Width = 380, PlaceholderText = @"C:\Tools\mytool.exe 或目录路径" };
            addRow.Children.Add(_pathBox);
            _typeBox = new ComboBox { Width = 130, SelectedIndex = 0 };
            _typeBox.Items.Add("文件/程序");
            _typeBox.Items.Add("目录");
            addRow.Children.Add(_typeBox);
            var addBtn = new Button { Content = "添加信任项", MinWidth = 110 };
            addBtn.Click += (_, _) => AddItem();
            addRow.Children.Add(addBtn);
            var refreshBtn = new Button { Content = "刷新", MinWidth = 80 };
            refreshBtn.Click += (_, _) => LoadList();
            addRow.Children.Add(refreshBtn);
            root.Children.Add(addRow);

            root.Children.Add(new TextBlock { Text = "信任列表", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            var list = new ListView { ItemsSource = _items, MaxHeight = 480, SelectionMode = ListViewSelectionMode.None };
            list.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""10"" Padding=""6"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
            <ColumnDefinition Width=""Auto""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <StackPanel>
            <TextBlock Text=""{Binding Name}"" FontWeight=""SemiBold""/>
            <TextBlock Text=""{Binding Path}"" Opacity=""0.6"" FontSize=""12"" TextTrimming=""CharacterEllipsis""/>
        </StackPanel>
        <TextBlock Grid.Column=""1"" Text=""{Binding Type}"" Opacity=""0.7"" VerticalAlignment=""Center""/>
        <TextBlock Grid.Column=""2"" Text=""{Binding AddTime}"" Opacity=""0.6"" FontSize=""12"" VerticalAlignment=""Center""/>
        <Button Grid.Column=""3"" Content=""移出信任"" Tag=""{Binding}"" MinWidth=""88""/>
    </Grid>
</DataTemplate>");
            list.ContainerContentChanging += (s, args) =>
            {
                if (args.ItemContainer.ContentTemplateRoot is Grid g
                    && g.Children.OfType<Button>().LastOrDefault() is Button b)
                {
                    b.Click -= OnRemoveClick;
                    b.Click += OnRemoveClick;
                }
            };
            root.Children.Add(list);

            return root;
        }

        private void AddItem()
        {
            var path = _pathBox.Text?.Trim();
            if (string.IsNullOrEmpty(path))
            {
                _state.Text = "请输入要信任的文件或目录路径";
                return;
            }
            try
            {
                bool isDir = _typeBox.SelectedIndex == 1 || Directory.Exists(path) && !File.Exists(path);
                if (!File.Exists(path) && !Directory.Exists(path))
                {
                    _state.Text = "路径不存在: " + path;
                    return;
                }

                var dm = DataManager.SharedInstance;
                var list = dm.LoadTrustList();
                if (list.Any(t => string.Equals(t.Path, path, StringComparison.OrdinalIgnoreCase)))
                {
                    _state.Text = "该路径已在信任列表中";
                    return;
                }

                list.Add(new TrustItem
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = isDir ? new DirectoryInfo(path).Name : Path.GetFileName(path),
                    Path = path,
                    Type = isDir ? "Directory" : "File",
                    AddTime = DateTime.Now,
                    Description = "用户手动添加信任",
                    AddedBy = "用户",
                    IsExplicit = true
                });
                dm.SaveTrustList();
                _state.Text = "已添加信任项: " + path;
                _pathBox.Text = "";
                LoadList();
            }
            catch (Exception ex)
            {
                _state.Text = "添加失败: " + ex.Message;
            }
        }

        private void OnRemoveClick(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.Tag is TrustRow row && row.Ref != null)
            {
                try
                {
                    var dm = DataManager.SharedInstance;
                    var list = dm.LoadTrustList();
                    var target = list.FirstOrDefault(t => t.Id == row.Ref.Id);
                    if (target != null)
                    {
                        list.Remove(target);
                        dm.SaveTrustList();
                        _state.Text = "已移出信任: " + row.Name;
                        LoadList();
                    }
                }
                catch (Exception ex)
                {
                    _state.Text = "移除失败: " + ex.Message;
                }
            }
        }

        private void LoadList()
        {
            _ = Task.Run(() =>
            {
                System.Collections.Generic.List<TrustItem> list = null;
                string error = null;
                try { list = DataManager.SharedInstance.LoadTrustList(); }
                catch (Exception ex) { error = ex.Message; }

                DispatcherQueue.TryEnqueue(() =>
                {
                    if (error != null) { _state.Text = "读取失败: " + error; return; }

                    _items.Clear();
                    foreach (var t in (list ?? new System.Collections.Generic.List<TrustItem>()).Take(500))
                    {
                        _items.Add(new TrustRow
                        {
                            Name = string.IsNullOrEmpty(t.Name) ? Path.GetFileName(t.Path) : t.Name,
                            Path = t.Path,
                            Type = t.Type,
                            AddTime = t.AddTime.ToString("yyyy-MM-dd"),
                            Description = t.Description,
                            Ref = t
                        });
                    }
                    _state.Text = $"信任列表共 {_items.Count} 项（参与引擎白名单判定）";
                });
            });
        }
    }
}