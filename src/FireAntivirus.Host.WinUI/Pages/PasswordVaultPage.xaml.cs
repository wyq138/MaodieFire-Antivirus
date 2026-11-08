// 密码库：真实调用 PasswordManager（加密存储 / 增删查 / 强密码生成）。
// UI 采用运行时模板（与 CleanPage/StartupPage 同模式）。
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class PasswordRow
    {
        public string Title { get; set; }
        public string Username { get; set; }
        public string Url { get; set; }
        public string Id { get; set; }
    }

    public sealed partial class PasswordVaultPage : Page
    {
        public ObservableCollection<PasswordRow> Items { get; } = new();
        private FireAntivirus.PasswordManager.PasswordManager _manager;
        private FireAntivirus.PasswordManager.PasswordManager Mgr =>
            _manager ??= new FireAntivirus.PasswordManager.PasswordManager(App.Data);
        private TextBlock _summary;

        public PasswordVaultPage()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[页面诊断] PasswordVaultPage 构造开始");
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                LoadPasswords();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("密码库", ex);
            }
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"[页面诊断] PasswordVaultPage 构造完成 {sw.ElapsedMilliseconds}ms");
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 12 };

            root.Children.Add(new TextBlock
            {
                Text = "密码库",
                FontSize = 22,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            });

            _summary = new TextBlock { Opacity = 0.7 };
            root.Children.Add(_summary);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            var addBtn = new Button { Content = "添加密码", MinWidth = 110 };
            addBtn.Click += async (_, _) => await AddPasswordDialog();
            btnRow.Children.Add(addBtn);

            var genBtn = new Button { Content = "生成强密码", MinWidth = 110 };
            genBtn.Click += async (_, _) => await GeneratePasswordDialog();
            btnRow.Children.Add(genBtn);
            root.Children.Add(btnRow);

            var list = new ListView { MaxHeight = 520, SelectionMode = ListViewSelectionMode.None };
            list.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""12"" Padding=""8"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <StackPanel>
            <TextBlock Text=""{Binding Title}"" FontWeight=""SemiBold""/>
            <TextBlock Text=""{Binding Username}"" Opacity=""0.7"" FontSize=""12""/>
            <TextBlock Text=""{Binding Url}"" Opacity=""0.5"" FontSize=""12"" TextTrimming=""CharacterEllipsis""/>
        </StackPanel>
        <Button Grid.Column=""1"" Content=""删除"" Tag=""{Binding Id}"" VerticalAlignment=""Center""/>
    </Grid>
</DataTemplate>");
            list.ContainerContentChanging += (s, args) =>
            {
                if (args.Item is PasswordRow row && args.ItemContainer.ContentTemplateRoot is Grid grid)
                {
                    var del = grid.Children.OfType<Button>().FirstOrDefault();
                    if (del != null) del.Click += async (_, _) => await DeletePassword(row);
                }
            };
            list.ItemsSource = Items;
            root.Children.Add(list);

            return root;
        }

        // 密码库解密加载（触达 App.Data + PasswordManager 构造）在后台线程执行，防页面打开冻结
        private void LoadPasswords() => _ = LoadPasswordsAsync();

        private async Task LoadPasswordsAsync()
        {
            _summary.Text = "正在加载密码库...";
            var rows = await Task.Run(() =>
            {
                try
                {
                    return Mgr.GetPasswordEntries()
                        .Select(p => new PasswordRow
                        {
                            Id = p.Id,
                            Title = p.Title,
                            Username = p.Username,
                            Url = p.Url
                        })
                        .ToList();
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 加载密码库失败: " + ex.Message);
                    return null;
                }
            });

            Items.Clear();
            if (rows != null)
            {
                foreach (var r in rows) Items.Add(r);
                _summary.Text = $"共 {Items.Count} 条密码记录（本地加密存储）";
            }
            else
            {
                _summary.Text = "加载失败";
            }
        }

        private async Task AddPasswordDialog()
        {
            var titleBox = new TextBox { PlaceholderText = "名称，例如：公司邮箱" };
            var userBox = new TextBox { PlaceholderText = "用户名" };
            var passBox = new TextBox { PlaceholderText = "密码" };
            var urlBox = new TextBox { PlaceholderText = "网址（可选）" };

            var panel = new StackPanel { Spacing = 10, MinWidth = 340 };
            panel.Children.Add(titleBox);
            panel.Children.Add(userBox);
            panel.Children.Add(passBox);
            panel.Children.Add(urlBox);

            var dialog = new ContentDialog
            {
                Title = "添加密码",
                Content = panel,
                PrimaryButtonText = "保存",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot
            };
            var result = await dialog.ShowAsync();
            if (result != ContentDialogResult.Primary) return;

            if (string.IsNullOrWhiteSpace(titleBox.Text) || string.IsNullOrWhiteSpace(passBox.Text))
            {
                await ShowMessage("名称与密码不能为空");
                return;
            }

            try
            {
                Mgr.AddPassword(new FireAntivirus.PasswordManager.PasswordEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Title = titleBox.Text.Trim(),
                    Username = userBox.Text?.Trim() ?? "",
                    Password = passBox.Text,
                    Url = urlBox.Text?.Trim() ?? ""
                });
                LoadPasswords();
                await ShowMessage("密码已加密保存");
            }
            catch (Exception ex)
            {
                await ShowMessage($"保存失败: {ex.Message}");
            }
        }

        private async Task DeletePassword(PasswordRow row)
        {
            try
            {
                // 加密库删除涉及文件重写，放后台防 UI 冻结
                await Task.Run(() => Mgr.DeletePassword(row.Id));
                LoadPasswords();
                await ShowMessage($"已删除 \"{row.Title}\"");
            }
            catch (Exception ex)
            {
                await ShowMessage($"删除失败: {ex.Message}");
            }
        }

        private async Task GeneratePasswordDialog()
        {
            var lengthBox = new TextBox { Text = "16" };
            var outputBox = new TextBox { IsReadOnly = true, PlaceholderText = "点击\"生成\"获得强密码" };

            var panel = new StackPanel { Spacing = 10, MinWidth = 340 };
            panel.Children.Add(new TextBlock { Text = "长度（8-64）" });
            panel.Children.Add(lengthBox);
            panel.Children.Add(outputBox);

            var dialog = new ContentDialog
            {
                Title = "强密码生成器",
                Content = panel,
                PrimaryButtonText = "生成",
                CloseButtonText = "关闭",
                XamlRoot = XamlRoot
            };

            while (true)
            {
                var result = await dialog.ShowAsync();
                if (result != ContentDialogResult.Primary) break;

                if (!int.TryParse(lengthBox.Text, out var length) || length < 8 || length > 64)
                {
                    outputBox.Text = "长度须在 8-64 之间";
                    continue;
                }

                outputBox.Text = Mgr.GeneratePassword(length);
            }
        }

        private async Task ShowMessage(string message)
        {
            await new ContentDialog
            {
                Title = "密码库",
                Content = message,
                CloseButtonText = "确定",
                XamlRoot = XamlRoot
            }.ShowAsync();
        }
    }
}