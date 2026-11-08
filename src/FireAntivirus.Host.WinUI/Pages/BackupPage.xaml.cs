// 数据备份：真实调用 BackupManager（CreateBackup/RestoreBackup/DeleteBackup/GetBackups），
// 文件真实复制到备份目录并可在恢复点还原。UI 采用运行时模板。
using System;
using System.Collections.Generic;
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
    public sealed class BackupRow
    {
        public string Name { get; set; }
        public string Detail { get; set; }
        public string Id { get; set; }
    }

    public sealed partial class BackupPage : Page
    {
        public ObservableCollection<BackupRow> Items { get; } = new();
        private DataManager _data => App.Data;
        private FireAntivirus.Backup.BackupManager _backupManager;
        private FireAntivirus.Backup.BackupManager Mgr =>
            _backupManager ??= new FireAntivirus.Backup.BackupManager(_data);
        private TextBlock _summary;

        public BackupPage()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[页面诊断] BackupPage 构造开始");
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                LoadBackups();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("数据备份", ex);
            }
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"[页面诊断] BackupPage 构造完成 {sw.ElapsedMilliseconds}ms");
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 12 };

            root.Children.Add(new TextBlock
            {
                Text = "数据备份",
                FontSize = 22,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            });

            _summary = new TextBlock { Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_summary);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            var createBtn = new Button { Content = "创建备份", MinWidth = 110 };
            createBtn.Click += async (_, _) => await CreateBackupDialog();
            btnRow.Children.Add(createBtn);
            root.Children.Add(btnRow);

            var list = new ListView { MaxHeight = 520, SelectionMode = ListViewSelectionMode.None };
            list.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""12"" Padding=""8"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <StackPanel>
            <TextBlock Text=""{Binding Name}"" FontWeight=""SemiBold""/>
            <TextBlock Text=""{Binding Detail}"" Opacity=""0.6"" FontSize=""12"" TextWrapping=""Wrap""/>
        </StackPanel>
        <Button Grid.Column=""1"" Content=""恢复"" Tag=""{Binding Id}"" VerticalAlignment=""Center""/>
        <Button Grid.Column=""2"" Content=""删除"" Tag=""{Binding Id}"" VerticalAlignment=""Center""/>
    </Grid>
</DataTemplate>");
            list.ContainerContentChanging += (s, args) =>
            {
                if (args.Item is BackupRow row && args.ItemContainer.ContentTemplateRoot is Grid grid)
                {
                    var buttons = grid.Children.OfType<Button>().ToList();
                    if (buttons.Count >= 2)
                    {
                        buttons[0].Click += async (_, _) => await RestoreBackup(row);
                        buttons[1].Click += async (_, _) => await DeleteBackup(row);
                    }
                }
            };
            list.ItemsSource = Items;
            root.Children.Add(list);

            return root;
        }

        // 备份目录枚举与服务构造（触达 App.Data）在后台线程执行，防页面打开冻结
        private void LoadBackups() => _ = LoadBackupsAsync();

        private async Task LoadBackupsAsync()
        {
            _summary.Text = "正在加载备份列表...";
            var rows = await Task.Run(() =>
            {
                try
                {
                    return Mgr.GetBackups()
                        .Select(b => new BackupRow
                        {
                            Id = b.Id,
                            Name = b.Name,
                            Detail = $"{b.Description} · 源路径: {b.Path}"
                        })
                        .ToList();
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 加载备份列表失败: " + ex.Message);
                    return null;
                }
            });

            Items.Clear();
            if (rows != null)
            {
                foreach (var r in rows) Items.Add(r);
                _summary.Text = $"共 {Items.Count} 个备份";
            }
            else
            {
                _summary.Text = "加载失败";
            }
        }

        private async Task CreateBackupDialog()
        {
            var nameBox = new TextBox { PlaceholderText = "备份名称，例如：文档备份" };
            var pathBox = new TextBox { PlaceholderText = "要备份的文件夹完整路径（多个用分号 ; 分隔）" };

            var panel = new StackPanel { Spacing = 10, MinWidth = 380 };
            panel.Children.Add(nameBox);
            panel.Children.Add(pathBox);

            var dialog = new ContentDialog
            {
                Title = "创建备份",
                Content = panel,
                PrimaryButtonText = "开始备份",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot
            };
            var result = await dialog.ShowAsync();
            if (result != ContentDialogResult.Primary) return;

            if (string.IsNullOrWhiteSpace(nameBox.Text) || string.IsNullOrWhiteSpace(pathBox.Text))
            {
                await ShowMessage("名称与路径不能为空");
                return;
            }

            var includePaths = pathBox.Text.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim().Trim('"'))
                .Where(p => Directory.Exists(p) || File.Exists(p))
                .ToList();

            if (includePaths.Count == 0)
            {
                await ShowMessage("没有有效的备份路径（路径必须存在）");
                return;
            }

            _summary.Text = "备份进行中...";
            try
            {
                var backupResult = await System.Threading.Tasks.Task.Run(() =>
                    Mgr.CreateBackup(
                        nameBox.Text.Trim(),
                        $"{includePaths.Count} 个路径",
                        includePaths,
                        FireAntivirus.Backup.BackupType.Full));

                await ShowMessage($"{(backupResult.Success ? "备份完成" : "备份失败")}: {backupResult.Message}");
            }
            catch (Exception ex)
            {
                await ShowMessage($"备份失败: {ex.Message}");
            }
            LoadBackups();
        }

        private async Task RestoreBackup(BackupRow row)
        {
            var restoreBox = new TextBox
            {
                PlaceholderText = "恢复目标目录（留空则还原到原位置旁的 restore 目录）",
                Text = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Restore", DateTime.Now.ToString("yyyyMMdd_HHmmss"))
            };

            var panel = new StackPanel { Spacing = 10, MinWidth = 380 };
            panel.Children.Add(new TextBlock { Text = $"将恢复备份 \"{row.Name}\" 到以下目录：" });
            panel.Children.Add(restoreBox);

            var dialog = new ContentDialog
            {
                Title = "恢复备份",
                Content = panel,
                PrimaryButtonText = "开始恢复",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot
            };
            var result = await dialog.ShowAsync();
            if (result != ContentDialogResult.Primary) return;

            try
            {
                var restoreResult = await System.Threading.Tasks.Task.Run(() =>
                    Mgr.RestoreBackup(row.Id, restoreBox.Text?.Trim()));

                await ShowMessage($"{(restoreResult.Success ? "恢复完成" : "恢复失败")}: {restoreResult.Message}");
            }
            catch (Exception ex)
            {
                await ShowMessage($"恢复失败: {ex.Message}");
            }
        }

        private async Task DeleteBackup(BackupRow row)
        {
            try
            {
                // 备份删除涉及文件目录删除，放后台防 UI 冻结
                await Task.Run(() => Mgr.DeleteBackup(row.Id));
                LoadBackups();
                await ShowMessage($"已删除备份 \"{row.Name}\"");
            }
            catch (Exception ex)
            {
                await ShowMessage($"删除失败: {ex.Message}");
            }
        }

        private async Task ShowMessage(string message)
        {
            await new ContentDialog
            {
                Title = "数据备份",
                Content = message,
                CloseButtonText = "确定",
                XamlRoot = XamlRoot
            }.ShowAsync();
        }
    }
}