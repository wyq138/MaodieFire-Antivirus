// 启动项管理：真实读取 HKCU/HKLM Run 键与启动文件夹，删除真实生效
// 列表模板用运行时 XamlReader 生成（绕开 XamlCompiler 对新增页面的崩溃）
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;
using Microsoft.Win32;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class StartupRow
    {
        public string EntryId { get; set; }      // 编码后的删除目标，形如 "reg|HKCU|Name" 或 "file|完整路径"
        public string EntryName { get; set; }
        public string CommandText { get; set; }
        public string LocationText { get; set; }
    }

    public sealed partial class StartupPage : Page
    {
        public ObservableCollection<StartupRow> Items { get; } = new();

        public StartupPage()
        {
            InitializeComponent();
            StartupList.ItemsSource = Items;
            // 运行时模板：不经过 XamlCompiler
            StartupList.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""12"" Padding=""6"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <StackPanel>
            <TextBlock Text=""{Binding EntryName}"" FontWeight=""SemiBold""/>
            <TextBlock Text=""{Binding CommandText}"" Opacity=""0.6"" FontSize=""12"" TextTrimming=""CharacterEllipsis""/>
        </StackPanel>
        <TextBlock Grid.Column=""1"" Text=""{Binding LocationText}"" Opacity=""0.6"" VerticalAlignment=""Center"" FontSize=""12""/>
        <Button Grid.Column=""2"" Content=""删除"" Tag=""{Binding EntryId}""/>
    </Grid>
</DataTemplate>");
            // 运行时模板里的按钮事件在容器生成时挂接（先减后加幂等，防容器复用重复订阅导致一次点击执行多次）
            StartupList.ContainerContentChanging += (s, args) =>
            {
                if (args.ItemContainer.ContentTemplateRoot is Grid root
                    && root.Children.OfType<Button>().LastOrDefault() is Button del)
                {
                    del.Click -= DelBtn_Click;
                    del.Click += DelBtn_Click;
                }
            };
            LoadStartupItems();
        }

        private bool _loading;

        private async Task LoadStartupItemsAsync()
        {
            if (_loading) return;
            _loading = true;
            try
            {
                CountText.Text = "正在枚举启动项...";
                var rows = await Task.Run(() =>
                {
                    var list = new System.Collections.Generic.List<StartupRow>();
                    void Add(string id, string name, string command, string location) =>
                        list.Add(new StartupRow
                        {
                            EntryId = id,
                            EntryName = name,
                            CommandText = command ?? "--",
                            LocationText = location
                        });

                    // 注册表启动项全量枚举：Run + RunOnce + WOW6432Node（与 WPF 版 StartupManager 对齐）
                    void AddRun(string hiveName, RegistryKey hive, string subPath, string location)
                    {
                        try
                        {
                            using var key = hive.OpenSubKey(subPath);
                            if (key == null) return;
                            foreach (var name in key.GetValueNames())
                                Add($"reg|{hiveName}|{subPath}|{name}", name, key.GetValue(name)?.ToString(), location);
                        }
                        catch (Exception ex)
                        {
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, $"WinUI 枚举启动项失败 {subPath}: {ex.Message}");
                        }
                    }

                    AddRun("HKCU", Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run");
                    AddRun("HKCU", Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce");
                    AddRun("HKLM", Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run（需管理员）");
                    AddRun("HKLM", Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce（需管理员）");
                    AddRun("HKLM", Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\WOW6432Node\\Run（需管理员）");

                    // 当前用户启动文件夹 + 公共启动文件夹
                    foreach (var (special, label) in new[]
                    {
                        (Environment.SpecialFolder.Startup, "启动文件夹（当前用户）"),
                        (Environment.SpecialFolder.CommonStartup, "启动文件夹（所有用户）")
                    })
                    {
                        var dir = Environment.GetFolderPath(special);
                        if (!Directory.Exists(dir)) continue;
                        try
                        {
                            foreach (var f in Directory.GetFiles(dir))
                                Add("file|" + f, Path.GetFileNameWithoutExtension(f), f, label);
                        }
                        catch (Exception ex)
                        {
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, $"WinUI 枚举启动文件夹失败 {dir}: {ex.Message}");
                        }
                    }

                    return list;
                });

                Items.Clear();
                foreach (var r in rows) Items.Add(r);
                CountText.Text = $"共 {Items.Count} 项";
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 加载启动项失败: " + ex.Message);
            }
            finally
            {
                _loading = false;
            }
        }

        private void LoadStartupItems() => _ = LoadStartupItemsAsync();

        private void Refresh_Click(object sender, RoutedEventArgs e) => _ = LoadStartupItemsAsync();

        private void DelBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string id)
            {
                _ = DeleteEntry(id);
            }
        }

        private async System.Threading.Tasks.Task DeleteEntry(string id)
        {
            string err = null; bool ok = true;
            try
            {
                var parts = id.Split('|', 4);
                if (parts[0] == "reg" && parts.Length == 4)
                {
                    var hive = parts[1] == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                    using var key = hive.CreateSubKey(parts[2]);
                    key.DeleteValue(parts[3], false);
                }
                else if (parts[0] == "file" && parts.Length == 2)
                {
                    if (File.Exists(parts[1])) File.Delete(parts[1]);
                }
                else ok = false;
            }
            catch (Exception ex) { ok = false; err = ex.Message; }

            if (ok) LoadStartupItems();
            try
            {
                if (XamlRoot == null) return;
                await new ContentDialog
                {
                    Title = ok ? "已删除" : "删除失败",
                    Content = ok ? "启动项已删除。" : $"失败原因：{err}\n（HKLM 项需要以管理员身份运行本程序）",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                }.ShowAsync();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 启动项弹窗失败: " + ex.Message);
            }
        }
    }
}
