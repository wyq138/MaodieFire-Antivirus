// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Win32;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class StartupItemRow
    {
        public string Name { get; set; } = "";
        public string Command { get; set; } = "";
        public string Status { get; set; } = "启用";
        public string KeyPath { get; set; } = "";
        public bool Enabled { get; set; } = true;
    }

    public sealed partial class StartupManagerPage : Page
    {
        private readonly ObservableCollection<StartupItemRow> _items = new();

        public StartupManagerPage()
        {
            InitializeComponent();
            StartupList.ItemsSource = _items;
            LoadStartupItems();
        }

        private void LoadStartupItems()
        {
            _items.Clear();
            try
            {
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    using var run = hive.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                    if (run == null) continue;
                    foreach (var name in run.GetValueNames())
                    {
                        var cmd = run.GetValue(name)?.ToString() ?? "";
                        _items.Add(new StartupItemRow
                        {
                            Name = name,
                            Command = cmd,
                            Status = "启用",
                            Enabled = true,
                            KeyPath = (hive == Registry.CurrentUser ? "HKCU" : "HKLM") + @"\...\Run"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "读取启动项失败: " + ex.Message);
            }
            CountText.Text = $"共 {_items.Count} 个启动项";
        }

        private void Toggle(string subKey, string name, bool enable)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(subKey, writable: true);
                if (key == null) return;
                foreach (var it in _items)
                {
                    if (!it.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
                    if (enable)
                        key.SetValue(name, it.Command, RegistryValueKind.String);
                    else
                        key.DeleteValue(name, false);
                    it.Enabled = enable;
                    it.Status = enable ? "启用" : "已禁用";
                    break;
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "修改启动项失败: " + ex.Message);
                _ = new ContentDialog { Title = "提示", Content = "修改失败: " + ex.Message, CloseButtonText = "确定", XamlRoot = XamlRoot }.ShowAsync();
            }
        }

        private const string RunRoot = @"Software\Microsoft\Windows\CurrentVersion\Run";

        private void Disable_Click(object sender, RoutedEventArgs e)
        {
            if (StartupList.SelectedItem is StartupItemRow row) Toggle(RunRoot, row.Name, false);
        }

        private void Enable_Click(object sender, RoutedEventArgs e)
        {
            if (StartupList.SelectedItem is StartupItemRow row) Toggle(RunRoot, row.Name, true);
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => LoadStartupItems();
    }
}