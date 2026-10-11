// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class ParentalControlPage : Page
    {
        private readonly ObservableCollection<string> _apps = new();
        private bool _enabled;

        public ParentalControlPage()
        {
            InitializeComponent();
            BlockedApps.ItemsSource = _apps;
        }

        private void EnableToggle_Toggled(object sender, RoutedEventArgs e)
        {
            _enabled = EnableToggle.IsOn;
            StatusText.Text = _enabled ? "已启用" : "已禁用";
            StatusText.Foreground = _enabled
                ? (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SafeBrush"]
                : (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
        }

        private void ApplyTime_Click(object sender, RoutedEventArgs e)
        {
            var start = StartTime.Text.Trim();
            var end = EndTime.Text.Trim();
            if (string.IsNullOrEmpty(start) || string.IsNullOrEmpty(end))
            {
                TimeStatus.Text = "请填写开始和结束时间（HH:mm）";
                return;
            }
            TimeStatus.Text = $"已应用上网时段：{start} - {end}（需启用家长控制后生效）";
        }

        private void AddApp_Click(object sender, RoutedEventArgs e)
        {
            var app = AppInput.Text.Trim();
            if (string.IsNullOrEmpty(app) || _apps.Contains(app)) return;
            _apps.Add(app);
            AppInput.Text = "";
        }

        private void RemoveApp_Click(object sender, RoutedEventArgs e)
        {
            if (BlockedApps.SelectedItem is string s) _apps.Remove(s);
        }
    }
}