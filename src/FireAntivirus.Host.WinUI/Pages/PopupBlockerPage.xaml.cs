// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class PopupBlockerPage : Page
    {
        private readonly ObservableCollection<string> _log = new();

        public PopupBlockerPage()
        {
            InitializeComponent();
            LogList.ItemsSource = _log;
        }

        private void GlobalToggle_Toggled(object sender, RoutedEventArgs e)
        {
            var on = GlobalToggle.IsOn;
            StatusText.Text = on ? "弹窗拦截已启用" : "弹窗拦截已禁用";
            StatusText.Foreground = on
                ? (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SafeBrush"]
                : (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
            _log.Insert(0, $"[{DateTime.Now:HH:mm:ss}] 全局弹窗拦截已{(on ? "启用" : "关闭")}");
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e) => _log.Clear();
    }
}