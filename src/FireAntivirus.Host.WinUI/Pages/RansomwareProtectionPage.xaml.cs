// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class RansomwareProtectionPage : Page
    {
        private readonly ObservableCollection<string> _folders = new();
        private bool _enabled = true;

        public RansomwareProtectionPage()
        {
            InitializeComponent();
            ProtectedFoldersList.ItemsSource = _folders;
            LoadProtectedFolders();
        }

        private void LoadProtectedFolders()
        {
            _folders.Clear();
            var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var pics = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
            var desk = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (!string.IsNullOrEmpty(docs)) _folders.Add(docs);
            if (!string.IsNullOrEmpty(pics)) _folders.Add(pics);
            if (!string.IsNullOrEmpty(desk)) _folders.Add(desk);
        }

        private async void AddFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
                picker.FileTypeFilter.Add("*");
                var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
                var folder = await picker.PickSingleFolderAsync();
                if (folder != null && !_folders.Contains(folder.Path))
                    _folders.Add(folder.Path);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "添加防护文件夹失败: " + ex.Message);
            }
        }

        private void RemoveFolder_Click(object sender, RoutedEventArgs e)
        {
            if (ProtectedFoldersList.SelectedItem is string f)
                _folders.Remove(f);
        }

        private void ProtectionToggle_Toggled(object sender, RoutedEventArgs e)
        {
            _enabled = ProtectionToggle.IsOn;
            StatusText.Text = _enabled ? "已启用" : "已禁用";
            StatusText.Foreground = _enabled
                ? (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["SafeBrush"]
                : (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["DangerBrush"];
        }
    }
}