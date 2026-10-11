// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Data;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class TrustRow
    {
        public string Type { get; set; } = "";
        public string Path { get; set; } = "";
        public string AddTime { get; set; } = "";
    }

    public sealed partial class TrustZonePage : Page
    {
        private readonly DataManager _data = new();
        private readonly ObservableCollection<TrustRow> _rows = new();

        public TrustZonePage()
        {
            InitializeComponent();
            TrustListGrid.ItemsSource = _rows;
            LoadTrustList();
        }

        private void LoadTrustList()
        {
            _rows.Clear();
            try
            {
                foreach (var item in _data.LoadTrustList())
                {
                    _rows.Add(new TrustRow
                    {
                        Type = item.Type,
                        Path = item.Path,
                        AddTime = item.AddTime.ToString("yyyy-MM-dd HH:mm")
                    });
                }
            }
            catch (System.Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "加载信任区失败: " + ex.Message);
            }
            CountText.Text = $"共 {_rows.Count} 项";
        }

        private async void AddTrustFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
                picker.FileTypeFilter.Add("*");
                var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
                var file = await picker.PickSingleFileAsync();
                if (file != null)
                {
                    _data.AddToWhitelist(file.Path, "手动信任", "User");
                    LoadTrustList();
                }
            }
            catch (System.Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "添加信任文件失败: " + ex.Message);
            }
        }

        private async void AddTrustFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
                picker.FileTypeFilter.Add("*");
                var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
                var folder = await picker.PickSingleFolderAsync();
                if (folder != null)
                {
                    _data.AddToWhitelist(folder.Path, "手动信任文件夹", "User");
                    LoadTrustList();
                }
            }
            catch (System.Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "添加信任文件夹失败: " + ex.Message);
            }
        }

        private void DeleteTrustItem_Click(object sender, RoutedEventArgs e)
        {
            if (TrustListGrid.SelectedItem is not TrustRow row) return;
            try
            {
                var target = _data.GetWhitelistEntries().Find(t => t.Path == row.Path);
                if (target != null) _data.RemoveFromWhitelist(target.Path);
                LoadTrustList();
            }
            catch (System.Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "移除信任项失败: " + ex.Message);
            }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => LoadTrustList();
    }
}