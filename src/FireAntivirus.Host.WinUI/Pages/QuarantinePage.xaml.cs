// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Data;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class QuarantineRow
    {
        public string Id { get; set; }
        public string FileName { get; set; }
        public string OriginalPath { get; set; }
        public string ThreatName { get; set; }
        public string When { get; set; }
    }

    public sealed partial class QuarantinePage : Page
    {
        private readonly DataManager _data = new();
        public ObservableCollection<QuarantineRow> Items { get; } = new();

        public QuarantinePage()
        {
            InitializeComponent();
            QuarantineList.ItemsSource = Items;
            LoadQuarantineFiles();
        }

        private void LoadQuarantineFiles()
        {
            try
            {
                Items.Clear();
                foreach (var item in _data.LoadQuarantine())
                    Items.Add(new QuarantineRow
                    {
                        Id = item.Id,
                        FileName = item.FileName,
                        OriginalPath = item.OriginalPath,
                        ThreatName = item.ThreatName,
                        When = item.QuarantineTime.ToString("yyyy-MM-dd HH:mm")
                    });
                CountText.Text = $"共 {Items.Count} 项";
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 加载隔离区失败: " + ex.Message);
            }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => LoadQuarantineFiles();

        private void Restore_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string id)
            {
                if (_data.RestoreFile(id))
                {
                    LoadQuarantineFiles();
                    _ = new ContentDialog
                    {
                        Title = "恢复成功", Content = "文件已恢复到原路径。", CloseButtonText = "确定", XamlRoot = XamlRoot
                    }.ShowAsync();
                }
            }
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string id)
            {
                if (_data.DeleteFromQuarantine(id))
                {
                    LoadQuarantineFiles();
                    _ = new ContentDialog
                    {
                        Title = "已删除", Content = "该文件已从隔离区删除。", CloseButtonText = "确定", XamlRoot = XamlRoot
                    }.ShowAsync();
                }
            }
        }

        private void ClearRestored_Click(object sender, RoutedEventArgs e)
        {
            _data.ClearQuarantine();
            LoadQuarantineFiles();
        }
    }
}