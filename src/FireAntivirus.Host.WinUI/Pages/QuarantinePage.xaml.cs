// 隔离区：读取真实 QuarantineStore 索引，支持恢复/彻底删除
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class QuarantineRow
    {
        public string Id { get; set; }
        public string FileName { get; set; }
        public string OriginalPath { get; set; }
        public string ThreatName { get; set; }
        public string Severity { get; set; }
        public string When { get; set; }
    }

    public sealed partial class QuarantinePage : Page
    {
        public ObservableCollection<QuarantineRow> Items { get; } = new();

        public QuarantinePage()
        {
            InitializeComponent();
            QuarantineList.ItemsSource = Items;
            LoadQuarantineFiles();
        }

        // 隔离区枚举（文件 IO）在后台线程执行，防页面打开冻结
        private void LoadQuarantineFiles() => _ = LoadQuarantineFilesAsync();

        private async Task LoadQuarantineFilesAsync()
        {
            CountText.Text = "正在加载隔离区...";
            var rows = await Task.Run(() =>
            {
                try { return QuarantineStore.ListAll().ToList(); }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 加载隔离区失败: " + ex.Message);
                    return null;
                }
            });

            Items.Clear();
            if (rows != null)
            {
                foreach (var item in rows)
                    Items.Add(new QuarantineRow
                    {
                        Id = item.QuarantinedPath,
                        FileName = System.IO.Path.GetFileName(item.OriginalPath),
                        OriginalPath = item.OriginalPath,
                        ThreatName = item.ThreatName,
                        Severity = item.Severity,
                        When = item.QuarantinedAt.ToString("yyyy-MM-dd HH:mm")
                    });
            }
            CountText.Text = $"共 {Items.Count} 项";
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => LoadQuarantineFiles();

        private void Restore_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string path)
            {
                var ok = QuarantineStore.Restore(path, out var err);
                LoadQuarantineFiles();
                _ = new ContentDialog
                {
                    Title = ok ? "恢复成功" : "恢复失败",
                    Content = ok ? "文件已恢复到原路径。" : $"失败原因：{err}",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                }.ShowAsync();
            }
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string path)
            {
                var ok = QuarantineStore.Delete(path, out var err);
                LoadQuarantineFiles();
                _ = new ContentDialog
                {
                    Title = ok ? "已删除" : "删除失败",
                    Content = ok ? "该文件已彻底删除。" : $"失败原因：{err}",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                }.ShowAsync();
            }
        }
    }
}
