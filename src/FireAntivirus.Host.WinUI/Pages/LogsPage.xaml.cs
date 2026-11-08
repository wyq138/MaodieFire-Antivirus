using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Data;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class LogRow
    {
        public string Time { get; set; } = "";
        public string Type { get; set; } = "";
        public string Message { get; set; } = "";
    }

    public sealed partial class LogsPage : Page
    {
        private readonly ObservableCollection<LogRow> _rows = new();
        private DataManager _data => App.Data;

        public LogsPage()
        {
            InitializeComponent();
            LogList.ItemsSource = _rows;
            LoadLogs();
        }

        // 日志表查询在后台线程执行（DataManager 构造 + 日志查询是 UI 线程冻结元凶）
        private void LoadLogs() => _ = LoadLogsAsync();

        private async Task LoadLogsAsync()
        {
            CountText.Text = "正在加载日志...";
            var logs = await Task.Run(() =>
            {
                try
                {
                    return _data.LoadLogs()
                        .OrderByDescending(l => l.Time)
                        .Take(200)
                        .ToList();
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "加载日志失败: " + ex.Message);
                    return null;
                }
            });

            _rows.Clear();
            if (logs == null)
            {
                _rows.Add(new LogRow { Time = "--", Type = "错误", Message = "无法加载日志" });
            }
            else
            {
                foreach (var item in logs)
                {
                    _rows.Add(new LogRow
                    {
                        Time = item.Time.ToString("MM-dd HH:mm:ss"),
                        Type = item.Type,
                        Message = item.Message
                    });
                }
            }
            CountText.Text = $"共 {_rows.Count} 条日志";
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => LoadLogs();

        private async void Clear_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await Task.Run(() => _data.ClearLogs());
                _rows.Clear();
                CountText.Text = "共 0 条日志";
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "清空日志失败: " + ex.Message);
            }
        }
    }
}