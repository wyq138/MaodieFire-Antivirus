// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Linq;
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
        private readonly DataManager _data = new();

        public LogsPage()
        {
            InitializeComponent();
            LogList.ItemsSource = _rows;
            LoadLogs();
        }

        private void LoadLogs()
        {
            _rows.Clear();
            try
            {
                var logs = _data.LoadLogs();
                foreach (var item in logs.OrderByDescending(l => l.Time).Take(200))
                {
                    _rows.Add(new LogRow
                    {
                        Time = item.Time.ToString("MM-dd HH:mm:ss"),
                        Type = item.Type,
                        Message = item.Message
                    });
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "加载日志失败: " + ex.Message);
                _rows.Add(new LogRow { Time = "--", Type = "错误", Message = "无法加载日志: " + ex.Message });
            }
            CountText.Text = $"共 {_rows.Count} 条日志";
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => LoadLogs();

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _data.ClearLogs();
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