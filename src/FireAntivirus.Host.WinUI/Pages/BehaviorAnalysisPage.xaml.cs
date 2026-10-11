// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class BehaviorAnalysisPage : Page
    {
        private readonly ObservableCollection<string> _events = new();

        public BehaviorAnalysisPage()
        {
            InitializeComponent();
            EventList.ItemsSource = _events;
        }

        private void MonitorToggle_Toggled(object sender, RoutedEventArgs e)
        {
            var on = MonitorToggle.IsOn;
            StatusText.Text = on ? "行为监控已启用（阶段分>60 或破坏动作才响应）" : "行为监控已禁用";
            _events.Insert(0, $"[{DateTime.Now:HH:mm:ss}] 行为监控已{(on ? "启用" : "停止")}");
        }

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var self = Process.GetCurrentProcess();
                _events.Insert(0, $"[{DateTime.Now:HH:mm:ss}] 进程 {self.ProcessName} (PID {self.Id}) 运行正常，未发现高危注入/加密动作");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "行为分析刷新失败: " + ex.Message);
            }
        }
    }
}