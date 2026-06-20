// 抖音用户 耙耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public class ReportItem
    {
        public string ReportName { get; set; }
        public string Type { get; set; }
        public string GeneratedTime { get; set; }
        public string Size { get; set; }
    }

    public partial class SecurityReportPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private SecurityReportService reportService;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private List<ReportItem> reportItems = new List<ReportItem>();

        public SecurityReportPage()
        {
            InitializeComponent();
                    
                    // 页面卸载时停止后台任务
                    Unloaded += (s, e) =>
                    {
                        _isLoaded = false;
                        _cts?.Cancel();
                    };
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            
            EnableScheduledCheck.Checked += (s, e) => { FrequencyCombo.IsEnabled = true; EmailTextBox.IsEnabled = true; };
            EnableScheduledCheck.Unchecked += (s, e) => { FrequencyCombo.IsEnabled = false; EmailTextBox.IsEnabled = false; };
            
            // 异步初始化，不阻塞UI
            Loaded += async (s, e) =>
            {
                await System.Threading.Tasks.Task.Run(() => InitializeService());
                await System.Threading.Tasks.Task.Run(() => LoadReports());
            };
        }

        private void InitializeService()
        {
            try { reportService = new SecurityReportService(); } catch { }
        }

        private void LoadReports()
        {
            reportItems.Clear();
            
            // 添加示例数据
            reportItems.Add(new ReportItem { ReportName = "完整安全报告_20260331.pdf", Type = "PDF", GeneratedTime = "2026-03-31 18:30", Size = "256 KB" });
            reportItems.Add(new ReportItem { ReportName = "扫描报告_20260330.html", Type = "HTML", GeneratedTime = "2026-03-30 15:20", Size = "128 KB" });
            reportItems.Add(new ReportItem { ReportName = "威胁分析_20260328.xml", Type = "XML", GeneratedTime = "2026-03-28 09:45", Size = "64 KB" });
            
            ReportsGrid.ItemsSource = null;
            ReportsGrid.ItemsSource = reportItems;
        }

        private void GenerateReport_Click(object sender, RoutedEventArgs e)
        {
            var reportType = ((ComboBoxItem)ReportTypeCombo.SelectedItem).Content.ToString();
            var timeRange = ((ComboBoxItem)TimeRangeCombo.SelectedItem).Content.ToString();
            
            // 模拟报告生成
            var newReport = new ReportItem
            {
                ReportName = $"{reportType}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf",
                Type = "PDF",
                GeneratedTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
                Size = "312 KB"
            };
            
            reportItems.Insert(0, newReport);
            ReportsGrid.ItemsSource = null;
            ReportsGrid.ItemsSource = reportItems;
            
            MessageBox.Show($"报告生成成功!\n\n类型: {reportType}\n时间范围: {timeRange}", "生成报告", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExportPdf_Click(object sender, RoutedEventArgs e)
        {
            if (ReportsGrid.SelectedItem is ReportItem item)
            {
                MessageBox.Show($"正在导出报告: {item.ReportName}\n\n导出格式: PDF", "导出报告", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("请先选择一个报告", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void ExportHtml_Click(object sender, RoutedEventArgs e)
        {
            if (ReportsGrid.SelectedItem is ReportItem item)
            {
                MessageBox.Show($"正在导出报告: {item.ReportName}\n\n导出格式: HTML", "导出报告", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("请先选择一个报告", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void ExportXml_Click(object sender, RoutedEventArgs e)
        {
            if (ReportsGrid.SelectedItem is ReportItem item)
            {
                MessageBox.Show($"正在导出报告: {item.ReportName}\n\n导出格式: XML", "导出报告", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("请先选择一个报告", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark) MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("SecurityReport", "安全报告"); } catch { }
        }
    }
}
