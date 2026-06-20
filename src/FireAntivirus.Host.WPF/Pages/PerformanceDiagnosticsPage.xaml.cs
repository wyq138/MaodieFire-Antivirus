using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 性能诊断页面，用于显示性能数据和优化建议
    /// </summary>
    public partial class PerformanceDiagnosticsPage : System.Windows.Controls.Page, IPageWithLifecycle
    {
        private PerformanceDiagnosticsViewModel _viewModel;

        public PerformanceDiagnosticsPage()
        {
            InitializeComponent();
            _viewModel = new PerformanceDiagnosticsViewModel();
            DataContext = _viewModel;
        }

        public void OnPageActivated()
        {
            _ = _viewModel.LoadPerformanceDataAsync();
        }

        public void OnPageCached() { }
        public void OnPageUnloaded() { }
        public DateTime GetLastAccessTime() => DateTime.Now;
        public float GetMemoryUsage() => 0f;
    }

    /// <summary>
    /// 性能诊断视图模型
    /// </summary>
    public class PerformanceDiagnosticsViewModel : INotifyPropertyChanged
    {
        private readonly PerformanceMonitor _performanceMonitor;
        private string _overallPerformance;
        private string _averageLoadTimeMs;
        private string _worstPerformingPage;
        private string _bestPerformingPage;
        private Brush _overallPerformanceColor;

        public PerformanceDiagnosticsViewModel()
        {
            _performanceMonitor = new PerformanceMonitor();
            PagePerformanceList = new ObservableCollection<PagePerformanceInfo>();
            RefreshCommand = new RelayCommand(async _ => await LoadPerformanceDataAsync());
            GenerateReportCommand = new RelayCommand(_ => GeneratePerformanceReport());
            ShowOptimizationCommand = new RelayCommand(ShowOptimizationSuggestions);
        }

        public async Task LoadPerformanceDataAsync()
        {
            await Task.Run(() =>
            {
                var report = _performanceMonitor.GenerateReport();
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                    OverallPerformance = report.OverallPerformance;
                    AverageLoadTimeMs = $"{report.AverageLoadTimeMs:F0}ms";
                    WorstPerformingPage = report.WorstPerformingPage ?? "无数据";
                    BestPerformingPage = report.BestPerformingPage ?? "无数据";

                    // 设置性能等级颜色
                    OverallPerformanceColor = report.OverallPerformance switch
                    {
                        "优秀" => Brushes.Green,
                        "良好" => Brushes.Blue,
                        "一般" => Brushes.Orange,
                        _ => Brushes.Red
                    };

                    // 更新页面性能列表
                    PagePerformanceList.Clear();
                    foreach (var pageStat in report.PageStatistics)
                    {
                        var pageInfo = new PagePerformanceInfo
                        {
                            PageName = pageStat.Key,
                            AverageTime = (int)pageStat.Value.AverageLoadTimeMs,
                            MaxTime = (int)pageStat.Value.MaxLoadTimeMs,
                            MinTime = (int)pageStat.Value.MinLoadTimeMs,
                            Percentile95Time = (int)pageStat.Value.LoadTime95Percentile
                        };

                        // 设置状态和颜色
                        pageInfo.Status = pageInfo.AverageTime switch
                        {
                            < 100 => "优秀性能",
                            < 300 => "良好性能",
                            < 500 => "一般性能",
                            _ => "需要优化"
                        };

                        pageInfo.StatusColor = pageInfo.AverageTime switch
                        {
                            < 100 => Brushes.Green,
                            < 300 => Brushes.Blue,
                            < 500 => Brushes.Orange,
                            _ => Brushes.Red
                        };

                        PagePerformanceList.Add(pageInfo);
                    }

                    OnPropertyChanged(nameof(PagePerformanceList));
                });
            });
        }

        private void GeneratePerformanceReport()
        {
            var report = _performanceMonitor.GenerateReport();
            var message = "性能报告生成完成！\n\n" +
                         $"总体性能: {report.OverallPerformance}\n" +
                         $"平均加载时间: {report.AverageLoadTimeMs:F0}ms\n" +
                         $"跟踪页面数: {report.TotalPagesTracked}\n\n" +
                         "优化建议:\n" + string.Join("\n", report.Recommendations);

            MessageBox.Show(message, "性能报告", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ShowOptimizationSuggestions(object pageNameObj)
        {
            if (pageNameObj is string pageName)
            {
                var report = _performanceMonitor.GenerateReport();
                if (report.PageStatistics.TryGetValue(pageName, out var stats))
                {
                    var suggestions = new List<string>();

                    if (stats.AverageLoadTimeMs > 300)
                        suggestions.Add($"• {pageName} 页面加载较慢，建议检查数据加载逻辑");
                    if (stats.AverageLoadTimeMs > 100)
                        suggestions.Add($"• 考虑为该页面添加预加载机制");
                    if (stats.RecentLoads.Count > 5)
                        suggestions.Add("• 页面缓存机制运行正常");
                    else
                        suggestions.Add("• 建议增加页面使用频率以获得更准确的性能数据");

                    var message = $"页面优化建议 - {pageName}\n\n" +
                                 $"平均加载时间: {stats.AverageLoadTimeMs:F0}ms\n" +
                                 $"95%加载时间: {stats.LoadTime95Percentile:F0}ms\n" +
                                 $"总加载次数: {stats.TotalLoads}\n\n" +
                                 "优化建议:\n" + string.Join("\n", suggestions);

                    MessageBox.Show(message, "页面优化建议", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }

        #region 属性

        public string OverallPerformance
        {
            get => _overallPerformance;
            set
            {
                _overallPerformance = value;
                OnPropertyChanged(nameof(OverallPerformance));
            }
        }

        public string AverageLoadTimeMs
        {
            get => _averageLoadTimeMs;
            set
            {
                _averageLoadTimeMs = value;
                OnPropertyChanged(nameof(AverageLoadTimeMs));
            }
        }

        public string WorstPerformingPage
        {
            get => _worstPerformingPage;
            set
            {
                _worstPerformingPage = value;
                OnPropertyChanged(nameof(WorstPerformingPage));
            }
        }

        public string BestPerformingPage
        {
            get => _bestPerformingPage;
            set
            {
                _bestPerformingPage = value;
                OnPropertyChanged(nameof(BestPerformingPage));
            }
        }

        public Brush OverallPerformanceColor
        {
            get => _overallPerformanceColor;
            set
            {
                _overallPerformanceColor = value;
                OnPropertyChanged(nameof(OverallPerformanceColor));
            }
        }

        public ObservableCollection<PagePerformanceInfo> PagePerformanceList { get; }

        #endregion

        #region 命令

        public ICommand RefreshCommand { get; }
        public ICommand GenerateReportCommand { get; }
        public ICommand ShowOptimizationCommand { get; }

        #endregion

        #region INotifyPropertyChanged实现

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }

    /// <summary>
    /// 页面性能信息
    /// </summary>
    public class PagePerformanceInfo
    {
        public string PageName { get; set; }
        public int AverageTime { get; set; }
        public int MaxTime { get; set; }
        public int MinTime { get; set; }
        public int Percentile95Time { get; set; }
        public string Status { get; set; }
        public Brush StatusColor { get; set; }
    }

    /// <summary>
    /// 简单的中继命令实现
    /// </summary>
    public class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        private readonly Func<object, bool> _canExecute;

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }

        public RelayCommand(Action<object> execute, Func<object, bool> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object parameter) => _canExecute == null || _canExecute(parameter);

        public void Execute(object parameter) => _execute(parameter);
    }
}