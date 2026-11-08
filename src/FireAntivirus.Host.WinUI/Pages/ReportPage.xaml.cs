// 安全报告：真实调用 SecurityReportManager（进程/日志/补丁/启动项多维真实数据汇总），
// 支持生成日/周/月/完整报告与 TXT/HTML/XML 真实导出。UI 采用运行时模板。
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using FireAntivirus.Data;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class ReportSectionRow
    {
        public string Title { get; set; }
        public string Content { get; set; }
        public string Status { get; set; }
    }

    public sealed partial class ReportPage : Page
    {
        public ObservableCollection<ReportSectionRow> Sections { get; } = new();
        private DataManager _data => App.Data;
        private FireAntivirus.SecurityReport.SecurityReportManager _reportManager;
        private FireAntivirus.SecurityReport.SecurityReportManager ReportManager =>
            _reportManager ??= new FireAntivirus.SecurityReport.SecurityReportManager(_data);
        private FireAntivirus.SecurityReport.Report _currentReport;
        private TextBlock _summary;
        private TextBlock _state;
        private Button _exportBtn;
        private ComboBox _typeCombo;

        public ReportPage()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[页面诊断] ReportPage 构造开始");
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("安全报告", ex);
            }
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"[页面诊断] ReportPage 构造完成 {sw.ElapsedMilliseconds}ms");
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 12 };

            root.Children.Add(new TextBlock
            {
                Text = "安全报告",
                FontSize = 22,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            });

            _state = new TextBlock { Text = "报告内容来自真实系统状态：防护进程、安全日志、系统补丁、活动连接、启动项", Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_state);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            _typeCombo = new ComboBox { MinWidth = 140, PlaceholderText = "报告类型" };
            foreach (var t in new[] { "每日报告", "每周报告", "每月报告", "完整报告" })
                _typeCombo.Items.Add(t);
            _typeCombo.SelectedIndex = 0;
            btnRow.Children.Add(_typeCombo);

            var genBtn = new Button { Content = "生成报告", MinWidth = 110 };
            genBtn.Click += async (_, _) => await GenerateReport();
            btnRow.Children.Add(genBtn);

            _exportBtn = new Button { Content = "导出 HTML", MinWidth = 110, IsEnabled = false };
            _exportBtn.Click += async (_, _) => await ExportReport();
            btnRow.Children.Add(_exportBtn);
            root.Children.Add(btnRow);

            _summary = new TextBlock { FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_summary);

            var list = new ListView { MaxHeight = 520, SelectionMode = ListViewSelectionMode.None };
            list.ItemTemplate = (DataTemplate)XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""12"" Padding=""8"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <StackPanel>
            <TextBlock Text=""{Binding Title}"" FontWeight=""SemiBold""/>
            <TextBlock Text=""{Binding Content}"" Opacity=""0.65"" FontSize=""12"" TextWrapping=""Wrap""/>
        </StackPanel>
        <TextBlock Grid.Column=""1"" Text=""{Binding Status}"" FontSize=""12"" VerticalAlignment=""Center"" Opacity=""0.8""/>
    </Grid>
</DataTemplate>");
            list.ContainerContentChanging += (s, args) =>
            {
                if (args.Item is ReportSectionRow row && args.ItemContainer.ContentTemplateRoot is Grid grid)
                {
                    var texts = grid.Children.OfType<TextBlock>().ToList();
                    if (texts.Count >= 2)
                    {
                        var color = row.Status switch
                        {
                            "Good" => Microsoft.UI.Colors.ForestGreen,
                            "Medium" => Microsoft.UI.Colors.Orange,
                            "Poor" => Microsoft.UI.Colors.OrangeRed,
                            "Critical" => Microsoft.UI.Colors.Red,
                            _ => Microsoft.UI.Colors.Gray
                        };
                        texts[1].Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(color);
                    }
                }
            };
            list.ItemsSource = Sections;
            root.Children.Add(list);

            return root;
        }

        private async Task GenerateReport()
        {
            try
            {
                var (type, span) = _typeCombo.SelectedIndex switch
                {
                    1 => (FireAntivirus.SecurityReport.ReportType.Weekly, TimeSpan.FromDays(7)),
                    2 => (FireAntivirus.SecurityReport.ReportType.Monthly, TimeSpan.FromDays(30)),
                    3 => (FireAntivirus.SecurityReport.ReportType.Full, TimeSpan.FromDays(90)),
                    _ => (FireAntivirus.SecurityReport.ReportType.Daily, TimeSpan.FromDays(1))
                };

                _state.Text = "正在收集系统真实状态生成报告...";
                Sections.Clear();
                _exportBtn.IsEnabled = false;

                _currentReport = await System.Threading.Tasks.Task.Run(() => ReportManager.GenerateSecurityReport(type, span));

                foreach (var section in _currentReport.Sections)
                {
                    Sections.Add(new ReportSectionRow
                    {
                        Title = section.Title,
                        Content = section.Content,
                        Status = section.Status
                    });
                }

                _summary.Text = $"总体安全状态: {_currentReport.OverallSecurityStatus} —— {_currentReport.Summary}";
                _state.Text = $"报告已生成（{_typeCombo.SelectedItem}，ID: {_currentReport.Id[..8]}）";
                _exportBtn.IsEnabled = true;
            }
            catch (Exception ex)
            {
                _state.Text = $"生成失败: {ex.Message}";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 安全报告生成失败: " + ex.Message);
            }
        }

        private async Task ExportReport()
        {
            if (_currentReport == null) return;

            try
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Reports");
                Directory.CreateDirectory(dir);
                var target = Path.Combine(dir, $"security_report_{DateTime.Now:yyyyMMdd_HHmmss}.html");

                bool ok = await System.Threading.Tasks.Task.Run(() =>
                    ReportManager.ExportReport(_currentReport.Id, "html", target));

                await new ContentDialog
                {
                    Title = ok ? "导出成功" : "导出失败",
                    Content = ok ? $"HTML 报告已导出到:\n{target}" : "导出失败，请检查报告是否仍存在。",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                }.ShowAsync();
            }
            catch (Exception ex)
            {
                await new ContentDialog
                {
                    Title = "导出失败",
                    Content = ex.Message,
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                }.ShowAsync();
            }
        }
    }
}