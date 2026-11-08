// 安全评分页（搬运自 WPF SecurityScorePage，WinUI 真实实现）：
// SecurityScoreService.CalculateSecurityScore 真实计算（防护状态/更新/漏洞/密码/隐私等维度加权），
// 展示总分/等级/分类明细/改进建议/趋势分析，全部为实时计算数据。
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using FireAntivirus.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class ScoreCategoryRow
    {
        public string Name { get; set; }
        public string ScoreText { get; set; }
        public string Status { get; set; }
        public string Details { get; set; }
    }

    public sealed class ScoreAdviceRow
    {
        public string Title { get; set; }
        public string Priority { get; set; }
        public string Description { get; set; }
    }

    public sealed partial class SecurityScorePage : Page
    {
        private readonly SecurityScoreService _service = new SecurityScoreService();
        private readonly ObservableCollection<ScoreCategoryRow> _categories = new();
        private readonly ObservableCollection<ScoreAdviceRow> _advices = new();

        private TextBlock _scoreText;
        private TextBlock _gradeText;
        private TextBlock _riskText;
        private TextBlock _trendText;
        private TextBlock _state;

        public SecurityScorePage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                Refresh();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("安全评分", ex);
            }
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 14 };

            root.Children.Add(new TextBlock { Text = "安全评分", FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            _state = new TextBlock { Text = "正在计算安全评分...", Opacity = 0.7 };
            root.Children.Add(_state);

            // 评分总览卡
            var scoreCard = new Border
            {
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(24),
                BorderBrush = new Microsoft.UI.Xaml.Media.SolidColorBrush(Windows.UI.Color.FromArgb(80, 0, 122, 204))
            };
            var scoreRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 28 };
            _scoreText = new TextBlock { Text = "--", FontSize = 64, FontWeight = Microsoft.UI.Text.FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center };
            scoreRow.Children.Add(_scoreText);
            var scoreInfo = new StackPanel { Spacing = 6, VerticalAlignment = VerticalAlignment.Center };
            _gradeText = new TextBlock { Text = "等级: --", FontSize = 18, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold };
            _riskText = new TextBlock { Text = "风险系数: --", Opacity = 0.75 };
            _trendText = new TextBlock { Text = "趋势: --", Opacity = 0.75 };
            scoreInfo.Children.Add(_gradeText);
            scoreInfo.Children.Add(_riskText);
            scoreInfo.Children.Add(_trendText);
            scoreRow.Children.Add(scoreInfo);
            scoreCard.Child = scoreRow;
            root.Children.Add(scoreCard);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            var refreshBtn = new Button { Content = "重新计算评分", MinWidth = 120 };
            refreshBtn.Click += (_, _) => Refresh();
            btnRow.Children.Add(refreshBtn);
            root.Children.Add(btnRow);

            root.Children.Add(new TextBlock { Text = "评分维度明细", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            root.Children.Add(new ListView { ItemsSource = _categories, MaxHeight = 260, SelectionMode = ListViewSelectionMode.None });

            root.Children.Add(new TextBlock { Text = "改进建议（按优先级）", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            root.Children.Add(new ListView { ItemsSource = _advices, MaxHeight = 220, SelectionMode = ListViewSelectionMode.None });

            return root;
        }

        private void Refresh()
        {
            _state.Text = "正在计算安全评分...";
            _ = Task.Run(() =>
            {
                SecurityScoreResult result = null;
                SecurityTrendAnalysis trend = null;
                string error = null;
                try
                {
                    result = _service.CalculateSecurityScore();
                    try { trend = _service.AnalyzeTrend(); } catch { }
                }
                catch (Exception ex) { error = ex.Message; }

                DispatcherQueue.TryEnqueue(() => Fill(result, trend, error));
            });
        }

        private void Fill(SecurityScoreResult result, SecurityTrendAnalysis trend, string error)
        {
            if (result == null)
            {
                _state.Text = "评分计算失败: " + error;
                return;
            }

            _scoreText.Text = result.TotalScore.ToString();
            _gradeText.Text = $"等级: {result.Grade}";
            _riskText.Text = $"风险系数: {result.RiskFactor:F2}";
            if (trend != null)
            {
                string dir = trend.Trend switch
                {
                    TrendDirection.Improving => "上升",
                    TrendDirection.Declining => "下降",
                    _ => "稳定"
                };
                _trendText.Text = $"趋势: {dir}（变化 {trend.ScoreChange:+#;-#;0}，预测 {trend.Projection}）";
            }

            _categories.Clear();
            foreach (var c in result.Categories ?? new System.Collections.Generic.List<SecurityCategory>())
            {
                _categories.Add(new ScoreCategoryRow
                {
                    Name = c.Name,
                    ScoreText = $"{c.Score:0.#}/{c.MaxScore}（权重 {c.Weight:P0}）",
                    Status = c.Status,
                    Details = string.Join("；", (c.Details ?? new System.Collections.Generic.List<string>()).Take(2))
                });
            }

            _advices.Clear();
            foreach (var a in result.Recommendations ?? new System.Collections.Generic.List<SecurityRecommendation>())
            {
                _advices.Add(new ScoreAdviceRow
                {
                    Title = a.Title,
                    Priority = "优先级 " + a.Priority,
                    Description = a.Description
                });
            }

            _state.Text = $"评分完成 · {DateTime.Now:HH:mm:ss}（共 {_categories.Count} 个维度，{_advices.Count} 条建议）";
        }
    }
}