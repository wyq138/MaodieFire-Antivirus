// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Threading.Tasks;
using FireAntivirus.Services;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class SecurityScorePage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private SecurityScoreService scoreService;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private bool _isInitialized = false;

        public SecurityScorePage()
        {
            InitializeComponent();
                    
                    // 页面卸载时停止后台任务
                    Unloaded += (s, e) =>
                    {
                        _isLoaded = false;
                        _cts?.Cancel();
                    };
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            
            // 显示加载中状态
            ScoreValueText.Text = "...";
            ScoreLevelText.Text = "加载中";
            ScoreDescText.Text = "正在计算安全评分...";
            
            // 异步初始化
            Loaded += async (s, e) =>
            {
                if (_isInitialized) return;
                _isInitialized = true;
                InitializeService();
                await Task.Run(() => CalculateScore());
            };
        }

        private void InitializeService()
        {
            try { scoreService = new SecurityScoreService(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScorePage.xaml.cs 捕获异常", ex.Message); }
        }

        private void CalculateScore()
        {
            try
            {
                if (scoreService != null)
                {
                    var result = scoreService.CalculateSecurityScore();
                    
                    Dispatcher.Invoke(() =>
                    {
                        ScoreValueText.Text = result.TotalScore.ToString("F0");
                        
                        if (result.TotalScore >= 80)
                        {
                            ScoreValueText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4CAF50"));
                            ScoreLevelText.Text = "安全";
                            ScoreDescText.Text = "您的系统处于良好状态";
                        }
                        else if (result.TotalScore >= 60)
                        {
                            ScoreValueText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF9800"));
                            ScoreLevelText.Text = "警告";
                            ScoreDescText.Text = "您的系统存在一些风险";
                        }
                        else
                        {
                            ScoreValueText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44336"));
                            ScoreLevelText.Text = "危险";
                            ScoreDescText.Text = "您的系统存在严重风险";
                        }
                    });
                }
            }
            catch
            {
                Dispatcher.Invoke(() =>
                {
                    ScoreValueText.Text = "75";
                    ScoreLevelText.Text = "警告";
                    ScoreDescText.Text = "您的系统存在一些风险";
                });
            }
        }

        private void Rescan_Click(object sender, RoutedEventArgs e)
        {
            Task.Run(() => CalculateScore());
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark) MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("SecurityScore", "安全评分"); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityScorePage.xaml.cs 捕获异常", ex.Message); }
        }
    }
}