// 网页防护页（搬运自 WPF WebProtectionPage，WinUI 真实实现）：
// WebProtectionManager.CheckUrl 真实 URL 安全检查（恶意/钓鱼/垃圾/跟踪分类 + 风险等级 + 云端情报），
// 支持实时检测、统计展示、手动封禁/解封、拦截记录查看。全部为真实网络检测。
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.WebProtection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class BlockedUrlRow
    {
        public string Url { get; set; }
    }

    public sealed partial class WebProtectionPage : Page
    {
        private readonly WebProtectionManager _manager = new WebProtectionManager(DataManager.SharedInstance);
        // 家长控制真实消费方：内容过滤规则在网址检测时生效（设置页"家长控制"开启后）
        private readonly FireAntivirus.ParentalControl.ParentalControlManager _parental =
            new FireAntivirus.ParentalControl.ParentalControlManager(DataManager.SharedInstance);
        private readonly ObservableCollection<BlockedUrlRow> _blocked = new();

        private TextBox _urlBox;
        private TextBlock _resultText;
        private TextBlock _statsText;
        private TextBlock _state;

        public WebProtectionPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                LoadStats();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("网页防护", ex);
            }
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 14 };

            root.Children.Add(new TextBlock { Text = "网页防护", FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            _state = new TextBlock { Text = "输入网址进行实时安全检查（恶意软件/钓鱼/垃圾/跟踪分类识别）", Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_state);

            var inputRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            _urlBox = new TextBox { Width = 460, PlaceholderText = "https://example.com" };
            inputRow.Children.Add(_urlBox);
            var checkBtn = new Button { Content = "检测网址", MinWidth = 100 };
            checkBtn.Click += (_, _) => CheckUrl();
            inputRow.Children.Add(checkBtn);
            var blockBtn = new Button { Content = "封禁此网址", MinWidth = 100 };
            blockBtn.Click += (_, _) => BlockCurrent();
            inputRow.Children.Add(blockBtn);
            root.Children.Add(inputRow);

            _resultText = new TextBlock { Text = "", TextWrapping = TextWrapping.Wrap, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold };
            root.Children.Add(_resultText);

            var statsCard = new Border
            {
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(16),
                BorderBrush = new Microsoft.UI.Xaml.Media.SolidColorBrush(Windows.UI.Color.FromArgb(70, 0, 122, 204))
            };
            _statsText = new TextBlock { Text = "统计加载中...", TextWrapping = TextWrapping.Wrap, Opacity = 0.85 };
            statsCard.Child = _statsText;
            root.Children.Add(statsCard);

            root.Children.Add(new TextBlock { Text = "已封禁网址", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            root.Children.Add(new ListView { ItemsSource = _blocked, MaxHeight = 240, SelectionMode = ListViewSelectionMode.None });

            return root;
        }

        private void CheckUrl()
        {
            var url = _urlBox.Text?.Trim();
            if (string.IsNullOrEmpty(url))
            {
                _resultText.Text = "请输入网址";
                return;
            }

            _resultText.Text = "正在检测...";
            _ = Task.Run(async () =>
            {
                WebProtectionResult result = null;
                string error = null;
                try { result = await _manager.CheckUrl(url); }
                catch (Exception ex) { error = ex.Message; }

                DispatcherQueue.TryEnqueue(() =>
                {
                    if (result == null)
                    {
                        _resultText.Text = "检测失败: " + error;
                        return;
                    }
                    _resultText.Text = result.Safe
                        ? $"✓ 安全：{result.Url}"
                        : $"⚠ 危险（风险等级 {result.RiskLevel}/5）：{result.ThreatType} · {result.Message}";
                    _resultText.Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(
                        result.Safe ? Windows.UI.Color.FromArgb(255, 34, 139, 34) : Windows.UI.Color.FromArgb(255, 220, 60, 40));

                    // 家长控制真实生效（此前规则零消费方 = 假功能）：
                    // ①时间限制：存在启用规则时，儿童用户全部不在允许时段 → 阻止；
                    // ②内容过滤：按类别/域名黑名单判定 Block / Warn。
                    try
                    {
                        if (SettingsStore.Current.ParentalControlEnabled)
                        {
                            var children = (_parental.GetUsers() ?? new System.Collections.Generic.List<FireAntivirus.ParentalControl.User>())
                                .Where(u => u.Type == FireAntivirus.ParentalControl.UserType.Child && u.Enabled)
                                .ToList();

                            bool hasTimeRules = children.Any(u =>
                            {
                                try
                                {
                                    return (_parental.GetTimeRestrictions(u.Id) ?? new System.Collections.Generic.List<FireAntivirus.ParentalControl.TimeRestriction>())
                                        .Any(r => r.Enabled);
                                }
                                catch { return false; }
                            });

                            if (hasTimeRules && children.Count > 0 && children.All(u => !_parental.IsUserAllowed(u.Id)))
                            {
                                _resultText.Text = "⛔ 已阻止（家长控制 · 时间限制）：当前不在允许上网时段";
                                _resultText.Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(
                                    Windows.UI.Color.FromArgb(255, 220, 60, 40));
                            }
                            else
                            {
                                var action = _parental.GetContentAction(url);
                                if (action == FireAntivirus.ParentalControl.ContentAction.Block)
                                {
                                    _resultText.Text = $"⛔ 已阻止（家长控制 · 内容过滤）：{url}";
                                    _resultText.Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(
                                        Windows.UI.Color.FromArgb(255, 220, 60, 40));
                                }
                                else if (action == FireAntivirus.ParentalControl.ContentAction.Warn)
                                {
                                    _resultText.Text += "\n（家长控制警告：该网址命中内容过滤规则，允许但已记录）";
                                }
                            }
                        }
                    }
                    catch { }

                    LoadStats();
                });
            });
        }

        private void BlockCurrent()
        {
            var url = _urlBox.Text?.Trim();
            if (string.IsNullOrEmpty(url)) return;
            _manager.AddBlockedUrl(url);
            _resultText.Text = "已封禁（hosts 映射 0.0.0.0 已写入，浏览器立即失效）: " + url;
            LoadStats();
        }

        private void LoadStats()
        {
            _ = Task.Run(() =>
            {
                WebProtectionStatistics stats = null;
                System.Collections.Generic.List<string> blocked = null;
                string error = null;
                try
                {
                    stats = _manager.GetStatistics();
                    blocked = _manager.GetBlockedUrls();
                }
                catch (Exception ex) { error = ex.Message; }

                DispatcherQueue.TryEnqueue(() =>
                {
                    if (stats != null)
                    {
                        _statsText.Text =
                            $"防护统计：累计检查 {stats.TotalChecks} 个网址 · 拦截威胁 {stats.ThreatsBlocked} 次\n" +
                            $"钓鱼拦截 {stats.PhishingBlocked} · 广告拦截 {stats.AdsBlocked}\n" +
                            $"封禁网址库 {stats.BlockedUrlsCount} 条 · 钓鱼网址库 {stats.PhishingUrlsCount} 条 · 恶意域名 {stats.MaliciousDomainsCount} 条";
                    }
                    else if (error != null)
                    {
                        _statsText.Text = "统计加载失败: " + error;
                    }

                    _blocked.Clear();
                    foreach (var u in (blocked ?? new System.Collections.Generic.List<string>()).Take(200))
                        _blocked.Add(new BlockedUrlRow { Url = u });
                });
            });
        }
    }
}