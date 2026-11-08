// 邮件安全页（搬运自 WPF EmailSecurityPage，WinUI 真实实现）：
// EmailSecurityManager.CheckEmail 真实邮件安全检测（发件人信誉/钓鱼主题/恶意链接/附件风险），
// 展示检查结果与已知垃圾发件人/恶意域名/可疑主题库。
// 加固：Manager（含 AntivirusEngine 重构造）改为惰性 + 后台创建——页面构造绝不因引擎异常而失败。
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.EmailSecurity;
using FireAntivirus.Engine;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class EmailRuleRow
    {
        public string Category { get; set; }
        public string Value { get; set; }
    }

    public sealed partial class EmailSecurityPage : Page
    {
        // 惰性创建：AntivirusEngine 构造（签名库/分析器）放在后台线程首次使用时，
        // 此前在页面构造里同步创建，任何异常都会让整个聚合页显示"加载失败"。
        private readonly Lazy<EmailSecurityManager> _lazyMgr = new(() =>
        {
            var dm = DataManager.SharedInstance;
            return new EmailSecurityManager(dm, new AntivirusEngine(dm));
        }, isThreadSafe: true);
        private EmailSecurityManager Mgr => _lazyMgr.Value;

        private readonly ObservableCollection<EmailRuleRow> _rules = new();

        private TextBox _senderBox;
        private TextBox _subjectBox;
        private TextBox _bodyBox;
        private TextBox _attachBox;
        private TextBlock _resultText;
        private TextBlock _state;

        public EmailSecurityPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                Content = BuildLayout();
                LoadRules();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("邮件安全", ex);
            }
        }

        private UIElement BuildLayout()
        {
            var root = new StackPanel { Margin = new Thickness(28, 10, 28, 24), Spacing = 12 };
            root.Children.Add(new TextBlock { Text = "邮件安全", FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            _state = new TextBlock { Text = "邮件内容安全检测：发件人信誉 / 钓鱼主题 / 恶意链接 / 附件风险", Opacity = 0.7, TextWrapping = TextWrapping.Wrap };
            root.Children.Add(_state);

            _senderBox = new TextBox { Header = "发件人", PlaceholderText = "sender@example.com", Width = 460, HorizontalAlignment = HorizontalAlignment.Left };
            root.Children.Add(_senderBox);
            _subjectBox = new TextBox { Header = "主题", PlaceholderText = "邮件主题", Width = 460, HorizontalAlignment = HorizontalAlignment.Left };
            root.Children.Add(_subjectBox);
            _bodyBox = new TextBox { Header = "正文", PlaceholderText = "粘贴邮件正文（可留空）", Width = 460, Height = 100, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, HorizontalAlignment = HorizontalAlignment.Left };
            root.Children.Add(_bodyBox);
            _attachBox = new TextBox { Header = "附件路径（多个用 ; 分隔）", PlaceholderText = @"C:\mail\附件.exe;D:\doc.pdf", Width = 460, HorizontalAlignment = HorizontalAlignment.Left };
            root.Children.Add(_attachBox);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            var checkBtn = new Button { Content = "检测邮件", MinWidth = 110 };
            checkBtn.Click += (_, _) => CheckEmail();
            btnRow.Children.Add(checkBtn);
            var refreshBtn = new Button { Content = "刷新规则库", MinWidth = 100 };
            refreshBtn.Click += (_, _) => LoadRules();
            btnRow.Children.Add(refreshBtn);
            root.Children.Add(btnRow);

            _resultText = new TextBlock { Text = "", TextWrapping = TextWrapping.Wrap, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold };
            root.Children.Add(_resultText);

            root.Children.Add(new TextBlock { Text = "已知风险库（垃圾发件人 / 恶意域名 / 可疑主题）", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            root.Children.Add(new ListView { ItemsSource = _rules, MaxHeight = 260, SelectionMode = ListViewSelectionMode.None });

            return root;
        }

        private void CheckEmail()
        {
            var sender = _senderBox.Text?.Trim() ?? "";
            var subject = _subjectBox.Text?.Trim() ?? "";
            var body = _bodyBox.Text ?? "";
            var attachments = (_attachBox.Text ?? "")
                .Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .Where(s => s.Length > 0)
                .ToList();

            if (string.IsNullOrEmpty(sender) && string.IsNullOrEmpty(subject))
            {
                _resultText.Text = "请至少填写发件人或主题";
                return;
            }

            _resultText.Text = "正在检测...";
            _ = Task.Run(() =>
            {
                EmailSecurityResult result = null;
                string error = null;
                try { result = Mgr.CheckEmail(sender, subject, body, attachments); }
                catch (Exception ex) { error = ex.Message; }

                DispatcherQueue.TryEnqueue(() =>
                {
                    if (result == null)
                    {
                        _resultText.Text = "检测失败: " + error;
                        return;
                    }
                    _resultText.Text = result.Safe
                        ? $"✓ 邮件安全：{result.Sender} · {result.Subject}"
                        : $"⚠ 发现风险：{result.ThreatType}\n{result.Message}";
                    _resultText.Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(
                        result.Safe ? Windows.UI.Color.FromArgb(255, 34, 139, 34) : Windows.UI.Color.FromArgb(255, 220, 60, 40));
                });
            });
        }

        private void LoadRules()
        {
            _ = Task.Run(() =>
            {
                System.Collections.Generic.List<string> spammers = null, domains = null, subjects = null;
                string error = null;
                try
                {
                    spammers = Mgr.GetSpamSenders();
                    domains = Mgr.GetMaliciousDomains();
                    subjects = Mgr.GetSuspiciousSubjects();
                }
                catch (Exception ex) { error = ex.Message; }

                DispatcherQueue.TryEnqueue(() =>
                {
                    if (error != null) { _state.Text = "规则库读取失败: " + error; return; }

                    _rules.Clear();
                    foreach (var s in (spammers ?? new System.Collections.Generic.List<string>()).Take(80))
                        _rules.Add(new EmailRuleRow { Category = "垃圾发件人", Value = s });
                    foreach (var d in (domains ?? new System.Collections.Generic.List<string>()).Take(80))
                        _rules.Add(new EmailRuleRow { Category = "恶意域名", Value = d });
                    foreach (var t in (subjects ?? new System.Collections.Generic.List<string>()).Take(80))
                        _rules.Add(new EmailRuleRow { Category = "可疑主题", Value = t });

                    _state.Text = $"规则库已加载 · {_rules.Count} 条（发件人/域名/主题）";
                });
            });
        }
    }
}