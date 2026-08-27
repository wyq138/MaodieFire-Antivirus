// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using System.Diagnostics;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;

namespace FireAntivirus.Host
{
    public partial class SecureBrowserPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;
        private SecureBrowserService _browserService;
        private TextBox _urlTextBox;
        private WebBrowser _webBrowser;
        private Label _statusLabel;
        private Panel _navigationBar;
        private ProgressBar _loadingProgress;

        public SecureBrowserPage()
        {
            InitializeComponent();
            InitializeService();
            UpdateUI();
        }

        private void InitializeService()
        {
            _browserService = new SecureBrowserService();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // SecureBrowserPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "SecureBrowserPage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
                if (_navigationBar != null)
                    _navigationBar.BackColor = Color.FromArgb(45, 45, 45);
                if (_urlTextBox != null)
                {
                    _urlTextBox.BackColor = Color.FromArgb(60, 60, 60);
                    _urlTextBox.ForeColor = Color.White;
                }
            }
            else
            {
                this.BackColor = Color.White;
                if (_navigationBar != null)
                    _navigationBar.BackColor = Color.FromArgb(240, 240, 240);
                if (_urlTextBox != null)
                {
                    _urlTextBox.BackColor = Color.White;
                    _urlTextBox.ForeColor = Color.Black;
                }
            }
        }

        private void UpdateUI()
        {
            this.Controls.Clear();

            // 标题栏
            var titlePanel = new Panel
            {
                Location = new Point(0, 0),
                Size = new Size(700, 45),
                BackColor = Color.FromArgb(25, 118, 210)
            };
            this.Controls.Add(titlePanel);

            var titleLabel = new Label
            {
                Text = "安全浏览器",
                Font = new Font("微软雅黑", 14, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(15, 10),
                AutoSize = true
            };
            titlePanel.Controls.Add(titleLabel);

            // 导航栏
            _navigationBar = new Panel
            {
                Location = new Point(0, 45),
                Size = new Size(700, 45),
                BackColor = Color.FromArgb(240, 240, 240)
            };
            this.Controls.Add(_navigationBar);

            // 后退按钮
            var backButton = new Button
            {
                Text = "←",
                Location = new Point(5, 8),
                Size = new Size(30, 30),
                Font = new Font("Arial", 12),
                BackColor = Color.Transparent,
                FlatStyle = FlatStyle.Flat
            };
            backButton.FlatAppearance.BorderSize = 0;
            backButton.Click += (s, e) => { if (_webBrowser?.CanGoBack == true) _webBrowser.GoBack(); };
            _navigationBar.Controls.Add(backButton);

            // 前进按钮
            var forwardButton = new Button
            {
                Text = "→",
                Location = new Point(35, 8),
                Size = new Size(30, 30),
                Font = new Font("Arial", 12),
                BackColor = Color.Transparent,
                FlatStyle = FlatStyle.Flat
            };
            forwardButton.FlatAppearance.BorderSize = 0;
            forwardButton.Click += (s, e) => { if (_webBrowser?.CanGoForward == true) _webBrowser.GoForward(); };
            _navigationBar.Controls.Add(forwardButton);

            // 刷新按钮
            var refreshButton = new Button
            {
                Text = "⟳",
                Location = new Point(65, 8),
                Size = new Size(30, 30),
                Font = new Font("Arial", 12),
                BackColor = Color.Transparent,
                FlatStyle = FlatStyle.Flat
            };
            refreshButton.FlatAppearance.BorderSize = 0;
            refreshButton.Click += (s, e) => _webBrowser?.Refresh();
            _navigationBar.Controls.Add(refreshButton);

            // URL输入框
            _urlTextBox = new TextBox
            {
                Location = new Point(100, 10),
                Size = new Size(480, 25),
                Font = new Font("微软雅黑", 10)
            };
            _urlTextBox.KeyDown += UrlTextBox_KeyDown;
            _navigationBar.Controls.Add(_urlTextBox);

            // 访问按钮
            var goButton = new Button
            {
                Text = "访问",
                Location = new Point(585, 8),
                Size = new Size(55, 28),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            goButton.FlatAppearance.BorderSize = 0;
            goButton.Click += (s, e) => NavigateToUrl();
            _navigationBar.Controls.Add(goButton);

            // 安全检查按钮
            var checkButton = new Button
            {
                Text = "安全检查",
                Location = new Point(645, 8),
                Size = new Size(50, 28),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 8)
            };
            checkButton.FlatAppearance.BorderSize = 0;
            checkButton.Click += CheckCurrentUrl;
            _navigationBar.Controls.Add(checkButton);

            // 加载进度条
            _loadingProgress = new ProgressBar
            {
                Location = new Point(0, 88),
                Size = new Size(700, 5),
                Style = ProgressBarStyle.Continuous,
                Visible = false
            };
            this.Controls.Add(_loadingProgress);

            // 状态栏
            _statusLabel = new Label
            {
                Text = "就绪",
                Font = new Font("微软雅黑", 8),
                ForeColor = Color.Gray,
                Location = new Point(5, 92),
                AutoSize = true
            };
            this.Controls.Add(_statusLabel);

            // 浏览器控件
            _webBrowser = new WebBrowser
            {
                Location = new Point(0, 110),
                Size = new Size(700, 420),
                ScriptErrorsSuppressed = true,
                WebBrowserShortcutsEnabled = true
            };
            _webBrowser.Navigating += WebBrowser_Navigating;
            _webBrowser.Navigated += WebBrowser_Navigated;
            _webBrowser.DocumentCompleted += WebBrowser_DocumentCompleted;
            _webBrowser.NewWindow += WebBrowser_NewWindow;
            this.Controls.Add(_webBrowser);

            // 底部工具栏
            var bottomPanel = new Panel
            {
                Location = new Point(0, 530),
                Size = new Size(700, 50),
                BackColor = Color.FromArgb(240, 240, 240)
            };
            this.Controls.Add(bottomPanel);

            // 设置按钮
            var settingsButton = new Button
            {
                Text = "安全设置",
                Location = new Point(10, 10),
                Size = new Size(90, 30),
                BackColor = Color.FromArgb(156, 39, 176),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            settingsButton.FlatAppearance.BorderSize = 0;
            settingsButton.Click += SettingsButton_Click;
            bottomPanel.Controls.Add(settingsButton);

            // 黑名单按钮
            var blacklistButton = new Button
            {
                Text = "网站黑名单",
                Location = new Point(110, 10),
                Size = new Size(90, 30),
                BackColor = Color.FromArgb(244, 67, 54),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            blacklistButton.FlatAppearance.BorderSize = 0;
            blacklistButton.Click += BlacklistButton_Click;
            bottomPanel.Controls.Add(blacklistButton);

            // 清除缓存按钮
            var clearCacheButton = new Button
            {
                Text = "清除缓存",
                Location = new Point(210, 10),
                Size = new Size(90, 30),
                BackColor = Color.FromArgb(255, 152, 0),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            clearCacheButton.FlatAppearance.BorderSize = 0;
            clearCacheButton.Click += (s, e) =>
            {
                _browserService.ClearBrowserCache();
                MessageBox.Show("浏览器缓存已清除", "完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            bottomPanel.Controls.Add(clearCacheButton);

            // 打开外部浏览器
            var externalButton = new Button
            {
                Text = "外部浏览器",
                Location = new Point(310, 10),
                Size = new Size(90, 30),
                BackColor = Color.FromArgb(0, 150, 136),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            externalButton.FlatAppearance.BorderSize = 0;
            externalButton.Click += (s, e) =>
            {
                var url = _urlTextBox.Text.Trim();
                if (!string.IsNullOrEmpty(url))
                {
                    if (!url.StartsWith("http")) url = "https://" + url;
                    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                }
            };
            bottomPanel.Controls.Add(externalButton);

            // 主页按钮
            var homeButton = new Button
            {
                Text = "主页",
                Location = new Point(410, 10),
                Size = new Size(70, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            homeButton.FlatAppearance.BorderSize = 0;
            homeButton.Click += (s, e) =>
            {
                _urlTextBox.Text = "https://www.baidu.com";
                NavigateToUrl();
            };
            bottomPanel.Controls.Add(homeButton);

            // 安全提示
            var safeTipLabel = new Label
            {
                Text = "🔒 安全浏览模式已启用",
                Font = new Font("微软雅黑", 8),
                ForeColor = Color.Green,
                Location = new Point(520, 18),
                AutoSize = true
            };
            bottomPanel.Controls.Add(safeTipLabel);
        }

        private void UrlTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                NavigateToUrl();
                e.Handled = true;
            }
        }

        private void NavigateToUrl()
        {
            var url = _urlTextBox.Text.Trim();
            if (string.IsNullOrEmpty(url))
                return;

            // 检查URL安全性
            var checkResult = _browserService.CheckUrl(url);
            
            if (!checkResult.IsSafe)
            {
                var result = MessageBox.Show(
                    $"⚠️ 安全警告\n\n" +
                    $"该网站可能存在以下风险：\n" +
                    string.Join("\n", checkResult.Threats) + "\n\n" +
                    $"风险等级: {checkResult.RiskLevel}/5\n\n" +
                    $"是否仍要访问？",
                    "安全警告",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (result != DialogResult.Yes)
                    return;
            }
            else if (checkResult.Warnings.Count > 0)
            {
                _statusLabel.Text = $"⚠️ {string.Join(", ", checkResult.Warnings)}";
                _statusLabel.ForeColor = Color.Orange;
            }

            // 添加协议
            if (!url.StartsWith("http://") && !url.StartsWith("https://"))
            {
                url = "https://" + url;
                _urlTextBox.Text = url;
            }

            try
            {
                _loadingProgress.Visible = true;
                _loadingProgress.Value = 0;
                _statusLabel.Text = "正在加载...";
                _webBrowser.Navigate(url);
            }
            catch (Exception ex)
            {
                _statusLabel.Text = $"导航失败: {ex.Message}";
                _loadingProgress.Visible = false;
            }
        }

        private void WebBrowser_Navigating(object sender, WebBrowserNavigatingEventArgs e)
        {
            // 检查目标URL
            var url = e.Url.ToString();
            if (!_browserService.IsUrlSafe(url))
            {
                var result = MessageBox.Show(
                    $"⚠️ 安全警告\n\n" +
                    $"目标链接可能不安全：\n{url}\n\n" +
                    $"是否继续访问？",
                    "安全警告",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (result != DialogResult.Yes)
                {
                    e.Cancel = true;
                    return;
                }
            }

            _loadingProgress.Visible = true;
            _statusLabel.Text = $"正在导航到: {e.Url.Host}";
        }

        private void WebBrowser_Navigated(object sender, WebBrowserNavigatedEventArgs e)
        {
            _urlTextBox.Text = e.Url.ToString();
            _loadingProgress.Value = 50;
        }

        private void WebBrowser_DocumentCompleted(object sender, WebBrowserDocumentCompletedEventArgs e)
        {
            _loadingProgress.Visible = false;
            _statusLabel.Text = $"完成 - {e.Url.Host}";
            
            // 检查是否为安全连接
            if (e.Url.Scheme == "https")
            {
                _statusLabel.ForeColor = Color.Green;
                _statusLabel.Text = "🔒 安全连接 - " + e.Url.Host;
            }
            else
            {
                _statusLabel.ForeColor = Color.Orange;
                _statusLabel.Text = "⚠️ 非安全连接 - " + e.Url.Host;
            }
        }

        private void WebBrowser_NewWindow(object sender, CancelEventArgs e)
        {
            // 阻止弹窗
            e.Cancel = true;
            _statusLabel.Text = "已拦截弹窗";
        }

        private void CheckCurrentUrl(object sender, EventArgs e)
        {
            var url = _urlTextBox.Text.Trim();
            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show("请先输入URL地址", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var result = _browserService.CheckUrl(url);

            var message = $"URL安全检查报告\n\n" +
                          $"URL: {result.Url}\n" +
                          $"域名: {result.Domain}\n" +
                          $"协议: {result.Protocol}\n" +
                          $"安全评分: {result.SafeScore}/100\n" +
                          $"风险等级: {result.RiskLevel}/5\n" +
                          $"状态: {(result.IsSafe ? "✅ 安全" : "❌ 不安全")}\n";

            if (result.Warnings.Count > 0)
            {
                message += "\n⚠️ 警告:\n";
                foreach (var warning in result.Warnings)
                    message += $"  • {warning}\n";
            }

            if (result.Threats.Count > 0)
            {
                message += "\n🚨 威胁:\n";
                foreach (var threat in result.Threats)
                    message += $"  • {threat}\n";
            }

            MessageBox.Show(message, "安全检查结果", MessageBoxButtons.OK, 
                result.IsSafe ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private void SettingsButton_Click(object sender, EventArgs e)
        {
            var settingsForm = new Form
            {
                Text = "浏览器安全设置",
                Size = new Size(400, 350),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var settings = _browserService.GetBrowserSettings();

            var popupCheck = new CheckBox
            {
                Text = "启用弹窗拦截",
                Location = new Point(20, 20),
                Checked = settings.PopupBlockerEnabled,
                Size = new Size(200, 25)
            };
            settingsForm.Controls.Add(popupCheck);

            var proxyCheck = new CheckBox
            {
                Text = "启用代理服务器",
                Location = new Point(20, 50),
                Checked = settings.ProxyEnabled,
                Size = new Size(200, 25)
            };
            settingsForm.Controls.Add(proxyCheck);

            var proxyLabel = new Label
            {
                Text = "代理服务器地址:",
                Location = new Point(40, 80),
                AutoSize = true
            };
            settingsForm.Controls.Add(proxyLabel);

            var proxyTextBox = new TextBox
            {
                Location = new Point(40, 100),
                Size = new Size(300, 25),
                Text = settings.ProxyServer ?? "",
                Enabled = settings.ProxyEnabled
            };
            settingsForm.Controls.Add(proxyTextBox);

            proxyCheck.CheckedChanged += (s, args) => proxyTextBox.Enabled = proxyCheck.Checked;

            var privacyLabel = new Label
            {
                Text = "隐私级别:",
                Location = new Point(20, 140),
                AutoSize = true
            };
            settingsForm.Controls.Add(privacyLabel);

            var privacyTrack = new TrackBar
            {
                Location = new Point(20, 160),
                Size = new Size(300, 45),
                Minimum = 0,
                Maximum = 3,
                Value = settings.PrivacyLevel,
                TickFrequency = 1
            };
            settingsForm.Controls.Add(privacyTrack);

            var privacyDescLabel = new Label
            {
                Location = new Point(20, 200),
                AutoSize = true
            };
            UpdatePrivacyLabel(privacyDescLabel, privacyTrack.Value);
            privacyTrack.Scroll += (s, args) => UpdatePrivacyLabel(privacyDescLabel, privacyTrack.Value);
            settingsForm.Controls.Add(privacyDescLabel);

            var saveButton = new Button
            {
                Text = "保存设置",
                Location = new Point(100, 250),
                Size = new Size(100, 35),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            saveButton.FlatAppearance.BorderSize = 0;
            saveButton.Click += (s, args) =>
            {
                settings.PopupBlockerEnabled = popupCheck.Checked;
                settings.ProxyEnabled = proxyCheck.Checked;
                settings.ProxyServer = proxyTextBox.Text;
                settings.PrivacyLevel = privacyTrack.Value;
                _browserService.ApplyBrowserSettings(settings);
                MessageBox.Show("设置已保存", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                settingsForm.Close();
            };
            settingsForm.Controls.Add(saveButton);

            var cancelButton = new Button
            {
                Text = "取消",
                Location = new Point(210, 250),
                Size = new Size(100, 35),
                DialogResult = DialogResult.Cancel
            };
            settingsForm.Controls.Add(cancelButton);

            settingsForm.ShowDialog();
        }

        private void UpdatePrivacyLabel(Label label, int value)
        {
            var descriptions = new[] { "接受所有Cookie", "中等级别", "阻止第三方Cookie", "阻止所有Cookie" };
            label.Text = $"当前: {descriptions[value]}";
        }

        private void BlacklistButton_Click(object sender, EventArgs e)
        {
            var blacklistForm = new Form
            {
                Text = "网站黑名单管理",
                Size = new Size(450, 400),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.Sizable
            };

            var listBox = new ListBox
            {
                Location = new Point(20, 20),
                Size = new Size(400, 250)
            };

            foreach (var domain in _browserService.GetBlacklistedDomains())
                listBox.Items.Add(domain);

            blacklistForm.Controls.Add(listBox);

            var addTextBox = new TextBox
            {
                Location = new Point(20, 280),
                Size = new Size(300, 25),
                PlaceholderText = "输入要屏蔽的域名"
            };
            blacklistForm.Controls.Add(addTextBox);

            var addButton = new Button
            {
                Text = "添加",
                Location = new Point(330, 278),
                Size = new Size(90, 28),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            addButton.FlatAppearance.BorderSize = 0;
            addButton.Click += (s, args) =>
            {
                var domain = addTextBox.Text.Trim();
                if (!string.IsNullOrEmpty(domain))
                {
                    _browserService.AddToBlacklist(domain);
                    listBox.Items.Add(domain);
                    addTextBox.Clear();
                }
            };
            blacklistForm.Controls.Add(addButton);

            var removeButton = new Button
            {
                Text = "移除选中",
                Location = new Point(20, 320),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(244, 67, 54),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            removeButton.FlatAppearance.BorderSize = 0;
            removeButton.Click += (s, args) =>
            {
                if (listBox.SelectedIndex >= 0)
                {
                    var domain = listBox.SelectedItem.ToString();
                    _browserService.RemoveFromBlacklist(domain);
                    listBox.Items.RemoveAt(listBox.SelectedIndex);
                }
            };
            blacklistForm.Controls.Add(removeButton);

            var blockHostsButton = new Button
            {
                Text = "系统级屏蔽",
                Location = new Point(130, 320),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(255, 152, 0),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            blockHostsButton.FlatAppearance.BorderSize = 0;
            blockHostsButton.Click += (s, args) =>
            {
                if (listBox.SelectedIndex >= 0)
                {
                    var domain = listBox.SelectedItem.ToString();
                    _browserService.AddToHostsFile(domain);
                    MessageBox.Show($"已将 {domain} 添加到系统Hosts文件\n该域名将被完全屏蔽", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };
            blacklistForm.Controls.Add(blockHostsButton);

            blacklistForm.ShowDialog();
        }
    }
}
