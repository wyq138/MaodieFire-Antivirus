// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Linq;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;
using SvcStartup = FireAntivirus.Services.StartupManager;

namespace FireAntivirus.Host
{
    public partial class StartupManagerPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;
        private SvcStartup _startupManager;
        private ListView _startupListView;
        private Button _refreshButton;
        private Button _disableButton;
        private Button _enableButton;
        private Button _deleteButton;
        private Button _optimizeButton;
        private Label _statusLabel;
        private ProgressBar _progressBar;

        public StartupManagerPage()
        {
            InitializeComponent();
            InitializeServices();
            UpdateUI();
        }

        private void InitializeServices()
        {
            _startupManager = new SvcStartup();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // StartupManagerPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "StartupManagerPage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
                if (_startupListView != null)
                {
                    _startupListView.BackColor = Color.FromArgb(45, 45, 45);
                    _startupListView.ForeColor = Color.White;
                }
            }
            else
            {
                this.BackColor = Color.White;
                if (_startupListView != null)
                {
                    _startupListView.BackColor = Color.White;
                    _startupListView.ForeColor = Color.Black;
                }
            }
        }

        private void UpdateUI()
        {
            this.Controls.Clear();

            // 标题
            var titleLabel = new Label
            {
                Text = "启动项管理",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 15),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 描述
            var descriptionLabel = new Label
            {
                Text = "管理系统启动项，优化系统启动速度",
                Font = new Font("微软雅黑", 10),
                ForeColor = Color.Gray,
                Location = new Point(20, 45),
                AutoSize = true
            };
            this.Controls.Add(descriptionLabel);

            // 状态标签
            _statusLabel = new Label
            {
                Text = "就绪",
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.FromArgb(100, 100, 100),
                Location = new Point(20, 70),
                AutoSize = true
            };
            this.Controls.Add(_statusLabel);

            // 进度条
            _progressBar = new ProgressBar
            {
                Location = new Point(150, 68),
                Size = new Size(200, 20),
                Style = ProgressBarStyle.Continuous,
                Visible = false
            };
            this.Controls.Add(_progressBar);

            // 启动项列表
            _startupListView = new ListView
            {
                Location = new Point(20, 100),
                Size = new Size(660, 380),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                Font = new Font("微软雅黑", 9)
            };
            _startupListView.Columns.Add("名称", 180);
            _startupListView.Columns.Add("路径", 250);
            _startupListView.Columns.Add("类型", 80);
            _startupListView.Columns.Add("状态", 60);
            _startupListView.Columns.Add("用户", 90);
            this.Controls.Add(_startupListView);

            // 按钮面板
            var buttonPanel = new Panel
            {
                Location = new Point(20, 490),
                Size = new Size(660, 50),
                BackColor = Color.Transparent
            };
            this.Controls.Add(buttonPanel);

            // 刷新按钮
            _refreshButton = new Button
            {
                Text = "刷新列表",
                Location = new Point(0, 10),
                Size = new Size(100, 32),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            _refreshButton.FlatAppearance.BorderSize = 0;
            _refreshButton.Click += RefreshButton_Click;
            buttonPanel.Controls.Add(_refreshButton);

            // 禁用按钮
            _disableButton = new Button
            {
                Text = "禁用",
                Location = new Point(110, 10),
                Size = new Size(80, 32),
                BackColor = Color.FromArgb(255, 152, 0),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            _disableButton.FlatAppearance.BorderSize = 0;
            _disableButton.Click += DisableButton_Click;
            buttonPanel.Controls.Add(_disableButton);

            // 启用按钮
            _enableButton = new Button
            {
                Text = "启用",
                Location = new Point(200, 10),
                Size = new Size(80, 32),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            _enableButton.FlatAppearance.BorderSize = 0;
            _enableButton.Click += EnableButton_Click;
            buttonPanel.Controls.Add(_enableButton);

            // 删除按钮
            _deleteButton = new Button
            {
                Text = "删除",
                Location = new Point(290, 10),
                Size = new Size(80, 32),
                BackColor = Color.FromArgb(244, 67, 54),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            _deleteButton.FlatAppearance.BorderSize = 0;
            _deleteButton.Click += DeleteButton_Click;
            buttonPanel.Controls.Add(_deleteButton);

            // 优化启动按钮
            _optimizeButton = new Button
            {
                Text = "智能优化启动",
                Location = new Point(500, 10),
                Size = new Size(120, 32),
                BackColor = Color.FromArgb(156, 39, 176),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            _optimizeButton.FlatAppearance.BorderSize = 0;
            _optimizeButton.Click += OptimizeButton_Click;
            buttonPanel.Controls.Add(_optimizeButton);

            // 统计信息
            var statsPanel = new Panel
            {
                Location = new Point(20, 545),
                Size = new Size(660, 30),
                BackColor = Color.Transparent
            };
            this.Controls.Add(statsPanel);

            var statsLabel = new Label
            {
                Name = "statsLabel",
                Text = "加载中...",
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.Gray,
                Location = new Point(0, 5),
                AutoSize = true
            };
            statsPanel.Controls.Add(statsLabel);

            // 自动加载启动项
            LoadStartupItems();
        }

        private void LoadStartupItems()
        {
            _statusLabel.Text = "正在扫描启动项...";
            _progressBar.Visible = true;
            _progressBar.Style = ProgressBarStyle.Marquee;
            _startupListView.Items.Clear();

            try
            {
                var items = _startupManager.GetStartupItems();
                
                foreach (var item in items)
                {
                    var listViewItem = new ListViewItem(item.Name);
                    listViewItem.SubItems.Add(TruncatePath(item.Path, 50));
                    listViewItem.SubItems.Add(item.Type.ToString());
                    listViewItem.SubItems.Add(item.Enabled ? "启用" : "禁用");
                    listViewItem.SubItems.Add(item.User ?? "System");
                    listViewItem.Tag = item;
                    listViewItem.ForeColor = item.Enabled ? Color.Black : Color.Gray;

                    // 无效项标红
                    if (!item.IsValid || !item.FileExists)
                    {
                        listViewItem.ForeColor = Color.FromArgb(244, 67, 54);
                    }

                    _startupListView.Items.Add(listViewItem);
                }

                // 更新统计信息
                var statsLabel = this.Controls.Find("statsLabel", true).FirstOrDefault() as Label;
                if (statsLabel != null)
                {
                    int enabled = items.Count(i => i.Enabled);
                    int disabled = items.Count(i => !i.Enabled);
                    int suspicious = items.Count(i => !i.IsValid || !i.FileExists);
                    statsLabel.Text = $"共 {items.Count} 个启动项 | 启用: {enabled} | 禁用: {disabled} | 可疑: {suspicious}";
                }

                _statusLabel.Text = $"扫描完成，共发现 {items.Count} 个启动项";
            }
            catch (Exception ex)
            {
                _statusLabel.Text = $"扫描失败: {ex.Message}";
                MessageBox.Show($"扫描启动项失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                _progressBar.Visible = false;
            }
        }

        private string TruncatePath(string path, int maxLength)
        {
            if (string.IsNullOrEmpty(path)) return "";
            if (path.Length <= maxLength) return path;
            return "..." + path.Substring(path.Length - maxLength + 3);
        }

        private void RefreshButton_Click(object sender, EventArgs e)
        {
            LoadStartupItems();
        }

        private void DisableButton_Click(object sender, EventArgs e)
        {
            if (_startupListView.SelectedItems.Count == 0)
            {
                MessageBox.Show("请先选择要禁用的启动项", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var result = MessageBox.Show("确定要禁用选中的启动项吗？", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (result != DialogResult.Yes) return;

            int success = 0, failed = 0;
            foreach (ListViewItem item in _startupListView.SelectedItems)
            {
                var startupItem = item.Tag as StartupItem;
                if (startupItem != null)
                {
                    if (_startupManager.DisableStartupItem(startupItem))
                        success++;
                    else
                        failed++;
                }
            }

            MessageBox.Show($"禁用完成\n成功: {success}\n失败: {failed}", "结果", MessageBoxButtons.OK, MessageBoxIcon.Information);
            LoadStartupItems();
        }

        private void EnableButton_Click(object sender, EventArgs e)
        {
            if (_startupListView.SelectedItems.Count == 0)
            {
                MessageBox.Show("请先选择要启用的启动项", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            int success = 0, failed = 0;
            foreach (ListViewItem item in _startupListView.SelectedItems)
            {
                var startupItem = item.Tag as StartupItem;
                if (startupItem != null)
                {
                    if (_startupManager.EnableStartupItem(startupItem))
                        success++;
                    else
                        failed++;
                }
            }

            MessageBox.Show($"启用完成\n成功: {success}\n失败: {failed}", "结果", MessageBoxButtons.OK, MessageBoxIcon.Information);
            LoadStartupItems();
        }

        private void DeleteButton_Click(object sender, EventArgs e)
        {
            if (_startupListView.SelectedItems.Count == 0)
            {
                MessageBox.Show("请先选择要删除的启动项", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var result = MessageBox.Show("确定要删除选中的启动项吗？此操作不可恢复！", "警告", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result != DialogResult.Yes) return;

            int success = 0, failed = 0;
            foreach (ListViewItem item in _startupListView.SelectedItems)
            {
                var startupItem = item.Tag as StartupItem;
                if (startupItem != null)
                {
                    if (_startupManager.DeleteStartupItem(startupItem))
                        success++;
                    else
                        failed++;
                }
            }

            MessageBox.Show($"删除完成\n成功: {success}\n失败: {failed}", "结果", MessageBoxButtons.OK, MessageBoxIcon.Information);
            LoadStartupItems();
        }

        private void OptimizeButton_Click(object sender, EventArgs e)
        {
            var result = MessageBox.Show(
                "智能优化将自动禁用以下类型的启动项：\n\n" +
                "• 无效的启动项（文件不存在）\n" +
                "• 可疑的启动项\n\n" +
                "是否继续？",
                "智能优化",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result != DialogResult.Yes) return;

            _statusLabel.Text = "正在优化启动项...";
            _progressBar.Visible = true;

            try
            {
                var suspiciousItems = _startupManager.GetSuspiciousStartupItems();
                int optimized = 0;

                foreach (var item in suspiciousItems)
                {
                    if (_startupManager.DisableStartupItem(item))
                        optimized++;
                }

                MessageBox.Show(
                    $"优化完成！\n\n" +
                    $"共发现 {suspiciousItems.Count} 个可疑启动项\n" +
                    $"成功禁用 {optimized} 个\n\n" +
                    "建议重启计算机以使更改生效。",
                    "优化结果",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);

                _statusLabel.Text = $"优化完成，已禁用 {optimized} 个可疑启动项";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"优化失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                _statusLabel.Text = "优化失败";
            }
            finally
            {
                _progressBar.Visible = false;
                LoadStartupItems();
            }
        }
    }
}
