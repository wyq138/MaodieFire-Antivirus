// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Linq;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;
using Microsoft.Win32;
using WinSaveFileDialog = System.Windows.Forms.SaveFileDialog;

namespace FireAntivirus.Host
{
    public partial class SecurityScorePage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;
        private SecurityScoreService _scoreService;
        private SecurityScoreResult _currentResult;
        private ProgressBar _scoreProgressBar;
        private Label _scoreLabel;
        private Label _gradeLabel;
        private ListView _categoryListView;
        private ListBox _recommendationsListBox;
        private Label _statusLabel;

        public SecurityScorePage()
        {
            InitializeComponent();
            InitializeService();
            UpdateUI();
        }

        private void InitializeService()
        {
            _scoreService = new SecurityScoreService();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // SecurityScorePage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "SecurityScorePage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
                if (_categoryListView != null)
                {
                    _categoryListView.BackColor = Color.FromArgb(45, 45, 45);
                    _categoryListView.ForeColor = Color.White;
                }
                if (_recommendationsListBox != null)
                {
                    _recommendationsListBox.BackColor = Color.FromArgb(45, 45, 45);
                    _recommendationsListBox.ForeColor = Color.White;
                }
            }
            else
            {
                this.BackColor = Color.White;
                if (_categoryListView != null)
                {
                    _categoryListView.BackColor = Color.White;
                    _categoryListView.ForeColor = Color.Black;
                }
                if (_recommendationsListBox != null)
                {
                    _recommendationsListBox.BackColor = Color.White;
                    _recommendationsListBox.ForeColor = Color.Black;
                }
            }
        }

        private void UpdateUI()
        {
            this.Controls.Clear();

            // 标题
            var titleLabel = new Label
            {
                Text = "安全评分",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 15),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 描述
            var descriptionLabel = new Label
            {
                Text = "综合评估系统安全状态，提供优化建议",
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

            // 分数面板
            var scorePanel = new Panel
            {
                Location = new Point(20, 95),
                Size = new Size(660, 100),
                BackColor = Color.FromArgb(240, 240, 240)
            };
            this.Controls.Add(scorePanel);

            // 分数进度条
            _scoreProgressBar = new ProgressBar
            {
                Location = new Point(30, 25),
                Size = new Size(500, 25),
                Maximum = 100,
                Value = 0,
                Style = ProgressBarStyle.Continuous
            };
            scorePanel.Controls.Add(_scoreProgressBar);

            // 分数标签
            _scoreLabel = new Label
            {
                Text = "计算中...",
                Font = new Font("微软雅黑", 12, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(540, 25),
                AutoSize = true
            };
            scorePanel.Controls.Add(_scoreLabel);

            // 等级标签
            _gradeLabel = new Label
            {
                Text = "",
                Font = new Font("微软雅黑", 11),
                ForeColor = Color.Gray,
                Location = new Point(30, 60),
                AutoSize = true
            };
            scorePanel.Controls.Add(_gradeLabel);

            // 重新评估按钮
            var analyzeButton = new Button
            {
                Text = "重新评估",
                Location = new Point(540, 55),
                Size = new Size(90, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            analyzeButton.FlatAppearance.BorderSize = 0;
            analyzeButton.Click += AnalyzeButton_Click;
            scorePanel.Controls.Add(analyzeButton);

            // 分类详情列表
            var categoryLabel = new Label
            {
                Text = "详细评分",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(60, 60, 60),
                Location = new Point(20, 205),
                AutoSize = true
            };
            this.Controls.Add(categoryLabel);

            _categoryListView = new ListView
            {
                Location = new Point(20, 230),
                Size = new Size(320, 220),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                Font = new Font("微软雅黑", 9)
            };
            _categoryListView.Columns.Add("项目", 100);
            _categoryListView.Columns.Add("分数", 60);
            _categoryListView.Columns.Add("状态", 80);
            _categoryListView.Columns.Add("详情", 70);
            _categoryListView.DoubleClick += CategoryListView_DoubleClick;
            this.Controls.Add(_categoryListView);

            // 建议列表
            var recommendLabel = new Label
            {
                Text = "优化建议",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(60, 60, 60),
                Location = new Point(360, 205),
                AutoSize = true
            };
            this.Controls.Add(recommendLabel);

            _recommendationsListBox = new ListBox
            {
                Location = new Point(360, 230),
                Size = new Size(320, 220),
                Font = new Font("微软雅黑", 9),
                ScrollAlwaysVisible = true
            };
            this.Controls.Add(_recommendationsListBox);

            // 一键修复按钮
            var fixAllButton = new Button
            {
                Text = "一键优化",
                Location = new Point(260, 465),
                Size = new Size(120, 35),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 10)
            };
            fixAllButton.FlatAppearance.BorderSize = 0;
            fixAllButton.Click += FixAllButton_Click;
            this.Controls.Add(fixAllButton);

            // 导出报告按钮
            var exportButton = new Button
            {
                Text = "导出报告",
                Location = new Point(400, 465),
                Size = new Size(100, 35),
                BackColor = Color.FromArgb(156, 39, 176),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            exportButton.FlatAppearance.BorderSize = 0;
            exportButton.Click += ExportButton_Click;
            this.Controls.Add(exportButton);

            // 自动计算
            CalculateScore();
        }

        private void CalculateScore()
        {
            _statusLabel.Text = "正在评估系统安全状态...";
            _scoreLabel.Text = "计算中...";
            _scoreProgressBar.Value = 0;

            try
            {
                _currentResult = _scoreService.CalculateSecurityScore();

                // 更新UI
                _scoreProgressBar.Value = _currentResult.TotalScore;
                _scoreLabel.Text = $"{_currentResult.TotalScore}/100";

                // 根据分数设置颜色和等级
                Color scoreColor;
                if (_currentResult.TotalScore >= 90)
                {
                    scoreColor = Color.FromArgb(76, 175, 80);
                    _gradeLabel.Text = "安全等级: 优秀";
                }
                else if (_currentResult.TotalScore >= 80)
                {
                    scoreColor = Color.FromArgb(139, 195, 74);
                    _gradeLabel.Text = "安全等级: 良好";
                }
                else if (_currentResult.TotalScore >= 70)
                {
                    scoreColor = Color.FromArgb(255, 193, 7);
                    _gradeLabel.Text = "安全等级: 一般";
                }
                else if (_currentResult.TotalScore >= 60)
                {
                    scoreColor = Color.FromArgb(255, 152, 0);
                    _gradeLabel.Text = "安全等级: 较差";
                }
                else
                {
                    scoreColor = Color.FromArgb(244, 67, 54);
                    _gradeLabel.Text = "安全等级: 危险";
                }

                _scoreLabel.ForeColor = scoreColor;
                _gradeLabel.ForeColor = scoreColor;

                // 更新分类列表
                _categoryListView.Items.Clear();
                foreach (var category in _currentResult.Categories)
                {
                    var item = new ListViewItem(category.Name);
                    item.SubItems.Add($"{category.Score}/{category.MaxScore}");
                    item.SubItems.Add(category.Status);

                    string detailHint = category.Details.Count > 0 ? "双击查看" : "-";
                    item.SubItems.Add(detailHint);
                    item.Tag = category;

                    // 根据得分比例设置颜色
                    double ratio = (double)category.Score / category.MaxScore;
                    if (ratio >= 0.8)
                        item.ForeColor = Color.FromArgb(76, 175, 80);
                    else if (ratio >= 0.5)
                        item.ForeColor = Color.FromArgb(255, 152, 0);
                    else
                        item.ForeColor = Color.FromArgb(244, 67, 54);

                    _categoryListView.Items.Add(item);
                }

                // 更新建议列表
                _recommendationsListBox.Items.Clear();
                foreach (var recommendation in _currentResult.Recommendations)
                {
                    _recommendationsListBox.Items.Add(recommendation);
                }

                _statusLabel.Text = $"评估完成 - 总分: {_currentResult.TotalScore}/100";
            }
            catch (Exception ex)
            {
                _statusLabel.Text = $"评估失败: {ex.Message}";
                MessageBox.Show($"评估失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AnalyzeButton_Click(object sender, EventArgs e)
        {
            CalculateScore();
        }

        private void CategoryListView_DoubleClick(object sender, EventArgs e)
        {
            if (_categoryListView.SelectedItems.Count == 0) return;

            var category = _categoryListView.SelectedItems[0].Tag as SecurityCategory;
            if (category == null) return;

            var detailForm = new Form
            {
                Text = $"{category.Name} 详情",
                Size = new Size(400, 300),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var detailLabel = new Label
            {
                Text = $"得分: {category.Score}/{category.MaxScore}  状态: {category.Status}",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                Location = new Point(20, 15),
                AutoSize = true
            };
            detailForm.Controls.Add(detailLabel);

            var detailListBox = new ListBox
            {
                Location = new Point(20, 45),
                Size = new Size(340, 180),
                Font = new Font("微软雅黑", 9)
            };
            foreach (var detail in category.Details)
            {
                detailListBox.Items.Add(detail);
            }
            detailForm.Controls.Add(detailListBox);

            var closeButton = new Button
            {
                Text = "关闭",
                Location = new Point(150, 230),
                Size = new Size(80, 30),
                DialogResult = DialogResult.OK
            };
            detailForm.Controls.Add(closeButton);

            detailForm.ShowDialog();
        }

        private void FixAllButton_Click(object sender, EventArgs e)
        {
            if (_currentResult == null)
            {
                MessageBox.Show("请先进行安全评估", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var result = MessageBox.Show(
                "一键优化将尝试自动修复以下安全问题：\n\n" +
                "• 启用防火墙\n" +
                "• 启用UAC\n" +
                "• 禁用危险服务\n" +
                "• 启用自动更新\n\n" +
                "是否继续？",
                "一键优化",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result != DialogResult.Yes) return;

            _statusLabel.Text = "正在优化...";
            int fixedCount = 0;

            try
            {
                // 启用防火墙
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", true))
                    {
                        if (key != null)
                        {
                            key.SetValue("EnableFirewall", 1);
                            fixedCount++;
                        }
                    }
                }
                catch { }

                // 启用UAC
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", true))
                    {
                        if (key != null)
                        {
                            key.SetValue("EnableLUA", 1);
                            key.SetValue("ConsentPromptBehaviorAdmin", 5);
                            fixedCount++;
                        }
                    }
                }
                catch { }

                // 启用自动更新
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update", true))
                    {
                        if (key != null)
                        {
                            key.SetValue("AUOptions", 3);
                            fixedCount++;
                        }
                    }
                }
                catch { }

                // 禁用SMBv1
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", true))
                    {
                        if (key != null)
                        {
                            key.SetValue("SMB1", 0);
                            fixedCount++;
                        }
                    }
                }
                catch { }

                MessageBox.Show(
                    $"优化完成！\n\n" +
                    $"已修复 {fixedCount} 项安全设置\n\n" +
                    "建议重启计算机以使所有更改生效。",
                    "优化结果",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);

                // 重新评估
                CalculateScore();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"优化失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ExportButton_Click(object sender, EventArgs e)
        {
            if (_currentResult == null)
            {
                MessageBox.Show("请先进行安全评估", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var saveDialog = new WinSaveFileDialog
            {
                Filter = "文本文件|*.txt",
                Title = "导出安全报告",
                FileName = $"安全报告_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (saveDialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    var report = GenerateReport();
                    System.IO.File.WriteAllText(saveDialog.FileName, report);
                    MessageBox.Show($"报告已保存到:\n{saveDialog.FileName}", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private string GenerateReport()
        {
            var report = "========================================\n";
            report += "        系统安全评估报告\n";
            report += "========================================\n\n";
            report += $"评估时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n";
            report += $"总分: {_currentResult.TotalScore}/100\n";
            report += $"等级: {_currentResult.Grade}\n\n";

            report += "----------------------------------------\n";
            report += "详细评分:\n";
            report += "----------------------------------------\n";

            foreach (var category in _currentResult.Categories)
            {
                report += $"\n【{category.Name}】\n";
                report += $"  得分: {category.Score}/{category.MaxScore}\n";
                report += $"  状态: {category.Status}\n";
                foreach (var detail in category.Details)
                {
                    report += $"  - {detail}\n";
                }
            }

            report += "\n----------------------------------------\n";
            report += "优化建议:\n";
            report += "----------------------------------------\n";
            foreach (var recommendation in _currentResult.Recommendations)
            {
                report += $"• {recommendation}\n";
            }

            report += "\n========================================\n";
            report += "    Fire Antivirus - 火蚁杀毒软件\n";
            report += "========================================\n";

            return report;
        }
    }
}
