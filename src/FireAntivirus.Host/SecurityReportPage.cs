// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using WinSaveFileDialog = System.Windows.Forms.SaveFileDialog;
using System.IO;
using System.Linq;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;
using SvcReport = FireAntivirus.Services.SecurityReport;
using SvcReportFileInfo = FireAntivirus.Services.ReportFileInfo;

namespace FireAntivirus.Host
{
    public partial class SecurityReportPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;
        private SecurityReportService _reportService;
        private SvcReport _currentReport;
        private RichTextBox _reportTextBox;
        private Label _statusLabel;
        private ProgressBar _progressBar;

        public SecurityReportPage()
        {
            InitializeComponent();
            InitializeService();
            UpdateUI();
        }

        private void InitializeService()
        {
            _reportService = new SecurityReportService();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // SecurityReportPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "SecurityReportPage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
                if (_reportTextBox != null)
                {
                    _reportTextBox.BackColor = Color.FromArgb(45, 45, 45);
                    _reportTextBox.ForeColor = Color.White;
                }
            }
            else
            {
                this.BackColor = Color.White;
                if (_reportTextBox != null)
                {
                    _reportTextBox.BackColor = Color.White;
                    _reportTextBox.ForeColor = Color.Black;
                }
            }
        }

        private void UpdateUI()
        {
            this.Controls.Clear();

            // 标题
            var titleLabel = new Label
            {
                Text = "安全报告",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 15),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 描述
            var descriptionLabel = new Label
            {
                Text = "生成详细的系统安全状态报告",
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
                Style = ProgressBarStyle.Marquee,
                Visible = false
            };
            this.Controls.Add(_progressBar);

            // 按钮面板
            var buttonPanel = new Panel
            {
                Location = new Point(20, 95),
                Size = new Size(660, 45),
                BackColor = Color.Transparent
            };
            this.Controls.Add(buttonPanel);

            // 生成报告按钮
            var generateButton = new Button
            {
                Text = "生成完整报告",
                Location = new Point(0, 5),
                Size = new Size(120, 35),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 10)
            };
            generateButton.FlatAppearance.BorderSize = 0;
            generateButton.Click += GenerateReportButton_Click;
            buttonPanel.Controls.Add(generateButton);

            // 快速扫描按钮
            var quickScanButton = new Button
            {
                Text = "快速检测",
                Location = new Point(130, 5),
                Size = new Size(100, 35),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            quickScanButton.FlatAppearance.BorderSize = 0;
            quickScanButton.Click += QuickScanButton_Click;
            buttonPanel.Controls.Add(quickScanButton);

            // 历史报告按钮
            var historyButton = new Button
            {
                Text = "历史报告",
                Location = new Point(240, 5),
                Size = new Size(100, 35),
                BackColor = Color.FromArgb(156, 39, 176),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            historyButton.FlatAppearance.BorderSize = 0;
            historyButton.Click += ViewReportsButton_Click;
            buttonPanel.Controls.Add(historyButton);

            // 导出按钮
            var exportButton = new Button
            {
                Text = "导出报告",
                Location = new Point(350, 5),
                Size = new Size(100, 35),
                BackColor = Color.FromArgb(255, 152, 0),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            exportButton.FlatAppearance.BorderSize = 0;
            exportButton.Click += ExportReportButton_Click;
            buttonPanel.Controls.Add(exportButton);

            // 保存按钮
            var saveButton = new Button
            {
                Text = "保存报告",
                Location = new Point(460, 5),
                Size = new Size(100, 35),
                BackColor = Color.FromArgb(0, 150, 136),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            saveButton.FlatAppearance.BorderSize = 0;
            saveButton.Click += SaveReportButton_Click;
            buttonPanel.Controls.Add(saveButton);

            // 打印按钮
            var printButton = new Button
            {
                Text = "打印",
                Location = new Point(570, 5),
                Size = new Size(80, 35),
                BackColor = Color.FromArgb(96, 125, 139),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            printButton.FlatAppearance.BorderSize = 0;
            printButton.Click += PrintReportButton_Click;
            buttonPanel.Controls.Add(printButton);

            // 报告显示区域
            _reportTextBox = new RichTextBox
            {
                Location = new Point(20, 150),
                Size = new Size(660, 380),
                Font = new Font("Consolas", 9),
                ReadOnly = true,
                BackColor = Color.White,
                ForeColor = Color.Black,
                ScrollBars = RichTextBoxScrollBars.Vertical
            };
            this.Controls.Add(_reportTextBox);

            // 显示欢迎信息
            ShowWelcomeMessage();
        }

        private void ShowWelcomeMessage()
        {
            _reportTextBox.Clear();
            _reportTextBox.AppendText("╔══════════════════════════════════════════════════════════════╗\n");
            _reportTextBox.AppendText("║                  火蚁杀毒软件 - 安全报告                      ║\n");
            _reportTextBox.AppendText("╚══════════════════════════════════════════════════════════════╝\n\n");
            _reportTextBox.AppendText("点击\"生成完整报告\"按钮开始生成系统安全报告。\n\n");
            _reportTextBox.AppendText("功能说明：\n");
            _reportTextBox.AppendText("• 生成完整报告 - 全面扫描系统并生成详细报告\n");
            _reportTextBox.AppendText("• 快速检测 - 快速检测关键安全项目\n");
            _reportTextBox.AppendText("• 历史报告 - 查看之前保存的报告\n");
            _reportTextBox.AppendText("• 导出报告 - 将报告导出为文件\n");
            _reportTextBox.AppendText("• 保存报告 - 保存当前报告\n");
            _reportTextBox.AppendText("• 打印 - 打印报告内容\n");
        }

        private void GenerateReportButton_Click(object sender, EventArgs e)
        {
            _statusLabel.Text = "正在生成报告...";
            _progressBar.Visible = true;
            _reportTextBox.Clear();
            Application.DoEvents();

            try
            {
                _currentReport = _reportService.GenerateFullReport();
                DisplayReport(_currentReport);
                _statusLabel.Text = $"报告生成完成 - {DateTime.Now:HH:mm:ss}";
            }
            catch (Exception ex)
            {
                _reportTextBox.Text = $"生成报告失败: {ex.Message}";
                _statusLabel.Text = "生成失败";
            }
            finally
            {
                _progressBar.Visible = false;
            }
        }

        private void QuickScanButton_Click(object sender, EventArgs e)
        {
            _statusLabel.Text = "正在进行快速检测...";
            _progressBar.Visible = true;
            _reportTextBox.Clear();
            Application.DoEvents();

            try
            {
                var report = _reportService.GenerateFullReport();
                _currentReport = report;

                _reportTextBox.Clear();
                _reportTextBox.AppendText("═══════════════ 快速安全检测结果 ═══════════════\n\n");

                // 安全状态
                _reportTextBox.AppendText("【安全状态】\n");
                _reportTextBox.AppendText($"  防病毒软件: {(report.SecurityStatus.HasAntivirus ? report.SecurityStatus.AntivirusName : "未检测到")}\n");
                _reportTextBox.AppendText($"  防火墙: {(report.SecurityStatus.FirewallEnabled ? "已启用" : "未启用")}\n");
                _reportTextBox.AppendText($"  UAC: {(report.SecurityStatus.UACEnabled ? "已启用" : "未启用")}\n");
                _reportTextBox.AppendText($"  自动更新: {(report.SecurityStatus.AutoUpdateEnabled ? "已启用" : "未启用")}\n\n");

                // 漏洞
                if (report.Vulnerabilities.Count > 0)
                {
                    _reportTextBox.AppendText("【发现安全问题】\n");
                    foreach (var vuln in report.Vulnerabilities)
                    {
                        Color color = vuln.Severity == "高危" ? Color.Red : Color.Orange;
                        AppendColoredText($"  [{vuln.Severity}] {vuln.Name}\n", color);
                    }
                    _reportTextBox.AppendText("\n");
                }
                else
                {
                    _reportTextBox.AppendText("【安全检测结果】\n");
                    _reportTextBox.AppendText("  未发现明显安全问题\n\n");
                }

                // 建议
                _reportTextBox.AppendText("【建议】\n");
                foreach (var rec in report.Recommendations)
                {
                    _reportTextBox.AppendText($"  • {rec}\n");
                }

                _statusLabel.Text = $"快速检测完成 - 发现 {report.Vulnerabilities.Count} 个问题";
            }
            catch (Exception ex)
            {
                _reportTextBox.Text = $"快速检测失败: {ex.Message}";
                _statusLabel.Text = "检测失败";
            }
            finally
            {
                _progressBar.Visible = false;
            }
        }

        private void ViewReportsButton_Click(object sender, EventArgs e)
        {
            var reports = _reportService.GetSavedReports();
            var reportFiles = reports.Select(r => r.FilePath).ToList();

            if (reports.Count == 0)
            {
                MessageBox.Show("暂无历史报告", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var historyForm = new Form
            {
                Text = "历史报告",
                Size = new Size(500, 400),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.Sizable
            };

            var listView = new ListView
            {
                View = View.Details,
                FullRowSelect = true,
                Dock = DockStyle.Top,
                Height = 250
            };
            listView.Columns.Add("报告名称", 200);
            listView.Columns.Add("创建时间", 150);
            listView.Columns.Add("大小", 80);

            foreach (var reportPath in reportFiles)
            {
                var fileInfo = new FileInfo(reportPath);
                var item = new ListViewItem(Path.GetFileName(reportPath));
                item.SubItems.Add(fileInfo.CreationTime.ToString("yyyy-MM-dd HH:mm"));
                item.SubItems.Add(FormatFileSize(fileInfo.Length));
                item.Tag = reportPath;
                listView.Items.Add(item);
            }

            listView.DoubleClick += (s, args) =>
            {
                if (listView.SelectedItems.Count > 0)
                {
                    var path = listView.SelectedItems[0].Tag.ToString();
                    var content = _reportService.LoadReport(path);
                    if (content != null)
                    {
                        _reportTextBox.Text = content;
                        historyForm.Close();
                    }
                }
            };

            var openButton = new Button
            {
                Text = "打开",
                Location = new Point(120, 270),
                Size = new Size(80, 30),
                DialogResult = DialogResult.OK
            };
            openButton.Click += (s, args) =>
            {
                if (listView.SelectedItems.Count > 0)
                {
                    var path = listView.SelectedItems[0].Tag.ToString();
                    var content = _reportService.LoadReport(path);
                    if (content != null)
                    {
                        _reportTextBox.Text = content;
                    }
                }
            };

            var deleteButton = new Button
            {
                Text = "删除",
                Location = new Point(210, 270),
                Size = new Size(80, 30)
            };
            deleteButton.Click += (s, args) =>
            {
                if (listView.SelectedItems.Count > 0)
                {
                    var path = listView.SelectedItems[0].Tag.ToString();
                    if (MessageBox.Show("确定要删除此报告吗？", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    {
                        File.Delete(path);
                        listView.Items.Remove(listView.SelectedItems[0]);
                    }
                }
            };

            var closeButton = new Button
            {
                Text = "关闭",
                Location = new Point(300, 270),
                Size = new Size(80, 30),
                DialogResult = DialogResult.Cancel
            };

            historyForm.Controls.Add(listView);
            historyForm.Controls.Add(openButton);
            historyForm.Controls.Add(deleteButton);
            historyForm.Controls.Add(closeButton);
            historyForm.ShowDialog();
        }

        private void ExportReportButton_Click(object sender, EventArgs e)
        {
            if (_currentReport == null && string.IsNullOrEmpty(_reportTextBox.Text))
            {
                MessageBox.Show("请先生成报告", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var saveDialog = new WinSaveFileDialog
            {
                Filter = "文本文件|*.txt|所有文件|*.*",
                Title = "导出安全报告",
                FileName = $"SecurityReport_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (saveDialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    File.WriteAllText(saveDialog.FileName, _reportTextBox.Text);
                    MessageBox.Show($"报告已导出到:\n{saveDialog.FileName}", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"导出失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void SaveReportButton_Click(object sender, EventArgs e)
        {
            if (_currentReport == null)
            {
                MessageBox.Show("请先生成报告", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            try
            {
                var filePath = _reportService.SaveReport(_currentReport);
                MessageBox.Show($"报告已保存到:\n{filePath}", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void PrintReportButton_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(_reportTextBox.Text))
            {
                MessageBox.Show("请先生成报告", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            try
            {
                var printDialog = new PrintDialog();
                var printDocument = new System.Drawing.Printing.PrintDocument();
                printDocument.DocumentName = "安全报告";

                string[] lines = _reportTextBox.Text.Split('\n');
                int currentLine = 0;

                printDocument.PrintPage += (s, args) =>
                {
                    float yPos = args.MarginBounds.Top;
                    float leftMargin = args.MarginBounds.Left;
                    var font = new Font("Consolas", 9);

                    while (currentLine < lines.Length && yPos < args.MarginBounds.Bottom)
                    {
                        args.Graphics.DrawString(lines[currentLine], font, Brushes.Black, leftMargin, yPos);
                        yPos += font.GetHeight(args.Graphics);
                        currentLine++;
                    }

                    args.HasMorePages = currentLine < lines.Length;
                };

                printDialog.Document = printDocument;

                if (printDialog.ShowDialog() == DialogResult.OK)
                {
                    printDocument.Print();
                    _statusLabel.Text = "报告已发送到打印机";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打印失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void DisplayReport(SvcReport report)
        {
            _reportTextBox.Clear();

            // 标题
            _reportTextBox.SelectionFont = new Font("微软雅黑", 12, FontStyle.Bold);
            _reportTextBox.AppendText("╔══════════════════════════════════════════════════════════════╗\n");
            _reportTextBox.AppendText("║                  火蚁杀毒软件 - 安全报告                      ║\n");
            _reportTextBox.AppendText("╚══════════════════════════════════════════════════════════════╝\n\n");

            // 系统信息
            _reportTextBox.SelectionFont = new Font("微软雅黑", 10, FontStyle.Bold);
            _reportTextBox.AppendText("═══════════════ 系统信息 ═══════════════\n");
            _reportTextBox.SelectionFont = new Font("Consolas", 9);
            _reportTextBox.AppendText($"计算机名: {report.SystemInfo.ComputerName}\n");
            _reportTextBox.AppendText($"用户名: {report.SystemInfo.UserName}\n");
            _reportTextBox.AppendText($"操作系统: {report.SystemInfo.OSVersion}\n");
            _reportTextBox.AppendText($"处理器: {report.SystemInfo.Processor}\n");
            _reportTextBox.AppendText($"内存: {report.SystemInfo.TotalMemory / (1024*1024*1024.0):F1} GB\n");
            _reportTextBox.AppendText($"系统启动时间: {(report.SystemInfo.LastBootTime.HasValue ? report.SystemInfo.LastBootTime.Value.ToString("yyyy-MM-dd HH:mm:ss") : "未知")}\n");
            _reportTextBox.AppendText($"运行时长: {report.SystemInfo.Uptime:dd\\天\\ hh\\小时\\ mm\\分钟}\n\n");

            // 安全状态
            _reportTextBox.SelectionFont = new Font("微软雅黑", 10, FontStyle.Bold);
            _reportTextBox.AppendText("═══════════════ 安全状态 ═══════════════\n");
            _reportTextBox.SelectionFont = new Font("Consolas", 9);

            string avStatus = report.SecurityStatus.HasAntivirus ? report.SecurityStatus.AntivirusName : "未检测到";
            _reportTextBox.AppendText($"防病毒软件: {avStatus}\n");

            AppendStatusText("防火墙", report.SecurityStatus.FirewallEnabled);
            AppendStatusText("UAC", report.SecurityStatus.UACEnabled);
            AppendStatusText("自动更新", report.SecurityStatus.AutoUpdateEnabled);

            _reportTextBox.AppendText($"最近更新: {report.SecurityStatus.LastUpdateDate ?? "未知"}\n\n");

            // 安全漏洞
            if (report.Vulnerabilities.Count > 0)
            {
                _reportTextBox.SelectionFont = new Font("微软雅黑", 10, FontStyle.Bold);
                _reportTextBox.AppendText("═══════════════ 安全漏洞 ═══════════════\n");
                _reportTextBox.SelectionFont = new Font("Consolas", 9);

                foreach (var vuln in report.Vulnerabilities)
                {
                    Color severityColor = vuln.Severity == "高危" ? Color.Red :
                                          vuln.Severity == "中危" ? Color.Orange : Color.Gray;
                    AppendColoredText($"[{vuln.Severity}] ", severityColor);
                    _reportTextBox.AppendText($"{vuln.Name}\n");
                    _reportTextBox.AppendText($"    描述: {vuln.Description}\n");
                    _reportTextBox.AppendText($"    类别: {vuln.Category}\n\n");
                }
            }

            // 启动项统计
            _reportTextBox.SelectionFont = new Font("微软雅黑", 10, FontStyle.Bold);
            _reportTextBox.AppendText("═══════════════ 启动项统计 ═══════════════\n");
            _reportTextBox.SelectionFont = new Font("Consolas", 9);
            _reportTextBox.AppendText($"启动项总数: {report.StartupItems.Count}\n\n");

            // 运行进程
            _reportTextBox.SelectionFont = new Font("微软雅黑", 10, FontStyle.Bold);
            _reportTextBox.AppendText("═══════════════ 运行进程 ═══════════════\n");
            _reportTextBox.SelectionFont = new Font("Consolas", 9);
            _reportTextBox.AppendText($"运行进程数: {report.RunningProcesses.Count}\n\n");

            // 建议
            _reportTextBox.SelectionFont = new Font("微软雅黑", 10, FontStyle.Bold);
            _reportTextBox.AppendText("═══════════════ 安全建议 ═══════════════\n");
            _reportTextBox.SelectionFont = new Font("Consolas", 9);
            foreach (var rec in report.Recommendations)
            {
                _reportTextBox.AppendText($"• {rec}\n");
            }

            _reportTextBox.AppendText("\n═══════════════════════════════════════\n");
            _reportTextBox.AppendText($"报告生成时间: {report.GeneratedTime:yyyy-MM-dd HH:mm:ss}\n");
            _reportTextBox.AppendText("═══════════════════════════════════════\n");
        }

        private void AppendStatusText(string name, bool status)
        {
            _reportTextBox.AppendText($"{name}: ");
            if (status)
            {
                AppendColoredText("已启用\n", Color.Green);
            }
            else
            {
                AppendColoredText("未启用\n", Color.Red);
            }
        }

        private void AppendColoredText(string text, Color color)
        {
            int start = _reportTextBox.TextLength;
            _reportTextBox.AppendText(text);
            _reportTextBox.Select(start, text.Length);
            _reportTextBox.SelectionColor = color;
            _reportTextBox.SelectionStart = _reportTextBox.TextLength;
            _reportTextBox.SelectionLength = 0;
        }

        private string FormatFileSize(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int counter = 0;
            decimal number = bytes;
            while (number >= 1024 && counter < suffixes.Length - 1)
            {
                number /= 1024;
                counter++;
            }
            return $"{number:F1} {suffixes[counter]}";
        }
    }
}
