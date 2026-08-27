// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;

namespace FireAntivirus.Host
{
    public partial class SystemOptimizerPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;
        private SystemOptimizerService _optimizerService;
        private List<JunkFileInfo> _junkFiles = new List<JunkFileInfo>();
        private ListView junkListView;
        private ProgressBar progressBar;
        private Label statusLabel;
        private Label sizeLabel;
        private Button scanButton;
        private Button cleanButton;
        private Button optimizeMemoryButton;
        private Button optimizeSystemButton;

        public SystemOptimizerPage()
        {
            InitializeComponent();
            InitializeService();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "SystemOptimizerPage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        private void InitializeService()
        {
            _optimizerService = new SystemOptimizerService();
            _optimizerService.ProgressChanged += (s, args) =>
            {
                if (this.InvokeRequired)
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar.Value = args.Progress;
                        statusLabel.Text = args.Message;
                    }));
                }
                else
                {
                    progressBar.Value = args.Progress;
                    statusLabel.Text = args.Message;
                }
            };
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
            }
            else
            {
                this.BackColor = Color.White;
            }
        }

        private void UpdateUI()
        {
            this.Controls.Clear();

            // 标题
            var titleLabel = new Label
            {
                Text = "系统优化",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 107, 53),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 描述
            var descriptionLabel = new Label
            {
                Text = "清理垃圾文件、优化内存、提升系统性能",
                Font = new Font("微软雅黑", 10),
                ForeColor = Color.Gray,
                Location = new Point(20, 50),
                AutoSize = true
            };
            this.Controls.Add(descriptionLabel);

            // 垃圾清理区域
            var junkCleanGroup = new GroupBox
            {
                Text = "垃圾文件清理",
                Location = new Point(20, 80),
                Size = new Size(660, 250),
                Font = new Font("微软雅黑", 9)
            };

            scanButton = new Button
            {
                Text = "扫描垃圾文件",
                Location = new Point(15, 25),
                Size = new Size(110, 32),
                BackColor = Color.FromArgb(255, 107, 53),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9),
                Cursor = Cursors.Hand
            };
            scanButton.FlatAppearance.BorderSize = 0;
            scanButton.Click += ScanJunkButton_Click;
            junkCleanGroup.Controls.Add(scanButton);

            cleanButton = new Button
            {
                Text = "清理选中项",
                Location = new Point(135, 25),
                Size = new Size(100, 32),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9),
                Cursor = Cursors.Hand,
                Enabled = false
            };
            cleanButton.FlatAppearance.BorderSize = 0;
            cleanButton.Click += CleanJunkButton_Click;
            junkCleanGroup.Controls.Add(cleanButton);

            sizeLabel = new Label
            {
                Text = "已发现: 0 MB",
                Location = new Point(520, 32),
                Size = new Size(120, 20),
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.FromArgb(100, 100, 100)
            };
            junkCleanGroup.Controls.Add(sizeLabel);

            junkListView = new ListView
            {
                Location = new Point(15, 65),
                Size = new Size(630, 130),
                View = View.Details,
                FullRowSelect = true,
                CheckBoxes = true,
                GridLines = true,
                Font = new Font("微软雅黑", 9)
            };
            junkListView.Columns.Add("类型", 120);
            junkListView.Columns.Add("文件路径", 350);
            junkListView.Columns.Add("大小", 80);
            junkListView.Columns.Add("最后访问", 100);
            junkCleanGroup.Controls.Add(junkListView);

            progressBar = new ProgressBar
            {
                Location = new Point(15, 200),
                Size = new Size(520, 20),
                Style = ProgressBarStyle.Continuous
            };
            junkCleanGroup.Controls.Add(progressBar);

            statusLabel = new Label
            {
                Text = "点击\"扫描垃圾文件\"开始",
                Location = new Point(15, 225),
                Size = new Size(630, 20),
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.FromArgb(100, 100, 100)
            };
            junkCleanGroup.Controls.Add(statusLabel);

            this.Controls.Add(junkCleanGroup);

            // 系统加速区域
            var systemSpeedGroup = new GroupBox
            {
                Text = "系统加速",
                Location = new Point(20, 340),
                Size = new Size(660, 130),
                Font = new Font("微软雅黑", 9)
            };

            optimizeMemoryButton = new Button
            {
                Text = "优化内存",
                Location = new Point(15, 25),
                Size = new Size(100, 40),
                BackColor = Color.FromArgb(33, 150, 243),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9),
                Cursor = Cursors.Hand
            };
            optimizeMemoryButton.FlatAppearance.BorderSize = 0;
            optimizeMemoryButton.Click += OptimizeMemoryButton_Click;
            systemSpeedGroup.Controls.Add(optimizeMemoryButton);

            var memoryDesc = new Label
            {
                Text = "释放未使用的内存，\n提升系统响应速度",
                Location = new Point(120, 25),
                Size = new Size(150, 45),
                Font = new Font("微软雅黑", 8),
                ForeColor = Color.Gray
            };
            systemSpeedGroup.Controls.Add(memoryDesc);

            optimizeSystemButton = new Button
            {
                Text = "系统优化",
                Location = new Point(300, 25),
                Size = new Size(100, 40),
                BackColor = Color.FromArgb(156, 39, 176),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9),
                Cursor = Cursors.Hand
            };
            optimizeSystemButton.FlatAppearance.BorderSize = 0;
            optimizeSystemButton.Click += OptimizeSystemButton_Click;
            systemSpeedGroup.Controls.Add(optimizeSystemButton);

            var systemDesc = new Label
            {
                Text = "优化服务、视觉效果\n和电源设置",
                Location = new Point(405, 25),
                Size = new Size(150, 45),
                Font = new Font("微软雅黑", 8),
                ForeColor = Color.Gray
            };
            systemSpeedGroup.Controls.Add(systemDesc);

            // 内存状态
            var memoryStatusLabel = new Label
            {
                Text = "内存状态: 检测中...",
                Location = new Point(15, 75),
                Size = new Size(630, 20),
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.FromArgb(100, 100, 100),
                Name = "memoryStatusLabel"
            };
            systemSpeedGroup.Controls.Add(memoryStatusLabel);

            this.Controls.Add(systemSpeedGroup);

            // 异步更新内存状态
            UpdateMemoryStatus();
        }

        private void ScanJunkButton_Click(object sender, EventArgs e)
        {
            scanButton.Enabled = false;
            scanButton.Text = "扫描中...";
            cleanButton.Enabled = false;
            junkListView.Items.Clear();
            _junkFiles.Clear();
            progressBar.Value = 0;

            Task.Run(() =>
            {
                try
                {
                    var scanResult = _optimizerService.ScanJunkFiles();
                    // 从扫描结果中提取所有垃圾文件
                    _junkFiles = scanResult.Categories
                        .SelectMany(c => c.Files)
                        .ToList();

                    Invoke(new Action(() =>
                    {
                        DisplayJunkFiles();
                        scanButton.Enabled = true;
                        scanButton.Text = "扫描垃圾文件";
                        cleanButton.Enabled = _junkFiles.Count > 0;
                    }));
                }
                catch (Exception ex)
                {
                    Invoke(new Action(() =>
                    {
                        statusLabel.Text = $"扫描出错: {ex.Message}";
                        scanButton.Enabled = true;
                        scanButton.Text = "扫描垃圾文件";
                    }));
                }
            });
        }

        private void DisplayJunkFiles()
        {
            junkListView.Items.Clear();
            long totalSize = 0;

            // 按类型分组
            var grouped = _junkFiles.GroupBy(f => f.Category).ToList();
            
            foreach (var group in grouped)
            {
                long groupSize = group.Sum(f => f.Size);
                totalSize += groupSize;

                var groupItem = new ListViewItem(group.Key);
                groupItem.SubItems.Add($"{group.Count()} 个文件");
                groupItem.SubItems.Add(FormatSize(groupSize));
                groupItem.SubItems.Add("");
                groupItem.Tag = group.ToList();
                groupItem.Checked = true;
                groupItem.ForeColor = Color.FromArgb(33, 150, 243);
                junkListView.Items.Add(groupItem);

                // 添加子项（前10个文件）
                foreach (var file in group.Take(10))
                {
                    var item = new ListViewItem("");
                    item.SubItems.Add(file.FilePath.Length > 50 ? "..." + file.FilePath.Substring(file.FilePath.Length - 47) : file.FilePath);
                    item.SubItems.Add(FormatSize(file.Size));
                    item.SubItems.Add(file.LastAccessTime.ToString("yyyy-MM-dd"));
                    item.Tag = file;
                    item.Checked = true;
                    junkListView.Items.Add(item);
                }

                if (group.Count() > 10)
                {
                    var moreItem = new ListViewItem("");
                    moreItem.SubItems.Add($"... 还有 {group.Count() - 10} 个文件");
                    moreItem.SubItems.Add("");
                    moreItem.SubItems.Add("");
                    moreItem.ForeColor = Color.Gray;
                    junkListView.Items.Add(moreItem);
                }
            }

            sizeLabel.Text = $"已发现: {FormatSize(totalSize)}";
            statusLabel.Text = $"扫描完成，共发现 {_junkFiles.Count} 个可清理文件";
        }

        private void CleanJunkButton_Click(object sender, EventArgs e)
        {
            var filesToClean = new List<JunkFileInfo>();
            
            foreach (ListViewItem item in junkListView.Items)
            {
                if (item.Checked && item.Tag is JunkFileInfo file)
                {
                    filesToClean.Add(file);
                }
                else if (item.Checked && item.Tag is List<JunkFileInfo> fileList)
                {
                    filesToClean.AddRange(fileList);
                }
            }

            if (filesToClean.Count == 0)
            {
                MessageBox.Show("请先选择要清理的文件", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var result = MessageBox.Show(
                $"确定要清理 {filesToClean.Count} 个文件吗？\n此操作不可撤销。",
                "确认清理",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result != DialogResult.Yes) return;

            cleanButton.Enabled = false;
            cleanButton.Text = "清理中...";

            Task.Run(() =>
            {
                try
                {
                    var cleanResult = _optimizerService.CleanJunkFiles(filesToClean);

                    Invoke(new Action(() =>
                    {
                        cleanButton.Enabled = true;
                        cleanButton.Text = "清理选中项";
                        
                        MessageBox.Show(
                            $"清理完成!\n\n" +
                            $"已清理: {cleanResult.CleanedFiles} 个文件\n" +
                            $"释放空间: {FormatSize(cleanResult.CleanedSize)}\n" +
                            $"失败: {cleanResult.FailedFiles} 个",
                            "清理结果",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);

                        // 重新扫描
                        ScanJunkButton_Click(scanButton, EventArgs.Empty);
                    }));
                }
                catch (Exception ex)
                {
                    Invoke(new Action(() =>
                    {
                        cleanButton.Enabled = true;
                        cleanButton.Text = "清理选中项";
                        statusLabel.Text = $"清理出错: {ex.Message}";
                    }));
                }
            });
        }

        private void OptimizeMemoryButton_Click(object sender, EventArgs e)
        {
            optimizeMemoryButton.Enabled = false;
            optimizeMemoryButton.Text = "优化中...";
            statusLabel.Text = "正在优化内存...";

            Task.Run(() =>
            {
                try
                {
                    var result = _optimizerService.OptimizeMemory();

                    Invoke(new Action(() =>
                    {
                        optimizeMemoryButton.Enabled = true;
                        optimizeMemoryButton.Text = "优化内存";

                        if (result.Success)
                        {
                            statusLabel.Text = $"内存优化完成，释放了 {result.FreedMB} MB";
                            var memoryStatusLabel = Controls.Find("memoryStatusLabel", true).FirstOrDefault() as Label;
                            if (memoryStatusLabel != null)
                            {
                                memoryStatusLabel.Text = $"内存: 可用 {result.AfterAvailableMB} MB / 已用 {result.AfterUsedPercent}%";
                            }

                            MessageBox.Show(
                                $"内存优化完成!\n\n" +
                                $"优化前可用: {result.BeforeAvailableMB} MB\n" +
                                $"优化后可用: {result.AfterAvailableMB} MB\n" +
                                $"释放内存: {result.FreedMB} MB",
                                "内存优化",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Information);
                        }
                        else
                        {
                            MessageBox.Show($"优化失败: {result.Error}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }

                        UpdateMemoryStatus();
                    }));
                }
                catch (Exception ex)
                {
                    Invoke(new Action(() =>
                    {
                        optimizeMemoryButton.Enabled = true;
                        optimizeMemoryButton.Text = "优化内存";
                        statusLabel.Text = $"优化出错: {ex.Message}";
                    }));
                }
            });
        }

        private void OptimizeSystemButton_Click(object sender, EventArgs e)
        {
            optimizeSystemButton.Enabled = false;
            optimizeSystemButton.Text = "优化中...";

            Task.Run(() =>
            {
                try
                {
                    var results = _optimizerService.OptimizeSystem();

                    Invoke(new Action(() =>
                    {
                        optimizeSystemButton.Enabled = true;
                        optimizeSystemButton.Text = "系统优化";

                        var message = "系统优化完成!\n\n";
                        foreach (var r in results)
                        {
                            message += $"【{r.Category}】{(r.Success ? r.Message : "失败: " + r.Message)}\n";
                        }

                        MessageBox.Show(message, "系统优化", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }));
                }
                catch (Exception ex)
                {
                    Invoke(new Action(() =>
                    {
                        optimizeSystemButton.Enabled = true;
                        optimizeSystemButton.Text = "系统优化";
                        MessageBox.Show($"优化失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }));
                }
            });
        }

        private void UpdateMemoryStatus()
        {
            Task.Run(() =>
            {
                try
                {
                    var memStatus = new Microsoft.VisualBasic.Devices.ComputerInfo();
                    var totalMB = (long)(memStatus.TotalPhysicalMemory / 1024 / 1024);
                    var availableMB = (long)(memStatus.AvailablePhysicalMemory / 1024 / 1024);
                    var usedPercent = (int)((1 - (double)availableMB / totalMB) * 100);

                    Invoke(new Action(() =>
                    {
                        var memoryStatusLabel = Controls.Find("memoryStatusLabel", true).FirstOrDefault() as Label;
                        if (memoryStatusLabel != null)
                        {
                            memoryStatusLabel.Text = $"内存: 总计 {totalMB} MB | 可用 {availableMB} MB | 已用 {usedPercent}%";
                        }
                    }));
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SystemOptimizerPage.cs 捕获异常", ex.Message); }
            });
        }

        private string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / 1024.0 / 1024.0:F1} MB";
            return $"{bytes / 1024.0 / 1024.0 / 1024.0:F2} GB";
        }
    }
}