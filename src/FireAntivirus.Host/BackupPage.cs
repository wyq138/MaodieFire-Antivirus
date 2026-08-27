// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;
using FireAntivirus.Data;

namespace FireAntivirus.Host
{
    public partial class BackupPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;

        public BackupPage()
        {
            InitializeComponent();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // BackupPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "BackupPage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        public void ApplyTheme(Theme theme)
        {
            // 应用主题
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
            }
            else
            {
                this.BackColor = Color.White;
            }
        }

        private TextBox backupPathTextBox;
        private BackupService backupService;

        private void UpdateUI()
        {
            // 清空现有控件
            this.Controls.Clear();

            // 创建标题
            var titleLabel = new Label
            {
                Text = "备份恢复",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 创建描述
            var descriptionLabel = new Label
            {
                Text = "备份重要文件和系统设置",
                Font = new Font("微软雅黑", 12),
                ForeColor = Color.Gray,
                Location = new Point(20, 50),
                AutoSize = true
            };
            this.Controls.Add(descriptionLabel);

            // 创建功能区域
            var featurePanel = new Panel
            {
                Location = new Point(20, 80),
                Size = new Size(660, 480),
                BackColor = Color.Transparent
            };
            this.Controls.Add(featurePanel);

            // 备份设置
            var backupGroup = new GroupBox
            {
                Text = "备份设置",
                Location = new Point(0, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(backupGroup);

            var backupPathLabel = new Label
            {
                Text = "备份路径:",
                Location = new Point(10, 30),
                AutoSize = true
            };
            backupGroup.Controls.Add(backupPathLabel);

            backupPathTextBox = new TextBox
            {
                Location = new Point(80, 30),
                Size = new Size(180, 20)
            };
            backupGroup.Controls.Add(backupPathTextBox);

            var selectPathButton = new Button
            {
                Text = "浏览",
                Location = new Point(260, 28),
                Size = new Size(50, 20)
            };
            selectPathButton.Click += SelectPathButton_Click;
            backupGroup.Controls.Add(selectPathButton);

            // 备份操作
            var backupOperationGroup = new GroupBox
            {
                Text = "备份操作",
                Location = new Point(340, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(backupOperationGroup);

            var createBackupButton = new Button
            {
                Text = "创建备份",
                Location = new Point(10, 30),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            createBackupButton.FlatAppearance.BorderSize = 0;
            createBackupButton.Click += CreateBackupButton_Click;
            backupOperationGroup.Controls.Add(createBackupButton);

            var restoreBackupButton = new Button
            {
                Text = "恢复备份",
                Location = new Point(10, 70),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            restoreBackupButton.FlatAppearance.BorderSize = 0;
            restoreBackupButton.Click += RestoreBackupButton_Click;
            backupOperationGroup.Controls.Add(restoreBackupButton);

            // 应用按钮
            var applyButton = new Button
            {
                Text = "应用设置",
                Location = new Point(250, 200),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            applyButton.FlatAppearance.BorderSize = 0;
            applyButton.Click += ApplyButton_Click;
            featurePanel.Controls.Add(applyButton);

            // 初始化备份服务
            InitializeBackupService();
        }

        private void InitializeBackupService()
        {
            try
            {
                var dataManager = new DataManager();
                backupService = new BackupService(dataManager);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"初始化备份服务失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SelectPathButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 选择路径
                using (var folderBrowser = new FolderBrowserDialog())
                {
                    if (folderBrowser.ShowDialog() == DialogResult.OK)
                    {
                        backupPathTextBox.Text = folderBrowser.SelectedPath;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"选择路径失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void CreateBackupButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 创建备份
                string backupPath = backupPathTextBox.Text;
                if (string.IsNullOrEmpty(backupPath))
                {
                    MessageBox.Show("请选择备份路径", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                
                // 创建备份任务
                var sourcePaths = new List<string>();
                sourcePaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
                sourcePaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
                
                backupService.CreateBackupTask("手动备份", sourcePaths, "手动");
                MessageBox.Show("备份任务创建成功", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"创建备份失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RestoreBackupButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 恢复备份
                string backupPath = backupPathTextBox.Text;
                if (string.IsNullOrEmpty(backupPath))
                {
                    MessageBox.Show("请选择备份路径", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                
                // 恢复到原位置
                string targetPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                backupService.RestoreBackup(backupPath, targetPath);
                MessageBox.Show("备份恢复成功", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"恢复备份失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ApplyButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 应用设置
                var dataManager = new DataManager();
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "BackupSettings",
                    Message = "备份设置已更新",
                    Details = $"备份路径: {backupPathTextBox.Text}"
                });
                
                MessageBox.Show("备份设置已应用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}