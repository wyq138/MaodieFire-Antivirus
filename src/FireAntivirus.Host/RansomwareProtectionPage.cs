// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Linq;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;

namespace FireAntivirus.Host
{
    public partial class RansomwareProtectionPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;
        private RansomwareProtectionService _protectionService;
        private ListView _foldersListView;
        private ListView _suspiciousFilesListView;
        private Label _statusLabel;
        private CheckBox _enableProtectionCheckBox;
        private CheckBox _protectDocumentsCheckBox;

        public RansomwareProtectionPage()
        {
            InitializeComponent();
            InitializeService();
            UpdateUI();
        }

        private void InitializeService()
        {
            _protectionService = new RansomwareProtectionService();
            _protectionService.RansomwareDetected += OnRansomwareDetected;
            _protectionService.FileChanged += OnFileChanged;
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // RansomwareProtectionPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "RansomwareProtectionPage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
                if (_foldersListView != null)
                {
                    _foldersListView.BackColor = Color.FromArgb(45, 45, 45);
                    _foldersListView.ForeColor = Color.White;
                }
                if (_suspiciousFilesListView != null)
                {
                    _suspiciousFilesListView.BackColor = Color.FromArgb(45, 45, 45);
                    _suspiciousFilesListView.ForeColor = Color.White;
                }
            }
            else
            {
                this.BackColor = Color.White;
                if (_foldersListView != null)
                {
                    _foldersListView.BackColor = Color.White;
                    _foldersListView.ForeColor = Color.Black;
                }
                if (_suspiciousFilesListView != null)
                {
                    _suspiciousFilesListView.BackColor = Color.White;
                    _suspiciousFilesListView.ForeColor = Color.Black;
                }
            }
        }

        private void UpdateUI()
        {
            this.Controls.Clear();

            // 标题
            var titleLabel = new Label
            {
                Text = "勒索防护",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(244, 67, 54),
                Location = new Point(20, 15),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 描述
            var descriptionLabel = new Label
            {
                Text = "保护您的文件免受勒索软件攻击",
                Font = new Font("微软雅黑", 10),
                ForeColor = Color.Gray,
                Location = new Point(20, 45),
                AutoSize = true
            };
            this.Controls.Add(descriptionLabel);

            // 状态栏
            _statusLabel = new Label
            {
                Text = "防护状态: 未启用",
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.Orange,
                Location = new Point(20, 70),
                AutoSize = true
            };
            this.Controls.Add(_statusLabel);

            // 设置面板
            var settingsPanel = new Panel
            {
                Location = new Point(20, 95),
                Size = new Size(320, 150),
                BackColor = Color.FromArgb(240, 240, 240)
            };
            this.Controls.Add(settingsPanel);

            var settingsTitle = new Label
            {
                Text = "防护设置",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(60, 60, 60),
                Location = new Point(10, 5),
                AutoSize = true
            };
            settingsPanel.Controls.Add(settingsTitle);

            _enableProtectionCheckBox = new CheckBox
            {
                Text = "启用勒索防护",
                Location = new Point(10, 30),
                Size = new Size(200, 25),
                Font = new Font("微软雅黑", 9)
            };
            _enableProtectionCheckBox.CheckedChanged += EnableProtectionCheckBox_CheckedChanged;
            settingsPanel.Controls.Add(_enableProtectionCheckBox);

            _protectDocumentsCheckBox = new CheckBox
            {
                Text = "自动保护文档文件夹",
                Location = new Point(10, 60),
                Size = new Size(200, 25),
                Font = new Font("微软雅黑", 9),
                Checked = true
            };
            settingsPanel.Controls.Add(_protectDocumentsCheckBox);

            var scanButton = new Button
            {
                Text = "扫描可疑文件",
                Location = new Point(10, 95),
                Size = new Size(130, 35),
                BackColor = Color.FromArgb(255, 152, 0),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            scanButton.FlatAppearance.BorderSize = 0;
            scanButton.Click += ScanButton_Click;
            settingsPanel.Controls.Add(scanButton);

            var extensionsButton = new Button
            {
                Text = "扩展名管理",
                Location = new Point(150, 95),
                Size = new Size(110, 35),
                BackColor = Color.FromArgb(156, 39, 176),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            extensionsButton.FlatAppearance.BorderSize = 0;
            extensionsButton.Click += ExtensionsButton_Click;
            settingsPanel.Controls.Add(extensionsButton);

            // 操作面板
            var actionPanel = new Panel
            {
                Location = new Point(360, 95),
                Size = new Size(320, 150),
                BackColor = Color.FromArgb(240, 240, 240)
            };
            this.Controls.Add(actionPanel);

            var actionTitle = new Label
            {
                Text = "防护操作",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(60, 60, 60),
                Location = new Point(10, 5),
                AutoSize = true
            };
            actionPanel.Controls.Add(actionTitle);

            var addFolderButton = new Button
            {
                Text = "添加受保护文件夹",
                Location = new Point(10, 30),
                Size = new Size(145, 35),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            addFolderButton.FlatAppearance.BorderSize = 0;
            addFolderButton.Click += AddProtectedFolderButton_Click;
            actionPanel.Controls.Add(addFolderButton);

            var removeFolderButton = new Button
            {
                Text = "移除选中文件夹",
                Location = new Point(165, 30),
                Size = new Size(145, 35),
                BackColor = Color.FromArgb(244, 67, 54),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            removeFolderButton.FlatAppearance.BorderSize = 0;
            removeFolderButton.Click += RemoveProtectedFolderButton_Click;
            actionPanel.Controls.Add(removeFolderButton);

            var backupButton = new Button
            {
                Text = "创建文件备份",
                Location = new Point(10, 75),
                Size = new Size(145, 35),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            backupButton.FlatAppearance.BorderSize = 0;
            backupButton.Click += BackupButton_Click;
            actionPanel.Controls.Add(backupButton);

            var restoreButton = new Button
            {
                Text = "恢复文件",
                Location = new Point(165, 75),
                Size = new Size(145, 35),
                BackColor = Color.FromArgb(0, 150, 136),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            restoreButton.FlatAppearance.BorderSize = 0;
            restoreButton.Click += RestoreButton_Click;
            actionPanel.Controls.Add(restoreButton);

            // 受保护文件夹列表
            var foldersLabel = new Label
            {
                Text = "受保护文件夹",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(60, 60, 60),
                Location = new Point(20, 255),
                AutoSize = true
            };
            this.Controls.Add(foldersLabel);

            _foldersListView = new ListView
            {
                Location = new Point(20, 280),
                Size = new Size(320, 180),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                Font = new Font("微软雅黑", 9)
            };
            _foldersListView.Columns.Add("文件夹路径", 280);
            this.Controls.Add(_foldersListView);

            // 可疑文件列表
            var suspiciousLabel = new Label
            {
                Text = "检测结果",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(60, 60, 60),
                Location = new Point(360, 255),
                AutoSize = true
            };
            this.Controls.Add(suspiciousLabel);

            _suspiciousFilesListView = new ListView
            {
                Location = new Point(360, 280),
                Size = new Size(320, 180),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                Font = new Font("微软雅黑", 9)
            };
            _suspiciousFilesListView.Columns.Add("文件", 200);
            _suspiciousFilesListView.Columns.Add("原因", 100);
            this.Controls.Add(_suspiciousFilesListView);

            // 应用按钮
            var applyButton = new Button
            {
                Text = "应用设置",
                Location = new Point(280, 475),
                Size = new Size(120, 35),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 10)
            };
            applyButton.FlatAppearance.BorderSize = 0;
            applyButton.Click += ApplySettings;
            this.Controls.Add(applyButton);

            // 加载受保护文件夹
            LoadProtectedFolders();
        }

        private void LoadProtectedFolders()
        {
            _foldersListView.Items.Clear();
            var folders = _protectionService.GetProtectedFolders();
            
            foreach (var folder in folders)
            {
                var item = new ListViewItem(folder);
                _foldersListView.Items.Add(item);
            }
        }

        private void EnableProtectionCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (_enableProtectionCheckBox.Checked)
            {
                _protectionService.EnableProtection();
                _statusLabel.Text = "防护状态: 已启用 ✓";
                _statusLabel.ForeColor = Color.Green;
            }
            else
            {
                _protectionService.DisableProtection();
                _statusLabel.Text = "防护状态: 未启用";
                _statusLabel.ForeColor = Color.Orange;
            }
        }

        private void ScanButton_Click(object sender, EventArgs e)
        {
            _statusLabel.Text = "正在扫描...";
            _suspiciousFilesListView.Items.Clear();
            Application.DoEvents();

            var result = _protectionService.ScanForRansomware();

            foreach (var file in result.SuspiciousFiles)
            {
                var item = new ListViewItem(System.IO.Path.GetFileName(file.FilePath));
                item.SubItems.Add(file.Reason);
                item.ForeColor = Color.Red;
                item.Tag = file.FilePath;
                _suspiciousFilesListView.Items.Add(item);
            }

            _statusLabel.Text = $"扫描完成 - 发现 {result.ThreatsFound} 个可疑文件";
            
            if (result.ThreatsFound > 0)
            {
                _statusLabel.ForeColor = Color.Red;
            }
            else
            {
                _statusLabel.ForeColor = Color.Green;
            }
        }

        private void ExtensionsButton_Click(object sender, EventArgs e)
        {
            var extensionsForm = new Form
            {
                Text = "可疑扩展名管理",
                Size = new Size(400, 450),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.Sizable
            };

            var listBox = new ListBox
            {
                Location = new Point(20, 20),
                Size = new Size(340, 300)
            };

            foreach (var ext in _protectionService.GetSuspiciousExtensions())
                listBox.Items.Add(ext);

            extensionsForm.Controls.Add(listBox);

            var addTextBox = new TextBox
            {
                Location = new Point(20, 330),
                Size = new Size(240, 25),
                PlaceholderText = "输入扩展名 (如: .xxx)"
            };
            extensionsForm.Controls.Add(addTextBox);

            var addButton = new Button
            {
                Text = "添加",
                Location = new Point(270, 328),
                Size = new Size(90, 28),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            addButton.FlatAppearance.BorderSize = 0;
            addButton.Click += (s, args) =>
            {
                var ext = addTextBox.Text.Trim();
                if (!string.IsNullOrEmpty(ext))
                {
                    _protectionService.AddSuspiciousExtension(ext);
                    listBox.Items.Add(ext.StartsWith(".") ? ext : "." + ext);
                    addTextBox.Clear();
                }
            };
            extensionsForm.Controls.Add(addButton);

            var closeButton = new Button
            {
                Text = "关闭",
                Location = new Point(150, 370),
                Size = new Size(100, 30),
                DialogResult = DialogResult.OK
            };
            extensionsForm.Controls.Add(closeButton);

            extensionsForm.ShowDialog();
        }

        private void AddProtectedFolderButton_Click(object sender, EventArgs e)
        {
            var dialog = new FolderBrowserDialog
            {
                Description = "选择要保护的文件夹",
                ShowNewFolderButton = true
            };

            if (dialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    _protectionService.AddProtectedFolder(dialog.SelectedPath);
                    LoadProtectedFolders();
                    MessageBox.Show($"已添加保护文件夹:\n{dialog.SelectedPath}", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"添加失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void RemoveProtectedFolderButton_Click(object sender, EventArgs e)
        {
            if (_foldersListView.SelectedItems.Count == 0)
            {
                MessageBox.Show("请先选择要移除的文件夹", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var folder = _foldersListView.SelectedItems[0].Text;
            var result = MessageBox.Show($"确定要移除此文件夹的保护吗？\n\n{folder}", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

            if (result == DialogResult.Yes)
            {
                _protectionService.RemoveProtectedFolder(folder);
                LoadProtectedFolders();
            }
        }

        private void BackupButton_Click(object sender, EventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "选择要备份的文件",
                Filter = "所有文件|*.*"
            };

            if (dialog.ShowDialog() == DialogResult.OK)
            {
                _protectionService.BackupFile(dialog.FileName);
                MessageBox.Show("文件已备份", "完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void RestoreButton_Click(object sender, EventArgs e)
        {
            var backups = _protectionService.GetBackupList();
            if (backups.Count == 0)
            {
                MessageBox.Show("暂无可恢复的备份文件", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var restoreForm = new Form
            {
                Text = "选择要恢复的文件",
                Size = new Size(500, 350),
                StartPosition = FormStartPosition.CenterParent
            };

            var listView = new ListView
            {
                Location = new Point(20, 20),
                Size = new Size(440, 200),
                View = View.Details,
                FullRowSelect = true
            };
            listView.Columns.Add("原路径", 250);
            listView.Columns.Add("备份时间", 120);
            listView.Columns.Add("大小", 60);

            foreach (var backup in backups)
            {
                var item = new ListViewItem(backup.OriginalPath);
                item.SubItems.Add(backup.BackupTime.ToString("yyyy-MM-dd HH:mm"));
                item.SubItems.Add(FormatFileSize(backup.OriginalSize));
                item.Tag = backup;
                listView.Items.Add(item);
            }

            restoreForm.Controls.Add(listView);

            var restoreBtn = new Button
            {
                Text = "恢复选中文件",
                Location = new Point(150, 240),
                Size = new Size(120, 35),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            restoreBtn.FlatAppearance.BorderSize = 0;
            restoreBtn.Click += (s, args) =>
            {
                if (listView.SelectedItems.Count > 0)
                {
                    var backup = (FileBackupInfo)listView.SelectedItems[0].Tag;
                    if (_protectionService.TryRestoreFile(backup.OriginalPath))
                    {
                        MessageBox.Show("文件恢复成功!", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show("文件恢复失败", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            };
            restoreForm.Controls.Add(restoreBtn);

            restoreForm.ShowDialog();
        }

        private void ApplySettings(object sender, EventArgs e)
        {
            var settings = _protectionService.GetSettings();
            settings.ProtectDocuments = _protectDocumentsCheckBox.Checked;
            settings.IsEnabled = _enableProtectionCheckBox.Checked;
            _protectionService.UpdateSettings(settings);
            MessageBox.Show("设置已保存", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void OnRansomwareDetected(object sender, RansomwareDetectedEventArgs e)
        {
            // 在UI线程上显示警告
            if (this.InvokeRequired)
            {
                this.Invoke(new Action(() => OnRansomwareDetected(sender, e)));
                return;
            }

            var result = MessageBox.Show(
                $"⚠️ 检测到勒索软件活动!\n\n" +
                $"文件: {e.FilePath}\n" +
                $"原因: {e.Reason}\n" +
                $"时间: {e.Timestamp:HH:mm:ss}\n\n" +
                $"是否尝试恢复文件?",
                "勒索软件警告",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result == DialogResult.Yes)
            {
                _protectionService.TryRestoreFile(e.FilePath);
            }

            // 更新状态
            _statusLabel.Text = $"警告: {e.Reason}";
            _statusLabel.ForeColor = Color.Red;
        }

        private void OnFileChanged(object sender, FileChangedEventArgs e)
        {
            // 可选: 记录文件变更
            System.Diagnostics.Debug.WriteLine($"文件变更: {e.FilePath} - {e.ChangeType}");
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
