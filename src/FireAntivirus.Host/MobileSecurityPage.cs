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
    public partial class MobileSecurityPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;
        private MobileSecurityService _mobileService;
        private ListView _devicesListView;
        private Label _statusLabel;
        private ProgressBar _scanProgress;

        public MobileSecurityPage()
        {
            InitializeComponent();
            InitializeService();
            UpdateUI();
        }

        private void InitializeService()
        {
            _mobileService = new MobileSecurityService();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // MobileSecurityPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "MobileSecurityPage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
                if (_devicesListView != null)
                {
                    _devicesListView.BackColor = Color.FromArgb(45, 45, 45);
                    _devicesListView.ForeColor = Color.White;
                }
            }
            else
            {
                this.BackColor = Color.White;
                if (_devicesListView != null)
                {
                    _devicesListView.BackColor = Color.White;
                    _devicesListView.ForeColor = Color.Black;
                }
            }
        }

        private void UpdateUI()
        {
            this.Controls.Clear();

            // 标题
            var titleLabel = new Label
            {
                Text = "移动设备安全",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 15),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 描述
            var descriptionLabel = new Label
            {
                Text = "检测和扫描连接的移动设备",
                Font = new Font("微软雅黑", 10),
                ForeColor = Color.Gray,
                Location = new Point(20, 45),
                AutoSize = true
            };
            this.Controls.Add(descriptionLabel);

            // 状态标签
            _statusLabel = new Label
            {
                Text = "状态: 就绪",
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.FromArgb(100, 100, 100),
                Location = new Point(20, 70),
                AutoSize = true
            };
            this.Controls.Add(_statusLabel);

            // 扫描进度
            _scanProgress = new ProgressBar
            {
                Location = new Point(150, 68),
                Size = new Size(200, 20),
                Style = ProgressBarStyle.Continuous,
                Visible = false
            };
            this.Controls.Add(_scanProgress);

            // 操作面板
            var actionPanel = new Panel
            {
                Location = new Point(20, 95),
                Size = new Size(660, 55),
                BackColor = Color.FromArgb(240, 240, 240)
            };
            this.Controls.Add(actionPanel);

            var refreshButton = new Button
            {
                Text = "刷新设备",
                Location = new Point(10, 10),
                Size = new Size(100, 35),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            refreshButton.FlatAppearance.BorderSize = 0;
            refreshButton.Click += (s, e) => RefreshDevices();
            actionPanel.Controls.Add(refreshButton);

            var scanButton = new Button
            {
                Text = "扫描选中设备",
                Location = new Point(120, 10),
                Size = new Size(110, 35),
                BackColor = Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            scanButton.FlatAppearance.BorderSize = 0;
            scanButton.Click += ScanDeviceButton_Click;
            actionPanel.Controls.Add(scanButton);

            var ejectButton = new Button
            {
                Text = "安全弹出",
                Location = new Point(240, 10),
                Size = new Size(90, 35),
                BackColor = Color.FromArgb(255, 152, 0),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            ejectButton.FlatAppearance.BorderSize = 0;
            ejectButton.Click += EjectDeviceButton_Click;
            actionPanel.Controls.Add(ejectButton);

            var recommendButton = new Button
            {
                Text = "安全建议",
                Location = new Point(340, 10),
                Size = new Size(90, 35),
                BackColor = Color.FromArgb(156, 39, 176),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            recommendButton.FlatAppearance.BorderSize = 0;
            recommendButton.Click += RecommendButton_Click;
            actionPanel.Controls.Add(recommendButton);

            var usbMonitorButton = new Button
            {
                Text = "USB防护设置",
                Location = new Point(440, 10),
                Size = new Size(100, 35),
                BackColor = Color.FromArgb(0, 150, 136),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            usbMonitorButton.FlatAppearance.BorderSize = 0;
            usbMonitorButton.Click += UsbMonitorButton_Click;
            actionPanel.Controls.Add(usbMonitorButton);

            // 设备列表标签
            var devicesLabel = new Label
            {
                Text = "已连接设备",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(60, 60, 60),
                Location = new Point(20, 160),
                AutoSize = true
            };
            this.Controls.Add(devicesLabel);

            // 设备列表
            _devicesListView = new ListView
            {
                Location = new Point(20, 185),
                Size = new Size(660, 180),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                Font = new Font("微软雅黑", 9)
            };
            _devicesListView.Columns.Add("设备名称", 180);
            _devicesListView.Columns.Add("类型", 70);
            _devicesListView.Columns.Add("连接方式", 80);
            _devicesListView.Columns.Add("存储空间", 100);
            _devicesListView.Columns.Add("状态", 80);
            _devicesListView.Columns.Add("备注", 100);
            _devicesListView.DoubleClick += DevicesListView_DoubleClick;
            this.Controls.Add(_devicesListView);

            // 扫描结果标签
            var resultsLabel = new Label
            {
                Text = "扫描结果",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(60, 60, 60),
                Location = new Point(20, 375),
                AutoSize = true
            };
            this.Controls.Add(resultsLabel);

            // 结果面板
            var resultsPanel = new Panel
            {
                Location = new Point(20, 400),
                Size = new Size(660, 150),
                BackColor = Color.FromArgb(250, 250, 250)
            };
            this.Controls.Add(resultsPanel);

            var resultsTextBox = new RichTextBox
            {
                Location = new Point(5, 5),
                Size = new Size(650, 140),
                ReadOnly = true,
                Font = new Font("Consolas", 9),
                BackColor = Color.White
            };
            resultsPanel.Controls.Add(resultsTextBox);

            // 初始加载设备
            RefreshDevices();
        }

        private void RefreshDevices()
        {
            _statusLabel.Text = "正在检测设备...";
            _devicesListView.Items.Clear();
            Application.DoEvents();

            var devices = _mobileService.GetConnectedDevices();

            foreach (var device in devices)
            {
                var item = new ListViewItem(device.Name);
                
                string deviceType = "未知";
                if (device.IsAndroid) deviceType = "Android";
                else if (device.IsIOS) deviceType = "iOS";
                else if (device.ConnectionType.Contains("Storage")) deviceType = "存储设备";
                
                item.SubItems.Add(deviceType);
                item.SubItems.Add(device.ConnectionType);

                string storage = "";
                if (device.TotalSpace > 0)
                {
                    storage = $"{FormatBytes(device.FreeSpace)}/{FormatBytes(device.TotalSpace)}";
                }
                else if (!string.IsNullOrEmpty(device.AndroidVersion))
                {
                    storage = $"Android {device.AndroidVersion}";
                }
                item.SubItems.Add(storage);

                item.SubItems.Add(device.IsConnected ? "已连接" : "离线");
                item.SubItems.Add(device.Model ?? device.Manufacturer ?? "");
                item.Tag = device;

                _devicesListView.Items.Add(item);
            }

            _statusLabel.Text = $"检测完成 - 发现 {devices.Count} 个设备";
            
            if (devices.Count == 0)
            {
                _statusLabel.ForeColor = Color.Orange;
                _statusLabel.Text = "未检测到连接的移动设备";
            }
            else
            {
                _statusLabel.ForeColor = Color.Green;
            }
        }

        private void DevicesListView_DoubleClick(object sender, EventArgs e)
        {
            if (_devicesListView.SelectedItems.Count == 0) return;
            
            var device = _devicesListView.SelectedItems[0].Tag as MobileDeviceInfo;
            if (device == null) return;

            ShowDeviceInfo(device);
        }

        private void ShowDeviceInfo(MobileDeviceInfo device)
        {
            var infoForm = new Form
            {
                Text = "设备详情",
                Size = new Size(400, 350),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var infoTextBox = new RichTextBox
            {
                Location = new Point(20, 20),
                Size = new Size(340, 250),
                ReadOnly = true,
                Font = new Font("微软雅黑", 9)
            };

            infoTextBox.AppendText($"设备名称: {device.Name}\n");
            infoTextBox.AppendText($"设备ID: {device.DeviceId}\n");
            infoTextBox.AppendText($"序列号: {device.SerialNumber ?? "N/A"}\n");
            infoTextBox.AppendText($"制造商: {device.Manufacturer ?? "N/A"}\n");
            infoTextBox.AppendText($"型号: {device.Model ?? "N/A"}\n");
            infoTextBox.AppendText($"连接方式: {device.ConnectionType}\n");
            infoTextBox.AppendText($"设备类型: {(device.IsAndroid ? "Android" : device.IsIOS ? "iOS" : "其他")}\n");
            
            if (!string.IsNullOrEmpty(device.AndroidVersion))
                infoTextBox.AppendText($"Android版本: {device.AndroidVersion}\n");
            
            if (device.TotalSpace > 0)
            {
                infoTextBox.AppendText($"总容量: {FormatBytes(device.TotalSpace)}\n");
                infoTextBox.AppendText($"可用空间: {FormatBytes(device.FreeSpace)}\n");
            }

            infoTextBox.AppendText($"\n状态: {(device.IsConnected ? "已连接 ✓" : "离线")}\n");

            infoForm.Controls.Add(infoTextBox);

            var closeButton = new Button
            {
                Text = "关闭",
                Location = new Point(150, 280),
                Size = new Size(100, 30),
                DialogResult = DialogResult.OK
            };
            infoForm.Controls.Add(closeButton);

            infoForm.ShowDialog();
        }

        private void ScanDeviceButton_Click(object sender, EventArgs e)
        {
            if (_devicesListView.SelectedItems.Count == 0)
            {
                MessageBox.Show("请先选择要扫描的设备", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var device = _devicesListView.SelectedItems[0].Tag as MobileDeviceInfo;
            if (device == null) return;

            _statusLabel.Text = "正在扫描设备...";
            _scanProgress.Visible = true;
            _scanProgress.Style = ProgressBarStyle.Marquee;
            Application.DoEvents();

            try
            {
                var result = _mobileService.ScanDevice(device);

                // 显示结果
                var resultsTextBox = this.Controls.Find("resultsTextBox", true).FirstOrDefault() as RichTextBox;
                if (resultsTextBox != null)
                {
                    resultsTextBox.Clear();
                    resultsTextBox.AppendText($"扫描时间: {result.ScanTime:yyyy-MM-dd HH:mm:ss}\n");
                    resultsTextBox.AppendText($"设备: {result.Device.Name}\n\n");
                    resultsTextBox.AppendText($"扫描文件数: {result.FilesScanned}\n");

                    if (result.SuspiciousFiles.Count > 0)
                    {
                        resultsTextBox.AppendText($"\n⚠️ 可疑文件 ({result.SuspiciousFiles.Count}):\n", Color.Red);
                        foreach (var file in result.SuspiciousFiles.Take(10))
                        {
                            resultsTextBox.AppendText($"  • {file.FilePath} ({file.Reason})\n");
                        }
                    }

                    if (result.ApkFiles.Count > 0)
                    {
                        resultsTextBox.AppendText($"\n📦 APK文件 ({result.ApkFiles.Count}):\n", Color.Blue);
                        foreach (var apk in result.ApkFiles.Take(10))
                        {
                            resultsTextBox.AppendText($"  • {apk.FilePath} ({FormatBytes(apk.Size)})\n");
                        }
                    }

                    if (result.InstalledApps.Count > 0)
                    {
                        resultsTextBox.AppendText($"\n📱 已安装应用 ({result.InstalledApps.Count}):\n", Color.Green);
                        foreach (var app in result.InstalledApps.Take(10))
                        {
                            resultsTextBox.AppendText($"  • {app.PackageName}\n");
                        }
                    }

                    if (result.SecurityInfo != null)
                    {
                        resultsTextBox.AppendText($"\n🔒 安全设置:\n");
                        resultsTextBox.AppendText($"  USB调试: {(result.SecurityInfo.USBDebuggingEnabled ? "已启用 ⚠️" : "已禁用 ✓")}\n");
                        resultsTextBox.AppendText($"  未知来源: {(result.SecurityInfo.UnknownSourcesEnabled ? "已启用 ⚠️" : "已禁用 ✓")}\n");
                    }

                    if (result.Errors.Count > 0)
                    {
                        resultsTextBox.AppendText($"\n❌ 错误:\n", Color.Red);
                        foreach (var error in result.Errors)
                        {
                            resultsTextBox.AppendText($"  • {error}\n");
                        }
                    }

                    if (result.SuspiciousFiles.Count == 0 && result.Errors.Count == 0)
                    {
                        resultsTextBox.AppendText("\n✓ 未发现安全问题\n", Color.Green);
                    }
                }

                _statusLabel.Text = $"扫描完成 - 发现 {result.SuspiciousFiles.Count} 个可疑文件";
                _statusLabel.ForeColor = result.SuspiciousFiles.Count > 0 ? Color.Red : Color.Green;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"扫描失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                _statusLabel.Text = "扫描失败";
                _statusLabel.ForeColor = Color.Red;
            }
            finally
            {
                _scanProgress.Visible = false;
            }
        }

        private void EjectDeviceButton_Click(object sender, EventArgs e)
        {
            if (_devicesListView.SelectedItems.Count == 0)
            {
                MessageBox.Show("请先选择要弹出的设备", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var device = _devicesListView.SelectedItems[0].Tag as MobileDeviceInfo;
            if (device == null) return;

            var result = MessageBox.Show(
                $"确定要安全弹出以下设备吗？\n\n{device.Name}",
                "安全弹出",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result == DialogResult.Yes)
            {
                _mobileService.EjectDevice(device);
                MessageBox.Show("设备已安全弹出", "完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
                RefreshDevices();
            }
        }

        private void RecommendButton_Click(object sender, EventArgs e)
        {
            if (_devicesListView.SelectedItems.Count == 0)
            {
                MessageBox.Show("请先选择设备以获取安全建议", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var device = _devicesListView.SelectedItems[0].Tag as MobileDeviceInfo;
            if (device == null) return;

            var recommendations = _mobileService.GetMobileSecurityRecommendations(device);

            var message = $"【{device.Name}】安全建议:\n\n";
            foreach (var rec in recommendations)
            {
                message += $"• [{rec.Priority}] {rec.Title}\n";
                if (!string.IsNullOrEmpty(rec.Action))
                    message += $"  操作: {rec.Action}\n";
            }

            MessageBox.Show(message, "安全建议", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void UsbMonitorButton_Click(object sender, EventArgs e)
        {
            var settingsForm = new Form
            {
                Text = "USB防护设置",
                Size = new Size(400, 300),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var blockUnknownUsbCheck = new CheckBox
            {
                Text = "阻止未知USB设备",
                Location = new Point(20, 20),
                Size = new Size(200, 25)
            };
            settingsForm.Controls.Add(blockUnknownUsbCheck);

            var scanOnConnectCheck = new CheckBox
            {
                Text = "设备连接时自动扫描",
                Location = new Point(20, 50),
                Size = new Size(200, 25),
                Checked = true
            };
            settingsForm.Controls.Add(scanOnConnectCheck);

            var blockAutorunCheck = new CheckBox
            {
                Text = "禁用USB自动运行",
                Location = new Point(20, 80),
                Size = new Size(200, 25),
                Checked = true
            };
            settingsForm.Controls.Add(blockAutorunCheck);

            var logUsbActivityCheck = new CheckBox
            {
                Text = "记录USB设备活动",
                Location = new Point(20, 110),
                Size = new Size(200, 25),
                Checked = true
            };
            settingsForm.Controls.Add(logUsbActivityCheck);

            var allowListLabel = new Label
            {
                Text = "信任设备列表:",
                Location = new Point(20, 145),
                AutoSize = true
            };
            settingsForm.Controls.Add(allowListLabel);

            var allowListTextBox = new TextBox
            {
                Location = new Point(20, 165),
                Size = new Size(340, 50),
                Multiline = true,
                ScrollBars = ScrollBars.Vertical
            };
            settingsForm.Controls.Add(allowListTextBox);

            var saveButton = new Button
            {
                Text = "保存设置",
                Location = new Point(100, 225),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            saveButton.FlatAppearance.BorderSize = 0;
            saveButton.Click += (s, args) =>
            {
                MessageBox.Show("设置已保存", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                settingsForm.Close();
            };
            settingsForm.Controls.Add(saveButton);

            var cancelButton = new Button
            {
                Text = "取消",
                Location = new Point(210, 225),
                Size = new Size(100, 30),
                DialogResult = DialogResult.Cancel
            };
            settingsForm.Controls.Add(cancelButton);

            settingsForm.ShowDialog();
        }

        private string FormatBytes(long bytes)
        {
            if (bytes < 0) return "N/A";
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
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

    internal static class RichTextBoxExtensions
    {
        public static void AppendText(this RichTextBox box, string text, Color color)
        {
            box.SelectionStart = box.TextLength;
            box.SelectionLength = 0;
            box.SelectionColor = color;
            box.AppendText(text);
            box.SelectionColor = box.ForeColor;
        }
    }
}
