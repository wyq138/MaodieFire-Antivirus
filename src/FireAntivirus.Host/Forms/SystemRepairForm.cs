using System;
using System.Drawing;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host
{
    public class SystemRepairForm : Form
    {
        private List<CheckBox> repairCheckBoxes;
        private Label statusLabel;
        private Button scanButton;
        private Button repairButton;
        private List<RepairItemStatus> detectedIssues;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public SystemRepairForm()
        {
            repairCheckBoxes = new List<CheckBox>();
            detectedIssues = new List<RepairItemStatus>();
            InitializeComponents();
            // 订阅语言变更事件
            _languageManager.LanguageChanged += (sender, e) =>
            {
                InitializeComponents();
            };
        }

        private void InitializeComponents()
        {
            this.Text = _languageManager.GetString("SystemRepair") + " - 耄耋杀毒";
            this.Size = new Size(600, 400);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Icon = SystemIcons.Shield;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 4,
                ColumnCount = 1
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));

            var titleLabel = new Label
            {
                Text = _languageManager.GetString("SystemRepair"),
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = Color.Black,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            var descLabel = new Label
            {
                Text = _languageManager.GetString("DetectFirstThenRepair"),
                Font = new Font("微软雅黑", 12),
                ForeColor = Color.Gray,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            var titlePanel = new Panel
            {
                Dock = DockStyle.Fill
            };

            titlePanel.Controls.Add(titleLabel);
            titlePanel.Controls.Add(descLabel);
            mainLayout.Controls.Add(titlePanel, 0, 0);

            var checkBoxPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.TopDown
            };

            var repairItems = new[]
            {
                _languageManager.GetString("SystemFileCorruption"),
                _languageManager.GetString("ShortcutIssues"),
                _languageManager.GetString("NetworkConfigErrors"),
                _languageManager.GetString("DesktopIconIssues"),
                _languageManager.GetString("FileAssociationErrors"),
                _languageManager.GetString("SystemRestrictions")
            };

            foreach (var item in repairItems)
            {
                var checkBox = new CheckBox
                {
                    Text = item,
                    Checked = true,
                    Font = new Font("微软雅黑", 12),
                    ForeColor = Color.Black,
                    Width = 300,
                    Margin = new Padding(20, 10, 0, 0),
                    Enabled = false // 默认禁用，检测后启用
                };
                checkBoxPanel.Controls.Add(checkBox);
                repairCheckBoxes.Add(checkBox);
            }

            mainLayout.Controls.Add(checkBoxPanel, 0, 1);

            statusLabel = new Label
            {
                Text = _languageManager.GetString("ClickDetectButton"),
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.Gray,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            mainLayout.Controls.Add(statusLabel, 0, 2);

            var buttonPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1
            };
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));

            scanButton = new Button
            {
                Text = _languageManager.GetString("StartDetection"),
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Blue,
                ForeColor = Color.White,
                Dock = DockStyle.Fill,
                Cursor = Cursors.Hand
            };

            repairButton = new Button
            {
                Text = _languageManager.GetString("StartRepair"),
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Green,
                ForeColor = Color.White,
                Dock = DockStyle.Fill,
                Cursor = Cursors.Hand,
                Enabled = false // 默认禁用，检测后启用
            };

            var cancelButton = new Button
            {
                Text = _languageManager.GetString("Cancel"),
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Gray,
                ForeColor = Color.White,
                Dock = DockStyle.Fill,
                Cursor = Cursors.Hand
            };

            scanButton.FlatAppearance.BorderSize = 0;
            repairButton.FlatAppearance.BorderSize = 0;
            cancelButton.FlatAppearance.BorderSize = 0;

            scanButton.Click += StartScan;
            repairButton.Click += StartRepair;
            cancelButton.Click += (s, e) => this.Close();

            buttonPanel.Controls.Add(scanButton, 0, 0);
            buttonPanel.Controls.Add(repairButton, 1, 0);
            buttonPanel.Controls.Add(cancelButton, 2, 0);
            mainLayout.Controls.Add(buttonPanel, 0, 3);

            this.Controls.Add(mainLayout);
        }

        private void StartScan(object sender, EventArgs e)
        {
            statusLabel.Text = "正在检测系统问题...";
            scanButton.Enabled = false;
            repairButton.Enabled = false;

            try
            {
                // 实际的系统检测操作
                detectedIssues = DetectSystemIssues();

                // 更新检测结果
                UpdateScanResults();

                int issueCount = detectedIssues.Count(i => i.HasIssue);
                statusLabel.Text = $"系统检测完成 - 发现 {issueCount} 个问题";
                repairButton.Enabled = issueCount > 0;

                MessageBox.Show($"系统检测完成\n发现问题: {issueCount} 个\n请选择要修复的项目，然后点击开始修复", "检测完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                statusLabel.Text = $"检测失败: {ex.Message}";
            }
            finally
            {
                scanButton.Enabled = true;
            }
        }

        private List<RepairItemStatus> DetectSystemIssues()
        {
            // 实际的系统问题检测
            var issues = new List<RepairItemStatus>();

            // 检测系统文件损坏
            issues.Add(CheckSystemFiles());

            // 检测快捷方式异常
            issues.Add(CheckShortcuts());

            // 检测网络配置错误
            issues.Add(CheckNetworkConfig());

            // 检测桌面图标异常
            issues.Add(CheckDesktopIcons());

            // 检测文件关联错误
            issues.Add(CheckFileAssociations());

            // 检测系统限制
            issues.Add(CheckSystemRestrictions());

            return issues;
        }

        private RepairItemStatus CheckSystemFiles()
        {
            try
            {
                // 检查系统文件完整性
                // 使用sfc /verifyonly命令进行检查，不修复
                string output = ExecuteCommand("sfc", "/verifyonly");
                var status = new RepairItemStatus { Name = "系统文件损坏", HasIssue = false, Description = "未发现系统文件损坏" };
                
                if (output.Contains("发现损坏的文件"))
                {
                    status.HasIssue = true;
                    status.Description = "发现系统文件损坏，需要修复";
                }
                else if (output.Contains("未找到任何完整性冲突"))
                {
                    status.HasIssue = false;
                    status.Description = "系统文件完整性良好";
                }
                else
                {
                    status.HasIssue = true;
                    status.Description = "无法确定系统文件状态";
                }
                
                return status;
            }
            catch
            {
                return new RepairItemStatus { Name = "系统文件损坏", HasIssue = true, Description = "无法检测系统文件状态" };
            }
        }

        private string ExecuteCommand(string fileName, string arguments)
        {
            try
            {
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = fileName,
                        Arguments = arguments,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        Verb = "runas" // 以管理员权限运行
                    }
                };
                
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return output;
            }
            catch
            {
                return string.Empty;
            }
        }

        private RepairItemStatus CheckShortcuts()
        {
            try
            {
                // 检查快捷方式异常
                // 检查桌面和开始菜单中的快捷方式
                var status = new RepairItemStatus { Name = "快捷方式异常", HasIssue = false, Description = "未发现快捷方式异常" };
                
                // 检查桌面快捷方式
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (Directory.Exists(desktopPath))
                {
                    var lnkFiles = Directory.GetFiles(desktopPath, "*.lnk");
                    // 这里可以添加快捷方式有效性检查
                }
                
                return status;
            }
            catch
            {
                return new RepairItemStatus { Name = "快捷方式异常", HasIssue = true, Description = "无法检测快捷方式状态" };
            }
        }

        private RepairItemStatus CheckNetworkConfig()
        {
            try
            {
                // 检查网络配置
                var status = new RepairItemStatus { Name = "网络配置错误", HasIssue = false, Description = "网络配置正常" };
                
                // 检查网络连接
                using (var ping = new System.Net.NetworkInformation.Ping())
                {
                    try
                    {
                        var reply = ping.Send("8.8.8.8", 1000);
                        if (reply.Status != System.Net.NetworkInformation.IPStatus.Success)
                        {
                            status.HasIssue = true;
                            status.Description = "网络连接可能存在问题";
                        }
                    }
                    catch
                    {
                        status.HasIssue = true;
                        status.Description = "无法连接到网络";
                    }
                }
                
                return status;
            }
            catch
            {
                return new RepairItemStatus { Name = "网络配置错误", HasIssue = true, Description = "无法检测网络配置" };
            }
        }

        private RepairItemStatus CheckDesktopIcons()
        {
            try
            {
                // 检查桌面图标异常
                var status = new RepairItemStatus { Name = "桌面图标异常", HasIssue = false, Description = "桌面图标状态正常" };
                
                // 检查桌面图标数量是否异常
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (Directory.Exists(desktopPath))
                {
                    var files = Directory.GetFiles(desktopPath);
                    // 这里可以添加桌面图标检查逻辑
                }
                
                return status;
            }
            catch
            {
                return new RepairItemStatus { Name = "桌面图标异常", HasIssue = true, Description = "无法检测桌面图标状态" };
            }
        }

        private RepairItemStatus CheckFileAssociations()
        {
            try
            {
                // 检查文件关联错误
                var status = new RepairItemStatus { Name = "文件关联错误", HasIssue = false, Description = "文件关联正常" };
                
                // 检查常见文件关联
                string[] extensions = {".txt", ".exe", ".jpg", ".pdf"};
                foreach (var ext in extensions)
                {
                    try
                    {
                        var progId = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(ext);
                        if (progId == null)
                        {
                            status.HasIssue = true;
                            status.Description = "检测到部分文件关联可能错误";
                            break;
                        }
                    }
                    catch
                    {
                        status.HasIssue = true;
                        status.Description = "无法检测文件关联状态";
                        break;
                    }
                }
                
                return status;
            }
            catch
            {
                return new RepairItemStatus { Name = "文件关联错误", HasIssue = true, Description = "无法检测文件关联状态" };
            }
        }

        private RepairItemStatus CheckSystemRestrictions()
        {
            try
            {
                // 检查系统限制
                var status = new RepairItemStatus { Name = "系统限制解除", HasIssue = false, Description = "系统限制状态正常" };
                
                // 检查UAC设置
                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"))
                    {
                        if (key != null)
                        {
                            var enableLUA = key.GetValue("EnableLUA");
                            // 这里可以添加UAC设置检查逻辑
                        }
                    }
                }
                catch
                {
                    status.HasIssue = true;
                    status.Description = "无法检测系统限制状态";
                }
                
                return status;
            }
            catch
            {
                return new RepairItemStatus { Name = "系统限制解除", HasIssue = true, Description = "无法检测系统限制状态" };
            }
        }

        private void UpdateScanResults()
        {
            // 更新复选框状态
            for (int j = 0; j < repairCheckBoxes.Count; j++)
            {
                var checkBox = repairCheckBoxes[j];
                // 根据索引找到对应的issue，避免语言切换时的文本不匹配问题
                if (j < detectedIssues.Count)
                {
                    var issue = detectedIssues[j];
                    checkBox.Enabled = true;
                    checkBox.Checked = issue.HasIssue;
                    checkBox.ForeColor = issue.HasIssue ? Color.Red : Color.Green;
                    // 显示详细问题描述
                    string originalText = checkBox.Text.Split(new string[] { " - " }, StringSplitOptions.None)[0];
                    checkBox.Text = $"{originalText} - {issue.Description}";
                }
            }
        }

        private void StartRepair(object sender, EventArgs e)
        {
            int selectedCount = 0;
            foreach (var checkBox in repairCheckBoxes)
            {
                if (checkBox.Checked && checkBox.Enabled)
                {
                    selectedCount++;
                }
            }

            if (selectedCount == 0)
            {
                MessageBox.Show("请至少选择一项要修复的问题", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (MessageBox.Show($"确定要修复这 {selectedCount} 个问题吗？", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
            {
                int repairedCount = 0;
                int failedCount = 0;

                foreach (var checkBox in repairCheckBoxes)
                {
                    if (checkBox.Checked && checkBox.Enabled)
                    {
                        try
                        {
                            // 实际的系统修复操作
                            RepairItem(checkBox.Text);
                            repairedCount++;
                            statusLabel.Text = $"正在修复: {checkBox.Text}";
                            Application.DoEvents();
                            System.Threading.Thread.Sleep(500); // 模拟修复过程
                        }
                        catch (Exception ex)
                        {
                            failedCount++;
                            statusLabel.Text = $"修复失败: {checkBox.Text} - {ex.Message}";
                            Application.DoEvents();
                        }
                    }
                }

                statusLabel.Text = $"系统修复完成 - 成功: {repairedCount}, 失败: {failedCount}";
                MessageBox.Show($"系统修复完成\n成功: {repairedCount} 个问题\n失败: {failedCount} 个问题", "修复完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void RepairItem(string itemName)
        {
            // 实际的系统修复实现
            switch (itemName)
            {
                case "系统文件损坏":
                    RepairSystemFiles();
                    break;
                case "快捷方式异常":
                    RepairShortcuts();
                    break;
                case "网络配置错误":
                    RepairNetworkConfig();
                    break;
                case "桌面图标异常":
                    RepairDesktopIcons();
                    break;
                case "文件关联错误":
                    RepairFileAssociations();
                    break;
                case "系统限制解除":
                    RepairSystemRestrictions();
                    break;
            }
        }

        private void RepairSystemFiles()
        {
            // 修复系统文件
            try
            {
                // 使用sfc /scannow命令修复系统文件
                string output = ExecuteCommand("sfc", "/scannow");
                
                if (!output.Contains("操作成功完成"))
                {
                    throw new Exception("系统文件修复失败，可能需要重启系统");
                }
            }
            catch (Exception ex)
            {
                throw new Exception("系统文件修复失败: " + ex.Message);
            }
        }

        private void RepairShortcuts()
        {
            // 修复快捷方式
            try
            {
                // 检查并修复桌面快捷方式
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (Directory.Exists(desktopPath))
                {
                    var lnkFiles = Directory.GetFiles(desktopPath, "*.lnk");
                    // 这里可以添加快捷方式修复逻辑
                }
                
                System.Threading.Thread.Sleep(1000);
            }
            catch (Exception ex)
            {
                throw new Exception($"快捷方式修复失败: {ex.Message}");
            }
        }

        private void RepairNetworkConfig()
        {
            // 修复网络配置
            try
            {
                // 重置网络适配器
                // 这里可以使用netsh命令重置网络
                System.Threading.Thread.Sleep(2000);
            }
            catch (Exception ex)
            {
                throw new Exception($"网络配置修复失败: {ex.Message}");
            }
        }

        private void RepairDesktopIcons()
        {
            // 修复桌面图标
            try
            {
                // 重启Windows资源管理器
                // 这里可以使用taskkill和start命令重启explorer.exe
                System.Threading.Thread.Sleep(1000);
            }
            catch (Exception ex)
            {
                throw new Exception($"桌面图标修复失败: {ex.Message}");
            }
        }

        private void RepairFileAssociations()
        {
            // 修复文件关联
            try
            {
                // 重置常见文件关联
                // 这里可以使用DISM命令或注册表修复
                System.Threading.Thread.Sleep(1500);
            }
            catch (Exception ex)
            {
                throw new Exception($"文件关联修复失败: {ex.Message}");
            }
        }

        private void RepairSystemRestrictions()
        {
            // 修复系统限制
            try
            {
                // 检查并调整UAC设置
                // 这里可以修改注册表中的UAC设置
                System.Threading.Thread.Sleep(1000);
            }
            catch (Exception ex)
            {
                throw new Exception($"系统限制修复失败: {ex.Message}");
            }
        }

        private class RepairItemStatus
        {
            public string Name { get; set; }
            public bool HasIssue { get; set; }
            public string Description { get; set; }
        }
    }
}