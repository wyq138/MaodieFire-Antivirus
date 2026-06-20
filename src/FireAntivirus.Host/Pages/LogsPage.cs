using System;
using System.Drawing;
using System.Windows.Forms;
using System.Linq;
using FireAntivirus.Data;

namespace FireAntivirus.Host
{
    public class LogsPage : UserControl, IThemed
    {
        private Panel logsPanel;
        private TabControl logsTabControl;
        private Theme currentTheme = Theme.Light;
        private DataManager dataManager;
        private Button clearLogsBtn;
        private Button exportLogsBtn;

        public LogsPage()
        {
            try
            {
                dataManager = new DataManager();
                InitializeComponents();
            }
            catch (Exception ex)
            {
                // 记录错误但不重新抛出，避免应用程序崩溃
                Console.WriteLine($"Error initializing LogsPage: {ex.Message}");
            }
        }

        private void InitializeComponents()
        {
            this.Dock = DockStyle.Fill;
            this.AutoScroll = false;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var headerPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(20, 15, 20, 15)
            };

            var titleLabel = new Label
            {
                Text = "日志中心",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            headerPanel.Controls.Add(titleLabel);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            logsPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(20)
            };

            var topPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 60,
                BackColor = Color.Transparent
            };

            clearLogsBtn = CreateControlButton("清空日志", ClearLogs);
            exportLogsBtn = CreateControlButton("导出日志", ExportLogs);

            clearLogsBtn.Location = new Point(0, 10);
            exportLogsBtn.Location = new Point(120, 10);

            topPanel.Controls.Add(clearLogsBtn);
            topPanel.Controls.Add(exportLogsBtn);

            logsTabControl = new TabControl
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Font = new Font("微软雅黑", 9)
            };

            var scanLogTab = new TabPage("查杀日志")
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var protectionLogTab = new TabPage("防护日志")
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var networkLogTab = new TabPage("网络日志")
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var systemLogTab = new TabPage("系统日志")
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var updateLogTab = new TabPage("更新日志")
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var scanLogList = CreateLogListBox();
            var protectionLogList = CreateLogListBox();
            var networkLogList = CreateLogListBox();
            var systemLogList = CreateLogListBox();
            var updateLogList = CreateLogListBox();

            LoadScanLogs(scanLogList);
            LoadProtectionLogs(protectionLogList);
            LoadNetworkLogs(networkLogList);
            LoadSystemLogs(systemLogList);
            LoadUpdateLogs(updateLogList);

            scanLogTab.Controls.Add(scanLogList);
            protectionLogTab.Controls.Add(protectionLogList);
            networkLogTab.Controls.Add(networkLogList);
            systemLogTab.Controls.Add(systemLogList);
            updateLogTab.Controls.Add(updateLogList);

            logsTabControl.TabPages.Add(scanLogTab);
            logsTabControl.TabPages.Add(protectionLogTab);
            logsTabControl.TabPages.Add(networkLogTab);
            logsTabControl.TabPages.Add(systemLogTab);
            logsTabControl.TabPages.Add(updateLogTab);

            var mainPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1
            };

            mainPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
            mainPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            mainPanel.Controls.Add(topPanel, 0, 0);
            mainPanel.Controls.Add(logsTabControl, 0, 1);

            logsPanel.Controls.Add(mainPanel);
            mainLayout.Controls.Add(logsPanel, 0, 1);

            this.Controls.Add(mainLayout);
        }

        private Button CreateControlButton(string text, Action action)
        {
            var btn = new Button
            {
                Text = text,
                Width = 100,
                Height = 40,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            btn.Click += (s, e) => action();
            return btn;
        }

        private ListBox CreateLogListBox()
        {
            var listBox = new ListBox
            {
                Dock = DockStyle.Fill,
                Font = new Font("微软雅黑", 9),
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                BorderStyle = BorderStyle.None,
                HorizontalScrollbar = true
            };
            return listBox;
        }

        private void LoadScanLogs(ListBox listBox)
        {
            // 加载真实的扫描日志
            LoadLogsFromFile(listBox, "ScanLogs.txt");
        }

        private void LoadProtectionLogs(ListBox listBox)
        {
            // 加载真实的防护日志
            LoadLogsFromFile(listBox, "ProtectionLogs.txt");
        }

        private void LoadNetworkLogs(ListBox listBox)
        {
            // 加载真实的网络日志
            LoadLogsFromFile(listBox, "NetworkLogs.txt");
        }

        private void LoadSystemLogs(ListBox listBox)
        {
            // 加载真实的系统日志
            LoadLogsFromFile(listBox, "SystemLogs.txt");
        }

        private void LoadUpdateLogs(ListBox listBox)
        {
            // 加载真实的更新日志
            LoadLogsFromFile(listBox, "UpdateLogs.txt");
        }

        private void LoadLogsFromFile(ListBox listBox, string fileName)
        {
            try
            {
                string logPath = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "哈基咪杀毒", "Logs", fileName);
                
                if (System.IO.File.Exists(logPath))
                {
                    var logs = System.IO.File.ReadAllLines(logPath);
                    // 只显示最近的50条日志
                    var recentLogs = logs.Skip(Math.Max(0, logs.Length - 50)).ToArray();
                    listBox.Items.AddRange(recentLogs);
                }
                else
                {
                    listBox.Items.Add("暂无日志记录");
                }
            }
            catch
            {
                listBox.Items.Add("无法加载日志文件");
            }
        }

        private void ClearLogs()
        {
            if (MessageBox.Show("确定要清空所有日志吗？", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                try
                {
                    string logsPath = System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "哈基咪杀毒", "Logs");
                    
                    if (System.IO.Directory.Exists(logsPath))
                    {
                        string[] logFiles = System.IO.Directory.GetFiles(logsPath);
                        foreach (string file in logFiles)
                        {
                            System.IO.File.Delete(file);
                        }
                    }
                    
                    // 重新加载日志
                    foreach (TabPage tabPage in logsTabControl.TabPages)
                    {
                        if (tabPage.Controls[0] is ListBox listBox)
                        {
                            listBox.Items.Clear();
                            listBox.Items.Add("暂无日志记录");
                        }
                    }
                    
                    MessageBox.Show("日志已清空", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch
                {
                    MessageBox.Show("清空日志失败", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void ExportLogs()
        {
            try
            {
                using (System.Windows.Forms.SaveFileDialog saveDialog = new System.Windows.Forms.SaveFileDialog())
                {
                    saveDialog.Filter = "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*";
                    saveDialog.FileName = $"FireAntivirus_Logs_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                    saveDialog.Title = "导出日志";
                    
                    if (saveDialog.ShowDialog() == DialogResult.OK)
                    {
                        string exportPath = saveDialog.FileName;
                        using (System.IO.StreamWriter writer = new System.IO.StreamWriter(exportPath))
                        {
                            writer.WriteLine("=== 哈基咪杀毒 日志导出 ===");
                            writer.WriteLine($"导出时间: {DateTime.Now}");
                            writer.WriteLine("==================================");
                            writer.WriteLine();
                            
                            foreach (TabPage tabPage in logsTabControl.TabPages)
                            {
                                writer.WriteLine($"=== {tabPage.Text} ===");
                                if (tabPage.Controls[0] is ListBox listBox)
                                {
                                    foreach (var item in listBox.Items)
                                    {
                                        writer.WriteLine(item.ToString());
                                    }
                                }
                                writer.WriteLine();
                            }
                        }
                        
                        MessageBox.Show("日志导出成功", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch
            {
                MessageBox.Show("导出日志失败", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            logsTabControl.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            logsTabControl.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
            // 设置TabControl的字体
            logsTabControl.Font = new Font("微软雅黑", 9);

            // 更新按钮主题
            clearLogsBtn.BackColor = GetThemeColor(ThemeColor.BgTertiary);
            clearLogsBtn.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
            clearLogsBtn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            
            exportLogsBtn.BackColor = GetThemeColor(ThemeColor.BgTertiary);
            exportLogsBtn.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
            exportLogsBtn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);

            foreach (TabPage tabPage in logsTabControl.TabPages)
            {
                tabPage.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                // 设置TabPage的字体
                tabPage.Font = new Font("微软雅黑", 9);
                foreach (Control control in tabPage.Controls)
                {
                    if (control is ListBox listBox)
                    {
                        listBox.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                        listBox.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                        // 设置ListBox的字体
                        listBox.Font = new Font("微软雅黑", 9);
                    }
                }
            }
        }

        private Color GetThemeColor(ThemeColor colorType)
        {
            if (currentTheme == Theme.Dark)
            {
                switch (colorType)
                {
                    case ThemeColor.TextPrimary:
                        return Color.White;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.FromArgb(30, 30, 30);
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(50, 50, 50);
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(60, 60, 60);
                    default:
                        return Color.Black;
                }
            }
            else
            {
                switch (colorType)
                {
                    case ThemeColor.TextPrimary:
                        return Color.Black;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.White;
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(243, 244, 246);
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(229, 231, 235);
                    default:
                        return Color.White;
                }
            }
        }
    }
}
