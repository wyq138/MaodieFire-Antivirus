using System;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using System.Collections.Generic;
using System.Threading;
using System.Diagnostics;
using System.Linq;

namespace FireAntivirus.Host
{
    public class CleanForm : Form
    {
        private TableLayoutPanel mainLayout;
        private FlowLayoutPanel checkBoxPanel;
        private Button scanButton;
        private Button cleanButton;
        private Button cancelButton;
        private Label statusLabel;
        private ProgressBar progressBar;
        private ListBox junkFilesListBox;
        private CheckBox deepScanCheckBox;
        private List<CheckBox> checkBoxes;
        private List<string> junkFiles;
        private long totalJunkSize;

        public CleanForm()
        {
            checkBoxes = new List<CheckBox>();
            junkFiles = new List<string>();
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            this.Text = "垃圾清理 - 哈基咪杀毒";
            this.Size = new Size(650, 450);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Icon = SystemIcons.Shield;

            mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 4,
                ColumnCount = 1
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));

            var titleLabel = new Label
            {
                Text = "垃圾清理",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = Color.Black,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            var descLabel = new Label
            {
                Text = "扫描并清理系统垃圾、缓存文件和临时文件",
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

            var contentPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.White
            };

            var contentLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };

            contentLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 35));
            contentLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 65));
            contentLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var cleanTypes = new[]
            {
                "系统垃圾",
                "缓存文件",
                "临时文件",
                "日志文件",
                "浏览器垃圾",
                "软件残留"
            };

            checkBoxPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.TopDown,
                AutoScroll = false,
                Padding = new Padding(10)
            };

            foreach (var type in cleanTypes)
            {
                var checkBox = new CheckBox
                {
                    Text = type,
                    Checked = true,
                    Font = new Font("微软雅黑", 12),
                    ForeColor = Color.Black,
                    Width = 200,
                    Margin = new Padding(20, 10, 0, 0)
                };
                checkBoxes.Add(checkBox);
                checkBoxPanel.Controls.Add(checkBox);
            }

            // 添加深层扫描选项
            deepScanCheckBox = new CheckBox
            {
                Text = "深层扫描",
                Checked = false,
                Font = new Font("微软雅黑", 12),
                ForeColor = Color.Black,
                Width = 200,
                Margin = new Padding(20, 20, 0, 0)
            };
            checkBoxPanel.Controls.Add(deepScanCheckBox);

            // 添加垃圾文件列表框
            var listBoxPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                Padding = new Padding(10)
            };

            var listBoxTitle = new Label
            {
                Text = "扫描结果",
                Font = new Font("微软雅黑", 12, FontStyle.Bold),
                ForeColor = Color.Black,
                Dock = DockStyle.Top,
                TextAlign = ContentAlignment.MiddleLeft,
                Height = 30
            };

            junkFilesListBox = new ListBox
            {
                Dock = DockStyle.Fill,
                Font = new Font("微软雅黑", 10),
                BackColor = Color.White,
                ForeColor = Color.Black,
                BorderStyle = BorderStyle.FixedSingle
            };

            listBoxPanel.Controls.Add(listBoxTitle);
            listBoxPanel.Controls.Add(junkFilesListBox);

            contentLayout.Controls.Add(checkBoxPanel, 0, 0);
            contentLayout.Controls.Add(listBoxPanel, 1, 0);

            contentPanel.Controls.Add(contentLayout);
            mainLayout.Controls.Add(contentPanel, 0, 1);

            var statusPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.White
            };

            statusLabel = new Label
            {
                Text = "就绪",
                Font = new Font("微软雅黑", 10),
                ForeColor = Color.Gray,
                Dock = DockStyle.Left,
                TextAlign = ContentAlignment.MiddleLeft,
                Margin = new Padding(20, 0, 0, 0)
            };

            progressBar = new ProgressBar
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(20, 10, 20, 10),
                Visible = false
            };

            statusPanel.Controls.Add(statusLabel);
            statusPanel.Controls.Add(progressBar);
            mainLayout.Controls.Add(statusPanel, 0, 2);

            var buttonPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.White,
                ColumnCount = 3,
                RowCount = 1,
                Padding = new Padding(10)
            };
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));
            buttonPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            scanButton = new Button
            {
                Text = "扫描垃圾",
                Dock = DockStyle.Fill,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Blue,
                ForeColor = Color.White,
                Margin = new Padding(10)
            };

            cleanButton = new Button
            {
                Text = "开始清理",
                Dock = DockStyle.Fill,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Green,
                ForeColor = Color.White,
                Margin = new Padding(10)
            };

            cancelButton = new Button
            {
                Text = "取消",
                Dock = DockStyle.Fill,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Gray,
                ForeColor = Color.White,
                Margin = new Padding(10)
            };

            cleanButton.Enabled = false;
            cancelButton.Click += (s, e) => this.Close();
            scanButton.Click += ScanButton_Click;
            cleanButton.Click += CleanButton_Click;

            buttonPanel.Controls.Add(scanButton, 0, 0);
            buttonPanel.Controls.Add(cleanButton, 1, 0);
            buttonPanel.Controls.Add(cancelButton, 2, 0);
            mainLayout.Controls.Add(buttonPanel, 0, 3);

            this.Controls.Add(mainLayout);
            
            // 设置窗口最小尺寸，确保所有控件都能正常显示
            this.MinimumSize = new Size(600, 400);
        }

        private void ScanButton_Click(object sender, EventArgs e)
        {
            scanButton.Enabled = false;
            cleanButton.Enabled = false;
            statusLabel.Text = "正在扫描垃圾文件...";
            progressBar.Visible = true;
            progressBar.Value = 0;

            // 后台扫描垃圾文件
            Thread scanThread = new Thread(() =>
            {
                junkFiles.Clear();
                totalJunkSize = 0;
                int progress = 0;

                try
                {
                    // 扫描系统垃圾
                    if (checkBoxes[0].Checked)
                    {
                        ScanSystemJunk();
                        progress += 20;
                        UpdateProgress(progress);
                    }

                    // 扫描缓存文件
                    if (checkBoxes[1].Checked)
                    {
                        ScanCacheFiles();
                        progress += 20;
                        UpdateProgress(progress);
                    }

                    // 扫描临时文件
                    if (checkBoxes[2].Checked)
                    {
                        ScanTempFiles();
                        progress += 20;
                        UpdateProgress(progress);
                    }

                    // 扫描日志文件
                    if (checkBoxes[3].Checked)
                    {
                        ScanLogFiles();
                        progress += 15;
                        UpdateProgress(progress);
                    }

                    // 扫描浏览器垃圾
                    if (checkBoxes[4].Checked)
                    {
                        ScanBrowserJunk();
                        progress += 15;
                        UpdateProgress(progress);
                    }

                    // 扫描软件残留
                    if (checkBoxes[5].Checked)
                    {
                        ScanSoftwareResidues();
                        progress += 10;
                        UpdateProgress(100);
                    }

                    // 完成扫描
                    this.Invoke(new Action(() =>
                    {
                        statusLabel.Text = $"扫描完成，发现 {junkFiles.Count} 个垃圾文件，总大小 {FormatFileSize(totalJunkSize)}";
                        scanButton.Enabled = true;
                        cleanButton.Enabled = junkFiles.Count > 0;
                        progressBar.Visible = false;
                        // 确保列表框显示所有找到的垃圾文件
                        junkFilesListBox.Items.Clear();
                        foreach (string file in junkFiles)
                        {
                            junkFilesListBox.Items.Add(file);
                        }
                    }));
                }
                catch (Exception ex)
                {
                    this.Invoke(new Action(() =>
                    {
                        statusLabel.Text = "扫描过程中出现错误";
                        scanButton.Enabled = true;
                        progressBar.Visible = false;
                        junkFilesListBox.Items.Add($"错误: {ex.Message}");
                    }));
                }
            });

            scanThread.Start();
        }

        private void UpdateJunkFilesList(string filePath)
        {
            this.Invoke(new Action(() =>
            {
                junkFilesListBox.Items.Add(filePath);
            }));
        }

        private void CleanButton_Click(object sender, EventArgs e)
        {
            scanButton.Enabled = false;
            cleanButton.Enabled = false;
            statusLabel.Text = "正在清理垃圾文件...";
            progressBar.Visible = true;
            progressBar.Value = 0;

            // 后台清理垃圾文件
            Thread cleanThread = new Thread(() =>
            {
                int cleanedCount = 0;
                long cleanedSize = 0;

                try
                {
                    for (int i = 0; i < junkFiles.Count; i++)
                    {
                        string file = junkFiles[i];
                        try
                        {
                            if (File.Exists(file))
                            {
                                FileInfo fileInfo = new FileInfo(file);
                                cleanedSize += fileInfo.Length;
                                File.Delete(file);
                                cleanedCount++;
                            }
                            else if (Directory.Exists(file))
                            {
                                DirectoryInfo dirInfo = new DirectoryInfo(file);
                                cleanedSize += GetDirectorySize(dirInfo);
                                Directory.Delete(file, true);
                                cleanedCount++;
                            }
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CleanForm.cs 捕获异常", ex.Message); }

                        // 更新进度
                        int progress = (i + 1) * 100 / junkFiles.Count;
                        UpdateProgress(progress);
                    }

                    // 完成清理
                    this.Invoke(new Action(() =>
                    {
                        statusLabel.Text = $"清理完成，共清理 {cleanedCount} 个文件，释放空间 {FormatFileSize(cleanedSize)}";
                        scanButton.Enabled = true;
                        cleanButton.Enabled = false;
                        progressBar.Visible = false;
                        junkFiles.Clear();
                    }));
                }
                catch
                {
                    this.Invoke(new Action(() =>
                    {
                        statusLabel.Text = "清理过程中出现错误";
                        scanButton.Enabled = true;
                        progressBar.Visible = false;
                    }));
                }
            });

            cleanThread.Start();
        }

        private void UpdateProgress(int value)
        {
            this.Invoke(new Action(() =>
            {
                progressBar.Value = value;
                statusLabel.Text = $"正在扫描垃圾文件... 已发现 {junkFiles.Count} 个文件，大小 {FormatFileSize(totalJunkSize)}";
            }));
        }

        private void ScanSystemJunk()
        {
            // 扫描系统垃圾文件
            string[] systemJunkPatterns = {
                "*.tmp", "*.temp", "*.log", "*.bak",
                "Thumbs.db", "Desktop.ini"
            };

            // 深层扫描时添加更多垃圾文件模式
            if (deepScanCheckBox.Checked)
            {
                systemJunkPatterns = systemJunkPatterns.Concat(new string[] {
                    "*.old", "*.chk", "*.dmp", "*.mdmp",
                    "*.swp", "*.swo", "*.~*", "*.backup",
                    "*.crash", "*.dump"
                }).ToArray();
            }

            string[] systemPaths = {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "WER", "ReportArchive"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "WER", "ReportQueue")
            };

            // 深层扫描时添加更多系统路径
            if (deepScanCheckBox.Checked)
            {
                systemPaths = systemPaths.Concat(new string[] {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "Caches"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "DeliveryOptimization", "Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "INetCache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "Prefetch")
                }).ToArray();
            }

            foreach (string path in systemPaths)
            {
                if (Directory.Exists(path))
                {
                    foreach (string pattern in systemJunkPatterns)
                    {
                        try
                        {
                            string[] files = Directory.GetFiles(path, pattern, SearchOption.AllDirectories);
                            foreach (string file in files)
                            {
                                junkFiles.Add(file);
                                totalJunkSize += new FileInfo(file).Length;
                                UpdateJunkFilesList(file);
                            }
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CleanForm.cs 捕获异常", ex.Message); }
                    }
                }
            }
        }

        private void ScanCacheFiles()
        {
            // 扫描缓存文件
            string[] cachePaths = {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "INetCache"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "IE"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Terminal Server Client", "Cache")
            };

            // 深层扫描时添加更多缓存路径
            if (deepScanCheckBox.Checked)
            {
                cachePaths = cachePaths.Concat(new string[] {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla", "Firefox", "Profiles")
                }).ToArray();
            }

            foreach (string path in cachePaths)
            {
                if (Directory.Exists(path))
                {
                    try
                    {
                        string[] files = Directory.GetFiles(path, "*.*", SearchOption.AllDirectories);
                        foreach (string file in files)
                        {
                            junkFiles.Add(file);
                            totalJunkSize += new FileInfo(file).Length;
                            UpdateJunkFilesList(file);
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CleanForm.cs 捕获异常", ex.Message); }
                }
            }
        }

        private void ScanTempFiles()
        {
            // 扫描临时文件
            string[] tempPaths = {
                Path.GetTempPath(),
                Environment.GetEnvironmentVariable("TEMP"),
                Environment.GetEnvironmentVariable("TMP")
            };

            // 深层扫描时添加更多临时路径
            if (deepScanCheckBox.Checked)
            {
                tempPaths = tempPaths.Concat(new string[] {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Temp"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Temp")
                }).ToArray();
            }

            foreach (string path in tempPaths)
            {
                if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                {
                    try
                    {
                        string[] files = Directory.GetFiles(path, "*.*", SearchOption.AllDirectories);
                        foreach (string file in files)
                        {
                            // 正常扫描只清理7天前的临时文件，深层扫描清理所有临时文件
                            if (!deepScanCheckBox.Checked && (DateTime.Now - File.GetCreationTime(file)).TotalDays > 7 || deepScanCheckBox.Checked)
                            {
                                junkFiles.Add(file);
                                totalJunkSize += new FileInfo(file).Length;
                                UpdateJunkFilesList(file);
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CleanForm.cs 捕获异常", ex.Message); }
                }
            }
        }

        private void ScanLogFiles()
        {
            // 扫描日志文件
            string[] logPaths = {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "WER"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Logs")
            };

            // 深层扫描时添加更多日志路径
            if (deepScanCheckBox.Checked)
            {
                logPaths = logPaths.Concat(new string[] {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "PowerShell", "Operational"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "Services", "AdmPwd"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "Sysmon")
                }).ToArray();
            }

            foreach (string path in logPaths)
            {
                if (Directory.Exists(path))
                {
                    try
                    {
                        string[] files = Directory.GetFiles(path, "*.log", SearchOption.AllDirectories);
                        foreach (string file in files)
                        {
                            // 正常扫描只清理30天前的日志文件，深层扫描清理15天前的日志文件
                            int daysThreshold = deepScanCheckBox.Checked ? 15 : 30;
                            if ((DateTime.Now - File.GetCreationTime(file)).TotalDays > daysThreshold)
                            {
                                junkFiles.Add(file);
                                totalJunkSize += new FileInfo(file).Length;
                                UpdateJunkFilesList(file);
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CleanForm.cs 捕获异常", ex.Message); }
                }
            }
        }

        private void ScanBrowserJunk()
        {
            // 扫描浏览器垃圾
            string[] browserPaths = {
                // Chrome
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Cache"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Cookies"),
                // Firefox
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla", "Firefox", "Profiles"),
                // Edge
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "Cache")
            };

            // 深层扫描时添加更多浏览器路径
            if (deepScanCheckBox.Checked)
            {
                browserPaths = browserPaths.Concat(new string[] {
                    // Chrome 更多路径
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Local Storage"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Default", "Media Cache"),
                    // Firefox 更多路径
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla", "Firefox", "Profiles", "*.default", "cache2"),
                    // Edge 更多路径
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Default", "Local Storage"),
                    // Opera
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Opera Software", "Opera Stable", "Cache"),
                    // Vivaldi
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Vivaldi", "User Data", "Default", "Cache")
                }).ToArray();
            }

            foreach (string path in browserPaths)
            {
                if (Directory.Exists(path))
                {
                    try
                    {
                        string[] files = Directory.GetFiles(path, "*.*", SearchOption.AllDirectories);
                        foreach (string file in files)
                        {
                            junkFiles.Add(file);
                            totalJunkSize += new FileInfo(file).Length;
                            UpdateJunkFilesList(file);
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CleanForm.cs 捕获异常", ex.Message); }
                }
            }
        }

        private void ScanSoftwareResidues()
        {
            // 扫描软件残留
            string[] residuePaths = {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Temp")
            };

            // 深层扫描时添加更多软件残留路径
            if (deepScanCheckBox.Checked)
            {
                residuePaths = residuePaths.Concat(new string[] {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Apps"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "Start Menu", "Programs"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Windows", "Start Menu", "Programs")
                }).ToArray();
            }

            foreach (string path in residuePaths)
            {
                if (Directory.Exists(path))
                {
                    try
                    {
                        string[] files = Directory.GetFiles(path, "*.*", SearchOption.AllDirectories);
                        foreach (string file in files)
                        {
                            // 深层扫描时清理更多类型的文件
                            string extension = Path.GetExtension(file).ToLower();
                            if (!deepScanCheckBox.Checked || (deepScanCheckBox.Checked && (extension == ".tmp" || extension == ".temp" || extension == ".log" || extension == ".bak" || extension == ".old")))
                            {
                                junkFiles.Add(file);
                                totalJunkSize += new FileInfo(file).Length;
                                UpdateJunkFilesList(file);
                            }
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CleanForm.cs 捕获异常", ex.Message); }
                }
            }
        }

        private string FormatFileSize(long bytes)
        {
            if (bytes >= 1073741824)
                return $"{bytes / 1073741824.0:F2} GB";
            else if (bytes >= 1048576)
                return $"{bytes / 1048576.0:F2} MB";
            else if (bytes >= 1024)
                return $"{bytes / 1024.0:F2} KB";
            else
                return $"{bytes} B";
        }

        private long GetDirectorySize(DirectoryInfo dir)
        {
            long size = 0;
            try
            {
                foreach (FileInfo file in dir.GetFiles("*.*", SearchOption.AllDirectories))
                {
                    size += file.Length;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "CleanForm.cs 捕获异常", ex.Message); }
            return size;
        }
    }
}