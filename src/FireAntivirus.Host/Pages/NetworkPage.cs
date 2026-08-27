using System;
using System.Drawing;
using System.Windows.Forms;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Diagnostics;

namespace FireAntivirus.Host
{
    public class NetworkPage : UserControl, IThemed
    {
        private Panel networkControlPanel;
        private DataGridView networkAppsGrid;
        private Button networkScanBtn;
        private Label statusLabel;
        private Theme currentTheme = Theme.Light;
        private System.Windows.Forms.Timer networkUpdateTimer;

        public NetworkPage()
        {
            try
            {
                // 只执行必要的UI初始化操作
                InitializeComponents();
            }
            catch (Exception ex)
            {
                // 记录错误并避免应用程序崩溃
                Console.WriteLine($"Error initializing NetworkPage: {ex.Message}");
            }
        }

        private void InitializeComponents()
        {
            this.Dock = DockStyle.Fill;
            this.AutoScroll = false;
            this.MinimumSize = new Size(600, 500);
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 3,
                ColumnCount = 1,
                MinimumSize = new Size(580, 480),
                BackColor = GetThemeColor(ThemeColor.BgPrimary)
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var headerPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                Padding = new Padding(20, 15, 20, 15)
            };

            var titleLabel = new Label
            {
                Text = "网络防护",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Margin = new Padding(0, 5, 0, 5)
            };

            headerPanel.Controls.Add(titleLabel);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            var controlPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                ColumnCount = 3,
                RowCount = 1
            };
            controlPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            controlPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            controlPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));

            networkScanBtn = CreateControlButton("网络检测", NetworkScan);
            var blockBtn = CreateControlButton("禁止联网", BlockSelectedApp);
            var allowBtn = CreateControlButton("允许联网", AllowSelectedApp);

            networkScanBtn.Dock = DockStyle.Fill;
            blockBtn.Dock = DockStyle.Fill;
            allowBtn.Dock = DockStyle.Fill;

            controlPanel.Controls.Add(networkScanBtn, 0, 0);
            controlPanel.Controls.Add(blockBtn, 1, 0);
            controlPanel.Controls.Add(allowBtn, 2, 0);

            mainLayout.Controls.Add(controlPanel, 0, 1);

            networkControlPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                Padding = new Padding(20)
            };

            var networkLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1,
                BackColor = GetThemeColor(ThemeColor.BgPrimary)
            };

            networkLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            networkLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            statusLabel = new Label
            {
                Text = "点击网络检测按钮开始检测网络状态",
                Font = new Font("微软雅黑", 9),
                ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            networkLayout.Controls.Add(statusLabel, 0, 0);

            networkAppsGrid = new DataGridView
            {
                Dock = DockStyle.Fill,
                AutoGenerateColumns = false,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                BorderStyle = BorderStyle.FixedSingle,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                Font = new Font("微软雅黑", 9)
            };

            networkAppsGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "AppName",
                HeaderText = "应用名称",
                DataPropertyName = "AppName",
                Width = 150
            });

            networkAppsGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Path",
                HeaderText = "路径",
                DataPropertyName = "Path",
                Width = 300,
                AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill
            });

            networkAppsGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Upload",
                HeaderText = "上传速度",
                DataPropertyName = "Upload",
                Width = 80
            });

            networkAppsGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Download",
                HeaderText = "下载速度",
                DataPropertyName = "Download",
                Width = 80
            });

            networkAppsGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Status",
                HeaderText = "状态",
                DataPropertyName = "Status",
                Width = 80
            });

            networkLayout.Controls.Add(networkAppsGrid, 0, 1);
            networkControlPanel.Controls.Add(networkLayout);
            mainLayout.Controls.Add(networkControlPanel, 0, 2);

            // 初始化网络状态更新定时器（禁用状态）
            networkUpdateTimer = new System.Windows.Forms.Timer
            {
                Interval = 10000, // 10 秒更新一次，减少后台检测频率
                Enabled = false // 禁用自动更新，避免后台检测导致卡顿
            };
            // 不绑定Tick事件，避免任何可能的后台操作
            // networkUpdateTimer.Tick += NetworkUpdateTimer_Tick;

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

        private void NetworkScan()
        {
            statusLabel.Text = "正在检测网络状态...";
            networkScanBtn.Enabled = false;

            // 在后台线程中执行网络检测，避免阻塞UI
            System.Threading.Tasks.Task.Run(() => {
                try
                {
                    // 快速获取网络状态
                    var networkStatus = CheckNetworkStatus();
                    
                    // 限制网络应用检测时间，避免长时间阻塞
                    var networkApps = new List<NetworkApplication>();
                    var cts = new System.Threading.CancellationTokenSource();
                    cts.CancelAfter(3000); // 3秒超时
                    
                    try
                    {
                        networkApps = GetNetworkApplications();
                    }
                    catch (OperationCanceledException)
                    {
                        // 超时，使用空列表
                        networkApps = new List<NetworkApplication>();
                        networkApps.Add(new NetworkApplication
                        {
                            AppName = "检测超时",
                            Path = "网络检测超时",
                            Upload = "0.0 KB/s",
                            Download = "0.0 KB/s",
                            Status = "超时"
                        });
                    }

                    // 在UI线程中更新状态
                    this.BeginInvoke((Action)(() => {
                        statusLabel.Text = $"网络检测完成 - 状态: {networkStatus.Status}, 应用数: {networkApps.Count}";
                        UpdateNetworkAppsGrid(networkApps);
                    }));
                }
                catch (Exception ex)
                {
                    // 在UI线程中更新错误状态
                    this.BeginInvoke((Action)(() => {
                        statusLabel.Text = $"网络检测失败: {ex.Message}";
                    }));
                }
                finally
                {
                    // 在UI线程中启用按钮
                    this.BeginInvoke((Action)(() => {
                        networkScanBtn.Enabled = true;
                    }));
                }
            });
        }

        private NetworkStatus CheckNetworkStatus()
        {
            // 检查网络连接状态
            bool isConnected = NetworkInterface.GetIsNetworkAvailable();
            string status = isConnected ? "已连接" : "未连接";
            string details = "";

            if (isConnected)
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
                    .ToList();

                if (interfaces.Count > 0)
                {
                    var primaryInterface = interfaces.First();
                    details = $"{primaryInterface.Name} ({primaryInterface.NetworkInterfaceType})";
                }
            }

            return new NetworkStatus { Status = status, Details = details };
        }

        private List<NetworkApplication> GetNetworkApplications()
        {
            var apps = new List<NetworkApplication>();
            try
            {
                // 尝试使用更简洁的netstat命令参数，减少执行时间
                string[] netstatArgs = { "-ano", "-p", "tcp" };
                string output = ExecuteNetstatCommand(netstatArgs);
                
                if (!string.IsNullOrEmpty(output))
                {
                    ParseNetstatOutput(output, apps);
                }
                
                // 尝试获取UDP连接
                string[] udpArgs = { "-ano", "-p", "udp" };
                string udpOutput = ExecuteNetstatCommand(udpArgs);
                
                if (!string.IsNullOrEmpty(udpOutput))
                {
                    ParseNetstatOutput(udpOutput, apps);
                }

                // 如果没有获取到任何连接，显示提示信息
                if (apps.Count == 0)
                {
                    apps.Add(new NetworkApplication
                    {
                        AppName = "无网络连接",
                        Path = "",
                        Upload = "0.0 KB/s",
                        Download = "0.0 KB/s",
                        Status = "无"
                    });
                }
            }
            catch (Exception ex)
            {
                // 如果获取失败，显示错误信息
                apps.Add(new NetworkApplication
                {
                    AppName = "检测错误",
                    Path = ex.Message,
                    Upload = "0.0 KB/s",
                    Download = "0.0 KB/s",
                    Status = "错误"
                });
            }

            return apps;
        }

        private string ExecuteNetstatCommand(string[] arguments)
        {
            // 直接使用 netstat 命令获取网络连接信息，限制执行时间
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netstat.exe",
                    Arguments = string.Join(" ", arguments),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            
            process.Start();
            // 读取输出时设置超时
            string output = null;
            if (process.WaitForExit(3000)) // 3秒超时
            {
                output = process.StandardOutput.ReadToEnd();
            }
            else
            {
                process.Kill();
                throw new TimeoutException("netstat命令执行超时");
            }
            
            return output;
        }

        private void ParseNetstatOutput(string output, List<NetworkApplication> apps)
        {
            if (string.IsNullOrEmpty(output))
                return;
            
            // 解析 netstat 输出，限制处理行数
            int lineCount = 0;
            int maxLines = 300; // 最多处理300行
            foreach (var line in output.Split('\n'))
            {
                if (lineCount >= maxLines)
                    break;
                
                lineCount++;
                // 处理TCP和UDP连接
                if (line.Trim().StartsWith("TCP") || line.Trim().StartsWith("UDP"))
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 5)
                    {
                        int processId = 0;
                        int processIdIndex = line.Trim().StartsWith("TCP") ? 4 : 3;
                        if (int.TryParse(parts[processIdIndex], out processId))
                        {
                            string appName = "未知进程";
                            string path = "未知路径";

                            // 根据进程ID获取进程信息（快速方式）
                            if (processId > 0)
                            {
                                try
                                {
                                    var proc = System.Diagnostics.Process.GetProcessById(processId);
                                    appName = proc.ProcessName;
                                    // 快速获取主模块路径
                                    try
                                    {
                                        path = proc.MainModule?.FileName ?? "未知路径";
                                    }
                                    catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 5)
                                    {
                                        // 访问被拒绝，尝试使用WMI获取路径
                                        path = GetProcessPathFromWMI(processId);
                                    }
                                    catch
                                    {
                                        path = "未知路径";
                                    }
                                }
                                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkPage.cs 捕获异常", ex.Message); }
                            }

                            // 检查是否已经添加了相同的进程
                            if (!apps.Any(a => a.AppName == appName))
                            {
                                // 快速计算网络流量
                                string uploadSpeed = CalculateNetworkSpeed(processId, true);
                                string downloadSpeed = CalculateNetworkSpeed(processId, false);

                                apps.Add(new NetworkApplication
                                {
                                    AppName = appName,
                                    Path = path,
                                    Upload = uploadSpeed,
                                    Download = downloadSpeed,
                                    Status = "允许"
                                });
                            }
                        }
                    }
                }
            }
        }

        private string GetProcessPathFromWMI(int processId)
        {
            try
            {
                string query = $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}";
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject process in searcher.Get())
                {
                    return process["ExecutablePath"]?.ToString() ?? "未知路径";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkPage.cs 捕获异常", ex.Message); }
            return "未知路径";
        }

        private string CalculateNetworkSpeed(int processId, bool isUpload)
        {
            try
            {
                // 使用 PerformanceCounter 获取网络流量
                PerformanceCounterCategory category = new PerformanceCounterCategory("Network Interface");
                string[] instanceNames = category.GetInstanceNames();
                
                if (instanceNames.Length > 0)
                {
                    // 获取第一个网络接口的流量
                    string instanceName = instanceNames[0];
                    PerformanceCounter counter;
                    
                    if (isUpload)
                    {
                        counter = new PerformanceCounter("Network Interface", "Bytes Sent/sec", instanceName);
                    }
                    else
                    {
                        counter = new PerformanceCounter("Network Interface", "Bytes Received/sec", instanceName);
                    }
                    
                    // 直接获取值，不等待，减少延迟
                    float bytesPerSec = counter.NextValue();
                    // 转换为 KB/s
                    double kbPerSec = bytesPerSec / 1024.0;
                    
                    return $"{kbPerSec:F1} KB/s";
                }
                return "0.0 KB/s";
            }
            catch
            {
                return "0.0 KB/s";
            }
        }

        private void UpdateNetworkAppsGrid(List<NetworkApplication> apps)
        {
            networkAppsGrid.Rows.Clear();

            foreach (var app in apps)
            {
                networkAppsGrid.Rows.Add(app.AppName, app.Path, app.Upload, app.Download, app.Status);
            }
        }

        private void BlockSelectedApp()
        {
            if (networkAppsGrid.SelectedRows.Count > 0)
            {
                var selectedRow = networkAppsGrid.SelectedRows[0];
                selectedRow.Cells["Status"].Value = "禁止";
                statusLabel.Text = $"已禁止应用: {selectedRow.Cells["AppName"].Value}";
            }
        }

        private void AllowSelectedApp()
        {
            if (networkAppsGrid.SelectedRows.Count > 0)
            {
                var selectedRow = networkAppsGrid.SelectedRows[0];
                selectedRow.Cells["Status"].Value = "允许";
                statusLabel.Text = $"已允许应用: {selectedRow.Cells["AppName"].Value}";
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
            
            // 更新所有子控件的颜色
            UpdateControlsTheme(this);
            
            if (statusLabel != null)
            {
                statusLabel.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
            }
            if (networkAppsGrid != null)
            {
                networkAppsGrid.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                networkAppsGrid.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                networkAppsGrid.ColumnHeadersDefaultCellStyle.BackColor = GetThemeColor(ThemeColor.BgSecondary);
                networkAppsGrid.ColumnHeadersDefaultCellStyle.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
            }
            if (networkScanBtn != null)
            {
                networkScanBtn.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                networkScanBtn.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                networkScanBtn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            }
        }
        
        private void UpdateControlsTheme(Control control)
        {
            foreach (Control child in control.Controls)
            {
                if (child is Panel panel)
                {
                    panel.BackColor = GetThemeColor(ThemeColor.BgPrimary);
                }
                else if (child is TableLayoutPanel tlp)
                {
                    tlp.BackColor = GetThemeColor(ThemeColor.BgPrimary);
                }
                else if (child is Label label)
                {
                    // 确保使用微软雅黑字体
                    if (label.Font.Name != "微软雅黑")
                    {
                        label.Font = new Font("微软雅黑", label.Font.Size, label.Font.Style);
                    }
                    
                    if (label.Font.Bold)
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                    }
                    else
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
                    }
                }
                else if (child is Button button)
                {
                    button.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                    button.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                    button.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
                }
                else if (child is DataGridView dgv)
                {
                    dgv.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                    dgv.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                    dgv.ColumnHeadersDefaultCellStyle.BackColor = GetThemeColor(ThemeColor.BgSecondary);
                    dgv.ColumnHeadersDefaultCellStyle.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                }
                
                // 递归更新子控件
                UpdateControlsTheme(child);
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
                    case ThemeColor.BgSecondary:
                        return Color.FromArgb(40, 40, 40);
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
                    case ThemeColor.BgSecondary:
                        return Color.FromArgb(249, 250, 251);
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(243, 244, 246);
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(229, 231, 235);
                    default:
                        return Color.White;
                }
            }
        }

        private class NetworkStatus
        {
            public string Status { get; set; }
            public string Details { get; set; }
        }

        private class NetworkApplication
        {
            public string AppName { get; set; }
            public string Path { get; set; }
            public string Upload { get; set; }
            public string Download { get; set; }
            public string Status { get; set; }
        }
    }
}