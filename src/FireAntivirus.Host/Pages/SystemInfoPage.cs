using System;
using System.Drawing;
using System.Windows.Forms;
using System.Management;
using System.Text;
using System.Collections.Generic;

namespace FireAntivirus.Host
{
    public class SystemInfoPage : UserControl, IThemed
    {
        private Panel mainPanel;
        private Theme currentTheme = Theme.Light;
        private Label statusLabel;
        private System.Windows.Forms.Timer updateTimer;

        public SystemInfoPage()
        {
            try
            {
                InitializeComponents();
            }
            catch (Exception ex)
            {
                // 记录错误但不重新抛出，避免应用程序崩溃
                Console.WriteLine($"Error initializing SystemInfoPage: {ex.Message}");
            }
        }

        private void InitializeComponents()
        {
            this.Dock = DockStyle.Fill;
            this.AutoScroll = true;
            this.MinimumSize = new Size(600, 600);
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);

            // 创建主面板
            mainPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                Padding = new Padding(20)
            };
            this.Controls.Add(mainPanel);

            // 创建标题标签
            var titleLabel = new Label
            {
                Text = "系统信息",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Location = new Point(20, 20),
                AutoSize = true
            };
            mainPanel.Controls.Add(titleLabel);

            // 创建状态标签
            statusLabel = new Label
            {
                Text = "正在加载系统信息...",
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                Location = new Point(20, 60),
                AutoSize = true
            };
            mainPanel.Controls.Add(statusLabel);

            // 创建占位面板，避免页面切换时的闪烁
            var placeholderPanel = new Panel
            {
                Location = new Point(20, 100),
                Size = new Size(mainPanel.Width - 40, 600),
                BackColor = GetThemeColor(ThemeColor.CardBg),
                BorderStyle = BorderStyle.None
            };
            mainPanel.Controls.Add(placeholderPanel);

            // 创建更新定时器，每10秒更新一次内存和磁盘信息
            updateTimer = new System.Windows.Forms.Timer
            {
                Interval = 10000
            };
            updateTimer.Tick += (s, e) => UpdateDynamicInfo();
        }
        
        // 当页面显示时调用
        public void OnPageShown()
        {
            // 延迟加载系统信息，避免阻塞UI线程
            System.Threading.Tasks.Task.Delay(100).ContinueWith((t) =>
            {
                this.Invoke((Action)(() =>
                {
                    LoadSystemInfo();
                    // 启动定时器
                    updateTimer.Start();
                }));
            });
        }

        private void LoadSystemInfo()
        {
            try
            {
                // 清除旧控件，但保留标题和状态标签
                var controlsToRemove = new System.Collections.Generic.List<Control>();
                foreach (Control control in mainPanel.Controls)
                {
                    if (control != statusLabel && control.Text != "系统信息")
                    {
                        controlsToRemove.Add(control);
                    }
                }
                foreach (Control control in controlsToRemove)
                {
                    mainPanel.Controls.Remove(control);
                    control.Dispose();
                }

                statusLabel.Text = "正在加载系统信息...";
                statusLabel.ForeColor = GetThemeColor(ThemeColor.TextSecondary);

                // 使用异步获取系统信息，避免阻塞UI线程
                System.Threading.Tasks.Task.Run(async () =>
                {
                    try
                    {
                        // 按顺序获取系统信息，减少系统负载
                        var osInfo = await System.Threading.Tasks.Task.Run(() => GetOSInfo());
                        var cpuInfo = await System.Threading.Tasks.Task.Run(() => GetCPUInfo());
                        var memoryInfo = await System.Threading.Tasks.Task.Run(() => GetMemoryInfo());
                        var diskInfo = await System.Threading.Tasks.Task.Run(() => GetDiskInfo());
                        var networkInfo = await System.Threading.Tasks.Task.Run(() => GetNetworkInfo());
                        var systemInfo = await System.Threading.Tasks.Task.Run(() => GetSystemInfo());

                        // 在UI线程中更新界面
                        this.Invoke((Action)(() =>
                        {
                            try
                            {
                                // 创建信息面板
                                int yPosition = 100;
                                int panelHeight = 130; // 减小面板高度，使页面更紧凑
                                int panelWidth = mainPanel.Width - 40;

                                // 操作系统信息
                                var osPanel = CreateInfoPanel("操作系统信息", osInfo, new Point(20, yPosition), new Size(panelWidth, panelHeight));
                                mainPanel.Controls.Add(osPanel);
                                yPosition += panelHeight + 15;

                                // 处理器信息
                                var cpuPanel = CreateInfoPanel("处理器信息", cpuInfo, new Point(20, yPosition), new Size(panelWidth, panelHeight));
                                mainPanel.Controls.Add(cpuPanel);
                                yPosition += panelHeight + 15;

                                // 内存信息
                                var memoryPanel = CreateInfoPanel("内存信息", memoryInfo, new Point(20, yPosition), new Size(panelWidth, panelHeight));
                                mainPanel.Controls.Add(memoryPanel);
                                yPosition += panelHeight + 15;

                                // 磁盘信息
                                var diskPanel = CreateInfoPanel("磁盘信息", diskInfo, new Point(20, yPosition), new Size(panelWidth, panelHeight));
                                mainPanel.Controls.Add(diskPanel);
                                yPosition += panelHeight + 15;

                                // 网络信息
                                var networkPanel = CreateInfoPanel("网络信息", networkInfo, new Point(20, yPosition), new Size(panelWidth, panelHeight));
                                mainPanel.Controls.Add(networkPanel);
                                yPosition += panelHeight + 15;

                                // 系统信息
                                var systemPanel = CreateInfoPanel("系统信息", systemInfo, new Point(20, yPosition), new Size(panelWidth, panelHeight));
                                mainPanel.Controls.Add(systemPanel);

                                // 更新状态
                                statusLabel.Text = "系统信息加载完成";
                                statusLabel.ForeColor = GetThemeColor(ThemeColor.PrimaryColor);
                            }
                            catch (Exception ex)
                            {
                                statusLabel.Text = "加载系统信息时出错: " + ex.Message;
                                statusLabel.ForeColor = Color.Red;
                            }
                        }));
                    }
                    catch (Exception ex)
                    {
                        // 在UI线程中更新错误状态
                        this.Invoke((Action)(() =>
                        {
                            statusLabel.Text = "加载系统信息时出错: " + ex.Message;
                            statusLabel.ForeColor = Color.Red;
                        }));
                    }
                });
            }
            catch (Exception ex)
            {
                statusLabel.Text = "加载系统信息时出错: " + ex.Message;
                statusLabel.ForeColor = Color.Red;
            }
        }

        private void UpdateDynamicInfo()
        {
            try
            {
                // 更新内存和磁盘信息
                var memoryInfo = GetMemoryInfo();
                var diskInfo = GetDiskInfo();

                foreach (Control control in mainPanel.Controls)
                {
                    if (control is Panel panel && panel.Tag != null)
                    {
                        if (panel.Tag.ToString() == "MemoryInfo")
                        {
                            UpdatePanelContent(panel, memoryInfo);
                        }
                        else if (panel.Tag.ToString() == "DiskInfo")
                        {
                            UpdatePanelContent(panel, diskInfo);
                        }
                    }
                }
            }
            catch { }
        }

        private Panel CreateInfoPanel(string title, string[] infoItems, Point location, Size size)
        {
            var panel = new Panel
            {
                Location = location,
                Size = size,
                BackColor = GetThemeColor(ThemeColor.CardBg),
                BorderStyle = BorderStyle.None,
                Tag = title.Replace("信息", "") + "Info"
            };

            // 标题标签
            var titleLabel = new Label
            {
                Text = title,
                Font = new Font("微软雅黑", 12, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Location = new Point(15, 15),
                AutoSize = true
            };
            panel.Controls.Add(titleLabel);

            // 信息内容
            int y = 45;
            foreach (string item in infoItems)
            {
                var infoLabel = new Label
                {
                    Text = item,
                    Font = new Font("微软雅黑", 10),
                    ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                    Location = new Point(15, y),
                    AutoSize = true,
                    MaximumSize = new Size(size.Width - 30, 0)
                };
                panel.Controls.Add(infoLabel);
                y += 20;
            }

            return panel;
        }

        private void UpdatePanelContent(Panel panel, string[] infoItems)
        {
            // 清除旧的信息标签
            var labelsToRemove = new System.Collections.Generic.List<Control>();
            foreach (Control control in panel.Controls)
            {
                if (control is Label label && !label.Font.Bold)
                {
                    labelsToRemove.Add(label);
                }
            }
            foreach (Control control in labelsToRemove)
            {
                panel.Controls.Remove(control);
                control.Dispose();
            }

            // 添加新的信息标签
            int y = 45;
            foreach (string item in infoItems)
            {
                var infoLabel = new Label
                {
                    Text = item,
                    Font = new Font("微软雅黑", 10),
                    ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                    Location = new Point(15, y),
                    AutoSize = true,
                    MaximumSize = new Size(panel.Width - 30, 0)
                };
                panel.Controls.Add(infoLabel);
                y += 20;
            }
        }

        // 缓存机制，减少重复查询
        private static Dictionary<string, object> infoCache = new Dictionary<string, object>();
        private static Dictionary<string, DateTime> cacheTimestamps = new Dictionary<string, DateTime>();
        private const int CACHE_DURATION_SECONDS = 30;

        private bool IsCacheValid(string key)
        {
            if (!cacheTimestamps.ContainsKey(key))
                return false;
            return (DateTime.Now - cacheTimestamps[key]).TotalSeconds < CACHE_DURATION_SECONDS;
        }

        private void UpdateCache(string key, object value)
        {
            infoCache[key] = value;
            cacheTimestamps[key] = DateTime.Now;
        }

        private string[] GetOSInfo()
        {
            const string cacheKey = "OSInfo";
            if (IsCacheValid(cacheKey))
                return (string[])infoCache[cacheKey];

            try
            {
                // 使用Task.Run和超时处理，避免WMI查询卡住
                var task = System.Threading.Tasks.Task.Run(() =>
                {
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, SystemDirectory FROM Win32_OperatingSystem");
                    foreach (ManagementObject os in searcher.Get())
                    {
                        return new string[]
                        {
                            $"操作系统: {os["Caption"]?.ToString() ?? "未知"}",
                            $"版本: {os["Version"]?.ToString() ?? "未知"} (Build {os["BuildNumber"]?.ToString() ?? "未知"})",
                            $"架构: {os["OSArchitecture"]?.ToString() ?? "未知"}",
                            $"安装日期: {GetInstallDate(os)}",
                            $"系统目录: {os["SystemDirectory"]?.ToString() ?? "未知"}"
                        };
                    }
                    return null;
                });

                if (task.Wait(1000)) // 1秒超时
                {
                    if (task.Result != null)
                    {
                        UpdateCache(cacheKey, task.Result);
                        return task.Result;
                    }
                }
            }
            catch (Exception ex)
            {
                var result = new string[]
                {
                    "操作系统: 未知",
                    "版本: 未知",
                    "架构: 未知",
                    "安装日期: 未知",
                    $"错误: {ex.Message}"
                };
                UpdateCache(cacheKey, result);
                return result;
            }

            var defaultResult = new string[]
            {
                "操作系统: 未知",
                "版本: 未知",
                "架构: 未知",
                "安装日期: 未知",
                "系统目录: 未知"
            };
            UpdateCache(cacheKey, defaultResult);
            return defaultResult;
        }
        
        private string GetInstallDate(ManagementObject os)
        {
            try
            {
                var installDate = os["InstallDate"]?.ToString();
                if (!string.IsNullOrEmpty(installDate))
                {
                    return ManagementDateTimeConverter.ToDateTime(installDate).ToString("yyyy-MM-dd HH:mm:ss");
                }
                return "未知";
            }
            catch
            {
                return "未知";
            }
        }

        private string[] GetCPUInfo()
        {
            const string cacheKey = "CPUInfo";
            if (IsCacheValid(cacheKey))
                return (string[])infoCache[cacheKey];

            try
            {
                // 使用Task.Run和超时处理，避免WMI查询卡住
                var task = System.Threading.Tasks.Task.Run(() =>
                {
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor");
                    foreach (ManagementObject cpu in searcher.Get())
                    {
                        return new string[]
                        {
                            $"处理器: {cpu["Name"]?.ToString() ?? "未知"}",
                            $"制造商: {cpu["Manufacturer"]?.ToString() ?? "未知"}",
                            $"核心数: {cpu["NumberOfCores"]?.ToString() ?? "未知"}",
                            $"逻辑处理器: {cpu["NumberOfLogicalProcessors"]?.ToString() ?? "未知"}",
                            $"最大时钟速度: {cpu["MaxClockSpeed"]?.ToString() ?? "未知"} MHz"
                        };
                    }
                    return null;
                });

                if (task.Wait(1000)) // 1秒超时
                {
                    if (task.Result != null)
                    {
                        UpdateCache(cacheKey, task.Result);
                        return task.Result;
                    }
                }
            }
            catch (Exception ex)
            {
                var result = new string[]
                {
                    "处理器: 未知",
                    "制造商: 未知",
                    "核心数: 未知",
                    "逻辑处理器: 未知",
                    $"错误: {ex.Message}"
                };
                UpdateCache(cacheKey, result);
                return result;
            }

            var defaultResult = new string[]
            {
                "处理器: 未知",
                "制造商: 未知",
                "核心数: 未知",
                "逻辑处理器: 未知",
                "最大时钟速度: 未知"
            };
            UpdateCache(cacheKey, defaultResult);
            return defaultResult;
        }

        private string[] GetMemoryInfo()
        {
            // 内存信息不缓存，因为需要实时更新
            try
            {
                // 物理内存
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                ulong totalPhysicalMemory = 0;
                foreach (ManagementObject computer in searcher.Get())
                {
                    totalPhysicalMemory = (ulong)(computer["TotalPhysicalMemory"] ?? 0);
                    break;
                }

                // 可用内存
                ulong freePhysicalMemory = 0;
                ulong totalVisibleMemorySize = 0;
                searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (ManagementObject os in searcher.Get())
                {
                    freePhysicalMemory = (ulong)(os["FreePhysicalMemory"] ?? 0);
                    totalVisibleMemorySize = (ulong)(os["TotalVisibleMemorySize"] ?? 0);
                    break;
                }

                // 计算内存使用情况
                double totalMemoryGB = totalPhysicalMemory / (1024.0 * 1024.0 * 1024.0);
                double availableMemoryGB = freePhysicalMemory / (1024.0 * 1024.0);
                int usagePercent = totalVisibleMemorySize > 0 ? (int)((totalVisibleMemorySize - freePhysicalMemory) * 100 / totalVisibleMemorySize) : 0;

                return new string[]
                {
                    $"物理内存: {Math.Round(totalMemoryGB, 2)} GB",
                    $"可用内存: {Math.Round(availableMemoryGB, 2)} GB",
                    $"内存使用率: {usagePercent}%",
                    $"总可见内存: {totalVisibleMemorySize / (1024 * 1024)} MB",
                    $"可用物理内存: {freePhysicalMemory / 1024} MB"
                };
            }
            catch (Exception ex)
            {
                return new string[]
                {
                    "物理内存: 未知",
                    "可用内存: 未知",
                    "内存使用率: 未知",
                    "总可见内存: 未知",
                    $"错误: {ex.Message}"
                };
            }
        }

        private string[] GetDiskInfo()
        {
            const string cacheKey = "DiskInfo";
            if (IsCacheValid(cacheKey))
                return (string[])infoCache[cacheKey];

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType=3");
                var diskInfo = new System.Collections.Generic.List<string>();
                int diskCount = 0;

                foreach (ManagementObject disk in searcher.Get())
                {
                    if (diskCount >= 4) break; // 最多显示4个磁盘
                    
                    string driveLetter = disk["DeviceID"]?.ToString() ?? "未知";
                    ulong size = (ulong)(disk["Size"] ?? 0);
                    ulong freeSpace = (ulong)(disk["FreeSpace"] ?? 0);
                    double sizeGB = size / (1024.0 * 1024.0 * 1024.0);
                    double freeSpaceGB = freeSpace / (1024.0 * 1024.0 * 1024.0);
                    int usagePercent = size > 0 ? (int)((size - freeSpace) * 100 / size) : 0;

                    diskInfo.Add($"{driveLetter}: {Math.Round(freeSpaceGB, 2)} GB / {Math.Round(sizeGB, 2)} GB ({usagePercent}%)");
                    diskCount++;
                }

                // 确保至少有5条信息
                while (diskInfo.Count < 5)
                {
                    diskInfo.Add("无数据");
                }

                var result = diskInfo.ToArray();
                UpdateCache(cacheKey, result);
                return result;
            }
            catch (Exception ex)
            {
                var result = new string[]
                {
                    "磁盘1: 未知",
                    "磁盘2: 未知",
                    "磁盘3: 未知",
                    "磁盘4: 未知",
                    $"错误: {ex.Message}"
                };
                UpdateCache(cacheKey, result);
                return result;
            }
        }

        private string[] GetNetworkInfo()
        {
            const string cacheKey = "NetworkInfo";
            if (IsCacheValid(cacheKey))
                return (string[])infoCache[cacheKey];

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True");
                var networkInfo = new System.Collections.Generic.List<string>();
                int adapterCount = 0;

                foreach (ManagementObject adapter in searcher.Get())
                {
                    if (adapterCount >= 3) break; // 最多显示3个网络适配器
                    
                    string name = adapter["Name"]?.ToString() ?? "未知";
                    string macAddress = adapter["MACAddress"]?.ToString() ?? "未知";
                    string speed = adapter["Speed"]?.ToString() ?? "未知";

                    networkInfo.Add($"{name}");
                    networkInfo.Add($"  MAC地址: {macAddress}");
                    networkInfo.Add($"  速度: {speed} bps");
                    adapterCount++;
                }

                // 确保至少有5条信息
                while (networkInfo.Count < 5)
                {
                    networkInfo.Add("无数据");
                }

                var result = networkInfo.ToArray();
                UpdateCache(cacheKey, result);
                return result;
            }
            catch (Exception ex)
            {
                var result = new string[]
                {
                    "网络适配器: 未知",
                    "MAC地址: 未知",
                    "速度: 未知",
                    "状态: 未知",
                    $"错误: {ex.Message}"
                };
                UpdateCache(cacheKey, result);
                return result;
            }
        }

        private string[] GetSystemInfo()
        {
            const string cacheKey = "SystemInfo";
            if (IsCacheValid(cacheKey))
                return (string[])infoCache[cacheKey];

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                string manufacturer = "未知";
                string model = "未知";
                string totalPhysicalMemory = "未知";

                foreach (ManagementObject computer in searcher.Get())
                {
                    manufacturer = computer["Manufacturer"]?.ToString() ?? "未知";
                    model = computer["Model"]?.ToString() ?? "未知";
                    ulong memory = (ulong)(computer["TotalPhysicalMemory"] ?? 0);
                    totalPhysicalMemory = $"{Math.Round(memory / (1024.0 * 1024.0 * 1024.0), 2)} GB";
                    break;
                }

                // 系统启动时间
                searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                string lastBootUpTime = "未知";
                foreach (ManagementObject os in searcher.Get())
                {
                    lastBootUpTime = ManagementDateTimeConverter.ToDateTime(os["LastBootUpTime"]?.ToString() ?? "").ToString("yyyy-MM-dd HH:mm:ss");
                    break;
                }

                var result = new string[]
                {
                    $"制造商: {manufacturer}",
                    $"型号: {model}",
                    $"总物理内存: {totalPhysicalMemory}",
                    $"上次启动时间: {lastBootUpTime}",
                    $"计算机名: {Environment.MachineName}"
                };
                UpdateCache(cacheKey, result);
                return result;
            }
            catch (Exception ex)
            {
                var result = new string[]
                {
                    "制造商: 未知",
                    "型号: 未知",
                    "总物理内存: 未知",
                    "上次启动时间: 未知",
                    $"错误: {ex.Message}"
                };
                UpdateCache(cacheKey, result);
                return result;
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
            mainPanel.BackColor = GetThemeColor(ThemeColor.BgPrimary);

            // 更新所有子控件的颜色
            UpdateControlsTheme(this);
        }

        private void UpdateControlsTheme(Control control)
        {
            foreach (Control child in control.Controls)
            {
                if (child is Panel panel)
                {
                    panel.BackColor = GetThemeColor(ThemeColor.CardBg);
                }
                else if (child is Label label)
                {
                    if (label.Font.Bold)
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                    }
                    else
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
                    }
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
                    case ThemeColor.PrimaryColor:
                        return Color.FromArgb(0, 212, 255);
                    case ThemeColor.TextPrimary:
                        return Color.White;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.FromArgb(30, 30, 30);
                    case ThemeColor.CardBg:
                        return Color.FromArgb(45, 45, 45);
                    default:
                        return Color.Black;
                }
            }
            else
            {
                switch (colorType)
                {
                    case ThemeColor.PrimaryColor:
                        return Color.FromArgb(37, 99, 235);
                    case ThemeColor.TextPrimary:
                        return Color.Black;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.White;
                    case ThemeColor.CardBg:
                        return Color.White;
                    default:
                        return Color.White;
                }
            }
        }
    }
}