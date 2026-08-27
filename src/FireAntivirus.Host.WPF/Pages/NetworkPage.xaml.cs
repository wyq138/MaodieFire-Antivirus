// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 网络防护页面 - 从WinForms转换
    /// </summary>
    public partial class NetworkPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private DispatcherTimer networkUpdateTimer;
        private System.Threading.CancellationTokenSource _cts = new();
        private bool _isLoaded = false;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public NetworkPage()
        {
            try
            {
                InitializeComponent();
                InitializeTimer();
                
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();        
                // 页面加载时自动扫描网络
                Loaded += (s, e) =>
                {
                    _isLoaded = true;
                    AutoScanNetwork();
                };
                
                // 页面卸载时停止后台任务
                Unloaded += (s, e) =>
                {
                    _isLoaded = false;
                    _cts?.Cancel();
                    networkUpdateTimer?.Stop();
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing NetworkPage: {ex.Message}");
            }
        }

        private void InitializeTimer()
        {
            networkUpdateTimer = new DispatcherTimer();
            networkUpdateTimer.Interval = TimeSpan.FromSeconds(10);
            networkUpdateTimer.IsEnabled = false;        }

        private void AutoScanNetwork()
        {
            StatusLabel.Text = "正在扫描网络...";
            Task.Run(() =>
            {
                try
                {
                    var networkStatus = CheckNetworkStatus();
                    var networkApps = GetNetworkApplications();

                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        if (!_cts.Token.IsCancellationRequested)
                        {
                            UpdateNetworkAppsGrid(networkApps);
                            // 更新网络状态
                            StatusLabel.Text = networkStatus.Status ?? "已连接";
                            StatusLabel.Text = "扫描完成";
                            networkUpdateTimer?.Start();
                        }
                    }));
                }
                catch (Exception ex)
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        StatusLabel.Text = "扫描失败: " + ex.Message;
                    }));
                }
            });
        }

        private void NetworkScan_Click(object sender, RoutedEventArgs e)
        {
            StatusLabel.Text = "正在检测网络状态...";
            NetworkScanBtn.IsEnabled = false;

            Task.Run(() =>
            {
                try
                {
                    var networkStatus = CheckNetworkStatus();
                    var networkApps = new List<NetworkApplication>();
                    var cts = new CancellationTokenSource();
                    cts.CancelAfter(3000);

                    try
                    {
                        networkApps = GetNetworkApplications();
                    }
                    catch (OperationCanceledException)
                    {
                        networkApps = new List<NetworkApplication>
                        {
                            new NetworkApplication
                            {
                                AppName = "检测超时",
                                Path = "网络检测超时",
                                Upload = "0.0 KB/s",
                                Download = "0.0 KB/s",
                                Status = "超时"
                            }
                        };
                    }

                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        StatusLabel.Text = $"网络检测完成 - 状态: {networkStatus.Status}, 应用数: {networkApps.Count}";
                        UpdateNetworkAppsGrid(networkApps);
                    }));
                }
                catch (Exception ex)
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        StatusLabel.Text = $"网络检测失败: {ex.Message}";
                    }));
                }
                finally
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        NetworkScanBtn.IsEnabled = true;
                    }));
                }
            });
        }

        private NetworkStatus CheckNetworkStatus()
        {
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
                string[] netstatArgs = { "-ano", "-p", "tcp" };
                string output = ExecuteNetstatCommand(netstatArgs);

                if (!string.IsNullOrEmpty(output))
                {
                    ParseNetstatOutput(output, apps);
                }

                string[] udpArgs = { "-ano", "-p", "udp" };
                string udpOutput = ExecuteNetstatCommand(udpArgs);

                if (!string.IsNullOrEmpty(udpOutput))
                {
                    ParseNetstatOutput(udpOutput, apps);
                }

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
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netstat.exe",
                    Arguments = string.Join(" ", arguments),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            string output = null;
            if (process.WaitForExit(3000))
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

            int lineCount = 0;
            int maxLines = 300;
            foreach (var line in output.Split('\n'))
            {
                if (lineCount >= maxLines)
                    break;

                lineCount++;
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

                            if (processId > 0)
                            {
                                try
                                {
                                    var proc = Process.GetProcessById(processId);
                                    appName = proc.ProcessName;
                                    try
                                    {
                                        path = proc.MainModule?.FileName ?? "未知路径";
                                    }
                                    catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 5)
                                    {
                                        path = GetProcessPathFromWMI(processId);
                                    }
                                    catch
                                    {
                                        path = "未知路径";
                                    }
                                }
                                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkPage.xaml.cs 捕获异常", ex.Message); }
                            }

                            if (!apps.Any(a => a.AppName == appName))
                            {
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
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkPage.xaml.cs 捕获异常", ex.Message); }
            return "未知路径";
        }

        private string CalculateNetworkSpeed(int processId, bool isUpload)
        {
            try
            {
                PerformanceCounterCategory category = new PerformanceCounterCategory("Network Interface");
                string[] instanceNames = category.GetInstanceNames();

                if (instanceNames.Length > 0)
                {
                    string instanceName = instanceNames[0];
                    System.Diagnostics.PerformanceCounter counter;

                    if (isUpload)
                    {
                        counter = new System.Diagnostics.PerformanceCounter("Network Interface", "Bytes Sent/sec", instanceName);
                    }
                    else
                    {
                        counter = new System.Diagnostics.PerformanceCounter("Network Interface", "Bytes Received/sec", instanceName);
                    }

                    float bytesPerSec = counter.NextValue();
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
            NetworkAppsGrid.ItemsSource = null;
            NetworkAppsGrid.ItemsSource = apps;
        }

        private void BlockSelectedApp_Click(object sender, RoutedEventArgs e)
        {
            if (NetworkAppsGrid.SelectedItem is NetworkApplication selectedApp)
            {
                selectedApp.Status = "禁止";
                NetworkAppsGrid.Items.Refresh();
                StatusLabel.Text = $"已禁止应用: {selectedApp.AppName}";
            }
        }

        private void AllowSelectedApp_Click(object sender, RoutedEventArgs e)
        {
            if (NetworkAppsGrid.SelectedItem is NetworkApplication selectedApp)
            {
                selectedApp.Status = "允许";
                NetworkAppsGrid.Items.Refresh();
                StatusLabel.Text = $"已允许应用: {selectedApp.AppName}";
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            var resources = Application.Current.Resources;

            if (currentTheme == Theme.Dark)
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
                NetworkAppsGrid.Background = new SolidColorBrush(Color.FromRgb(50, 50, 50));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Colors.White);
                NetworkAppsGrid.Background = new SolidColorBrush(Color.FromRgb(243, 244, 246));
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("NetworkProtection", "网络防护");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NetworkPage.xaml.cs 捕获异常", ex.Message); }
        }

        private class NetworkStatus
        {
            public string Status { get; set; }
            public string Details { get; set; }
        }
    }

    public class NetworkApplication
    {
        public string AppName { get; set; }
        public string Path { get; set; }
        public string Upload { get; set; }
        public string Download { get; set; }
        public string Status { get; set; }
    }
}