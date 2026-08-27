// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 日志中心页面 - 从WinForms转换
    /// </summary>
    public partial class LogsPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public LogsPage()
        {
            try
            {
                InitializeComponent();
                LoadAllLogs();
                
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing LogsPage: {ex.Message}");
            }
        }

        private void LoadAllLogs()
        {
            LoadLogsFromFile(ScanLogList, "ScanLogs.txt");
            LoadLogsFromFile(ProtectionLogList, "ProtectionLogs.txt");
            LoadLogsFromFile(NetworkLogList, "NetworkLogs.txt");
            LoadLogsFromFile(SystemLogList, "SystemLogs.txt");
            LoadLogsFromFile(UpdateLogList, "UpdateLogs.txt");
        }

        private void LoadLogsFromFile(ListBox listBox, string fileName)
        {
            try
            {
                string logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "哈基咪杀毒", "Logs", fileName);

                if (File.Exists(logPath))
                {
                    var logs = File.ReadAllLines(logPath);
                    // 只显示最近的50条日志
                    var recentLogs = logs.Skip(Math.Max(0, logs.Length - 50)).ToArray();
                    listBox.Items.Clear();
                    foreach (var log in recentLogs)
                    {
                        listBox.Items.Add(log);
                    }
                }
                else
                {
                    listBox.Items.Clear();
                    listBox.Items.Add("暂无日志记录");
                }
            }
            catch
            {
                listBox.Items.Clear();
                listBox.Items.Add("无法加载日志文件");
            }
        }

        private void ClearLogs_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("确定要清空所有日志吗？", "确认", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                try
                {
                    string logsPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "哈基咪杀毒", "Logs");

                    if (Directory.Exists(logsPath))
                    {
                        string[] logFiles = Directory.GetFiles(logsPath);
                        foreach (string file in logFiles)
                        {
                            File.Delete(file);
                        }
                    }

                    // 清空所有列表
                    ScanLogList.Items.Clear();
                    ScanLogList.Items.Add("暂无日志记录");
                    ProtectionLogList.Items.Clear();
                    ProtectionLogList.Items.Add("暂无日志记录");
                    NetworkLogList.Items.Clear();
                    NetworkLogList.Items.Add("暂无日志记录");
                    SystemLogList.Items.Clear();
                    SystemLogList.Items.Add("暂无日志记录");
                    UpdateLogList.Items.Clear();
                    UpdateLogList.Items.Add("暂无日志记录");

                    MessageBox.Show("日志已清空", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch
                {
                    MessageBox.Show("清空日志失败", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportLogs_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var saveDialog = new SaveFileDialog
                {
                    Filter = "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
                    FileName = $"FireAntivirus_Logs_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                    Title = "导出日志"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    using (StreamWriter writer = new StreamWriter(saveDialog.FileName))
                    {
                        writer.WriteLine("=== 哈基咪杀毒 日志导出 ===");
                        writer.WriteLine($"导出时间: {DateTime.Now}");
                        writer.WriteLine("==================================");
                        writer.WriteLine();

                        // 导出查杀日志
                        writer.WriteLine("=== 查杀日志 ===");
                        foreach (var item in ScanLogList.Items)
                        {
                            writer.WriteLine(item.ToString());
                        }
                        writer.WriteLine();

                        // 导出防护日志
                        writer.WriteLine("=== 防护日志 ===");
                        foreach (var item in ProtectionLogList.Items)
                        {
                            writer.WriteLine(item.ToString());
                        }
                        writer.WriteLine();

                        // 导出网络日志
                        writer.WriteLine("=== 网络日志 ===");
                        foreach (var item in NetworkLogList.Items)
                        {
                            writer.WriteLine(item.ToString());
                        }
                        writer.WriteLine();

                        // 导出系统日志
                        writer.WriteLine("=== 系统日志 ===");
                        foreach (var item in SystemLogList.Items)
                        {
                            writer.WriteLine(item.ToString());
                        }
                        writer.WriteLine();

                        // 导出更新日志
                        writer.WriteLine("=== 更新日志 ===");
                        foreach (var item in UpdateLogList.Items)
                        {
                            writer.WriteLine(item.ToString());
                        }
                    }

                    MessageBox.Show("日志导出成功", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch
            {
                MessageBox.Show("导出日志失败", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            if (currentTheme == Theme.Dark)
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
                LogsTabControl.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
                ScanLogList.Background = new SolidColorBrush(Color.FromRgb(50, 50, 50));
                ProtectionLogList.Background = new SolidColorBrush(Color.FromRgb(50, 50, 50));
                NetworkLogList.Background = new SolidColorBrush(Color.FromRgb(50, 50, 50));
                SystemLogList.Background = new SolidColorBrush(Color.FromRgb(50, 50, 50));
                UpdateLogList.Background = new SolidColorBrush(Color.FromRgb(50, 50, 50));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Colors.White);
                LogsTabControl.Background = new SolidColorBrush(Colors.White);
                ScanLogList.Background = new SolidColorBrush(Color.FromRgb(243, 244, 246));
                ProtectionLogList.Background = new SolidColorBrush(Color.FromRgb(243, 244, 246));
                NetworkLogList.Background = new SolidColorBrush(Color.FromRgb(243, 244, 246));
                SystemLogList.Background = new SolidColorBrush(Color.FromRgb(243, 244, 246));
                UpdateLogList.Background = new SolidColorBrush(Color.FromRgb(243, 244, 246));
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("Logs", "日志中心");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "LogsPage.xaml.cs 捕获异常", ex.Message); }
        }
    }
}