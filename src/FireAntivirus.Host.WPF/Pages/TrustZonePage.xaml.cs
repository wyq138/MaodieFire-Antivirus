// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 信任区页面 - 从WinForms转换
    /// </summary>
    public partial class TrustZonePage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public TrustZonePage()
        {
            try
            {
                InitializeComponent();
                LoadTrustList();
                
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing TrustZonePage: {ex.Message}");
            }
        }

        private void LoadTrustList()
        {
            try
            {
                var trustItems = new List<TrustItem>();
                string trustListPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "哈基咪杀毒", "trustlist.txt");

                if (File.Exists(trustListPath))
                {
                    string[] lines = File.ReadAllLines(trustListPath);
                    foreach (string line in lines)
                    {
                        if (!string.IsNullOrEmpty(line))
                        {
                            string[] parts = line.Split('|');
                            if (parts.Length >= 3)
                            {
                                trustItems.Add(new TrustItem
                                {
                                    Type = parts[0],
                                    Path = parts[1],
                                    AddTime = parts[2]
                                });
                            }
                        }
                    }
                }

                TrustListGrid.ItemsSource = trustItems;
            }
            catch
            {
                TrustListGrid.ItemsSource = new List<TrustItem>();
            }
        }

        private void AddTrustFile_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "所有文件 (*.*)|*.*",
                Title = "选择要添加到信任区的文件"
            };

            if (ofd.ShowDialog() == true)
            {
                string addTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                SaveTrustItem("文件", ofd.FileName, addTime);
                LoadTrustList();
                MessageBox.Show($"文件 {Path.GetFileName(ofd.FileName)} 已添加到信任区", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void AddTrustFolder_Click(object sender, RoutedEventArgs e)
        {
            // WPF没有内置的FolderBrowserDialog，使用WinForms版本
            var fbd = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "选择要添加到信任区的文件夹"
            };

            if (fbd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                string addTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                SaveTrustItem("文件夹", fbd.SelectedPath, addTime);
                LoadTrustList();
                MessageBox.Show($"文件夹 {Path.GetFileName(fbd.SelectedPath)} 已添加到信任区", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void SaveTrustItem(string type, string path, string addTime)
        {
            try
            {
                string trustListPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "哈基咪杀毒", "trustlist.txt");

                // 确保目录存在
                Directory.CreateDirectory(Path.GetDirectoryName(trustListPath));

                // 追加到文件
                using (StreamWriter writer = File.AppendText(trustListPath))
                {
                    writer.WriteLine($"{type}|{path}|{addTime}");
                }
            }
            catch
            {
                // 保存失败时忽略错误
            }
        }

        private void DeleteTrustItem_Click(object sender, RoutedEventArgs e)
        {
            if (TrustListGrid.SelectedItem is TrustItem selectedItem)
            {
                try
                {
                    string trustListPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "哈基咪杀毒", "trustlist.txt");

                    if (File.Exists(trustListPath))
                    {
                        var lines = new List<string>(File.ReadAllLines(trustListPath));
                        lines.RemoveAll(l => l.Contains(selectedItem.Path));
                        File.WriteAllLines(trustListPath, lines);
                    }

                    LoadTrustList();
                    MessageBox.Show($"信任项 {selectedItem.Path} 已删除", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch
                {
                    MessageBox.Show("删除信任项失败", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
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
                TrustListGrid.Background = new SolidColorBrush(Color.FromRgb(50, 50, 50));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Colors.White);
                TrustListGrid.Background = new SolidColorBrush(Color.FromRgb(243, 244, 246));
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("TrustZone", "信任区");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "TrustZonePage.xaml.cs 捕获异常", ex.Message); }
        }
    }

    // 信任项类
    public class TrustItem
    {
        public string Type { get; set; }
        public string Path { get; set; }
        public string AddTime { get; set; }
    }
}