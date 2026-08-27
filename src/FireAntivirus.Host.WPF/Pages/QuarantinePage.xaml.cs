// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Data;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 隔离区页面 - 从WinForms转换
    /// </summary>
    public partial class QuarantinePage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private DataManager dataManager;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public QuarantinePage()
        {
            try
            {
                InitializeComponent();
                
                // 延迟加载: 仅在页面显示时初始化数据
                Loaded += (s, e) => 
                {
                    dataManager = new DataManager();
                    LoadQuarantineFiles();
                };
                
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing QuarantinePage: {ex.Message}");
            }
        }

        private void LoadQuarantineFiles_Click(object sender, RoutedEventArgs e)
        {
            LoadQuarantineFiles();
        }

        private void LoadQuarantineFiles()
        {
            try
            {
                var quarantineItems = new List<QuarantineItemView>();
                var items = dataManager.LoadQuarantine();
                
                foreach (var item in items)
                {
                    quarantineItems.Add(new QuarantineItemView
                    {
                        Id = item.Id,
                        FileName = item.FileName,
                        OriginalPath = item.OriginalPath,
                        ThreatType = item.ThreatType,
                        QuarantineTime = item.QuarantineTime.ToString("yyyy-MM-dd HH:mm"),
                        Size = FormatFileSize(item.Size)
                    });
                }
                
                QuarantineGrid.ItemsSource = quarantineItems;
            }
            catch
            {
                // 如果读取失败，显示空列表
                QuarantineGrid.ItemsSource = new List<QuarantineItemView>();
            }
        }

        private string FormatFileSize(long sizeInBytes)
        {
            if (sizeInBytes < 1024)
            {
                return $"{sizeInBytes} B";
            }
            else if (sizeInBytes < 1024 * 1024)
            {
                double sizeInKB = sizeInBytes / 1024.0;
                return $"{sizeInKB:F1} KB";
            }
            else
            {
                double sizeInMB = sizeInBytes / (1024.0 * 1024.0);
                return $"{sizeInMB:F1} MB";
            }
        }

        private void RestoreSelectedFiles_Click(object sender, RoutedEventArgs e)
        {
            if (QuarantineGrid.SelectedItem is QuarantineItemView selectedItem)
            {
                bool success = dataManager.RestoreFile(selectedItem.Id);
                if (success)
                {
                    MessageBox.Show($"文件 {selectedItem.FileName} 已恢复到原路径", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    LoadQuarantineFiles();
                }
                else
                {
                    MessageBox.Show($"恢复文件 {selectedItem.FileName} 失败", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void DeleteSelectedFiles_Click(object sender, RoutedEventArgs e)
        {
            if (QuarantineGrid.SelectedItem is QuarantineItemView selectedItem)
            {
                bool success = dataManager.DeleteFromQuarantine(selectedItem.Id);
                if (success)
                {
                    MessageBox.Show($"文件 {selectedItem.FileName} 已从隔离区删除", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    LoadQuarantineFiles();
                }
                else
                {
                    MessageBox.Show($"删除文件 {selectedItem.FileName} 失败", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ClearQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("确定要清空整个隔离区吗？", "确认", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                dataManager.ClearQuarantine();
                LoadQuarantineFiles();
                MessageBox.Show("隔离区已清空", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
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
                QuarantineGrid.Background = new SolidColorBrush(Color.FromRgb(50, 50, 50));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Colors.White);
                QuarantineGrid.Background = new SolidColorBrush(Color.FromRgb(243, 244, 246));
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("Quarantine", "隔离区");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "QuarantinePage.xaml.cs 捕获异常", ex.Message); }
        }
    }

    // 隔离区项视图类
    public class QuarantineItemView
    {
        public string Id { get; set; }
        public string FileName { get; set; }
        public string OriginalPath { get; set; }
        public string ThreatType { get; set; }
        public string QuarantineTime { get; set; }
        public string Size { get; set; }
    }
}