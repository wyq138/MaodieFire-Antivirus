// 抖音用户 耙耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host.WPF.Pages
{
    public class StartupItem
    {
        public string Name { get; set; }
        public string Publisher { get; set; }
        public string Path { get; set; }
        public string Status { get; set; }
        public string Impact { get; set; }
    }

    public partial class StartupManagerPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private StartupManager startupManager;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private List<StartupItem> startupItems = new List<StartupItem>();

        public StartupManagerPage()
        {
            InitializeComponent();
            
            // 延迟加载: 仅在页面显示时初始化数据
            Loaded += (s, e) => 
            {
                InitializeService();
                LoadStartupItems();
            };
            
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
        }

        private void InitializeService()
        {
            try { startupManager = new StartupManager(); } catch { }
        }

        private void LoadStartupItems()
        {
            startupItems.Clear();
            
            // 添加示例数据
            startupItems.Add(new StartupItem { Name = "Windows Defender", Publisher = "Microsoft", Path = @"C:\Program Files\Windows Defender\MSASCui.exe", Status = "已启用", Impact = "低" });
            startupItems.Add(new StartupItem { Name = "OneDrive", Publisher = "Microsoft", Path = @"C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDrive.exe", Status = "已启用", Impact = "低" });
            startupItems.Add(new StartupItem { Name = "Steam", Publisher = "Valve", Path = @"C:\Program Files (x86)\Steam\steam.exe", Status = "已禁用", Impact = "中" });
            startupItems.Add(new StartupItem { Name = "Spotify", Publisher = "Spotify AB", Path = @"C:\Users\User\AppData\Roaming\Spotify\Spotify.exe", Status = "已启用", Impact = "中" });
            startupItems.Add(new StartupItem { Name = "NVIDIA GeForce Experience", Publisher = "NVIDIA", Path = @"C:\Program Files\NVIDIA Corporation\NVIDIA GeForce Experience\NVIDIA GeForce Experience.exe", Status = "已启用", Impact = "高" });
            
            StartupGrid.ItemsSource = null;
            StartupGrid.ItemsSource = startupItems;
            
            UpdateStatistics();
        }

        private void UpdateStatistics()
        {
            int total = startupItems.Count;
            int enabled = 0;
            int disabled = 0;
            
            foreach (var item in startupItems)
            {
                if (item.Status == "已启用") enabled++;
                else disabled++;
            }
            
            TotalStartupText.Text = total.ToString();
            EnabledStartupText.Text = enabled.ToString();
            DisabledStartupText.Text = disabled.ToString();
        }

        private void AddStartup_Click(object sender, RoutedEventArgs e)
        {
            var input = Microsoft.VisualBasic.Interaction.InputBox("请输入启动项路径:", "添加启动项", "");
            if (!string.IsNullOrEmpty(input))
            {
                MessageBox.Show($"已添加启动项: {input}", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                LoadStartupItems();
            }
        }

        private void RefreshStartup_Click(object sender, RoutedEventArgs e)
        {
            LoadStartupItems();
            MessageBox.Show("启动项列表已刷新", "完成", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void EnableStartup_Click(object sender, RoutedEventArgs e)
        {
            if (StartupGrid.SelectedItem is StartupItem item)
            {
                item.Status = "已启用";
                StartupGrid.Items.Refresh();
                UpdateStatistics();
                MessageBox.Show($"已启用: {item.Name}", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("请先选择一个启动项", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void DisableStartup_Click(object sender, RoutedEventArgs e)
        {
            if (StartupGrid.SelectedItem is StartupItem item)
            {
                item.Status = "已禁用";
                StartupGrid.Items.Refresh();
                UpdateStatistics();
                MessageBox.Show($"已禁用: {item.Name}", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("请先选择一个启动项", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void DeleteStartup_Click(object sender, RoutedEventArgs e)
        {
            if (StartupGrid.SelectedItem is StartupItem item)
            {
                var result = MessageBox.Show($"确定要删除启动项: {item.Name}?", "确认删除", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    startupItems.Remove(item);
                    StartupGrid.ItemsSource = null;
                    StartupGrid.ItemsSource = startupItems;
                    UpdateStatistics();
                    MessageBox.Show("启动项已删除", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            else
            {
                MessageBox.Show("请先选择一个启动项", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark) MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("StartupManager", "启动管理"); } catch { }
        }
    }
}
