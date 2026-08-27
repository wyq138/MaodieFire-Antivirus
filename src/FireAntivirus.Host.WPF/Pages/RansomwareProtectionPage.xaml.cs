// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class RansomwareProtectionPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private List<string> protectedFolders = new List<string>();

        public RansomwareProtectionPage()
        {
            InitializeComponent();
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            
            // 异步加载，不阻塞UI
            Loaded += (s, e) =>
            {
                _ = System.Threading.Tasks.Task.Run(() =>
                {
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        LoadProtectedFolders();
                    }));
                });
            };
        }

        private void LoadProtectedFolders()
        {
            try
            {
                protectedFolders.Clear();
                protectedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
                protectedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));
                protectedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
                
                ProtectedFoldersList.ItemsSource = null;
                ProtectedFoldersList.ItemsSource = protectedFolders;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void AddFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog();
            dialog.Description = "选择要保护的文件夹";
            
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                if (!protectedFolders.Contains(dialog.SelectedPath))
                {
                    protectedFolders.Add(dialog.SelectedPath);
                    ProtectedFoldersList.ItemsSource = null;
                    ProtectedFoldersList.ItemsSource = protectedFolders;
                }
            }
        }

        private void RemoveFolder_Click(object sender, RoutedEventArgs e)
        {
            if (ProtectedFoldersList.SelectedItem is string selectedFolder)
            {
                protectedFolders.Remove(selectedFolder);
                ProtectedFoldersList.ItemsSource = null;
                ProtectedFoldersList.ItemsSource = protectedFolders;
            }
        }

        private void StartProtection_Click(object sender, RoutedEventArgs e)
        {
            StatusText.Text = "已启用";
            StatusText.Foreground = new SolidColorBrush(Colors.Green);
        }

        private void StopProtection_Click(object sender, RoutedEventArgs e)
        {
            StatusText.Text = "已禁用";
            StatusText.Foreground = new SolidColorBrush(Colors.Red);
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            MainGrid.Background = theme == Theme.Dark 
                ? new SolidColorBrush(Color.FromRgb(30, 30, 30))
                : Brushes.White;
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("RansomwareProtection", "勒索防护");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "RansomwareProtectionPage.xaml.cs 捕获异常", ex.Message); }
        }
    }
}