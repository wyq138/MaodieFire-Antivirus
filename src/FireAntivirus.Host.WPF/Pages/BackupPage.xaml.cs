// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class BackupPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private BackupService backupService;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private List<BackupTaskInfo> backupTasks = new List<BackupTaskInfo>();

        public BackupPage()
        {
            InitializeComponent();
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            
            // 异步加载，不阻塞UI
            Loaded += (s, e) =>
            {
                _ = System.Threading.Tasks.Task.Run(() =>
                {
                    try { backupService = new BackupService(new DataManager()); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackupPage.xaml.cs 捕获异常", ex.Message); }
                    
                    Dispatcher.BeginInvoke(new Action(() =>
                    {
                        LoadBackupTasks();
                    }));
                });
            };
        }

        private void LoadBackupTasks()
        {
            try
            {
                string backupDir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Backups");
                
                BackupPath.Text = backupDir;
                
                if (!System.IO.Directory.Exists(backupDir))
                {
                    System.IO.Directory.CreateDirectory(backupDir);
                }
                
                backupTasks.Clear();
                foreach (var dir in System.IO.Directory.GetDirectories(backupDir))
                {
                    try
                    {
                        var info = new System.IO.DirectoryInfo(dir);
                        backupTasks.Add(new BackupTaskInfo
                        {
                            Name = info.Name,
                            CreatedTime = info.CreationTime.ToString("yyyy-MM-dd HH:mm"),
                            Size = FormatSize(GetDirectorySize(dir))
                        });
                    } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackupPage.xaml.cs 捕获异常", ex.Message); }
                }
                BackupTasksGrid.ItemsSource = null;
                BackupTasksGrid.ItemsSource = backupTasks;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackupPage.xaml.cs 捕获异常", ex.Message); }
        }

        private long GetDirectorySize(string path)
        {
            long size = 0;
            try
            {
                foreach (var file in System.IO.Directory.GetFiles(path, "*.*", System.IO.SearchOption.AllDirectories))
                    size += new System.IO.FileInfo(file).Length;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackupPage.xaml.cs 捕获异常", ex.Message); }
            return size;
        }

        private string FormatSize(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int i = 0;
            double size = bytes;
            while (size >= 1024 && i < suffixes.Length - 1) { size /= 1024; i++; }
            return string.Format("{0:F1} {1}", size, suffixes[i]);
        }

        private void BrowsePath_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog();
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                BackupPath.Text = dialog.SelectedPath;
            }
        }

        private void CreateBackup_Click(object sender, RoutedEventArgs e)
        {
            // 状态更新
        }

        private void Restore_Click(object sender, RoutedEventArgs e)
        {
            if (BackupTasksGrid.SelectedItem is BackupTaskInfo task)
            {
                // 状态更新
            }
        }

        private void DeleteBackup_Click(object sender, RoutedEventArgs e)
        {
            if (BackupTasksGrid.SelectedItem is BackupTaskInfo task)
            {
                backupTasks.Remove(task);
                BackupTasksGrid.ItemsSource = null;
                BackupTasksGrid.ItemsSource = backupTasks;
            }
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
                TitleText.Text = _languageManager.GetString("Backup", "备份恢复");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackupPage.xaml.cs 捕获异常", ex.Message); }
        }
    }

    public class BackupTaskInfo
    {
        public string Name { get; set; }
        public string CreatedTime { get; set; }
        public string Size { get; set; }
    }
}