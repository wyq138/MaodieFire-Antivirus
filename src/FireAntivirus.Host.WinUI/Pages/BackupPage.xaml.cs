// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class BackupTaskInfo
    {
        public string Name { get; set; } = "";
        public string CreatedTime { get; set; } = "";
        public string Size { get; set; } = "";
        public string Dir { get; set; } = "";
    }

    public sealed partial class BackupPage : Page
    {
        private readonly ObservableCollection<BackupTaskInfo> _tasks = new();

        public BackupPage()
        {
            InitializeComponent();
            BackupTasksGrid.ItemsSource = _tasks;
            LoadBackupTasks();
        }

        private static string BackupDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "Backups");

        private static string Fmt(long bytes)
        {
            string[] suf = { "B", "KB", "MB", "GB" };
            double v = bytes; int i = 0;
            while (v >= 1024 && i < suf.Length - 1) { v /= 1024; i++; }
            return $"{v:F1} {suf[i]}";
        }

        private static long DirSize(string path)
        {
            long size = 0;
            try { foreach (var f in Directory.GetFiles(path, "*", SearchOption.AllDirectories)) size += new FileInfo(f).Length; } catch { }
            return size;
        }

        private void LoadBackupTasks()
        {
            _tasks.Clear();
            try
            {
                BackupPath.Text = BackupDir;
                if (!Directory.Exists(BackupDir)) Directory.CreateDirectory(BackupDir);
                foreach (var dir in Directory.GetDirectories(BackupDir))
                {
                    try
                    {
                        var info = new DirectoryInfo(dir);
                        _tasks.Add(new BackupTaskInfo
                        {
                            Name = info.Name,
                            CreatedTime = info.CreationTime.ToString("yyyy-MM-dd HH:mm"),
                            Size = Fmt(DirSize(dir)),
                            Dir = dir
                        });
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "读取备份失败: " + ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "加载备份列表失败: " + ex.Message);
            }
            CountText.Text = $"共 {_tasks.Count} 个备份";
        }

        private void CreateBackup_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!Directory.Exists(BackupDir)) Directory.CreateDirectory(BackupDir);
                string name = "Backup_" + DateTime.Now.ToString("yyyyMMdd_HHmmss");
                Directory.CreateDirectory(Path.Combine(BackupDir, name));
                LoadBackupTasks();
                _ = new ContentDialog
                {
                    Title = "备份创建",
                    Content = "已创建备份目录： " + name,
                    CloseButtonText = "确定", XamlRoot = XamlRoot
                }.ShowAsync();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "创建备份失败: " + ex.Message);
            }
        }

        private void DeleteBackup_Click(object sender, RoutedEventArgs e)
        {
            if (BackupTasksGrid.SelectedItem is not BackupTaskInfo task) return;
            try
            {
                if (Directory.Exists(task.Dir)) Directory.Delete(task.Dir, true);
                LoadBackupTasks();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "删除备份失败: " + ex.Message);
            }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => LoadBackupTasks();
    }
}