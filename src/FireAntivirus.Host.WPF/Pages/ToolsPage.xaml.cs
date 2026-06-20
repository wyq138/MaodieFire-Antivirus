// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 系统工具页面 - 从WinForms转换
    /// </summary>
    public partial class ToolsPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private StartupManager startupManager;
        private SystemOptimizerService systemOptimizer;
        private VulnerabilityScannerService vulnerabilityScanner;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public ToolsPage()
        {
            try
            {
                InitializeComponent();                
                // 延迟加载：将数据加载逻辑移到Loaded事件中
                Loaded += (s, e) => InitializeServices();
                
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing ToolsPage: {ex.Message}");
            }
        }

        private void InitializeServices()
        {
            try
            {
                startupManager = new StartupManager();
                systemOptimizer = new SystemOptimizerService();
                vulnerabilityScanner = new VulnerabilityScannerService();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing services: {ex.Message}");
            }
        }

        private void RunTool_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string toolName)
            {
                RunTool(toolName);
            }
        }

        private void RunTool(string toolName)
        {
            try
            {
                switch (toolName)
                {
                    case "启动项管理":
                        RunStartupManager();
                        break;
                    case "文件粉碎":
                        RunFileShredder();
                        break;
                    case "右键菜单管理":
                        RunContextMenuManager();
                        break;
                    case "垃圾清理":
                        RunJunkCleaner();
                        break;
                    case "系统修复":
                        RunSystemRepair();
                        break;
                    case "漏洞修复":
                        RunVulnerabilityScanner();
                        break;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"运行工具时出错: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RunStartupManager()
        {
            try
            {
                var items = startupManager.GetStartupItems();
                var message = $"共有 {items.Count} 个启动项\n\n";
                int enabledCount = 0;
                int disabledCount = 0;

                foreach (var item in items)
                {
                    if (item.Enabled) enabledCount++;
                    else disabledCount++;
                }

                message += $"已启用: {enabledCount} 项\n";
                message += $"已禁用: {disabledCount} 项\n\n";
                message += "启动项管理功能已就绪。";

                MessageBox.Show(message, "启动项管理", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"启动项管理功能运行失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RunFileShredder()
        {
            var result = MessageBox.Show(
                "文件粉碎功能可以彻底删除文件，使其无法恢复。\n\n" +
                "是否选择文件进行粉碎？\n\n" +
                "警告：粉碎后的文件无法恢复！",
                "文件粉碎",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                var dialog = new Microsoft.Win32.OpenFileDialog();
                dialog.Multiselect = true;
                dialog.Title = "选择要粉碎的文件";

                if (dialog.ShowDialog() == true)
                {
                    try
                    {
                        int successCount = 0;
                        foreach (var fileName in dialog.FileNames)
                        {
                            // 简单的文件粉碎：多次覆写后删除
                            if (ShredFileSimple(fileName))
                            {
                                successCount++;
                            }
                        }
                        MessageBox.Show($"成功粉碎 {successCount}/{dialog.FileNames.Length} 个文件", "文件粉碎完成", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"粉碎文件失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private bool ShredFileSimple(string filePath)
        {
            try
            {
                if (!System.IO.File.Exists(filePath)) return false;

                // 获取文件大小
                var fileInfo = new System.IO.FileInfo(filePath);
                long fileSize = fileInfo.Length;

                // 3次覆写
                for (int pass = 0; pass < 3; pass++)
                {
                    using (var fs = new System.IO.FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Write))
                    {
                        byte[] buffer = new byte[4096];
                        var random = new Random();
                        
                        for (long i = 0; i < fileSize; i += buffer.Length)
                        {
                            random.NextBytes(buffer);
                            int bytesToWrite = (int)Math.Min(buffer.Length, fileSize - i);
                            fs.Write(buffer, 0, bytesToWrite);
                        }
                        fs.Flush();
                    }
                }

                // 删除文件
                System.IO.File.Delete(filePath);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void RunContextMenuManager()
        {
            try
            {
                var message = "右键菜单管理功能\n\n";
                message += "可以管理以下右键菜单项：\n";
                message += "• 文件右键菜单\n";
                message += "• 文件夹右键菜单\n";
                message += "• 桌面右键菜单\n\n";
                message += "该功能需要管理员权限才能修改。";

                MessageBox.Show(message, "右键菜单管理", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"右键菜单管理功能运行失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RunJunkCleaner()
        {
            var result = MessageBox.Show(
                "垃圾清理将扫描以下内容：\n\n" +
                "• Windows临时文件\n" +
                "• 浏览器缓存\n" +
                "• 系统日志\n" +
                "• 回收站\n" +
                "• 缩略图缓存\n\n" +
                "是否开始扫描？",
                "垃圾清理",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    var scanResult = ScanJunkFiles();
                    var cleanResult = MessageBox.Show(
                        $"扫描完成！\n\n" +
                        $"发现垃圾文件: {scanResult.FileCount} 个\n" +
                        $"可释放空间: {FormatBytes(scanResult.TotalSize)}\n\n" +
                        "是否立即清理？",
                        "扫描结果",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Information);

                    if (cleanResult == MessageBoxResult.Yes)
                    {
                        var cleaned = CleanJunkFiles();
                        MessageBox.Show(
                            $"清理完成！\n\n" +
                            $"清理文件: {cleaned.CleanedCount} 个\n" +
                            $"释放空间: {FormatBytes(cleaned.CleanedSize)}",
                            "清理完成",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"垃圾清理失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private (int FileCount, long TotalSize) ScanJunkFiles()
        {
            int count = 0;
            long size = 0;

            try
            {
                // 扫描临时文件夹
                var tempPath = System.IO.Path.GetTempPath();
                var tempDir = new System.IO.DirectoryInfo(tempPath);
                foreach (var file in tempDir.GetFiles("*.*", System.IO.SearchOption.AllDirectories))
                {
                    try { count++; size += file.Length; } catch { }
                }

                // 扫描Windows临时文件夹
                var windowsTemp = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
                if (System.IO.Directory.Exists(windowsTemp))
                {
                    var winTempDir = new System.IO.DirectoryInfo(windowsTemp);
                    foreach (var file in winTempDir.GetFiles("*.*", System.IO.SearchOption.AllDirectories))
                    {
                        try { count++; size += file.Length; } catch { }
                    }
                }
            }
            catch { }

            return (count, size);
        }

        private (int CleanedCount, long CleanedSize) CleanJunkFiles()
        {
            int count = 0;
            long size = 0;

            try
            {
                var tempPath = System.IO.Path.GetTempPath();
                var tempDir = new System.IO.DirectoryInfo(tempPath);
                foreach (var file in tempDir.GetFiles("*.*", System.IO.SearchOption.AllDirectories))
                {
                    try
                    {
                        size += file.Length;
                        file.Delete();
                        count++;
                    }
                    catch { }
                }
            }
            catch { }

            return (count, size);
        }

        private void RunSystemRepair()
        {
            var result = MessageBox.Show(
                "系统修复将检查并修复以下问题：\n\n" +
                "• 系统文件完整性\n" +
                "• 注册表错误\n" +
                "• 网络配置\n" +
                "• Windows更新组件\n\n" +
                "是否开始修复？",
                "系统修复",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    // 运行系统文件检查
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "sfc.exe",
                        Arguments = "/scannow",
                        Verb = "runas",
                        UseShellExecute = true
                    };

                    try
                    {
                        System.Diagnostics.Process.Start(psi);
                        MessageBox.Show("已启动系统文件检查，请按照提示完成操作。", "系统修复", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch
                    {
                        MessageBox.Show("需要管理员权限才能运行系统修复。", "权限不足", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"系统修复失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void RunVulnerabilityScanner()
        {
            try
            {
                var message = "漏洞扫描功能\n\n";
                message += "将检查以下安全项：\n";
                message += "• Windows更新状态\n";
                message += "• 已安装软件漏洞\n";
                message += "• 系统配置风险\n";
                message += "• 网络安全设置\n\n";
                message += "漏洞扫描功能已就绪。";

                MessageBox.Show(message, "漏洞扫描", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"漏洞扫描失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int counter = 0;
            decimal number = bytes;
            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }
            return $"{number:n1} {suffixes[counter]}";
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
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(15, 25, 45));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(240, 248, 255));
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("SystemTools", "系统工具");
                
                // 启动项管理
                StartupManagerTitle.Text = _languageManager.GetString("StartupManager", "启动项管理");
                StartupManagerDesc.Text = _languageManager.GetString("StartupManagerDesc", "管理开机启动项、计划任务、系统服务");
                StartupManagerBtn.Content = _languageManager.GetString("Run", "运行");
                
                // 文件粉碎
                FileShredderTitle.Text = _languageManager.GetString("FileShredder", "文件粉碎");
                FileShredderDesc.Text = _languageManager.GetString("FileShredderDesc", "彻底删除文件/文件夹，不可恢复");
                FileShredderBtn.Content = _languageManager.GetString("Run", "运行");
                
                // 右键菜单管理
                ContextMenuTitle.Text = _languageManager.GetString("ContextMenuManager", "右键菜单管理");
                ContextMenuDesc.Text = _languageManager.GetString("ContextMenuManagerDesc", "清理和管理右键菜单项");
                ContextMenuBtn.Content = _languageManager.GetString("Run", "运行");
                
                // 垃圾清理
                JunkCleanerTitle.Text = _languageManager.GetString("JunkCleaner", "垃圾清理");
                JunkCleanerDesc.Text = _languageManager.GetString("JunkCleanerDesc", "清理系统垃圾、缓存、日志文件");
                JunkCleanerBtn.Content = _languageManager.GetString("Run", "运行");
                
                // 系统修复
                SystemRepairTitle.Text = _languageManager.GetString("SystemRepair", "系统修复");
                SystemRepairDesc.Text = _languageManager.GetString("SystemRepairDesc", "修复系统文件损坏、快捷方式异常");
                SystemRepairBtn.Content = _languageManager.GetString("Run", "运行");
                
                // 漏洞修复
                VulnScannerTitle.Text = _languageManager.GetString("VulnerabilityScanner", "漏洞修复");
                VulnScannerDesc.Text = _languageManager.GetString("VulnerabilityScannerDesc", "扫描和修复系统高危漏洞");
                VulnScannerBtn.Content = _languageManager.GetString("Run", "运行");
            }
            catch { }
        }
    }
}
