// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.IO;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class ToolsPage : Page
    {
        public ToolsPage()
        {
            InitializeComponent();
            RunSelfCheck();
            EngineText.Text = $"天盾引擎 · PE/导入表/YARA/启发式/行为/网络 多阶段评分管线";
        }

        private void RunSelfCheck()
        {
            try
            {
                var (ok, yara, pe, kf, pub, err) = FireAntivirus.Engine.Data.EmbeddedThreatDatabase.SelfCheck();
                SelfCheckText.Text = ok
                    ? $"正常：YARA {yara} 条 · PE 特征 {pe} 条 · 已知文件 {kf} 条 · 白名单 {pub} 家"
                    : $"异常：{err}";
            }
            catch (Exception ex)
            {
                SelfCheckText.Text = $"自检异常：{ex.Message}";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 工具箱自检失败: " + ex.Message);
            }
        }

        private void SelfCheck_Click(object sender, RoutedEventArgs e) => RunSelfCheck();

        private async void Update_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                UpdateBtn.IsEnabled = false;
                UpdateBtn.Content = "更新中...";
                var result = await FireAntivirus.Engine.SignatureDatabaseUpdater.UpdateAsync();
                UpdateBtn.Content = result.Succeeded ? "更新成功" : "更新失败";
                UpdateBtn.IsEnabled = true;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 工具箱更新失败: " + ex.Message);
                UpdateBtn.Content = "更新失败";
                UpdateBtn.IsEnabled = true;
            }
        }

        private void Optimize_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                long freed = 0;
                if (Directory.Exists(Path.GetTempPath()))
                    freed = Directory.EnumerateFiles(Path.GetTempPath(), "*", SearchOption.AllDirectories)
                        .Where(f =>
                        {
                            try { File.Delete(f); return true; }
                            catch { return false; }
                        }).Count();
                OptText.Text = $"已清理临时文件 {freed} 个，释放空间请查看任务管理器统计。";
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "WinUI 系统优化失败: " + ex.Message);
            }
        }
    }
}