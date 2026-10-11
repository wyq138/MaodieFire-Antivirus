// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Linq;
using System.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using FireAntivirus.Data;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class ReportPage : Page
    {
        private readonly DataManager _data = new();

        public ReportPage()
        {
            InitializeComponent();
        }

        private void Generate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var quarantine = _data.LoadQuarantine();
                var signatures = _data.LoadSignatures();

                var sb = new StringBuilder();
                sb.AppendLine("【病毒库状态】");
                sb.AppendLine($"本地特征条目：{signatures.Count}");
                sb.AppendLine($"内嵌威胁规则：YARA {FireAntivirus.Engine.Data.EmbeddedThreatDatabase.YaraRules.Length} · PE特征 " +
                              $"{FireAntivirus.Engine.Data.EmbeddedThreatDatabase.PeFeatures.Length} · 已知文件 " +
                              $"{FireAntivirus.Engine.Data.EmbeddedThreatDatabase.KnownMaliciousFiles.Length} · 可信发布者 " +
                              $"{FireAntivirus.Engine.Data.EmbeddedThreatDatabase.TrustedPublishers.Length}");
                sb.AppendLine();
                sb.AppendLine("【扫描统计】");
                sb.AppendLine($"历史隔离威胁：{quarantine.Count}");
                sb.AppendLine();
                sb.AppendLine("【当前隔离区】");
                if (quarantine.Any())
                {
                    foreach (var q in quarantine.Take(20))
                        sb.AppendLine($"- {q.FileName}（{q.ThreatName}）{q.QuarantineTime:yyyy-MM-dd HH:mm}");
                }
                else
                {
                    sb.AppendLine("- 暂无隔离文件");
                }
                sb.AppendLine();
                sb.AppendLine("【安全建议】");
                sb.AppendLine("1. 保持实时防护开启，并定期更新病毒库；");
                sb.AppendLine("2. 避免运行来源不明的可执行文件，下载前先扫描；");
                sb.AppendLine("3. 更新操作系统与软件补丁，降低漏洞利用风险；");
                sb.AppendLine("4. 不在浏览器中开启小键盘及保存明文密码。");

                ReportBody.Text = sb.ToString();
                StatusText.Text = $"生成于 {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 生成报告失败: " + ex.Message);
                StatusText.Text = "生成失败";
            }
        }
    }
}