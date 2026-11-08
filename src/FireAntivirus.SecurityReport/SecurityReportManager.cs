using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.SecurityReport
{
    public class SecurityReportManager
    {
        private DataManager _dataManager;
        private List<Report> _reports;

        public SecurityReportManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _reports = new List<Report>();
        }

        public Report GenerateSecurityReport(ReportType reportType, TimeSpan timeSpan)
        {
            var report = new Report
            {
                Id = Guid.NewGuid().ToString(),
                ReportType = reportType,
                GeneratedAt = DateTime.Now,
                TimeRange = timeSpan,
                StartTime = DateTime.Now - timeSpan,
                EndTime = DateTime.Now,
                Sections = new List<ReportSection>()
            };

            // 添加报告节（数据全部来自真实系统状态与安全日志）
            switch (reportType)
            {
                case ReportType.Daily:
                    AddDailyReportSections(report);
                    break;
                case ReportType.Weekly:
                    AddWeeklyReportSections(report);
                    break;
                case ReportType.Monthly:
                    AddMonthlyReportSections(report);
                    break;
                case ReportType.Full:
                    AddFullReportSections(report);
                    break;
            }

            // 计算总体安全状态
            report.OverallSecurityStatus = CalculateOverallSecurityStatus(report);
            report.Summary = GenerateReportSummary(report);

            _reports.Add(report);
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SecurityReportGenerated",
                Message = "安全报告已生成",
                Details = $"类型: {reportType}, 时间范围: {timeSpan.TotalHours}小时"
            });

            return report;
        }

        private void AddDailyReportSections(Report report)
        {
            AddProtectionStatusSection(report);
            AddVirusDefinitionSection(report, report.StartTime);
            AddScanResultSection(report, report.StartTime);
            AddSystemUpdateSection(report, report.StartTime);
            AddSecurityEventSection(report, report.StartTime);
        }

        private void AddWeeklyReportSections(Report report)
        {
            AddProtectionStatusSection(report);
            AddVirusDefinitionSection(report, report.StartTime);
            AddScanResultSection(report, report.StartTime);
            AddSystemUpdateSection(report, report.StartTime);
            AddSecurityEventSection(report, report.StartTime);
            AddNetworkActivitySection(report);
        }

        private void AddMonthlyReportSections(Report report)
        {
            AddProtectionStatusSection(report);
            AddVirusDefinitionSection(report, report.StartTime);
            AddScanResultSection(report, report.StartTime);
            AddSystemUpdateSection(report, report.StartTime);
            AddSecurityEventSection(report, report.StartTime);
            AddNetworkActivitySection(report);
            AddStartupItemsSection(report);
        }

        private void AddFullReportSections(Report report)
        {
            AddProtectionStatusSection(report);
            AddVirusDefinitionSection(report, report.StartTime);
            AddScanResultSection(report, report.StartTime);
            AddSystemUpdateSection(report, report.StartTime);
            AddSecurityEventSection(report, report.StartTime);
            AddNetworkActivitySection(report);
            AddStartupItemsSection(report);
            AddVulnerabilitySection(report, report.StartTime);
            AddRansomwareProtectionSection(report);
        }

        #region 真实数据收集

        private void AddSection(Report report, string title, string content, string status)
        {
            report.Sections.Add(new ReportSection { Title = title, Content = content, Status = status });
        }

        private void AddProtectionStatusSection(Report report)
        {
            // 真实检测本软件防护进程是否在运行
            bool serviceRunning = false, mainRunning = false;
            try { serviceRunning = Process.GetProcessesByName("FireAntivirus.ServiceHost").Length > 0; } catch { }
            try { mainRunning = Process.GetProcessesByName("FireAntivirus").Length > 0; } catch { }

            if (serviceRunning && mainRunning)
                AddSection(report, "实时防护状态", "主程序与后台防护服务均在正常运行", "Good");
            else if (serviceRunning || mainRunning)
                AddSection(report, "实时防护状态", $"部分防护组件在运行（后台服务: {(serviceRunning ? "运行中" : "未运行")}，主程序: {(mainRunning ? "运行中" : "未运行")}）", "Medium");
            else
                AddSection(report, "实时防护状态", "未检测到防护进程运行", "Critical");
        }

        private void AddVirusDefinitionSection(Report report, DateTime since)
        {
            // 从安全日志统计报告期内的病毒库更新事件
            int updates = 0;
            DateTime? lastUpdate = null;
            try
            {
                var logs = _dataManager.FilterLogs(startDate: since);
                foreach (var log in logs)
                {
                    var type = log.Type ?? string.Empty;
                    var message = log.Message ?? string.Empty;
                    bool isUpdateEvent = type.IndexOf("Update", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                         type.IndexOf("Database", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool isDefinitionEvent = message.Contains("病毒") || message.Contains("特征") || message.Contains("定义库") ||
                                             message.Contains("签名") || message.Contains("数据库");

                    if (isUpdateEvent && isDefinitionEvent)
                    {
                        updates++;
                        if (lastUpdate == null || log.Time > lastUpdate) lastUpdate = log.Time;
                    }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportManager.cs exception", ex.Message);
            }

            AddSection(report, "病毒定义更新",
                updates > 0
                    ? $"报告期内共记录 {updates} 次病毒库更新，最近一次: {lastUpdate:yyyy-MM-dd HH:mm}"
                    : "报告期内未记录到病毒库更新，建议手动执行更新",
                updates > 0 ? "Good" : "Medium");
        }

        private void AddScanResultSection(Report report, DateTime since)
        {
            // 从安全日志统计扫描与威胁事件
            int scanCount = 0, threatCount = 0;
            try
            {
                var logs = _dataManager.FilterLogs(startDate: since);
                scanCount = logs.Count(l => l.Type != null && l.Type.IndexOf("Scan", StringComparison.OrdinalIgnoreCase) >= 0);
                threatCount = logs.Count(l => l.Type != null &&
                    (l.Type.IndexOf("Threat", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     l.Type.IndexOf("Virus", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     l.Type.IndexOf("Malware", StringComparison.OrdinalIgnoreCase) >= 0));
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportManager.cs exception", ex.Message);
            }

            AddSection(report, "扫描结果",
                threatCount > 0
                    ? $"报告期内记录 {scanCount} 次扫描活动，发现 {threatCount} 条威胁记录，请及时处理"
                    : $"报告期内记录 {scanCount} 次扫描活动，未发现威胁",
                threatCount > 0 ? "Medium" : (scanCount > 0 ? "Good" : "Medium"));
        }

        private void AddSystemUpdateSection(Report report, DateTime since)
        {
            // 通过 WMI 查询报告期内真实安装的 Windows 补丁
            int patchCount = 0;
            DateTime? lastPatch = null;
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering");
                foreach (var obj in searcher.Get())
                {
                    if (obj["InstalledOn"] is DateTime installedOn && installedOn >= since)
                    {
                        patchCount++;
                        if (lastPatch == null || installedOn > lastPatch) lastPatch = installedOn;
                    }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportManager.cs exception", ex.Message);
            }

            AddSection(report, "系统更新",
                lastPatch.HasValue
                    ? $"报告期内安装了 {patchCount} 个系统补丁，最近一次: {lastPatch:yyyy-MM-dd}"
                    : "报告期内未安装系统更新，建议运行 Windows 更新",
                patchCount > 0 ? "Good" : "Medium");
        }

        private void AddSecurityEventSection(Report report, DateTime since)
        {
            // 从安全日志统计威胁/拦截/告警/错误事件
            int events = 0;
            try
            {
                var logs = _dataManager.FilterLogs(startDate: since);
                events = logs.Count(l => l.Type != null &&
                    (l.Type.IndexOf("Alert", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     l.Type.IndexOf("Blocked", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     l.Type.IndexOf("Detect", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     l.Type.IndexOf("Quarantine", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     l.Type.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0));
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportManager.cs exception", ex.Message);
            }

            AddSection(report, "安全事件",
                events > 0 ? $"报告期内共记录 {events} 条安全事件，详情见日志" : "报告期内未发生安全事件",
                events == 0 ? "Good" : (events < 10 ? "Medium" : "Poor"));
        }

        private void AddNetworkActivitySection(Report report)
        {
            // 真实统计当前活动 TCP 连接数
            int connectionCount = 0;
            try
            {
                connectionCount = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpConnections().Length;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportManager.cs exception", ex.Message);
            }

            AddSection(report, "网络活动", $"当前系统共 {connectionCount} 个活动 TCP 连接", "Good");
        }

        private void AddStartupItemsSection(Report report)
        {
            // 真实统计注册表自启动项数量
            int startupCount = 0;
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
                    startupCount += key?.GetValueNames().Length ?? 0;
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
                    startupCount += key?.GetValueNames().Length ?? 0;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportManager.cs exception", ex.Message);
            }

            AddSection(report, "启动项状态",
                $"当前注册表自启动项共 {startupCount} 项{(startupCount > 15 ? "，启动项偏多，建议使用启动项管理工具清理" : "")}",
                startupCount <= 15 ? "Good" : "Medium");
        }

        private void AddVulnerabilitySection(Report report, DateTime since)
        {
            // 从安全日志统计漏洞相关事件
            int vulnCount = 0;
            try
            {
                var logs = _dataManager.FilterLogs(startDate: since);
                vulnCount = logs.Count(l => l.Type != null && l.Type.IndexOf("Vulnerab", StringComparison.OrdinalIgnoreCase) >= 0);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportManager.cs exception", ex.Message);
            }

            AddSection(report, "漏洞扫描",
                vulnCount > 0
                    ? $"报告期内记录 {vulnCount} 条漏洞相关事件，建议执行完整漏洞扫描"
                    : "报告期内未记录漏洞事件",
                vulnCount == 0 ? "Good" : "Medium");
        }

        private void AddRansomwareProtectionSection(Report report)
        {
            // 真实检测后台防护服务（承担文件监控/勒索防护）是否运行
            bool running = false;
            try { running = Process.GetProcessesByName("FireAntivirus.ServiceHost").Length > 0; } catch { }

            AddSection(report, "勒索软件防护",
                running ? "后台防护服务正在运行，关键文件监控处于活动状态" : "后台防护服务未运行，勒索防护能力受限，请启动防护服务",
                running ? "Good" : "Critical");
        }

        #endregion

        private string CalculateOverallSecurityStatus(Report report)
        {
            // 基于各报告节的真实状态汇总计算
            int goodSections = report.Sections.Count(s => s.Status == "Good");
            int totalSections = report.Sections.Count;

            if (totalSections == 0)
            {
                return "Unknown";
            }

            double goodPercentage = (double)goodSections / totalSections * 100;

            if (goodPercentage >= 90)
            {
                return "Excellent";
            }
            else if (goodPercentage >= 75)
            {
                return "Good";
            }
            else if (goodPercentage >= 60)
            {
                return "Medium";
            }
            else if (goodPercentage >= 40)
            {
                return "Poor";
            }
            else
            {
                return "Critical";
            }
        }

        private string GenerateReportSummary(Report report)
        {
            // 基于真实报告节生成摘要
            int goodSections = report.Sections.Count(s => s.Status == "Good");
            int totalSections = report.Sections.Count;

            return $"本次安全报告共包含 {totalSections} 个部分，其中 {goodSections} 个部分状态良好。总体安全状态为 {report.OverallSecurityStatus}。";
        }

        public List<Report> GetReports()
        {
            return _reports;
        }

        public Report GetReport(string id)
        {
            return _reports.FirstOrDefault(r => r.Id == id);
        }

        public bool ExportReport(string reportId, string format, string filePath)
        {
            var report = _reports.FirstOrDefault(r => r.Id == reportId);
            if (report == null)
            {
                return false;
            }

            try
            {
                switch (format.ToLower())
                {
                    case "txt":
                        ExportReportAsText(report, filePath);
                        break;
                    case "html":
                        ExportReportAsHtml(report, filePath);
                        break;
                    case "xml":
                        ExportReportAsXml(report, filePath);
                        break;
                    default:
                        return false;
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ReportExported",
                    Message = "安全报告已导出",
                    Details = $"ID: {reportId}, 格式: {format}, 路径: {filePath}"
                });

                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ReportExportError",
                    Message = "安全报告导出失败",
                    Details = $"错误: {ex.Message}"
                });
                return false;
            }
        }

        private void ExportReportAsText(Report report, string filePath)
        {
            // 导出为真实文本文件
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine("========================================");
                writer.WriteLine("FireAntivirus 安全报告");
                writer.WriteLine("========================================");
                writer.WriteLine($"报告类型: {report.ReportType}");
                writer.WriteLine($"生成时间: {report.GeneratedAt}");
                writer.WriteLine($"时间范围: {report.StartTime} 至 {report.EndTime}");
                writer.WriteLine($"总体安全状态: {report.OverallSecurityStatus}");
                writer.WriteLine($"摘要: {report.Summary}");
                writer.WriteLine("========================================");
                writer.WriteLine("详细信息:");
                writer.WriteLine("========================================");

                foreach (var section in report.Sections)
                {
                    writer.WriteLine($"\n{section.Title}");
                    writer.WriteLine($"状态: {section.Status}");
                    writer.WriteLine($"内容: {section.Content}");
                    writer.WriteLine("----------------------------------------");
                }

                writer.WriteLine("========================================");
            }
        }

        private void ExportReportAsHtml(Report report, string filePath)
        {
            // 导出为真实 HTML 文件
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine("<!DOCTYPE html>");
                writer.WriteLine("<html>");
                writer.WriteLine("<head>");
                writer.WriteLine("<title>FireAntivirus 安全报告</title>");
                writer.WriteLine("<style>");
                writer.WriteLine("body { font-family: Arial, sans-serif; margin: 20px; }");
                writer.WriteLine(".header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; margin-bottom: 20px; }");
                writer.WriteLine(".section { margin-bottom: 15px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }");
                writer.WriteLine(".good { border-left: 5px solid green; }");
                writer.WriteLine(".medium { border-left: 5px solid yellow; }");
                writer.WriteLine(".poor { border-left: 5px solid orange; }");
                writer.WriteLine(".critical { border-left: 5px solid red; }");
                writer.WriteLine("</style>");
                writer.WriteLine("</head>");
                writer.WriteLine("<body>");
                writer.WriteLine("<div class='header'>");
                writer.WriteLine("<h1>FireAntivirus 安全报告</h1>");
                writer.WriteLine($"<p>报告类型: {report.ReportType}</p>");
                writer.WriteLine($"<p>生成时间: {report.GeneratedAt}</p>");
                writer.WriteLine($"<p>时间范围: {report.StartTime} 至 {report.EndTime}</p>");
                writer.WriteLine($"<p>总体安全状态: <strong>{report.OverallSecurityStatus}</strong></p>");
                writer.WriteLine($"<p>摘要: {report.Summary}</p>");
                writer.WriteLine("</div>");
                writer.WriteLine("<h2>详细信息</h2>");

                foreach (var section in report.Sections)
                {
                    string statusClass = "good";
                    switch (section.Status.ToLower())
                    {
                        case "medium":
                            statusClass = "medium";
                            break;
                        case "poor":
                            statusClass = "poor";
                            break;
                        case "critical":
                            statusClass = "critical";
                            break;
                    }

                    writer.WriteLine($"<div class='section {statusClass}'>");
                    writer.WriteLine($"<h3>{section.Title}</h3>");
                    writer.WriteLine($"<p><strong>状态:</strong> {section.Status}</p>");
                    writer.WriteLine($"<p><strong>内容:</strong> {section.Content}</p>");
                    writer.WriteLine("</div>");
                }

                writer.WriteLine("</body>");
                writer.WriteLine("</html>");
            }
        }

        private void ExportReportAsXml(Report report, string filePath)
        {
            // 导出为真实 XML 文件
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine("<?xml version='1.0' encoding='utf-8'?>");
                writer.WriteLine("<SecurityReport>");
                writer.WriteLine($"  <Id>{report.Id}</Id>");
                writer.WriteLine($"  <ReportType>{report.ReportType}</ReportType>");
                writer.WriteLine($"  <GeneratedAt>{report.GeneratedAt}</GeneratedAt>");
                writer.WriteLine($"  <StartTime>{report.StartTime}</StartTime>");
                writer.WriteLine($"  <EndTime>{report.EndTime}</EndTime>");
                writer.WriteLine($"  <OverallSecurityStatus>{report.OverallSecurityStatus}</OverallSecurityStatus>");
                writer.WriteLine($"  <Summary>{report.Summary}</Summary>");
                writer.WriteLine("  <Sections>");

                foreach (var section in report.Sections)
                {
                    writer.WriteLine("    <Section>");
                    writer.WriteLine($"      <Title>{System.Security.SecurityElement.Escape(section.Title ?? "")}</Title>");
                    writer.WriteLine($"      <Content>{System.Security.SecurityElement.Escape(section.Content ?? "")}</Content>");
                    writer.WriteLine($"      <Status>{System.Security.SecurityElement.Escape(section.Status ?? "")}</Status>");
                    writer.WriteLine("    </Section>");
                }

                writer.WriteLine("  </Sections>");
                writer.WriteLine("</SecurityReport>");
            }
        }

        public void DeleteReport(string reportId)
        {
            var report = _reports.FirstOrDefault(r => r.Id == reportId);
            if (report != null)
            {
                _reports.Remove(report);
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ReportDeleted",
                    Message = "安全报告已删除",
                    Details = $"ID: {reportId}"
                });
            }
        }

        public void ClearReports()
        {
            _reports.Clear();
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ReportsCleared",
                Message = "所有安全报告已清除"
            });
        }
    }
}