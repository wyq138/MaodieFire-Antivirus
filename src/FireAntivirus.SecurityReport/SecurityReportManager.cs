using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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

            // 添加报告节
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
            // 模拟添加每日报告节
            report.Sections.Add(new ReportSection
            {
                Title = "实时防护状态",
                Content = "实时防护已启用并正常运行",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "病毒定义更新",
                Content = "病毒定义库已更新至最新版本",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "扫描结果",
                Content = "今日执行了1次快速扫描，未发现威胁",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "系统更新",
                Content = "系统已更新至最新版本",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "安全事件",
                Content = "今日未发生安全事件",
                Status = "Good"
            });
        }

        private void AddWeeklyReportSections(Report report)
        {
            // 模拟添加每周报告节
            report.Sections.Add(new ReportSection
            {
                Title = "实时防护状态",
                Content = "实时防护本周持续启用并正常运行",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "病毒定义更新",
                Content = "病毒定义库本周更新了2次",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "扫描结果",
                Content = "本周执行了3次快速扫描和1次全系统扫描，未发现威胁",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "系统更新",
                Content = "系统本周安装了1个安全更新",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "安全事件",
                Content = "本周未发生安全事件",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "网络活动",
                Content = "本周网络活动正常，未检测到异常流量",
                Status = "Good"
            });
        }

        private void AddMonthlyReportSections(Report report)
        {
            // 模拟添加每月报告节
            report.Sections.Add(new ReportSection
            {
                Title = "实时防护状态",
                Content = "实时防护本月持续启用并正常运行",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "病毒定义更新",
                Content = "病毒定义库本月更新了8次",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "扫描结果",
                Content = "本月执行了12次快速扫描和2次全系统扫描，未发现威胁",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "系统更新",
                Content = "系统本月安装了4个安全更新",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "安全事件",
                Content = "本月未发生安全事件",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "网络活动",
                Content = "本月网络活动正常，未检测到异常流量",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "应用程序行为",
                Content = "本月应用程序行为正常，未检测到可疑活动",
                Status = "Good"
            });
        }

        private void AddFullReportSections(Report report)
        {
            // 模拟添加完整报告节
            report.Sections.Add(new ReportSection
            {
                Title = "实时防护状态",
                Content = "实时防护已启用并正常运行",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "病毒定义更新",
                Content = "病毒定义库已更新至最新版本",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "扫描结果",
                Content = "最近执行了1次全系统扫描，未发现威胁",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "系统更新",
                Content = "系统已更新至最新版本",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "安全事件",
                Content = "最近未发生安全事件",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "网络活动",
                Content = "最近网络活动正常，未检测到异常流量",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "应用程序行为",
                Content = "最近应用程序行为正常，未检测到可疑活动",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "启动项状态",
                Content = "启动项状态正常，未发现可疑启动项",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "漏洞扫描",
                Content = "最近执行了漏洞扫描，未发现严重漏洞",
                Status = "Good"
            });

            report.Sections.Add(new ReportSection
            {
                Title = "勒索软件防护",
                Content = "勒索软件防护已启用并正常运行",
                Status = "Good"
            });
        }

        private string CalculateOverallSecurityStatus(Report report)
        {
            // 模拟计算总体安全状态
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
            // 模拟生成报告摘要
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
            // 模拟导出为文本文件
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
            // 模拟导出为HTML文件
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
            // 模拟导出为XML文件
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
                    writer.WriteLine($"      <Title>{section.Title}</Title>");
                    writer.WriteLine($"      <Content>{section.Content}</Content>");
                    writer.WriteLine($"      <Status>{section.Status}</Status>");
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