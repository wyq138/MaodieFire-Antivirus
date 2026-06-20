using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.ApplicationMonitor
{
    public class ApplicationMonitorManager
    {
        private DataManager _dataManager;
        private List<MonitoredApplication> _applications;
        private List<ApplicationAlert> _alerts;
        private bool _isEnabled;

        public ApplicationMonitorManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _applications = new List<MonitoredApplication>();
            _alerts = new List<ApplicationAlert>();
            _isEnabled = true;
            InitializeMonitor();
        }

        private void InitializeMonitor()
        {
            // 初始化应用程序监控
        }

        public void StartMonitoring()
        {
            _isEnabled = true;
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ApplicationMonitoringStarted",
                Message = "应用程序监控已启动"
            });
        }

        public void StopMonitoring()
        {
            _isEnabled = false;
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ApplicationMonitoringStopped",
                Message = "应用程序监控已停止"
            });
        }

        public bool IsEnabled()
        {
            return _isEnabled;
        }

        public List<MonitoredApplication> GetMonitoredApplications()
        {
            if (!_isEnabled)
            {
                return new List<MonitoredApplication>();
            }

            // 模拟获取监控的应用程序
            _applications.Clear();
            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes.Take(10)) // 只取前10个进程
                {
                    try
                    {
                        _applications.Add(new MonitoredApplication
                        {
                            Id = Guid.NewGuid().ToString(),
                            ProcessName = process.ProcessName,
                            ProcessId = process.Id,
                            MainWindowTitle = process.MainWindowTitle,
                            StartTime = process.StartTime,
                            CpuUsage = GetProcessCpuUsage(process),
                            MemoryUsage = process.WorkingSet64,
                            Status = "Running"
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ApplicationMonitorError",
                    Message = "应用程序监控错误",
                    Details = $"错误: {ex.Message}"
                });
            }

            return _applications;
        }

        private float GetProcessCpuUsage(Process process)
        {
            // 模拟获取进程CPU使用率
            return (float)(new Random().NextDouble() * 100);
        }

        public List<ApplicationAlert> GetAlerts()
        {
            return _alerts;
        }

        public void AnalyzeApplications()
        {
            if (!_isEnabled)
            {
                return;
            }

            var applications = GetMonitoredApplications();
            foreach (var app in applications)
            {
                // 检查CPU使用率
                if (app.CpuUsage > 80)
                {
                    var alert = new ApplicationAlert
                    {
                        Id = Guid.NewGuid().ToString(),
                        AlertType = "HighCpuUsage",
                        Severity = AlertSeverity.Medium,
                        ProcessName = app.ProcessName,
                        ProcessId = app.ProcessId,
                        Message = "应用程序CPU使用率过高",
                        Details = $"进程: {app.ProcessName}, CPU: {app.CpuUsage}%",
                        Timestamp = DateTime.Now
                    };
                    _alerts.Add(alert);
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ApplicationAlert",
                        Message = "应用程序警报",
                        Details = alert.Details
                    });
                }

                // 检查内存使用率
                if (app.MemoryUsage > 1024 * 1024 * 500) // 500MB
                {
                    var alert = new ApplicationAlert
                    {
                        Id = Guid.NewGuid().ToString(),
                        AlertType = "HighMemoryUsage",
                        Severity = AlertSeverity.Medium,
                        ProcessName = app.ProcessName,
                        ProcessId = app.ProcessId,
                        Message = "应用程序内存使用率过高",
                        Details = $"进程: {app.ProcessName}, 内存: {app.MemoryUsage / (1024 * 1024)}MB",
                        Timestamp = DateTime.Now
                    };
                    _alerts.Add(alert);
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ApplicationAlert",
                        Message = "应用程序警报",
                        Details = alert.Details
                    });
                }

                // 检查可疑进程
                if (IsSuspiciousProcess(app.ProcessName))
                {
                    var alert = new ApplicationAlert
                    {
                        Id = Guid.NewGuid().ToString(),
                        AlertType = "SuspiciousProcess",
                        Severity = AlertSeverity.High,
                        ProcessName = app.ProcessName,
                        ProcessId = app.ProcessId,
                        Message = "检测到可疑进程",
                        Details = $"进程: {app.ProcessName}, PID: {app.ProcessId}",
                        Timestamp = DateTime.Now
                    };
                    _alerts.Add(alert);
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ApplicationAlert",
                        Message = "应用程序警报",
                        Details = alert.Details
                    });
                }
            }
        }

        private bool IsSuspiciousProcess(string processName)
        {
            // 模拟检查可疑进程
            string[] suspiciousProcesses = { "malware.exe", "virus.exe", "trojan.exe", "ransomware.exe" };
            return suspiciousProcesses.Contains(processName);
        }

        public void TerminateProcess(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                process.Kill();
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessTerminated",
                    Message = "进程已终止",
                    Details = $"PID: {processId}, 进程名: {process.ProcessName}"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessTerminationError",
                    Message = "进程终止失败",
                    Details = $"PID: {processId}, 错误: {ex.Message}"
                });
            }
        }

        public void AddToWatchlist(string processName)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ProcessAddedToWatchlist",
                Message = "进程已添加到监控列表",
                Details = $"进程名: {processName}"
            });
        }

        public void RemoveFromWatchlist(string processName)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ProcessRemovedFromWatchlist",
                Message = "进程已从监控列表中移除",
                Details = $"进程名: {processName}"
            });
        }

        public ApplicationActivityReport GenerateActivityReport(TimeSpan timeSpan)
        {
            var report = new ApplicationActivityReport
            {
                StartTime = DateTime.Now - timeSpan,
                EndTime = DateTime.Now,
                TotalProcesses = 50,
                ActiveProcesses = 15,
                Alerts = _alerts.Where(a => a.Timestamp >= DateTime.Now - timeSpan).ToList(),
                TopCpuProcesses = new List<ProcessResourceUsage>(),
                TopMemoryProcesses = new List<ProcessResourceUsage>()
            };

            // 模拟生成报告数据
            report.TopCpuProcesses.Add(new ProcessResourceUsage
            {
                ProcessName = "chrome.exe",
                CpuUsage = 35.5f,
                MemoryUsage = 1024 * 1024 * 300 // 300MB
            });

            report.TopCpuProcesses.Add(new ProcessResourceUsage
            {
                ProcessName = "firefox.exe",
                CpuUsage = 25.2f,
                MemoryUsage = 1024 * 1024 * 250 // 250MB
            });

            report.TopCpuProcesses.Add(new ProcessResourceUsage
            {
                ProcessName = "svchost.exe",
                CpuUsage = 15.8f,
                MemoryUsage = 1024 * 1024 * 100 // 100MB
            });

            report.TopMemoryProcesses.Add(new ProcessResourceUsage
            {
                ProcessName = "chrome.exe",
                CpuUsage = 35.5f,
                MemoryUsage = 1024 * 1024 * 300 // 300MB
            });

            report.TopMemoryProcesses.Add(new ProcessResourceUsage
            {
                ProcessName = "firefox.exe",
                CpuUsage = 25.2f,
                MemoryUsage = 1024 * 1024 * 250 // 250MB
            });

            report.TopMemoryProcesses.Add(new ProcessResourceUsage
            {
                ProcessName = "explorer.exe",
                CpuUsage = 5.2f,
                MemoryUsage = 1024 * 1024 * 150 // 150MB
            });

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ApplicationActivityReportGenerated",
                Message = "应用程序活动报告已生成",
                Details = $"时间范围: {timeSpan.TotalHours}小时"
            });

            return report;
        }

        public void ClearAlerts()
        {
            _alerts.Clear();
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ApplicationAlertsCleared",
                Message = "应用程序警报已清除"
            });
        }
    }
}