using System;
using System.Collections.Generic;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class BrowserMonitor : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private HashSet<string> suspiciousUrls;
        private HashSet<string> alertedUrls;
        
        public BrowserMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            suspiciousUrls = new HashSet<string>
            {
                "malware", "virus", "phishing", "scam", "ransomware",
                "trojan", "keylogger", "spyware", "adware", "botnet",
                "hack", "crack", "warez", "pirate", "serial", "keygen",
                "adult", "xxx", "porn", "gambling", "casino"
            };
            alertedUrls = new HashSet<string>();
        }
        
        public void Start()
        {
            isRunning = true;
            monitorThread = new Thread(MonitorBrowser);
            monitorThread.Start();
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BrowserMonitorStart",
                Message = "浏览器监控已启动",
                Details = "开始监控浏览器活动"
            });
        }
        
        public void Stop()
        {
            isRunning = false;
            monitorThread?.Join(2000);
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BrowserMonitorStop",
                Message = "浏览器监控已停止",
                Details = string.Empty
            });
        }
        
        private void MonitorBrowser()
        {
            while (isRunning)
            {
                try
                {
                    CheckBrowserProcesses();
                }
                catch (Exception ex)
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "BrowserMonitorError",
                        Message = "浏览器监控错误",
                        Details = ex.Message
                    });
                }
                
                Thread.Sleep(10000); // 每10秒检查一次
            }
        }
        
        private void CheckBrowserProcesses()
        {
            string[] browserProcesses = { "chrome", "firefox", "msedge", "iexplore", "brave", "opera" };
            
            foreach (var processName in browserProcesses)
            {
                try
                {
                    var processes = System.Diagnostics.Process.GetProcessesByName(processName);
                    foreach (var process in processes)
                    {
                        CheckBrowserProcess(process);
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BrowserMonitor.cs 捕获异常", ex.Message); }
            }
        }
        
        private void CheckBrowserProcess(System.Diagnostics.Process process)
        {
            try
            {
                string commandLine = GetProcessCommandLine(process.Id);
                if (!string.IsNullOrEmpty(commandLine))
                {
                    foreach (string keyword in suspiciousUrls)
                    {
                        if (commandLine.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            // 提取URL
                            string detectedUrl = ExtractUrl(commandLine, keyword);
                            
                            // 避免重复弹窗
                            if (!string.IsNullOrEmpty(detectedUrl) && alertedUrls.Contains(detectedUrl))
                                continue;
                            
                            string message = $"检测到可疑浏览器活动\n浏览器: {process.ProcessName}\n可疑关键词: {keyword}\n命令行: {commandLine}";
                            
                            dataManager.AddLog(new LogEntry
                            {
                                Id = Guid.NewGuid().ToString(),
                                Time = DateTime.Now,
                                Type = "SuspiciousBrowserActivity",
                                Message = "发现可疑浏览器活动",
                                Details = message
                            });
                            
                            // 弹窗警告
                            ShowThreatNotification("可疑浏览器活动警告", message, NotificationType.Warning);
                            
                            if (!string.IsNullOrEmpty(detectedUrl))
                            {
                                alertedUrls.Add(detectedUrl);
                            }
                            
                            break;
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BrowserMonitor.cs 捕获异常", ex.Message); }
        }
        
        private string ExtractUrl(string commandLine, string keyword)
        {
            try
            {
                // 尝试从命令行中提取URL
                int keywordIndex = commandLine.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
                if (keywordIndex >= 0)
                {
                    // 查找周围的URL
                    int start = Math.Max(0, keywordIndex - 100);
                    int end = Math.Min(commandLine.Length, keywordIndex + 200);
                    return commandLine.Substring(start, end - start);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BrowserMonitor.cs 捕获异常", ex.Message); }
            return string.Empty;
        }
        
        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return obj["CommandLine"] as string;
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BrowserMonitor.cs 捕获异常", ex.Message); }
            return string.Empty;
        }
        
        private void ShowThreatNotification(string title, string message, NotificationType type)
        {
            try
            {
                NotificationService.Instance.ShowNotification(title, message, type);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BrowserMonitor.cs 捕获异常", ex.Message); }
        }
    }
}
