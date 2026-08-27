using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    public class ApplicationMonitor : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private Dictionary<int, ProcessInfo> _processInfos;
        private int _maxMemoryUsage = 500; // 提高到500MB，减少误报
        private int _maxCpuUsage = 80; // 百分比

        // 系统进程白名单
        private static readonly string[] SystemProcesses = { "System", "Registry", "smss", "csrss", "wininit", "services", "lsass", "svchost", "fontdrvhost", "dwm", "Memory Compression" };
        
        // 大型应用白名单（这些应用内存使用高是正常的）
        private static readonly string[] LargeAppProcesses = { "chrome", "firefox", "msedge", "code", "devenv", "rider", "idea", "android", "studio", "unity", "blender", "photoshop", "premiere", "discord", "teams", "slack" };

        public ApplicationMonitor(DataManager dataManager)
        {
            _dataManager = dataManager;
            _processInfos = new Dictionary<int, ProcessInfo>();
        }

        public void Start()
        {
            _isRunning = true;
            _monitorThread = new Thread(MonitorApplications);
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ApplicationMonitorStart",
                Message = "应用监控服务已启动",
                Details = "开始监控应用程序活动"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            _monitorThread?.Join(2000);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ApplicationMonitorStop",
                Message = "应用监控服务已停止",
                Details = string.Empty
            });
        }

        private void MonitorApplications()
        {
            while (_isRunning)
            {
                try
                {
                    CheckRunningProcesses();
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ApplicationMonitorError",
                        Message = "应用监控服务错误",
                        Details = ex.Message
                    });
                }

                Thread.Sleep(30000); // 每30秒检查一次
            }
        }

        private void CheckRunningProcesses()
        {
            try
            {
                Process[] processes = Process.GetProcesses();
                foreach (Process process in processes)
                {
                    try
                    {
                        MonitorProcess(process);
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitor.cs 捕获异常", ex.Message); }
                }

                // 清理已结束的进程信息
                CleanupProcessInfos(processes);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitor.cs 捕获异常", ex.Message); }
        }

        private void MonitorProcess(Process process)
        {
            try
            {
                ProcessInfo processInfo;
                if (!_processInfos.TryGetValue(process.Id, out processInfo))
                {
                    processInfo = new ProcessInfo
                    {
                        ProcessId = process.Id,
                        ProcessName = process.ProcessName,
                        StartTime = DateTime.Now
                    };
                    _processInfos[process.Id] = processInfo;

                    // 记录进程启动
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ProcessStarted",
                        Message = "进程已启动",
                        Details = $"进程名: {process.ProcessName}, PID: {process.Id}"
                    });
                }

                // 检查进程资源使用情况
                CheckProcessResources(process, processInfo);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitor.cs 捕获异常", ex.Message); }
        }

        private void CheckProcessResources(Process process, ProcessInfo processInfo)
        {
            try
            {
                // 检查内存使用 - 排除系统进程和大型应用
                long memoryUsage = process.WorkingSet64 / (1024 * 1024); // MB
                
                bool isSystemProcess = Array.Exists(SystemProcesses, p => process.ProcessName.Equals(p, StringComparison.OrdinalIgnoreCase));
                bool isLargeApp = Array.Exists(LargeAppProcesses, p => process.ProcessName.ToLower().Contains(p));
                
                // 只有非系统进程且超过更高阈值才告警
                if (!isSystemProcess && !isLargeApp && memoryUsage > _maxMemoryUsage)
                {
                    // 只有内存使用超过1GB才弹窗
                    if (memoryUsage > 1024)
                    {
                        NotificationService.Instance.ShowNotification(
                            "资源使用警告",
                            $"进程 {process.ProcessName} 内存使用过高: {memoryUsage}MB",
                            NotificationType.Warning
                        );
                    }

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "HighMemoryUsage",
                        Message = "进程内存使用过高",
                        Details = $"进程名: {process.ProcessName}, PID: {process.Id}, 内存使用: {memoryUsage}MB"
                    });
                }

                // 检查CPU使用
                // 注意：获取CPU使用率需要特殊处理，这里简化处理
                // 实际实现中应该使用性能计数器
                
                // 更新进程信息
                processInfo.LastUpdate = DateTime.Now;
                processInfo.MemoryUsage = memoryUsage;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationMonitor.cs 捕获异常", ex.Message); }
        }

        private void CleanupProcessInfos(Process[] currentProcesses)
        {
            List<int> processIdsToRemove = new List<int>();
            foreach (var kvp in _processInfos)
            {
                bool processExists = false;
                foreach (Process process in currentProcesses)
                {
                    if (process.Id == kvp.Key)
                    {
                        processExists = true;
                        break;
                    }
                }

                if (!processExists)
                {
                    // 记录进程结束
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ProcessEnded",
                        Message = "进程已结束",
                        Details = $"进程名: {kvp.Value.ProcessName}, PID: {kvp.Key}"
                    });

                    processIdsToRemove.Add(kvp.Key);
                }
            }

            foreach (int processId in processIdsToRemove)
            {
                _processInfos.Remove(processId);
            }
        }

        public List<ProcessInfo> GetRunningProcesses()
        {
            List<ProcessInfo> processList = new List<ProcessInfo>();
            foreach (var kvp in _processInfos)
            {
                processList.Add(kvp.Value);
            }
            return processList;
        }

        public void SetResourceLimits(int maxMemoryUsage, int maxCpuUsage)
        {
            _maxMemoryUsage = maxMemoryUsage;
            _maxCpuUsage = maxCpuUsage;

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ResourceLimitsUpdated",
                Message = "资源限制已更新",
                Details = $"最大内存使用: {maxMemoryUsage}MB, 最大CPU使用: {maxCpuUsage}%"
            });
        }
    }

    public class ProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime LastUpdate { get; set; }
        public long MemoryUsage { get; set; }
        public double CpuUsage { get; set; }
        public string FilePath { get; set; }
        public string CommandLine { get; set; }
        public int ParentProcessId { get; set; }
        public string FileHash { get; set; }
        public long FileSize { get; set; }
        public bool DigitalSignature { get; set; }
    }
}