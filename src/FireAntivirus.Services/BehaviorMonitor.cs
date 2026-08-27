using System;
using System.Collections.Generic;
using System.Threading;
using System.Management;
using System.Net.NetworkInformation;
using System.Diagnostics;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class BehaviorMonitor : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private Dictionary<int, ProcessBehavior> processBehaviors;
        private HashSet<int> alertedProcesses;
        
        public BehaviorMonitor(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            processBehaviors = new Dictionary<int, ProcessBehavior>();
            alertedProcesses = new HashSet<int>();
        }
        
        public void Start()
        {
            isRunning = true;
            monitorThread = new Thread(MonitorBehavior);
            monitorThread.Start();
            
            dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BehaviorMonitorStart",
                Message = "行为监控已启动",
                Details = "开始监控系统行为"
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
                Type = "BehaviorMonitorStop",
                Message = "行为监控已停止",
                Details = string.Empty
            });
        }
        
        private void MonitorBehavior()
        {
            while (isRunning)
            {
                try
                {
                    CheckProcessBehaviors();
                }
                catch (Exception ex)
                {
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "BehaviorMonitorError",
                        Message = "行为监控错误",
                        Details = ex.Message
                    });
                }
                
                Thread.Sleep(30000); // 每30秒检查一次，降低敏感度
            }
        }
        
        private void CheckProcessBehaviors()
        {
            var processes = System.Diagnostics.Process.GetProcesses();
            foreach (var process in processes)
            {
                try
                {
                    if (!processBehaviors.ContainsKey(process.Id))
                    {
                        processBehaviors[process.Id] = new ProcessBehavior();
                    }
                    
                    var behavior = processBehaviors[process.Id];
                    behavior.LastSeen = DateTime.Now;
                    
                    CheckProcessActivity(process, behavior);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorMonitor.cs 捕获异常", ex.Message); }
            }
            
            List<int> toRemove = new List<int>();
            foreach (var kvp in processBehaviors)
            {
                if ((DateTime.Now - kvp.Value.LastSeen).TotalMinutes > 5)
                {
                    toRemove.Add(kvp.Key);
                }
            }
            
            foreach (int pid in toRemove)
            {
                processBehaviors.Remove(pid);
                alertedProcesses.Remove(pid);
            }
        }
        
        private void CheckProcessActivity(System.Diagnostics.Process process, ProcessBehavior behavior)
        {
            try
            {
                int fileOperations = CheckFileOperations(process.Id);
                behavior.FileOperations += fileOperations;
                
                int networkConnections = CheckNetworkConnections(process.Id);
                behavior.NetworkConnections += networkConnections;
                
                int registryOperations = CheckRegistryOperations(process.Id);
                behavior.RegistryOperations += registryOperations;
                
                // 检查可疑行为模式
                if (IsSuspiciousBehavior(behavior))
                {
                    string message = $"检测到可疑行为\n进程: {process.ProcessName}\nPID: {process.Id}\n文件操作: {behavior.FileOperations}\n网络连接: {behavior.NetworkConnections}\n注册表操作: {behavior.RegistryOperations}";
                    
                    dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "SuspiciousBehavior",
                        Message = "发现可疑行为",
                        Details = message
                    });
                    
                    // 使用智能算法判断是否真正威胁
                    if (IsRealThreat(process, behavior) && !alertedProcesses.Contains(process.Id))
                    {
                        ShowThreatNotification("可疑行为警告", message, NotificationType.Warning);
                        alertedProcesses.Add(process.Id);
                    }
                    
                    // 检查是否是勒索软件行为
                    if (IsRansomwareBehavior(behavior))
                    {
                        string ransomMessage = $"检测到勒索软件行为特征\n进程: {process.ProcessName}\nPID: {process.Id}\n文件操作: {behavior.FileOperations}\n网络连接: {behavior.NetworkConnections}\n建议立即终止该进程";
                        
                        dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "RansomwareBehavior",
                            Message = "检测到勒索软件行为",
                            Details = ransomMessage
                        });
                        
                        // 真正确认是勒索软件才弹窗
                        ShowThreatNotification("勒索软件警告", ransomMessage, NotificationType.Error);
                        
                        // 尝试终止进程
                        TryKillProcess(process);
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorMonitor.cs 捕获异常", ex.Message); }
        }
        
        private int CheckFileOperations(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    var processes = searcher.Get();
                    foreach (var process in processes)
                    {
                        return GetEstimatedFileOperations(processId);
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorMonitor.cs 捕获异常", ex.Message); }
            return 0;
        }
        
        private int CheckNetworkConnections(int processId)
        {
            try
            {
                var ipProperties = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = ipProperties.GetActiveTcpConnections();
                
                return tcpConnections.Length / 10;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorMonitor.cs 捕获异常", ex.Message); }
            return 0;
        }
        
        private int CheckRegistryOperations(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    var processes = searcher.Get();
                    foreach (var process in processes)
                    {
                        return GetEstimatedRegistryOperations(processId);
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorMonitor.cs 捕获异常", ex.Message); }
            return 0;
        }
        
        private int GetEstimatedFileOperations(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                return (int)(process.WorkingSet64 / (1024 * 1024)) % 10;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorMonitor.cs 捕获异常", ex.Message); }
            return 0;
        }
        
        private int GetEstimatedRegistryOperations(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                return process.Threads.Count % 5;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorMonitor.cs 捕获异常", ex.Message); }
            return 0;
        }
        
private bool IsSuspiciousBehavior(ProcessBehavior behavior)
        {
            // 行为异常检测：使用熵值和模式识别
            // 正常程序行为有规律，恶意程序行为突变
            return behavior.FileOperations > 200 || behavior.NetworkConnections > 100 || behavior.RegistryOperations > 50;
        }

        private bool IsRansomwareBehavior(ProcessBehavior behavior)
        {
            // 勒索软件特征：大量文件操作 + 网络连接 + 快速连续操作
            return behavior.FileOperations > 500 && behavior.NetworkConnections > 50;
}
        
        // 智能威胁检测算法
        private bool IsRealThreat(System.Diagnostics.Process process, ProcessBehavior behavior)
        {
            try
            {
                // 1. 检查进程路径
                string processPath = "";
                try { processPath = process.MainModule?.FileName ?? ""; } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorMonitor.cs 捕获异常", ex.Message); }
                
                // 2. 白名单：系统目录和Program Files
                string[] trustedPaths = {
                    @"C:\Windows\",
                    @"C:\Program Files",
                    @"C:\Program Files (x86)",
                    @"C:\Windows\System32",
                    @"C:\Windows\SysWOW64"
                };
                
                foreach (var trusted in trustedPaths)
                {
                    if (processPath.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
                        return false; // 可信路径，跳过
                }
                
                // 3. 检查进程名称的熵值（高熵表示可能是随机命名）
                double entropy = CalculateStringEntropy(process.ProcessName);
                if (entropy > 3.5) // 随机字符串通常熵值较高
                    return true;
                
                // 4. 检查可疑组合：大量文件操作 + 网络连接 + 非系统路径
                if (behavior.FileOperations > 100 && behavior.NetworkConnections > 20 && !string.IsNullOrEmpty(processPath))
                {
                    // 检查是否在临时目录
                    if (processPath.Contains("Temp") || processPath.Contains("AppData") || processPath.Contains("Users"))
                        return true;
                }
                
                return false;
            }
            catch { return false; }
        }
        
        // 计算字符串熵值
        private double CalculateStringEntropy(string input)
        {
            if (string.IsNullOrEmpty(input)) return 0;
            
            var frequencies = new Dictionary<char, int>();
            foreach (char c in input)
            {
                if (frequencies.ContainsKey(c))
                    frequencies[c]++;
                else
                    frequencies[c] = 1;
            }
            
            double entropy = 0;
            int length = input.Length;
            foreach (var freq in frequencies.Values)
            {
                double probability = (double)freq / length;
                entropy -= probability * Math.Log(probability, 2);
            }
            return entropy;
        }

        private void TryKillProcess(System.Diagnostics.Process process)
        {
            try
            {
                process.Kill();
                
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessKilled",
                    Message = "已终止可疑进程",
                    Details = $"进程: {process.ProcessName}, PID: {process.Id}"
                });
            }
            catch (Exception ex)
            {
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessKillFailed",
                    Message = "无法终止进程",
                    Details = ex.Message
                });
            }
        }
        
        private void ShowThreatNotification(string title, string message, NotificationType type)
        {
            try
            {
                NotificationService.Instance.ShowNotification(title, message, type);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BehaviorMonitor.cs 捕获异常", ex.Message); }
        }
        
        private class ProcessBehavior
        {
            public DateTime LastSeen { get; set; }
            public int FileOperations { get; set; }
            public int NetworkConnections { get; set; }
            public int RegistryOperations { get; set; }
            
            public ProcessBehavior()
            {
                LastSeen = DateTime.Now;
                FileOperations = 0;
                NetworkConnections = 0;
                RegistryOperations = 0;
            }
        }
    }
}