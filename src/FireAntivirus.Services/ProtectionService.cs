using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Linq;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    public interface IMonitor
    {
        void Start();
        void Stop();
    }

    public class ProtectionService
    {
        private Thread _protectionThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private SelfProtectionService _selfProtectionService;
        private readonly List<IMonitor> _monitors = new List<IMonitor>();
        private readonly Dictionary<string, MonitorPriority> _monitorPriorities = new Dictionary<string, MonitorPriority>();
        private readonly List<MonitorResourceInfo> _monitorResources = new List<MonitorResourceInfo>();
        private PerformanceCounter _performanceCounter;
        private AdaptiveResourceManager _resourceManager;
        private string _logPath;
        private List<string> _initErrors = new List<string>();
        private int _lastCpuUsage;
        private long _lastMemoryUsage;
        private DateTime _lastHealthCheck = DateTime.MinValue;

        public ProtectionService()
        {
            _logPath = Path.Combine(
                Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? ".",
                "protection_service.log");
            
            Log("ProtectionService 构造函数开始");
            
            try
            {
                _dataManager = new DataManager();
                Log("DataManager 初始化成功");
            }
            catch (Exception ex)
            {
                Log($"DataManager 初始化失败: {ex.Message}");
                _initErrors.Add($"DataManager: {ex.Message}");
            }
            
            try
            {
                _antivirusEngine = new AntivirusEngine();
                Log("AntivirusEngine 初始化成功");
            }
            catch (Exception ex)
            {
                Log($"AntivirusEngine 初始化失败: {ex.Message}");
                _initErrors.Add($"AntivirusEngine: {ex.Message}");
            }
            
            try
            {
                _selfProtectionService = new SelfProtectionService(_dataManager);
                Log("SelfProtectionService 初始化成功");
            }
            catch (Exception ex)
            {
                Log($"SelfProtectionService 初始化失败: {ex.Message}");
                _initErrors.Add($"SelfProtectionService: {ex.Message}");
            }
            
            InitializeMonitors();
            Log($"ProtectionService 构造函数完成，初始化了 {_monitors.Count} 个监控器");
        }

        private void Log(string message)
        {
            try
            {
                File.AppendAllText(_logPath, $"[{DateTime.Now}] {message}\n");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }
        }

        private void InitializeMonitors()
        {
            // 安全初始化各种监控器
            SafeAddMonitor(() => new ProcessMonitor(_dataManager, _antivirusEngine), "ProcessMonitor");
            SafeAddMonitor(() => new FileMonitor(_dataManager, _antivirusEngine), "FileMonitor");
            SafeAddMonitor(() => new RegistryMonitor(_dataManager, _antivirusEngine), "RegistryMonitor");
            SafeAddMonitor(() => new NetworkMonitor(_dataManager, _antivirusEngine), "NetworkMonitor");
            SafeAddMonitor(() => new USBMonitor(_dataManager, _antivirusEngine), "USBMonitor");
            SafeAddMonitor(() => new ScriptMonitor(_dataManager, _antivirusEngine), "ScriptMonitor");
            SafeAddMonitor(() => new BehaviorMonitor(_dataManager, _antivirusEngine), "BehaviorMonitor");
            SafeAddMonitor(() => new BrowserMonitor(_dataManager, _antivirusEngine), "BrowserMonitor");
            SafeAddMonitor(() => new DocumentMonitor(_dataManager, _antivirusEngine), "DocumentMonitor");
            SafeAddMonitor(() => new FirewallManager(_dataManager, _antivirusEngine), "FirewallManager");
            SafeAddMonitor(() => new KernelMonitor(_dataManager, _antivirusEngine), "KernelMonitor");
            SafeAddMonitor(() => new PartitionTableMonitor(_dataManager, _antivirusEngine), "PartitionTableMonitor");
            SafeAddMonitor(() => new UEFIMonitor(_dataManager, _antivirusEngine), "UEFIMonitor");
            SafeAddMonitor(() => new AntiPhishing(_dataManager), "AntiPhishing");
            SafeAddMonitor(() => new ParentalControl(_dataManager), "ParentalControl");
            SafeAddMonitor(() => new EmailSecurity(_dataManager, _antivirusEngine), "EmailSecurity");
            SafeAddMonitor(() => new PasswordManager(_dataManager), "PasswordManager");
            SafeAddMonitor(() => new WebProtection(_dataManager, _antivirusEngine), "WebProtection");
            SafeAddMonitor(() => new ApplicationMonitor(_dataManager), "ApplicationMonitor");
            SafeAddMonitor(() => new BackupService(_dataManager), "BackupService");
            SafeAddMonitor(() => new BehaviorAnalysisService(_dataManager), "BehaviorAnalysisService");
            SafeAddMonitor(() => new CloudScannerService(_dataManager, _antivirusEngine), "CloudScannerService");
            SafeAddMonitor(() => new DeviceControlService(_dataManager), "DeviceControlService");
            // 内存防护（VirtualQueryEx RWX 区域检测/堆喷射识别）——真实能力挂载（原实现未接线）
            SafeAddMonitor(() => new MemoryProtection(_dataManager, _antivirusEngine), "MemoryProtection");
        }

        private void SafeAddMonitor(Func<IMonitor> createMonitor, string name)
        {
            try
            {
                var monitor = createMonitor();
                _monitors.Add(monitor);
                Log($"{name} 初始化成功");
            }
            catch (Exception ex)
            {
                Log($"{name} 初始化失败: {ex.Message}");
                _initErrors.Add($"{name}: {ex.Message}");
            }
        }

        public void Start()
        {
            if (_isRunning)
            {
                Log("服务已在运行中，跳过启动");
                return;
            }

            Log("正在启动保护服务...");
            _isRunning = true;
            
            _protectionThread = new Thread(RunProtection);
            _protectionThread.IsBackground = true;
            _protectionThread.Start();
            Log("保护线程已启动");

            // 启动自我保护服务
            try
            {
                _selfProtectionService?.Start();
                Log("自我保护服务已启动");
            }
            catch (Exception ex)
            {
                Log($"自我保护服务启动失败: {ex.Message}");
            }

            // 启动所有监控器
            int started = 0, failed = 0;
            foreach (var monitor in _monitors)
            {
                try
                {
                    monitor.Start();
                    started++;
                }
                catch (Exception ex)
                {
                    failed++;
                    Log($"监控器启动失败: {ex.Message}");
                }
            }
            Log($"监控器启动完成: {started} 成功, {failed} 失败");

            // 启动通知服务
            try
            {
                NotificationService.Instance.Start();
                Log("通知服务已启动");
            }
            catch (Exception ex)
            {
                Log($"通知服务启动失败: {ex.Message}");
            }

            try
            {
                _dataManager?.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProtectionServiceStart",
                    Message = "保护服务已启动",
                    Details = $"监控器: {started}成功/{failed}失败, 初始化错误: {_initErrors.Count}"
                });
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }
            
            Log("保护服务启动完成");
        }

        public void Stop()
        {
            Log("正在停止保护服务...");
            _isRunning = false;
            
            if (_protectionThread != null && _protectionThread.IsAlive)
            {
                _protectionThread.Join(2000);
            }

            // 停止所有监控器
            foreach (var monitor in _monitors)
            {
                try { monitor.Stop(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }
            }

            // 停止通知服务
            try { NotificationService.Instance.Stop(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }

            // 停止自我保护服务
            try { _selfProtectionService?.Stop(); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }

            try
            {
                _dataManager?.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProtectionServiceStop",
                    Message = "保护服务已停止",
                    Details = "所有监控器已停止"
                });
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }
            
            Log("保护服务已停止");
        }

        private void RunProtection()
        {
            Log("保护线程开始运行");
            try
            {
                while (_isRunning)
                {
                    // 执行定期保护任务
                    PerformRegularTasks();
                    Thread.Sleep(60000); // 每分钟执行一次
                }
            }
            catch (Exception ex)
            {
                Log($"保护线程错误: {ex.Message}");
                try
                {
                    _dataManager?.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ProtectionServiceError",
                        Message = "保护服务错误",
                        Details = ex.Message
                    });
                }
                catch (System.Exception ex2) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex2.Message); }
            }
            Log("保护线程退出");
        }

        private void PerformRegularTasks()
        {
            try
            {
                // 检查病毒库更新
                CheckVirusDefinitionsUpdate();

                // 清理隔离区过期文件
                CleanupQuarantine();

                // 清理日志
                CleanupLogs();
            }
            catch (Exception ex)
            {
                Log($"定期任务错误: {ex.Message}");
            }
        }

        private void CheckVirusDefinitionsUpdate()
        {
            try
            {
                _dataManager?.UpdateVirusDatabase();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }
        }

        private void CleanupQuarantine()
        {
            try
            {
                var quarantineItems = _dataManager?.LoadQuarantine();
                if (quarantineItems == null) return;
                
                var cutoffDate = DateTime.Now.AddDays(-30);
                var oldItems = quarantineItems.Where(item => item.QuarantineTime < cutoffDate).ToList();

                foreach (var item in oldItems)
                {
                    try { _dataManager?.DeleteFromQuarantine(item.Id); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }
        }

        private void CleanupLogs()
        {
            try
            {
                _dataManager?.CleanupOldLogs(30);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionService.cs 捕获异常", ex.Message); }
    }

    public enum MonitorPriority
    {
        Low,
        Medium,
        High,
        Critical
    }

    public class MonitorResourceInfo
    {
        public string MonitorName { get; set; }
        public MonitorPriority Priority { get; set; }
        public double CpuUsagePercent { get; set; }
        public long MemoryUsageBytes { get; set; }
        public DateTime LastUpdated { get; set; }
        public bool IsActive { get; set; }
    }

    public class PerformanceCounter
    {
        public int CpuUsagePercent { get; set; }
        public long MemoryUsageBytes { get; set; }
        public int ActiveThreadCount { get; set; }
        public DateTime LastSampleTime { get; set; }
        public double AverageCpuUsage { get; set; }
        public long PeakMemoryUsage { get; set; }
    }

    public class AdaptiveResourceManager
    {
        public void RegisterMonitor(string name, MonitorPriority priority) { }
        public void UpdateResourceUsage(string name, double cpuPercent, long memoryBytes) { }
        public void AdjustPriorities() { }
        public bool IsResourcePressureHigh() => false;
    }
}
}