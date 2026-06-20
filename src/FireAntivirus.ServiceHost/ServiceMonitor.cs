using FireAntivirus.Common;
using FireAntivirus.Data;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Threading.Tasks;

namespace FireAntivirus.ServiceHost
{
    public class ServiceMonitor
    {
        private readonly string _serviceName;
        private readonly int _monitorIntervalMs;
        private readonly int _maxRestartAttempts;
        private readonly int _restartDelayMs;

        private bool _isMonitoring;
        private int _restartAttempts;
        private DateTime _lastRestartTime;

        public event EventHandler<ServiceStatusChangedEventArgs> ServiceStatusChanged;
        public event EventHandler<ServiceErrorEventArgs> ServiceError;
        public event EventHandler<ServiceRestartEventArgs> ServiceRestarted;

        public ServiceMonitor(string serviceName, int monitorIntervalMs = 5000, int maxRestartAttempts = 3, int restartDelayMs = 10000)
        {
            _serviceName = serviceName;
            _monitorIntervalMs = monitorIntervalMs;
            _maxRestartAttempts = maxRestartAttempts;
            _restartDelayMs = restartDelayMs;
            _isMonitoring = false;
            _restartAttempts = 0;
            _lastRestartTime = DateTime.MinValue;
        }

        public async Task StartMonitoringAsync()
        {
            if (_isMonitoring)
            {
                LogHelper.Info("Monitoring already started");
                return;
            }

            _isMonitoring = true;
            LogHelper.Info($"Starting service monitoring for: {_serviceName}");

            while (_isMonitoring)
            {
                try
                {
                    await MonitorServiceAsync();
                }
                catch (Exception ex)
                {
                    LogHelper.Error($"Monitoring error: {ex.Message}");
                    OnServiceError(new ServiceErrorEventArgs { ErrorMessage = ex.Message, Timestamp = DateTime.UtcNow });
                }

                await Task.Delay(_monitorIntervalMs);
            }

            LogHelper.Info($"Stopped service monitoring for: {_serviceName}");
        }

        public void StopMonitoring()
        {
            _isMonitoring = false;
            LogHelper.Info($"Stopping service monitoring for: {_serviceName}");
        }

        public async Task<ServiceMonitorStatus> GetMonitorStatusAsync()
        {
            var serviceStatus = GetServiceStatus();

            return new ServiceMonitorStatus
            {
                ServiceName = _serviceName,
                IsMonitoring = _isMonitoring,
                ServiceStatus = serviceStatus,
                RestartAttempts = _restartAttempts,
                LastRestartTime = _lastRestartTime,
                MonitorIntervalMs = _monitorIntervalMs,
                MaxRestartAttempts = _maxRestartAttempts,
                RestartDelayMs = _restartDelayMs
            };
        }

        public async Task<ServiceHealthStatus> GetServiceHealthAsync()
        {
            var healthStatus = new ServiceHealthStatus
            {
                ServiceName = _serviceName,
                CheckTime = DateTime.UtcNow,
                Metrics = new List<ServiceMetric>()
            };

            try
            {
                var serviceStatus = GetServiceStatus();
                healthStatus.Status = serviceStatus.Status;

                // 获取服务进程信息
                var processInfo = GetServiceProcessInfo();
                if (processInfo != null)
                {
                    healthStatus.Metrics.Add(new ServiceMetric { Name = "CPU Usage", Value = processInfo.CpuUsage, Unit = "%" });
                    healthStatus.Metrics.Add(new ServiceMetric { Name = "Memory Usage", Value = processInfo.MemoryUsage / (1024 * 1024), Unit = "MB" });
                    healthStatus.Metrics.Add(new ServiceMetric { Name = "Process Id", Value = processInfo.ProcessId, Unit = "" });
                    healthStatus.Metrics.Add(new ServiceMetric { Name = "Thread Count", Value = processInfo.ThreadCount, Unit = "" });
                }

                // 获取服务启动时间
                var startupTime = GetServiceStartupTime();
                if (startupTime.HasValue)
                {
                    var uptime = DateTime.UtcNow - startupTime.Value;
                    healthStatus.Metrics.Add(new ServiceMetric { Name = "Uptime", Value = uptime.TotalMinutes, Unit = "minutes" });
                }

                // 评估服务健康状态
                healthStatus.HealthStatus = EvaluateHealthStatus(serviceStatus.Status, healthStatus.Metrics);
            }
            catch (Exception ex)
            {
                LogHelper.Error($"Service health check error: {ex.Message}");
                healthStatus.HealthStatus = HealthStatus.Error;
                healthStatus.ErrorMessage = ex.Message;
            }

            return healthStatus;
        }

        public async Task<List<ServiceHealthStatus>> GetAllServicesHealthAsync()
        {
            var healthStatuses = new List<ServiceHealthStatus>();

            try
            {
                var services = ServiceController.GetServices();
                foreach (var service in services)
                {
                    var monitor = new ServiceMonitor(service.ServiceName);
                    var healthStatus = await monitor.GetServiceHealthAsync();
                    healthStatuses.Add(healthStatus);
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error($"Get all services health error: {ex.Message}");
            }

            return healthStatuses;
        }

        private async Task MonitorServiceAsync()
        {
            var serviceStatus = GetServiceStatus();

            // 检查服务状态
            if (serviceStatus.Status == ServiceControllerStatus.Stopped || serviceStatus.Status == ServiceControllerStatus.StopPending)
            {
                LogHelper.Warning($"Service {_serviceName} is stopped or stopping");
                OnServiceStatusChanged(new ServiceStatusChangedEventArgs { NewStatus = serviceStatus.Status, OldStatus = ServiceControllerStatus.Running, Timestamp = DateTime.UtcNow });

                // 尝试重启服务
                await TryRestartServiceAsync();
            }
            else if (serviceStatus.Status == ServiceControllerStatus.Running)
            {
                // 服务运行正常，重置重启计数
                _restartAttempts = 0;
            }

            // 检查服务健康状态
            var healthStatus = await GetServiceHealthAsync();
            if (healthStatus.HealthStatus == HealthStatus.Critical)
            {
                LogHelper.Warning($"Service {_serviceName} health is critical");
                OnServiceError(new ServiceErrorEventArgs { ErrorMessage = "Service health is critical", Timestamp = DateTime.UtcNow });
            }
        }

        private async Task TryRestartServiceAsync()
        {
            // 检查是否达到最大重启尝试次数
            if (_restartAttempts >= _maxRestartAttempts)
            {
                LogHelper.Error($"Max restart attempts reached for service: {_serviceName}");
                OnServiceError(new ServiceErrorEventArgs { ErrorMessage = "Max restart attempts reached", Timestamp = DateTime.UtcNow });
                return;
            }

            // 检查重启间隔
            if (DateTime.UtcNow - _lastRestartTime < TimeSpan.FromMilliseconds(_restartDelayMs))
            {
                LogHelper.Info($"Restart delay not elapsed for service: {_serviceName}");
                return;
            }

            try
            {
                LogHelper.Info($"Attempting to restart service: {_serviceName} (Attempt {_restartAttempts + 1}/{_maxRestartAttempts})");

                using (var serviceController = new ServiceController(_serviceName))
                {
                    serviceController.Start();
                    serviceController.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                }

                _restartAttempts++;
                _lastRestartTime = DateTime.UtcNow;

                LogHelper.Info($"Service {_serviceName} restarted successfully");
                OnServiceRestarted(new ServiceRestartEventArgs { RestartAttempt = _restartAttempts, Timestamp = DateTime.UtcNow });
                OnServiceStatusChanged(new ServiceStatusChangedEventArgs { NewStatus = ServiceControllerStatus.Running, OldStatus = ServiceControllerStatus.Stopped, Timestamp = DateTime.UtcNow });
            }
            catch (Exception ex)
            {
                LogHelper.Error($"Failed to restart service {_serviceName}: {ex.Message}");
                OnServiceError(new ServiceErrorEventArgs { ErrorMessage = $"Failed to restart service: {ex.Message}", Timestamp = DateTime.UtcNow });
            }
        }

        private ServiceStatus GetServiceStatus()
        {
            try
            {
                using (var serviceController = new ServiceController(_serviceName))
                {
                    return new ServiceStatus
                    {
                        ServiceName = _serviceName,
                        DisplayName = serviceController.DisplayName,
                        Status = serviceController.Status,
                        IsInstalled = true
                    };
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error($"Get service status error: {ex.Message}");
                return new ServiceStatus
                {
                    ServiceName = _serviceName,
                    Status = ServiceControllerStatus.Stopped,
                    IsInstalled = false,
                    ErrorMessage = ex.Message
                };
            }
        }

        private ServiceProcessInfo GetServiceProcessInfo()
        {
            try
            {
                using (var serviceController = new ServiceController(_serviceName))
                {
                    if (serviceController.Status == ServiceControllerStatus.Running)
                    {
                        var processId = GetServiceProcessId(serviceController.ServiceName);
                        if (processId > 0)
                        {
                            using (var process = Process.GetProcessById(processId))
                            {
                                return new ServiceProcessInfo
                                {
                                    ProcessId = processId,
                                    CpuUsage = GetProcessCpuUsage(process),
                                    MemoryUsage = process.WorkingSet64,
                                    ThreadCount = process.Threads.Count
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error($"Get service process info error: {ex.Message}");
            }

            return null;
        }

        private int GetServiceProcessId(string serviceName)
        {
            // 实现获取服务进程ID的逻辑
            // 这里简化处理，实际应该使用WMI或其他方法
            return 0;
        }

        private double GetProcessCpuUsage(Process process)
        {
            // 实现获取进程CPU使用率的逻辑
            // 这里简化处理，实际应该使用性能计数器
            return 0.0;
        }

        private DateTime? GetServiceStartupTime()
        {
            // 实现获取服务启动时间的逻辑
            // 这里简化处理，实际应该使用WMI或其他方法
            return DateTime.UtcNow.AddHours(-1);
        }

        private HealthStatus EvaluateHealthStatus(ServiceControllerStatus status, List<ServiceMetric> metrics)
        {
            if (status != ServiceControllerStatus.Running)
            {
                return HealthStatus.Critical;
            }

            // 检查CPU使用率
            var cpuMetric = metrics.FirstOrDefault(m => m.Name == "CPU Usage");
            if (cpuMetric != null && cpuMetric.Value > 90)
            {
                return HealthStatus.Critical;
            }

            // 检查内存使用率
            var memoryMetric = metrics.FirstOrDefault(m => m.Name == "Memory Usage");
            if (memoryMetric != null && memoryMetric.Value > 1024) // 1GB
            {
                return HealthStatus.Warning;
            }

            return HealthStatus.Good;
        }

        protected virtual void OnServiceStatusChanged(ServiceStatusChangedEventArgs e)
        {
            ServiceStatusChanged?.Invoke(this, e);
        }

        protected virtual void OnServiceError(ServiceErrorEventArgs e)
        {
            ServiceError?.Invoke(this, e);
        }

        protected virtual void OnServiceRestarted(ServiceRestartEventArgs e)
        {
            ServiceRestarted?.Invoke(this, e);
        }
    }

    public class ServiceMonitorStatus
    {
        public string ServiceName { get; set; }
        public bool IsMonitoring { get; set; }
        public ServiceStatus ServiceStatus { get; set; }
        public int RestartAttempts { get; set; }
        public DateTime LastRestartTime { get; set; }
        public int MonitorIntervalMs { get; set; }
        public int MaxRestartAttempts { get; set; }
        public int RestartDelayMs { get; set; }
    }

    public class ServiceHealthStatus
    {
        public string ServiceName { get; set; }
        public DateTime CheckTime { get; set; }
        public ServiceControllerStatus Status { get; set; }
        public HealthStatus HealthStatus { get; set; }
        public string ErrorMessage { get; set; }
        public List<ServiceMetric> Metrics { get; set; }
    }

    public class ServiceMetric
    {
        public string Name { get; set; }
        public double Value { get; set; }
        public string Unit { get; set; }
    }

    public class ServiceProcessInfo
    {
        public int ProcessId { get; set; }
        public double CpuUsage { get; set; }
        public long MemoryUsage { get; set; }
        public int ThreadCount { get; set; }
    }

    public class ServiceStatusChangedEventArgs : EventArgs
    {
        public ServiceControllerStatus OldStatus { get; set; }
        public ServiceControllerStatus NewStatus { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class ServiceErrorEventArgs : EventArgs
    {
        public string ErrorMessage { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class ServiceRestartEventArgs : EventArgs
    {
        public int RestartAttempt { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum HealthStatus
    {
        Good,
        Warning,
        Critical,
        Error
    }
}
