using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;

namespace FireAntivirus.Host
{
    public class ServiceManager
    {
        private DataManager dataManager;
        private Dictionary<string, ServiceInfo> services;
        private Dictionary<string, ServiceStatus> serviceStatuses;
        private Dictionary<string, ServiceConfiguration> serviceConfigurations;
        private Dictionary<string, ServiceDependency> serviceDependencies;
        private Dictionary<string, ServicePerformance> servicePerformances;
        private Dictionary<string, ServiceStatistics> serviceStatistics;
        private Dictionary<string, ServiceHealth> serviceHealths;

        public ServiceManager()
        {
            dataManager = new DataManager();
            services = new Dictionary<string, ServiceInfo>();
            serviceStatuses = new Dictionary<string, ServiceStatus>();
            serviceConfigurations = new Dictionary<string, ServiceConfiguration>();
            serviceDependencies = new Dictionary<string, ServiceDependency>();
            servicePerformances = new Dictionary<string, ServicePerformance>();
            serviceStatistics = new Dictionary<string, ServiceStatistics>();
            serviceHealths = new Dictionary<string, ServiceHealth>();
            InitializeServices();
        }

        private void InitializeServices()
        {
            services["FireAntivirusService"] = new ServiceInfo
            {
                Name = "FireAntivirusService",
                DisplayName = "耄耋杀毒服务",
                Description = "提供实时病毒防护和系统安全监控",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.ServiceHost.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            services["FireAntivirusNetworkService"] = new ServiceInfo
            {
                Name = "FireAntivirusNetworkService",
                DisplayName = "耄耋杀毒网络服务",
                Description = "提供网络安全防护和网络流量监控",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.NetworkService.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            services["FireAntivirusWebService"] = new ServiceInfo
            {
                Name = "FireAntivirusWebService",
                DisplayName = "耄耋杀毒网页服务",
                Description = "提供网页安全防护和恶意网站拦截",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.WebService.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            services["FireAntivirusEmailService"] = new ServiceInfo
            {
                Name = "FireAntivirusEmailService",
                DisplayName = "耄耋杀毒邮件服务",
                Description = "提供邮件安全防护和恶意邮件拦截",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.EmailService.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            services["FireAntivirusUSBSevice"] = new ServiceInfo
            {
                Name = "FireAntivirusUSBSevice",
                DisplayName = "耄耋杀毒USB服务",
                Description = "提供USB设备安全防护和恶意文件检测",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.USBSevice.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            services["FireAntivirusBluetoothService"] = new ServiceInfo
            {
                Name = "FireAntivirusBluetoothService",
                DisplayName = "耄耋杀毒蓝牙服务",
                Description = "提供蓝牙设备安全防护和恶意连接检测",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.BluetoothService.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            services["FireAntivirusWifiService"] = new ServiceInfo
            {
                Name = "FireAntivirusWifiService",
                DisplayName = "耄耋杀毒WiFi服务",
                Description = "提供WiFi网络安全防护和恶意网络检测",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.WifiService.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            services["FireAntivirusApplicationService"] = new ServiceInfo
            {
                Name = "FireAntivirusApplicationService",
                DisplayName = "耄耋杀毒应用服务",
                Description = "提供应用程序控制和恶意应用检测",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.ApplicationService.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            services["FireAntivirusPrivacyService"] = new ServiceInfo
            {
                Name = "FireAntivirusPrivacyService",
                DisplayName = "耄耋杀毒隐私服务",
                Description = "提供用户隐私保护和数据安全监控",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.PrivacyService.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            services["FireAntivirusRansomwareService"] = new ServiceInfo
            {
                Name = "FireAntivirusRansomwareService",
                DisplayName = "耄耋杀毒勒索软件服务",
                Description = "提供勒索软件防护和文件加密监控",
                Path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.RansomwareService.exe"),
                StartupType = ServiceStartupType.Automatic,
                Status = ServiceControllerStatus.Stopped
            };

            InitializeServiceStatuses();
            InitializeServiceConfigurations();
            InitializeServiceDependencies();
            InitializeServicePerformances();
            InitializeServiceStatistics();
            InitializeServiceHealths();
        }

        private void InitializeServiceStatuses()
        {
            foreach (var service in services)
            {
                serviceStatuses[service.Key] = new ServiceStatus
                {
                    ServiceName = service.Key,
                    Status = ServiceControllerStatus.Stopped,
                    StartTime = DateTime.MinValue,
                    StopTime = DateTime.MinValue,
                    LastStatusChange = DateTime.MinValue,
                    IsRunning = false
                };
            }
        }

        private void InitializeServiceConfigurations()
        {
            foreach (var service in services)
            {
                serviceConfigurations[service.Key] = new ServiceConfiguration
                {
                    ServiceName = service.Key,
                    DisplayName = service.Value.DisplayName,
                    Description = service.Value.Description,
                    Path = service.Value.Path,
                    StartupType = service.Value.StartupType,
                    Dependencies = new List<string>(),
                    Account = "LocalSystem",
                    DelayedAutoStart = false,
                    DesktopInteract = false
                };
            }
        }

        private void InitializeServiceDependencies()
        {
            foreach (var service in services)
            {
                serviceDependencies[service.Key] = new ServiceDependency
                {
                    ServiceName = service.Key,
                    Dependencies = new List<string>(),
                    DependentServices = new List<string>(),
                    DependencyStatus = new Dictionary<string, ServiceControllerStatus>()
                };
            }
        }

        private void InitializeServicePerformances()
        {
            foreach (var service in services)
            {
                servicePerformances[service.Key] = new ServicePerformance
                {
                    ServiceName = service.Key,
                    CPUUsage = 0.0,
                    MemoryUsage = 0L,
                    DiskUsage = 0L,
                    NetworkUsage = 0L,
                    HandleCount = 0,
                    ThreadCount = 0,
                    ProcessId = 0,
                    PerformanceHistory = new List<PerformanceData>()
                };
            }
        }

        private void InitializeServiceStatistics()
        {
            foreach (var service in services)
            {
                serviceStatistics[service.Key] = new ServiceStatistics
                {
                    ServiceName = service.Key,
                    StartCount = 0,
                    StopCount = 0,
                    RestartCount = 0,
                    ErrorCount = 0,
                    WarningCount = 0,
                    InformationCount = 0,
                    Uptime = TimeSpan.Zero,
                    AverageResponseTime = TimeSpan.Zero,
                    LastStart = DateTime.MinValue,
                    LastStop = DateTime.MinValue,
                    LastError = DateTime.MinValue
                };
            }
        }

        private void InitializeServiceHealths()
        {
            foreach (var service in services)
            {
                serviceHealths[service.Key] = new ServiceHealth
                {
                    ServiceName = service.Key,
                    HealthStatus = ServiceHealthStatus.Healthy,
                    LastHealthCheck = DateTime.MinValue,
                    HealthCheckInterval = TimeSpan.FromMinutes(5),
                    HealthScore = 100.0,
                    Issues = new List<ServiceIssue>(),
                    Recommendations = new List<ServiceRecommendation>()
                };
            }
        }

        public bool StartService(string serviceName)
        {
            try
            {
                if (!services.ContainsKey(serviceName))
                {
                    dataManager.LogError($"服务不存在: {serviceName}", "服务管理器", "ServiceManager");
                    return false;
                }

                var serviceInfo = services[serviceName];
                var serviceStatus = serviceStatuses[serviceName];
                var serviceStats = serviceStatistics[serviceName];

                if (serviceStatus.IsRunning)
                {
                    dataManager.LogInfo($"服务已经在运行: {serviceName}", "服务管理器", "ServiceManager");
                    return true;
                }

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = serviceInfo.Path,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = Path.GetDirectoryName(serviceInfo.Path)
                };

                using (Process process = Process.Start(psi))
                {
                    serviceStatus.Status = ServiceControllerStatus.Running;
                    serviceStatus.StartTime = DateTime.Now;
                    serviceStatus.LastStatusChange = DateTime.Now;
                    serviceStatus.IsRunning = true;
                    serviceStatus.ProcessId = process.Id;

                    serviceStats.StartCount++;
                    serviceStats.LastStart = DateTime.Now;

                    dataManager.LogInfo($"服务已启动: {serviceName} (PID: {process.Id})", "服务管理器", "ServiceManager");

                    Task.Run(() => MonitorService(serviceName, process.Id));

                    return true;
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"启动服务失败: {serviceName}", ex.Message, "ServiceManager");
                return false;
            }
        }

        public bool StopService(string serviceName)
        {
            try
            {
                if (!services.ContainsKey(serviceName))
                {
                    dataManager.LogError($"服务不存在: {serviceName}", "服务管理器", "ServiceManager");
                    return false;
                }

                var serviceStatus = serviceStatuses[serviceName];
                var serviceStats = serviceStatistics[serviceName];

                if (!serviceStatus.IsRunning)
                {
                    dataManager.LogInfo($"服务已经停止: {serviceName}", "服务管理器", "ServiceManager");
                    return true;
                }

                if (serviceStatus.ProcessId > 0)
                {
                    Process process = Process.GetProcessById(serviceStatus.ProcessId);
                    process.Kill();
                    process.WaitForExit(5000);
                }

                serviceStatus.Status = ServiceControllerStatus.Stopped;
                serviceStatus.StopTime = DateTime.Now;
                serviceStatus.LastStatusChange = DateTime.Now;
                serviceStatus.IsRunning = false;
                serviceStatus.ProcessId = 0;

                serviceStats.StopCount++;
                serviceStats.LastStop = DateTime.Now;
                serviceStats.Uptime += DateTime.Now - serviceStatus.StartTime;

                dataManager.LogInfo($"服务已停止: {serviceName}", "服务管理器", "ServiceManager");

                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"停止服务失败: {serviceName}", ex.Message, "ServiceManager");
                return false;
            }
        }

        public bool RestartService(string serviceName)
        {
            try
            {
                StopService(serviceName);
                Thread.Sleep(1000);
                bool result = StartService(serviceName);

                if (result)
                {
                    serviceStatistics[serviceName].RestartCount++;
                    dataManager.LogInfo($"服务已重启: {serviceName}", "服务管理器", "ServiceManager");
                }

                return result;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"重启服务失败: {serviceName}", ex.Message, "ServiceManager");
                return false;
            }
        }

        public bool PauseService(string serviceName)
        {
            try
            {
                if (!services.ContainsKey(serviceName))
                {
                    dataManager.LogError($"服务不存在: {serviceName}", "服务管理器", "ServiceManager");
                    return false;
                }

                var serviceStatus = serviceStatuses[serviceName];

                if (!serviceStatus.IsRunning)
                {
                    dataManager.LogInfo($"服务未运行，无法暂停: {serviceName}", "服务管理器", "ServiceManager");
                    return false;
                }

                serviceStatus.Status = ServiceControllerStatus.Paused;
                serviceStatus.LastStatusChange = DateTime.Now;

                dataManager.LogInfo($"服务已暂停: {serviceName}", "服务管理器", "ServiceManager");

                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"暂停服务失败: {serviceName}", ex.Message, "ServiceManager");
                return false;
            }
        }

        public bool ContinueService(string serviceName)
        {
            try
            {
                if (!services.ContainsKey(serviceName))
                {
                    dataManager.LogError($"服务不存在: {serviceName}", "服务管理器", "ServiceManager");
                    return false;
                }

                var serviceStatus = serviceStatuses[serviceName];

                if (serviceStatus.Status != ServiceControllerStatus.Paused)
                {
                    dataManager.LogInfo($"服务未暂停，无法继续: {serviceName}", "服务管理器", "ServiceManager");
                    return false;
                }

                serviceStatus.Status = ServiceControllerStatus.Running;
                serviceStatus.LastStatusChange = DateTime.Now;

                dataManager.LogInfo($"服务已继续: {serviceName}", "服务管理器", "ServiceManager");

                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"继续服务失败: {serviceName}", ex.Message, "ServiceManager");
                return false;
            }
        }

        public ServiceControllerStatus GetServiceStatus(string serviceName)
        {
            if (!services.ContainsKey(serviceName))
            {
                return ServiceControllerStatus.Stopped;
            }

            return serviceStatuses[serviceName].Status;
        }

        public bool IsServiceRunning(string serviceName)
        {
            if (!services.ContainsKey(serviceName))
            {
                return false;
            }

            return serviceStatuses[serviceName].IsRunning;
        }

        public void StartAllServices()
        {
            foreach (var service in services)
            {
                StartService(service.Key);
                Thread.Sleep(500);
            }
        }

        public void StopAllServices()
        {
            foreach (var service in services)
            {
                StopService(service.Key);
                Thread.Sleep(500);
            }
        }

        public void RestartAllServices()
        {
            StopAllServices();
            Thread.Sleep(2000);
            StartAllServices();
        }

        public void MonitorService(string serviceName, int processId)
        {
            try
            {
                while (true)
                {
                    if (!serviceStatuses[serviceName].IsRunning)
                    {
                        break;
                    }

                    try
                    {
                        Process process = Process.GetProcessById(processId);
                        var performance = servicePerformances[serviceName];

                        performance.CPUUsage = GetProcessCPUUsage(process);
                        performance.MemoryUsage = process.WorkingSet64;
                        performance.DiskUsage = GetProcessDiskUsage(process);
                        performance.NetworkUsage = GetProcessNetworkUsage(process);
                        performance.HandleCount = process.HandleCount;
                        performance.ThreadCount = process.Threads.Count;
                        performance.ProcessId = process.Id;

                        performance.PerformanceHistory.Add(new PerformanceData
                        {
                            Timestamp = DateTime.Now,
                            CPUUsage = performance.CPUUsage,
                            MemoryUsage = performance.MemoryUsage,
                            DiskUsage = performance.DiskUsage,
                            NetworkUsage = performance.NetworkUsage
                        });

                        if (performance.PerformanceHistory.Count > 100)
                        {
                            performance.PerformanceHistory.RemoveAt(0);
                        }
                    }
                    catch
                    {
                        var serviceStatus = serviceStatuses[serviceName];
                        var serviceStats = serviceStatistics[serviceName];

                        serviceStatus.Status = ServiceControllerStatus.Stopped;
                        serviceStatus.StopTime = DateTime.Now;
                        serviceStatus.LastStatusChange = DateTime.Now;
                        serviceStatus.IsRunning = false;
                        serviceStatus.ProcessId = 0;

                        serviceStats.StopCount++;
                        serviceStats.LastStop = DateTime.Now;
                        serviceStats.Uptime += DateTime.Now - serviceStatus.StartTime;

                        dataManager.LogWarning($"服务意外停止: {serviceName}", "服务管理器", "ServiceManager");
                        break;
                    }

                    Thread.Sleep(1000);
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"监控服务失败: {serviceName}", ex.Message, "ServiceManager");
            }
        }

        private double GetProcessCPUUsage(Process process)
        {
            try
            {
                var startTime = DateTime.Now;
                var startCpuUsage = process.TotalProcessorTime;
                Thread.Sleep(100);
                var endTime = DateTime.Now;
                var endCpuUsage = process.TotalProcessorTime;

                var cpuUsedMs = (endCpuUsage - startCpuUsage).TotalMilliseconds;
                var totalMsPassed = (endTime - startTime).TotalMilliseconds;
                var cpuUsageTotal = cpuUsedMs / (Environment.ProcessorCount * totalMsPassed);

                return cpuUsageTotal * 100;
            }
            catch
            {
                return 0.0;
            }
        }

        private long GetProcessDiskUsage(Process process)
        {
            try
            {
                return process.WorkingSet64;
            }
            catch
            {
                return 0L;
            }
        }

        private long GetProcessNetworkUsage(Process process)
        {
            try
            {
                return 0L;
            }
            catch
            {
                return 0L;
            }
        }

        public ServiceInfo GetServiceInfo(string serviceName)
        {
            if (services.ContainsKey(serviceName))
            {
                return services[serviceName];
            }
            return null;
        }

        public ServiceStatus GetServiceStatusInfo(string serviceName)
        {
            if (serviceStatuses.ContainsKey(serviceName))
            {
                return serviceStatuses[serviceName];
            }
            return null;
        }

        public ServiceConfiguration GetServiceConfiguration(string serviceName)
        {
            if (serviceConfigurations.ContainsKey(serviceName))
            {
                return serviceConfigurations[serviceName];
            }
            return null;
        }

        public ServiceDependency GetServiceDependency(string serviceName)
        {
            if (serviceDependencies.ContainsKey(serviceName))
            {
                return serviceDependencies[serviceName];
            }
            return null;
        }

        public ServicePerformance GetServicePerformance(string serviceName)
        {
            if (servicePerformances.ContainsKey(serviceName))
            {
                return servicePerformances[serviceName];
            }
            return null;
        }

        public ServiceStatistics GetServiceStatistics(string serviceName)
        {
            if (serviceStatistics.ContainsKey(serviceName))
            {
                return serviceStatistics[serviceName];
            }
            return null;
        }

        public ServiceHealth GetServiceHealth(string serviceName)
        {
            if (serviceHealths.ContainsKey(serviceName))
            {
                return serviceHealths[serviceName];
            }
            return null;
        }

        public List<ServiceInfo> GetAllServices()
        {
            return services.Values.ToList();
        }

        public List<ServiceStatus> GetAllServiceStatuses()
        {
            return serviceStatuses.Values.ToList();
        }

        public List<ServicePerformance> GetAllServicePerformances()
        {
            return servicePerformances.Values.ToList();
        }

        public List<ServiceHealth> GetAllServiceHealths()
        {
            return serviceHealths.Values.ToList();
        }

        public void UpdateServiceHealth(string serviceName)
        {
            if (!services.ContainsKey(serviceName))
            {
                return;
            }

            var health = serviceHealths[serviceName];
            var status = serviceStatuses[serviceName];
            var performance = servicePerformances[serviceName];

            health.LastHealthCheck = DateTime.Now;
            health.Issues.Clear();
            health.Recommendations.Clear();

            if (!status.IsRunning)
            {
                health.HealthStatus = ServiceHealthStatus.Critical;
                health.HealthScore = 0.0;
                health.Issues.Add(new ServiceIssue
                {
                    IssueId = Guid.NewGuid().ToString(),
                    IssueType = "ServiceStopped",
                    Severity = "Critical",
                    Description = "服务未运行",
                    Timestamp = DateTime.Now,
                    Status = "Active"
                });
            }
            else
            {
                health.HealthStatus = ServiceHealthStatus.Healthy;
                health.HealthScore = 100.0;

                if (performance.CPUUsage > 50.0)
                {
                    health.HealthStatus = ServiceHealthStatus.Warning;
                    health.HealthScore -= 20.0;
                    health.Issues.Add(new ServiceIssue
                    {
                        IssueId = Guid.NewGuid().ToString(),
                        IssueType = "HighCPUUsage",
                        Severity = "Warning",
                        Description = "CPU使用率过高",
                        Timestamp = DateTime.Now,
                        Status = "Active"
                    });
                }

                if (performance.MemoryUsage > 1024 * 1024 * 1024) // 1GB
                {
                    health.HealthStatus = ServiceHealthStatus.Warning;
                    health.HealthScore -= 20.0;
                    health.Issues.Add(new ServiceIssue
                    {
                        IssueId = Guid.NewGuid().ToString(),
                        IssueType = "HighMemoryUsage",
                        Severity = "Warning",
                        Description = "内存使用率过高",
                        Timestamp = DateTime.Now,
                        Status = "Active"
                    });
                }

                if (health.HealthScore < 0)
                {
                    health.HealthScore = 0;
                }
            }

            dataManager.LogInfo($"服务健康检查: {serviceName} (评分: {health.HealthScore:F2}) 状态: {health.HealthStatus}", "服务管理器", "ServiceManager");
        }

        public void UpdateAllServiceHealths()
        {
            foreach (var service in services)
            {
                UpdateServiceHealth(service.Key);
                Thread.Sleep(100);
            }
        }

        public void Cleanup()
        {
            StopAllServices();
            services.Clear();
            serviceStatuses.Clear();
            serviceConfigurations.Clear();
            serviceDependencies.Clear();
            servicePerformances.Clear();
            serviceStatistics.Clear();
            serviceHealths.Clear();
        }
    }

    public class ServiceInfo
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }
        public string Path { get; set; }
        public ServiceStartupType StartupType { get; set; }
        public ServiceControllerStatus Status { get; set; }
    }

    public class ServiceStatus
    {
        public string ServiceName { get; set; }
        public ServiceControllerStatus Status { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime StopTime { get; set; }
        public DateTime LastStatusChange { get; set; }
        public bool IsRunning { get; set; }
        public int ProcessId { get; set; }
    }

    public class ServiceConfiguration
    {
        public string ServiceName { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }
        public string Path { get; set; }
        public ServiceStartupType StartupType { get; set; }
        public List<string> Dependencies { get; set; }
        public string Account { get; set; }
        public bool DelayedAutoStart { get; set; }
        public bool DesktopInteract { get; set; }
    }

    public class ServiceDependency
    {
        public string ServiceName { get; set; }
        public List<string> Dependencies { get; set; }
        public List<string> DependentServices { get; set; }
        public Dictionary<string, ServiceControllerStatus> DependencyStatus { get; set; }
    }

    public class ServicePerformance
    {
        public string ServiceName { get; set; }
        public double CPUUsage { get; set; }
        public long MemoryUsage { get; set; }
        public long DiskUsage { get; set; }
        public long NetworkUsage { get; set; }
        public int HandleCount { get; set; }
        public int ThreadCount { get; set; }
        public int ProcessId { get; set; }
        public List<PerformanceData> PerformanceHistory { get; set; }
    }

    public class PerformanceData
    {
        public DateTime Timestamp { get; set; }
        public double CPUUsage { get; set; }
        public long MemoryUsage { get; set; }
        public long DiskUsage { get; set; }
        public long NetworkUsage { get; set; }
    }

    public class ServiceStatistics
    {
        public string ServiceName { get; set; }
        public int StartCount { get; set; }
        public int StopCount { get; set; }
        public int RestartCount { get; set; }
        public int ErrorCount { get; set; }
        public int WarningCount { get; set; }
        public int InformationCount { get; set; }
        public TimeSpan Uptime { get; set; }
        public TimeSpan AverageResponseTime { get; set; }
        public DateTime LastStart { get; set; }
        public DateTime LastStop { get; set; }
        public DateTime LastError { get; set; }
    }

    public class ServiceHealth
    {
        public string ServiceName { get; set; }
        public ServiceHealthStatus HealthStatus { get; set; }
        public DateTime LastHealthCheck { get; set; }
        public TimeSpan HealthCheckInterval { get; set; }
        public double HealthScore { get; set; }
        public List<ServiceIssue> Issues { get; set; }
        public List<ServiceRecommendation> Recommendations { get; set; }
    }

    public class ServiceIssue
    {
        public string IssueId { get; set; }
        public string IssueType { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public DateTime Timestamp { get; set; }
        public string Status { get; set; }
    }

    public class ServiceRecommendation
    {
        public string RecommendationId { get; set; }
        public string Type { get; set; }
        public string Description { get; set; }
        public string Action { get; set; }
        public DateTime Timestamp { get; set; }
        public string Status { get; set; }
    }

    public enum ServiceStartupType
    {
        Automatic,
        Manual,
        Disabled
    }

    public enum ServiceHealthStatus
    {
        Healthy,
        Warning,
        Critical
    }
}
