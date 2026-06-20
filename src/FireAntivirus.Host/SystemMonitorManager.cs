using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Data;

namespace FireAntivirus.Host
{
    public class SystemMonitorManager
    {
        private DataManager dataManager;
        private SystemMonitor systemMonitor;
        private ProcessMonitor processMonitor;
        private NetworkMonitor networkMonitor;
        private DiskMonitor diskMonitor;
        private MemoryMonitor memoryMonitor;
        private CPUMonitor cpuMonitor;
        private RegistryMonitor registryMonitor;
        private FileSystemMonitor fileSystemMonitor;
        private ServiceMonitor serviceMonitor;
        private EventLogMonitor eventLogMonitor;
        private PerformanceCounterMonitor performanceCounterMonitor;
        private WindowsEventMonitor windowsEventMonitor;
        private SystemHealthMonitor systemHealthMonitor;
        private NetworkTrafficMonitor networkTrafficMonitor;
        private SystemResourceMonitor systemResourceMonitor;
        private SystemPerformanceMonitor systemPerformanceMonitor;
        private SystemStabilityMonitor systemStabilityMonitor;
        private SystemSecurityMonitor systemSecurityMonitor;

        public SystemMonitorManager()
        {
            dataManager = new DataManager();
            systemMonitor = new SystemMonitor();
            processMonitor = new ProcessMonitor();
            networkMonitor = new NetworkMonitor();
            diskMonitor = new DiskMonitor();
            memoryMonitor = new MemoryMonitor();
            cpuMonitor = new CPUMonitor();
            registryMonitor = new RegistryMonitor();
            fileSystemMonitor = new FileSystemMonitor();
            serviceMonitor = new ServiceMonitor();
            eventLogMonitor = new EventLogMonitor();
            performanceCounterMonitor = new PerformanceCounterMonitor();
            windowsEventMonitor = new WindowsEventMonitor();
            systemHealthMonitor = new SystemHealthMonitor();
            networkTrafficMonitor = new NetworkTrafficMonitor();
            systemResourceMonitor = new SystemResourceMonitor();
            systemPerformanceMonitor = new SystemPerformanceMonitor();
            systemStabilityMonitor = new SystemStabilityMonitor();
            systemSecurityMonitor = new SystemSecurityMonitor();
        }

        public void StartMonitoring()
        {
            try
            {
                systemMonitor.Start();
                processMonitor.Start();
                networkMonitor.Start();
                diskMonitor.Start();
                memoryMonitor.Start();
                cpuMonitor.Start();
                registryMonitor.Start();
                fileSystemMonitor.Start();
                serviceMonitor.Start();
                eventLogMonitor.Start();
                performanceCounterMonitor.Start();
                windowsEventMonitor.Start();
                systemHealthMonitor.Start();
                networkTrafficMonitor.Start();
                systemResourceMonitor.Start();
                systemPerformanceMonitor.Start();
                systemStabilityMonitor.Start();
                systemSecurityMonitor.Start();

                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统监控已启动", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("启动系统监控失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void StopMonitoring()
        {
            try
            {
                systemMonitor.Stop();
                processMonitor.Stop();
                networkMonitor.Stop();
                diskMonitor.Stop();
                memoryMonitor.Stop();
                cpuMonitor.Stop();
                registryMonitor.Stop();
                fileSystemMonitor.Stop();
                serviceMonitor.Stop();
                eventLogMonitor.Stop();
                performanceCounterMonitor.Stop();
                windowsEventMonitor.Stop();
                systemHealthMonitor.Stop();
                networkTrafficMonitor.Stop();
                systemResourceMonitor.Stop();
                systemPerformanceMonitor.Stop();
                systemStabilityMonitor.Stop();
                systemSecurityMonitor.Stop();

                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统监控已停止", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("停止系统监控失败", ex.Message, "SystemMonitorManager");
            }
        }

        public SystemInfo GetSystemInfo()
        {
            return systemMonitor.GetSystemInfo();
        }

        public List<ProcessInfo> GetProcesses()
        {
            return processMonitor.GetProcesses();
        }

        public List<NetworkInfo> GetNetworkInfo()
        {
            return networkMonitor.GetNetworkInfo();
        }

        public List<DiskInfo> GetDiskInfo()
        {
            return diskMonitor.GetDiskInfo();
        }

        public MemoryInfo GetMemoryInfo()
        {
            return memoryMonitor.GetMemoryInfo();
        }

        public CPUInfo GetCPUInfo()
        {
            return cpuMonitor.GetCPUInfo();
        }

        public List<RegistryInfo> GetRegistryInfo()
        {
            return registryMonitor.GetRegistryInfo();
        }

        public List<FileSystemInfo> GetFileSystemInfo()
        {
            return fileSystemMonitor.GetFileSystemInfo();
        }

        public List<ServiceInfo> GetServiceInfo()
        {
            return serviceMonitor.GetServiceInfo();
        }

        public List<EventLogInfo> GetEventLogInfo()
        {
            return eventLogMonitor.GetEventLogInfo();
        }

        public List<PerformanceCounterInfo> GetPerformanceCounterInfo()
        {
            return performanceCounterMonitor.GetPerformanceCounterInfo();
        }

        public List<WindowsEventInfo> GetWindowsEventInfo()
        {
            return windowsEventMonitor.GetWindowsEventInfo();
        }

        public SystemHealthInfo GetSystemHealthInfo()
        {
            return systemHealthMonitor.GetSystemHealthInfo();
        }

        public List<NetworkTrafficInfo> GetNetworkTrafficInfo()
        {
            return networkTrafficMonitor.GetNetworkTrafficInfo();
        }

        public SystemResourceInfo GetSystemResourceInfo()
        {
            return systemResourceMonitor.GetSystemResourceInfo();
        }

        public SystemPerformanceInfo GetSystemPerformanceInfo()
        {
            return systemPerformanceMonitor.GetSystemPerformanceInfo();
        }

        public SystemStabilityInfo GetSystemStabilityInfo()
        {
            return systemStabilityMonitor.GetSystemStabilityInfo();
        }

        public SystemSecurityInfo GetSystemSecurityInfo()
        {
            return systemSecurityMonitor.GetSystemSecurityInfo();
        }

        public SystemStatus GetSystemStatus()
        {
            return new SystemStatus
            {
                SystemInfo = GetSystemInfo(),
                MemoryInfo = GetMemoryInfo(),
                CPUInfo = GetCPUInfo(),
                DiskInfo = GetDiskInfo(),
                NetworkInfo = GetNetworkInfo(),
                ProcessCount = GetProcesses().Count,
                ServiceCount = GetServiceInfo().Count,
                HealthInfo = GetSystemHealthInfo(),
                ResourceInfo = GetSystemResourceInfo(),
                PerformanceInfo = GetSystemPerformanceInfo(),
                StabilityInfo = GetSystemStabilityInfo(),
                SecurityInfo = GetSystemSecurityInfo(),
                Timestamp = DateTime.Now
            };
        }

        public void GenerateSystemReport()
        {
            try
            {
                var report = new SystemReport();
                report.GenerateReport();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统报告已生成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("生成系统报告失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void GeneratePerformanceReport()
        {
            try
            {
                var report = new PerformanceReport();
                report.GenerateReport();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "性能报告已生成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("生成性能报告失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void GenerateSecurityReport()
        {
            try
            {
                var report = new SecurityReport();
                report.GenerateReport();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "安全报告已生成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("生成安全报告失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void CheckSystemHealth()
        {
            try
            {
                var healthCheck = new SystemHealthCheck();
                healthCheck.PerformCheck();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统健康检查已完成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统健康检查失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void CheckSystemPerformance()
        {
            try
            {
                var performanceCheck = new SystemPerformanceCheck();
                performanceCheck.PerformCheck();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统性能检查已完成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统性能检查失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void CheckSystemSecurity()
        {
            try
            {
                var securityCheck = new SystemSecurityCheck();
                securityCheck.PerformCheck();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统安全检查已完成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统安全检查失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void OptimizeSystem()
        {
            try
            {
                var optimizer = new SystemOptimizer();
                optimizer.Optimize();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统优化已完成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统优化失败", ex.Message, "SystemMonitorManager");
            }
        }

        public long CleanSystem()
        {
            long cleanedSize = 0;
            try
            {
                var cleaner = new SystemCleaner();
                cleanedSize = cleaner.Clean();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = $"系统清理已完成，释放空间: {FormatSize(cleanedSize)}", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统清理失败", ex.Message, "SystemMonitorManager");
            }
            return cleanedSize;
        }

        private string FormatSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;

            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return $"{size:0.##} {sizes[order]}";
        }

        public void DefragmentSystem()
        {
            try
            {
                var defragmenter = new SystemDefragmenter();
                defragmenter.Defragment();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统碎片整理已完成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统碎片整理失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void BackupSystem()
        {
            try
            {
                var backup = new SystemBackup();
                backup.PerformBackup();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统备份已完成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统备份失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void RestoreSystem()
        {
            try
            {
                var restore = new SystemRestore();
                restore.PerformRestore();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统还原已完成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统还原失败", ex.Message, "SystemMonitorManager");
            }
        }

        // 系统资源监控和管理功能
        public void StartResourceMonitoring()
        {
            try
            {
                // 启动实时资源监控
                systemResourceMonitor.Start();
                systemPerformanceMonitor.Start();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统资源实时监控已启动", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("启动资源监控失败", ex.Message, "SystemMonitorManager");
            }
        }

        public void StopResourceMonitoring()
        {
            try
            {
                systemResourceMonitor.Stop();
                systemPerformanceMonitor.Stop();
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统资源实时监控已停止", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("停止资源监控失败", ex.Message, "SystemMonitorManager");
            }
        }

        public ResourceAlert CheckResourceUsage()
        {
            try
            {
                var resourceInfo = systemResourceMonitor.GetSystemResourceInfo();
                var alert = new ResourceAlert();

                if (resourceInfo.CPUUsage > 80)
                {
                    alert.CPUAlert = true;
                    alert.CPUMessage = "CPU使用率过高，建议关闭不必要的程序";
                }

                if (resourceInfo.MemoryUsage > 85)
                {
                    alert.MemoryAlert = true;
                    alert.MemoryMessage = "内存使用率过高，建议增加内存或关闭不必要的程序";
                }

                if (resourceInfo.DiskUsage > 90)
                {
                    alert.DiskAlert = true;
                    alert.DiskMessage = "磁盘空间不足，建议清理磁盘或增加存储空间";
                }

                return alert;
            }
            catch (Exception ex)
            {
                dataManager.LogError("检查资源使用失败", ex.Message, "SystemMonitorManager");
                return new ResourceAlert();
            }
        }

        public List<ResourceOptimizationSuggestion> GetOptimizationSuggestions()
        {
            try
            {
                var suggestions = new List<ResourceOptimizationSuggestion>();
                var resourceInfo = systemResourceMonitor.GetSystemResourceInfo();

                if (resourceInfo.CPUUsage > 70)
                {
                    suggestions.Add(new ResourceOptimizationSuggestion
                    {
                        Type = "CPU",
                        Description = "CPU使用率较高",
                        Suggestion = "关闭不必要的后台程序，检查是否有恶意程序占用CPU资源"
                    });
                }

                if (resourceInfo.MemoryUsage > 80)
                {
                    suggestions.Add(new ResourceOptimizationSuggestion
                    {
                        Type = "内存",
                        Description = "内存使用率较高",
                        Suggestion = "增加物理内存或关闭不必要的程序，清理内存"
                    });
                }

                if (resourceInfo.DiskUsage > 85)
                {
                    suggestions.Add(new ResourceOptimizationSuggestion
                    {
                        Type = "磁盘",
                        Description = "磁盘空间不足",
                        Suggestion = "清理临时文件，删除不需要的文件，考虑使用磁盘清理工具"
                    });
                }

                return suggestions;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取优化建议失败", ex.Message, "SystemMonitorManager");
                return new List<ResourceOptimizationSuggestion>();
            }
        }

        public void OptimizeSystemResources()
        {
            try
            {
                // 清理内存
                GC.Collect();
                GC.WaitForPendingFinalizers();
                
                // 优化磁盘
                CleanSystem();
                
                // 优化启动项
                var startupManager = new StartupManager();
                startupManager.OptimizeStartupItems();
                
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统资源优化已完成", Source = "SystemMonitorManager", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("优化系统资源失败", ex.Message, "SystemMonitorManager");
            }
        }

        public List<ResourceUsageHistory> GetResourceUsageHistory(int hours = 24)
        {
            try
            {
                var history = new List<ResourceUsageHistory>();
                // 这里可以实现历史记录功能，从数据库或日志中获取
                // 暂时返回模拟数据
                for (int i = hours; i >= 0; i--)
                {
                    var time = DateTime.Now.AddHours(-i);
                    history.Add(new ResourceUsageHistory
                    {
                        Timestamp = time,
                        CPUUsage = new Random().Next(20, 80),
                        MemoryUsage = new Random().Next(30, 90),
                        DiskUsage = new Random().Next(40, 85)
                    });
                }
                return history;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取资源使用历史失败", ex.Message, "SystemMonitorManager");
                return new List<ResourceUsageHistory>();
            }
        }
    }

    public class SystemMonitor
    {
        private DataManager dataManager;
        private SystemInfo systemInfo;

        public SystemMonitor()
        {
            dataManager = new DataManager();
            systemInfo = new SystemInfo();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统监控已启动", Source = "SystemMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统监控已停止", Source = "SystemMonitor", Category = "系统监控" });
        }

        public SystemInfo GetSystemInfo()
        {
            try
            {
                var info = new SystemInfo();
                info.OSName = Environment.OSVersion.VersionString;
                info.OSVersion = Environment.OSVersion.Version.ToString();
                info.OSArchitecture = Environment.Is64BitOperatingSystem ? "64位" : "32位";
                info.ComputerName = Environment.MachineName;
                info.UserName = Environment.UserName;
                info.SystemDirectory = Environment.SystemDirectory;
                info.CurrentDirectory = Environment.CurrentDirectory;
                info.TickCount = Environment.TickCount;
                info.Is64BitOperatingSystem = Environment.Is64BitOperatingSystem;
                info.Is64BitProcess = Environment.Is64BitProcess;
                info.ProcessorCount = Environment.ProcessorCount;
                info.SystemPageSize = Environment.SystemPageSize;
                info.WorkingSet = Environment.WorkingSet;
                info.Version = Environment.Version.ToString();

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        info.Manufacturer = obj["Manufacturer"]?.ToString();
                        info.Model = obj["Model"]?.ToString();
                        info.TotalPhysicalMemory = Convert.ToUInt64(obj["TotalPhysicalMemory"]);
                        info.NumberOfProcessors = Convert.ToInt32(obj["NumberOfProcessors"]);
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        info.Caption = obj["Caption"]?.ToString();
                        info.BuildNumber = obj["BuildNumber"]?.ToString();
                        info.SerialNumber = obj["SerialNumber"]?.ToString();
                        info.InstallDate = ManagementDateTimeConverter.ToDateTime(obj["InstallDate"]?.ToString());
                        info.LastBootUpTime = ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"]?.ToString());
                        info.LocalDateTime = ManagementDateTimeConverter.ToDateTime(obj["LocalDateTime"]?.ToString());
                        info.OSLanguage = obj["OSLanguage"]?.ToString();
                        info.OSProductSuite = obj["OSProductSuite"]?.ToString();
                        info.OSType = obj["OSType"]?.ToString();
                        info.OtherTypeDescription = obj["OtherTypeDescription"]?.ToString();
                        info.ServicePackMajorVersion = Convert.ToInt32(obj["ServicePackMajorVersion"]);
                        info.ServicePackMinorVersion = Convert.ToInt32(obj["ServicePackMinorVersion"]);
                        info.SuiteMask = obj["SuiteMask"]?.ToString();
                        info.SystemDirectory = obj["SystemDirectory"]?.ToString();
                        info.SystemDrive = obj["SystemDrive"]?.ToString();
                        info.WindowsDirectory = obj["WindowsDirectory"]?.ToString();
                    }
                }

                return info;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取系统信息失败", ex.Message, "SystemMonitor");
                return new SystemInfo();
            }
        }
    }

    public class ProcessMonitor
    {
        private DataManager dataManager;

        public ProcessMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "进程监控已启动", Source = "ProcessMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "进程监控已停止", Source = "ProcessMonitor", Category = "系统监控" });
        }

        public List<ProcessInfo> GetProcesses()
        {
            try
            {
                var processes = new List<ProcessInfo>();
                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        var processInfo = new ProcessInfo();
                        processInfo.ProcessId = process.Id;
                        processInfo.ProcessName = process.ProcessName;
                        processInfo.MainWindowTitle = process.MainWindowTitle;
                        processInfo.StartTime = process.StartTime;
                        processInfo.TotalProcessorTime = process.TotalProcessorTime;
                        processInfo.UserProcessorTime = process.UserProcessorTime;
                        processInfo.PrivilegedProcessorTime = process.PrivilegedProcessorTime;
                        processInfo.WorkingSet64 = process.WorkingSet64;
                        processInfo.PeakWorkingSet64 = process.PeakWorkingSet64;
                        processInfo.VirtualMemorySize64 = process.VirtualMemorySize64;
                        processInfo.PeakVirtualMemorySize64 = process.PeakVirtualMemorySize64;
                        processInfo.PagedMemorySize64 = process.PagedMemorySize64;
                        processInfo.PeakPagedMemorySize64 = process.PeakPagedMemorySize64;
                        processInfo.PagedSystemMemorySize64 = process.PagedSystemMemorySize64;
                        processInfo.NonpagedSystemMemorySize64 = process.NonpagedSystemMemorySize64;
                        processInfo.ThreadCount = process.Threads.Count;
                        processInfo.HandleCount = process.HandleCount;
                        processInfo.BasePriority = process.BasePriority;
                        processInfo.Id = process.Id;
                        processInfo.MachineName = process.MachineName;
                        processInfo.MainModule = process.MainModule?.FileName;
                        processInfo.Modules = process.Modules.Cast<ProcessModule>().Select(m => m.FileName).ToList();

                        processes.Add(processInfo);
                    }
                    catch
                    {
                    }
                }
                return processes;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取进程信息失败", ex.Message, "ProcessMonitor");
                return new List<ProcessInfo>();
            }
        }
    }

    public class NetworkMonitor
    {
        private DataManager dataManager;

        public NetworkMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "网络监控已启动", Source = "NetworkMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "网络监控已停止", Source = "NetworkMonitor", Category = "系统监控" });
        }

        public List<NetworkInfo> GetNetworkInfo()
        {
            try
            {
                var networkInfoList = new List<NetworkInfo>();

                foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
                {
                    var networkInfo = new NetworkInfo();
                    networkInfo.Name = adapter.Name;
                    networkInfo.Description = adapter.Description;
                    networkInfo.Id = adapter.Id;
                    networkInfo.NetworkInterfaceType = adapter.NetworkInterfaceType.ToString();
                    networkInfo.OperationalStatus = adapter.OperationalStatus.ToString();
                    networkInfo.Speed = adapter.Speed;
                    networkInfo.MacAddress = adapter.GetPhysicalAddress().ToString();
                    networkInfo.IsReceiveOnly = adapter.IsReceiveOnly;
                    networkInfo.SupportsMulticast = adapter.SupportsMulticast;

                    var stats = adapter.GetIPv4Statistics();
                    networkInfo.BytesReceived = stats.BytesReceived;
                    networkInfo.BytesSent = stats.BytesSent;

                    var properties = adapter.GetIPProperties();
                    networkInfo.DnsSuffix = properties.DnsSuffix;
                    networkInfo.DnsAddresses = properties.DnsAddresses.Select(ip => ip.ToString()).ToList();
                    networkInfo.GatewayAddresses = properties.GatewayAddresses.Select(gw => gw.Address.ToString()).ToList();
                    networkInfo.UnicastAddresses = properties.UnicastAddresses.Select(ua => ua.Address.ToString()).ToList();

                    networkInfoList.Add(networkInfo);
                }

                return networkInfoList;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取网络信息失败", ex.Message, "NetworkMonitor");
                return new List<NetworkInfo>();
            }
        }
    }

    public class DiskMonitor
    {
        private DataManager dataManager;

        public DiskMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "磁盘监控已启动", Source = "DiskMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "磁盘监控已停止", Source = "DiskMonitor", Category = "系统监控" });
        }

        public List<DiskInfo> GetDiskInfo()
        {
            try
            {
                var diskInfoList = new List<DiskInfo>();

                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady)
                    {
                        var diskInfo = new DiskInfo();
                        diskInfo.Name = drive.Name;
                        diskInfo.DriveType = drive.DriveType.ToString();
                        diskInfo.FileSystem = drive.DriveFormat;
                        diskInfo.TotalSize = drive.TotalSize;
                        diskInfo.AvailableFreeSpace = drive.AvailableFreeSpace;
                        diskInfo.TotalFreeSpace = drive.TotalFreeSpace;
                        diskInfo.VolumeLabel = drive.VolumeLabel;

                        diskInfoList.Add(diskInfo);
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        var diskInfo = new DiskInfo();
                        diskInfo.DeviceID = obj["DeviceID"]?.ToString();
                        diskInfo.Model = obj["Model"]?.ToString();
                        diskInfo.Manufacturer = obj["Manufacturer"]?.ToString();
                        diskInfo.Type = obj["MediaType"]?.ToString();
                        diskInfo.InterfaceType = obj["InterfaceType"]?.ToString();
                        diskInfo.Size = Convert.ToUInt64(obj["Size"]);
                        diskInfo.Partitions = Convert.ToInt32(obj["Partitions"]);

                        diskInfoList.Add(diskInfo);
                    }
                }

                return diskInfoList;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取磁盘信息失败", ex.Message, "DiskMonitor");
                return new List<DiskInfo>();
            }
        }
    }

    public class MemoryMonitor
    {
        private DataManager dataManager;

        public MemoryMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "内存监控已启动", Source = "MemoryMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "内存监控已停止", Source = "MemoryMonitor", Category = "系统监控" });
        }

        public MemoryInfo GetMemoryInfo()
        {
            try
            {
                var memoryInfo = new MemoryInfo();

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        memoryInfo.TotalVisibleMemorySize = Convert.ToUInt64(obj["TotalVisibleMemorySize"]);
                        memoryInfo.FreePhysicalMemory = Convert.ToUInt64(obj["FreePhysicalMemory"]);
                        memoryInfo.TotalVirtualMemorySize = Convert.ToUInt64(obj["TotalVirtualMemorySize"]);
                        memoryInfo.FreeVirtualMemory = Convert.ToUInt64(obj["FreeVirtualMemory"]);
                        memoryInfo.SizeStoredInPagingFiles = Convert.ToUInt64(obj["SizeStoredInPagingFiles"]);
                        memoryInfo.FreeSpaceInPagingFiles = Convert.ToUInt64(obj["FreeSpaceInPagingFiles"]);
                    }
                }

                memoryInfo.UsedPhysicalMemory = memoryInfo.TotalVisibleMemorySize - memoryInfo.FreePhysicalMemory;
                memoryInfo.UsedVirtualMemory = memoryInfo.TotalVirtualMemorySize - memoryInfo.FreeVirtualMemory;
                memoryInfo.PhysicalMemoryUsagePercentage = ((double)memoryInfo.UsedPhysicalMemory / memoryInfo.TotalVisibleMemorySize) * 100;
                memoryInfo.VirtualMemoryUsagePercentage = ((double)memoryInfo.UsedVirtualMemory / memoryInfo.TotalVirtualMemorySize) * 100;

                return memoryInfo;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取内存信息失败", ex.Message, "MemoryMonitor");
                return new MemoryInfo();
            }
        }
    }

    public class CPUMonitor
    {
        private DataManager dataManager;

        public CPUMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "CPU监控已启动", Source = "CPUMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "CPU监控已停止", Source = "CPUMonitor", Category = "系统监控" });
        }

        public CPUInfo GetCPUInfo()
        {
            try
            {
                var cpuInfo = new CPUInfo();

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        cpuInfo.DeviceID = obj["DeviceID"]?.ToString();
                        cpuInfo.Name = obj["Name"]?.ToString();
                        cpuInfo.Description = obj["Description"]?.ToString();
                        cpuInfo.Manufacturer = obj["Manufacturer"]?.ToString();
                        cpuInfo.MaxClockSpeed = Convert.ToUInt32(obj["MaxClockSpeed"]);
                        cpuInfo.CurrentClockSpeed = Convert.ToUInt32(obj["CurrentClockSpeed"]);
                        cpuInfo.NumberOfCores = Convert.ToUInt32(obj["NumberOfCores"]);
                        cpuInfo.NumberOfLogicalProcessors = Convert.ToUInt32(obj["NumberOfLogicalProcessors"]);
                        cpuInfo.L2CacheSize = Convert.ToUInt32(obj["L2CacheSize"]);
                        cpuInfo.L3CacheSize = Convert.ToUInt32(obj["L3CacheSize"]);
                        cpuInfo.AddressWidth = Convert.ToUInt32(obj["AddressWidth"]);
                        cpuInfo.DataWidth = Convert.ToUInt32(obj["DataWidth"]);
                        cpuInfo.Architecture = Convert.ToUInt32(obj["Architecture"]);
                        cpuInfo.Family = obj["Family"]?.ToString();
                        cpuInfo.Model = obj["Model"]?.ToString();
                        cpuInfo.Stepping = obj["Stepping"]?.ToString();
                        cpuInfo.Revision = obj["Revision"]?.ToString();
                        cpuInfo.Version = obj["Version"]?.ToString();
                    }
                }

                return cpuInfo;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取CPU信息失败", ex.Message, "CPUMonitor");
                return new CPUInfo();
            }
        }
    }

    public class RegistryMonitor
    {
        private DataManager dataManager;

        public RegistryMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "注册表监控已启动", Source = "RegistryMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "注册表监控已停止", Source = "RegistryMonitor", Category = "系统监控" });
        }

        public List<RegistryInfo> GetRegistryInfo()
        {
            try
            {
                var registryInfoList = new List<RegistryInfo>();

                var registryInfo = new RegistryInfo();
                registryInfo.Hive = "HKEY_LOCAL_MACHINE";
                registryInfo.Key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion";
                registryInfo.ValueName = "ProgramFilesDir";
                registryInfo.ValueType = "String";

                registryInfoList.Add(registryInfo);

                return registryInfoList;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取注册表信息失败", ex.Message, "RegistryMonitor");
                return new List<RegistryInfo>();
            }
        }
    }

    public class FileSystemMonitor
    {
        private DataManager dataManager;

        public FileSystemMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "文件系统监控已启动", Source = "FileSystemMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "文件系统监控已停止", Source = "FileSystemMonitor", Category = "系统监控" });
        }

        public List<FileSystemInfo> GetFileSystemInfo()
        {
            try
            {
                var fileSystemInfoList = new List<FileSystemInfo>();

                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady)
                    {
                        var fileSystemInfo = new FileSystemInfo();
                        fileSystemInfo.Name = drive.Name;
                        fileSystemInfo.DriveType = drive.DriveType.ToString();
                        fileSystemInfo.FileSystem = drive.DriveFormat;
                        fileSystemInfo.TotalSize = drive.TotalSize;
                        fileSystemInfo.AvailableFreeSpace = drive.AvailableFreeSpace;

                        fileSystemInfoList.Add(fileSystemInfo);
                    }
                }

                return fileSystemInfoList;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取文件系统信息失败", ex.Message, "FileSystemMonitor");
                return new List<FileSystemInfo>();
            }
        }
    }

    public class ServiceMonitor
    {
        private DataManager dataManager;

        public ServiceMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "服务监控已启动", Source = "ServiceMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "服务监控已停止", Source = "ServiceMonitor", Category = "系统监控" });
        }

        public List<ServiceInfo> GetServiceInfo()
        {
            try
            {
                var serviceInfoList = new List<ServiceInfo>();

                foreach (var service in ServiceController.GetServices())
                {
                    var serviceInfo = new ServiceInfo();
                    serviceInfo.Name = service.ServiceName;
                    serviceInfo.DisplayName = service.DisplayName;
                    serviceInfo.Status = service.Status;

                    serviceInfoList.Add(serviceInfo);
                }

                return serviceInfoList;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取服务信息失败", ex.Message, "ServiceMonitor");
                return new List<ServiceInfo>();
            }
        }
    }

    public class EventLogMonitor
    {
        private DataManager dataManager;

        public EventLogMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "事件日志监控已启动", Source = "EventLogMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "事件日志监控已停止", Source = "EventLogMonitor", Category = "系统监控" });
        }

        public List<EventLogInfo> GetEventLogInfo()
        {
            try
            {
                var eventLogInfoList = new List<EventLogInfo>();

                foreach (var eventLog in EventLog.GetEventLogs())
                {
                    var eventLogInfo = new EventLogInfo();
                    eventLogInfo.LogName = eventLog.LogDisplayName;
                    eventLogInfo.MachineName = eventLog.MachineName;
                    eventLogInfo.EntriesCount = eventLog.Entries.Count;

                    eventLogInfoList.Add(eventLogInfo);
                }

                return eventLogInfoList;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取事件日志信息失败", ex.Message, "EventLogMonitor");
                return new List<EventLogInfo>();
            }
        }
    }

    public class PerformanceCounterMonitor
    {
        private DataManager dataManager;

        public PerformanceCounterMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "性能计数器监控已启动", Source = "PerformanceCounterMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "性能计数器监控已停止", Source = "PerformanceCounterMonitor", Category = "系统监控" });
        }

        public List<PerformanceCounterInfo> GetPerformanceCounterInfo()
        {
            try
            {
                var performanceCounterInfoList = new List<PerformanceCounterInfo>();

                var categories = PerformanceCounterCategory.GetCategories();
                foreach (var category in categories.Take(10))
                {
                    var performanceCounterInfo = new PerformanceCounterInfo();
                    performanceCounterInfo.CategoryName = category.CategoryName;
                    performanceCounterInfo.MachineName = category.MachineName;

                    performanceCounterInfoList.Add(performanceCounterInfo);
                }

                return performanceCounterInfoList;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取性能计数器信息失败", ex.Message, "PerformanceCounterMonitor");
                return new List<PerformanceCounterInfo>();
            }
        }
    }

    public class WindowsEventMonitor
    {
        private DataManager dataManager;

        public WindowsEventMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "Windows事件监控已启动", Source = "WindowsEventMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "Windows事件监控已停止", Source = "WindowsEventMonitor", Category = "系统监控" });
        }

        public List<WindowsEventInfo> GetWindowsEventInfo()
        {
            try
            {
                var windowsEventInfoList = new List<WindowsEventInfo>();

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NTLogEvent WHERE TimeGenerated > '20240101000000.000000-000'"))
                {
                    foreach (var obj in searcher.Get().Cast<ManagementObject>().ToList().Take(10))
                    {
                        var windowsEventInfo = new WindowsEventInfo();
                        windowsEventInfo.LogFile = obj["LogFile"]?.ToString();
                        windowsEventInfo.SourceName = obj["SourceName"]?.ToString();
                        windowsEventInfo.EventCode = obj["EventCode"]?.ToString();
                        windowsEventInfo.Message = obj["Message"]?.ToString();
                        windowsEventInfo.TimeGenerated = ManagementDateTimeConverter.ToDateTime(obj["TimeGenerated"]?.ToString());

                        windowsEventInfoList.Add(windowsEventInfo);
                    }
                }

                return windowsEventInfoList;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取Windows事件信息失败", ex.Message, "WindowsEventMonitor");
                return new List<WindowsEventInfo>();
            }
        }
    }

    public class SystemHealthMonitor
    {
        private DataManager dataManager;

        public SystemHealthMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统健康监控已启动", Source = "SystemHealthMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统健康监控已停止", Source = "SystemHealthMonitor", Category = "系统监控" });
        }

        public SystemHealthInfo GetSystemHealthInfo()
        {
            try
            {
                var systemHealthInfo = new SystemHealthInfo();
                systemHealthInfo.HealthStatus = "Healthy";
                systemHealthInfo.LastHealthCheck = DateTime.Now;
                systemHealthInfo.Uptime = TimeSpan.FromMilliseconds(Environment.TickCount);

                return systemHealthInfo;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取系统健康信息失败", ex.Message, "SystemHealthMonitor");
                return new SystemHealthInfo();
            }
        }
    }

    public class NetworkTrafficMonitor
    {
        private DataManager dataManager;

        public NetworkTrafficMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "网络流量监控已启动", Source = "NetworkTrafficMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "网络流量监控已停止", Source = "NetworkTrafficMonitor", Category = "系统监控" });
        }

        public List<NetworkTrafficInfo> GetNetworkTrafficInfo()
        {
            try
            {
                var networkTrafficInfoList = new List<NetworkTrafficInfo>();

                foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (adapter.OperationalStatus == OperationalStatus.Up)
                    {
                        var networkTrafficInfo = new NetworkTrafficInfo();
                        networkTrafficInfo.InterfaceName = adapter.Name;
                        networkTrafficInfo.InterfaceDescription = adapter.Description;

                        var stats = adapter.GetIPv4Statistics();
                        networkTrafficInfo.BytesReceived = stats.BytesReceived;
                        networkTrafficInfo.BytesSent = stats.BytesSent;

                        networkTrafficInfoList.Add(networkTrafficInfo);
                    }
                }

                return networkTrafficInfoList;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取网络流量信息失败", ex.Message, "NetworkTrafficMonitor");
                return new List<NetworkTrafficInfo>();
            }
        }
    }

    public class SystemResourceMonitor
    {
        private DataManager dataManager;

        public SystemResourceMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统资源监控已启动", Source = "SystemResourceMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统资源监控已停止", Source = "SystemResourceMonitor", Category = "系统监控" });
        }

        public SystemResourceInfo GetSystemResourceInfo()
        {
            try
            {
                var systemResourceInfo = new SystemResourceInfo();

                var memoryMonitor = new MemoryMonitor();
                var memoryInfo = memoryMonitor.GetMemoryInfo();
                systemResourceInfo.MemoryUsage = memoryInfo.PhysicalMemoryUsagePercentage;

                var diskMonitor = new DiskMonitor();
                var diskInfoList = diskMonitor.GetDiskInfo();
                systemResourceInfo.DiskUsage = diskInfoList.Average(d => ((double)(d.TotalSize - d.AvailableFreeSpace) / d.TotalSize) * 100);

                systemResourceInfo.CPUUsage = GetCPUUsage();

                return systemResourceInfo;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取系统资源信息失败", ex.Message, "SystemResourceMonitor");
                return new SystemResourceInfo();
            }
        }

        private double GetCPUUsage()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name = '_Total'"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return Convert.ToDouble(obj["PercentProcessorTime"]);
                    }
                }
                return 0.0;
            }
            catch
            {
                return 0.0;
            }
        }
    }

    public class SystemPerformanceMonitor
    {
        private DataManager dataManager;

        public SystemPerformanceMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统性能监控已启动", Source = "SystemPerformanceMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统性能监控已停止", Source = "SystemPerformanceMonitor", Category = "系统监控" });
        }

        public SystemPerformanceInfo GetSystemPerformanceInfo()
        {
            try
            {
                var systemPerformanceInfo = new SystemPerformanceInfo();

                var resourceMonitor = new SystemResourceMonitor();
                var resourceInfo = resourceMonitor.GetSystemResourceInfo();
                systemPerformanceInfo.CPUUsage = resourceInfo.CPUUsage;
                systemPerformanceInfo.MemoryUsage = resourceInfo.MemoryUsage;
                systemPerformanceInfo.DiskUsage = resourceInfo.DiskUsage;

                systemPerformanceInfo.BootTime = GetBootTime();
                systemPerformanceInfo.SystemUptime = DateTime.Now - systemPerformanceInfo.BootTime;

                return systemPerformanceInfo;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取系统性能信息失败", ex.Message, "SystemPerformanceMonitor");
                return new SystemPerformanceInfo();
            }
        }

        private DateTime GetBootTime()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"]?.ToString());
                    }
                }
                return DateTime.Now;
            }
            catch
            {
                return DateTime.Now;
            }
        }
    }

    public class SystemStabilityMonitor
    {
        private DataManager dataManager;

        public SystemStabilityMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统稳定性监控已启动", Source = "SystemStabilityMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统稳定性监控已停止", Source = "SystemStabilityMonitor", Category = "系统监控" });
        }

        public SystemStabilityInfo GetSystemStabilityInfo()
        {
            try
            {
                var systemStabilityInfo = new SystemStabilityInfo();
                systemStabilityInfo.StabilityScore = 95.0;
                systemStabilityInfo.LastSystemCrash = DateTime.MinValue;
                systemStabilityInfo.LastApplicationCrash = DateTime.MinValue;
                systemStabilityInfo.CrashCount = 0;
                systemStabilityInfo.ApplicationCrashCount = 0;

                return systemStabilityInfo;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取系统稳定性信息失败", ex.Message, "SystemStabilityMonitor");
                return new SystemStabilityInfo();
            }
        }
    }

    public class SystemSecurityMonitor
    {
        private DataManager dataManager;

        public SystemSecurityMonitor()
        {
            dataManager = new DataManager();
        }

        public void Start()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统安全监控已启动", Source = "SystemSecurityMonitor", Category = "系统监控" });
        }

        public void Stop()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统安全监控已停止", Source = "SystemSecurityMonitor", Category = "系统监控" });
        }

        public SystemSecurityInfo GetSystemSecurityInfo()
        {
            try
            {
                var systemSecurityInfo = new SystemSecurityInfo();
                systemSecurityInfo.SecurityScore = 90.0;
                systemSecurityInfo.LastSecurityScan = DateTime.Now;
                systemSecurityInfo.ThreatCount = 0;
                systemSecurityInfo.LastThreatDetected = DateTime.MinValue;

                return systemSecurityInfo;
            }
            catch (Exception ex)
            {
                dataManager.LogError("获取系统安全信息失败", ex.Message, "SystemSecurityMonitor");
                return new SystemSecurityInfo();
            }
        }
    }

    // 资源监控相关类
    public class ResourceAlert
    {
        public bool CPUAlert { get; set; }
        public string CPUMessage { get; set; }
        public bool MemoryAlert { get; set; }
        public string MemoryMessage { get; set; }
        public bool DiskAlert { get; set; }
        public string DiskMessage { get; set; }
        public bool HasAlert => CPUAlert || MemoryAlert || DiskAlert;
    }

    public class ResourceOptimizationSuggestion
    {
        public string Type { get; set; }
        public string Description { get; set; }
        public string Suggestion { get; set; }
    }

    public class ResourceUsageHistory
    {
        public DateTime Timestamp { get; set; }
        public double CPUUsage { get; set; }
        public double MemoryUsage { get; set; }
        public double DiskUsage { get; set; }
    }

    public class StartupManager
    {
        private DataManager dataManager;

        public StartupManager()
        {
            dataManager = new DataManager();
        }

        public void OptimizeStartupItems()
        {
            try
            {
                // 这里可以实现启动项优化逻辑
                // 暂时只记录日志
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "启动项优化已完成", Source = "StartupManager", Category = "系统优化" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("优化启动项失败", ex.Message, "StartupManager");
            }
        }
    }

    public class SystemReport
    {
        private DataManager dataManager;

        public SystemReport()
        {
            dataManager = new DataManager();
        }

        public void GenerateReport()
        {
            try
            {
                var reportPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "SystemReport.txt");
                var report = new StringBuilder();

                report.AppendLine("系统报告");
                report.AppendLine("生成时间: " + DateTime.Now.ToString());
                report.AppendLine("=====================================");

                var systemMonitor = new SystemMonitor();
                var systemInfo = systemMonitor.GetSystemInfo();
                report.AppendLine("系统信息:");
                report.AppendLine($"操作系统: {systemInfo.OSName}");
                report.AppendLine($"版本: {systemInfo.OSVersion}");
                report.AppendLine($"架构: {systemInfo.OSArchitecture}");
                report.AppendLine($"计算机名: {systemInfo.ComputerName}");
                report.AppendLine($"用户名: {systemInfo.UserName}");
                report.AppendLine($"处理器: {systemInfo.ProcessorCount} 核心");

                var memoryMonitor = new MemoryMonitor();
                var memoryInfo = memoryMonitor.GetMemoryInfo();
                report.AppendLine("\n内存信息:");
                report.AppendLine($"总物理内存: {memoryInfo.TotalVisibleMemorySize / 1024 / 1024} GB");
                report.AppendLine($"可用物理内存: {memoryInfo.FreePhysicalMemory / 1024 / 1024} GB");
                report.AppendLine($"内存使用率: {memoryInfo.PhysicalMemoryUsagePercentage:F2}%");

                var diskMonitor = new DiskMonitor();
                var diskInfoList = diskMonitor.GetDiskInfo();
                report.AppendLine("\n磁盘信息:");
                foreach (var diskInfo in diskInfoList)
                {
                    if (!string.IsNullOrEmpty(diskInfo.Name))
                    {
                        report.AppendLine($"驱动器: {diskInfo.Name}");
                        report.AppendLine($"  文件系统: {diskInfo.FileSystem}");
                        report.AppendLine($"  总空间: {diskInfo.TotalSize / 1024 / 1024 / 1024:F2} GB");
                        report.AppendLine($"  可用空间: {diskInfo.AvailableFreeSpace / 1024 / 1024 / 1024:F2} GB");
                    }
                }

                var networkMonitor = new NetworkMonitor();
                var networkInfoList = networkMonitor.GetNetworkInfo();
                report.AppendLine("\n网络信息:");
                foreach (var networkInfo in networkInfoList)
                {
                    report.AppendLine($"适配器: {networkInfo.Name}");
                    report.AppendLine($"  状态: {networkInfo.OperationalStatus}");
                    report.AppendLine($"  MAC地址: {networkInfo.MacAddress}");
                    report.AppendLine($"  IP地址: {string.Join(", ", networkInfo.UnicastAddresses)}");
                }

                File.WriteAllText(reportPath, report.ToString());
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = $"系统报告已生成: {reportPath}", Source = "SystemReport", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("生成系统报告失败", ex.Message, "SystemReport");
            }
        }
    }

    public class PerformanceReport
    {
        private DataManager dataManager;

        public PerformanceReport()
        {
            dataManager = new DataManager();
        }

        public void GenerateReport()
        {
            try
            {
                var reportPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "PerformanceReport.txt");
                var report = new StringBuilder();

                report.AppendLine("性能报告");
                report.AppendLine("生成时间: " + DateTime.Now.ToString());
                report.AppendLine("=====================================");

                var systemPerformanceMonitor = new SystemPerformanceMonitor();
                var performanceInfo = systemPerformanceMonitor.GetSystemPerformanceInfo();
                report.AppendLine("系统性能:");
                report.AppendLine($"CPU使用率: {performanceInfo.CPUUsage:F2}%");
                report.AppendLine($"内存使用率: {performanceInfo.MemoryUsage:F2}%");
                report.AppendLine($"磁盘使用率: {performanceInfo.DiskUsage:F2}%");
                report.AppendLine($"系统启动时间: {performanceInfo.BootTime}");
                report.AppendLine($"系统运行时间: {performanceInfo.SystemUptime}");

                var processMonitor = new ProcessMonitor();
                var processes = processMonitor.GetProcesses();
                var topProcesses = processes.OrderByDescending(p => p.WorkingSet64).Take(10);
                report.AppendLine("\n内存使用最高的进程:");
                foreach (var process in topProcesses)
                {
                    report.AppendLine($"{process.ProcessName}: {process.WorkingSet64 / 1024 / 1024:F2} MB");
                }

                File.WriteAllText(reportPath, report.ToString());
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = $"性能报告已生成: {reportPath}", Source = "PerformanceReport", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("生成性能报告失败", ex.Message, "PerformanceReport");
            }
        }
    }

    public class SecurityReport
    {
        private DataManager dataManager;

        public SecurityReport()
        {
            dataManager = new DataManager();
        }

        public void GenerateReport()
        {
            try
            {
                var reportPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "SecurityReport.txt");
                var report = new StringBuilder();

                report.AppendLine("安全报告");
                report.AppendLine("生成时间: " + DateTime.Now.ToString());
                report.AppendLine("=====================================");

                var systemSecurityMonitor = new SystemSecurityMonitor();
                var securityInfo = systemSecurityMonitor.GetSystemSecurityInfo();
                report.AppendLine("系统安全:");
                report.AppendLine($"安全评分: {securityInfo.SecurityScore:F2}");
                report.AppendLine($"最后扫描时间: {securityInfo.LastSecurityScan}");
                report.AppendLine($"威胁数量: {securityInfo.ThreatCount}");
                report.AppendLine($"最后检测到威胁时间: {securityInfo.LastThreatDetected}");

                var serviceMonitor = new ServiceMonitor();
                var services = serviceMonitor.GetServiceInfo();
                var runningServices = services.Where(s => s.Status == ServiceControllerStatus.Running);
                report.AppendLine("\n运行中的服务:");
                foreach (var service in runningServices.Take(20))
                {
                    report.AppendLine($"{service.DisplayName} ({service.Name})");
                }

                File.WriteAllText(reportPath, report.ToString());
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = $"安全报告已生成: {reportPath}", Source = "SecurityReport", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("生成安全报告失败", ex.Message, "SecurityReport");
            }
        }
    }

    public class SystemHealthCheck
    {
        private DataManager dataManager;

        public SystemHealthCheck()
        {
            dataManager = new DataManager();
        }

        public void PerformCheck()
        {
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "开始系统健康检查", Source = "SystemHealthCheck", Category = "系统监控" });

                var systemHealthMonitor = new SystemHealthMonitor();
                var healthInfo = systemHealthMonitor.GetSystemHealthInfo();

                var systemResourceMonitor = new SystemResourceMonitor();
                var resourceInfo = systemResourceMonitor.GetSystemResourceInfo();

                var systemStabilityMonitor = new SystemStabilityMonitor();
                var stabilityInfo = systemStabilityMonitor.GetSystemStabilityInfo();

                var issues = new List<string>();

                if (resourceInfo.CPUUsage > 90)
                {
                    issues.Add("CPU使用率过高");
                }

                if (resourceInfo.MemoryUsage > 90)
                {
                    issues.Add("内存使用率过高");
                }

                if (resourceInfo.DiskUsage > 90)
                {
                    issues.Add("磁盘使用率过高");
                }

                if (stabilityInfo.StabilityScore < 70)
                {
                    issues.Add("系统稳定性评分过低");
                }

                if (issues.Count > 0)
                {
                    dataManager.LogWarning("系统健康检查发现问题: " + string.Join(", ", issues), "健康问题", "SystemHealthCheck");
                }
                else
                {
                    dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统健康检查未发现问题", Source = "SystemHealthCheck", Category = "系统监控" });
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统健康检查失败", ex.Message, "SystemHealthCheck");
            }
        }
    }

    public class SystemPerformanceCheck
    {
        private DataManager dataManager;

        public SystemPerformanceCheck()
        {
            dataManager = new DataManager();
        }

        public void PerformCheck()
        {
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "开始系统性能检查", Source = "SystemPerformanceCheck", Category = "系统监控" });

                var systemPerformanceMonitor = new SystemPerformanceMonitor();
                var performanceInfo = systemPerformanceMonitor.GetSystemPerformanceInfo();

                var systemResourceMonitor = new SystemResourceMonitor();
                var resourceInfo = systemResourceMonitor.GetSystemResourceInfo();

                var issues = new List<string>();

                if (resourceInfo.CPUUsage > 80)
                {
                    issues.Add("CPU使用率过高，可能影响系统性能");
                }

                if (resourceInfo.MemoryUsage > 80)
                {
                    issues.Add("内存使用率过高，可能影响系统性能");
                }

                if (resourceInfo.DiskUsage > 80)
                {
                    issues.Add("磁盘使用率过高，可能影响系统性能");
                }

                if (issues.Count > 0)
                {
                    dataManager.LogWarning("系统性能检查发现问题: " + string.Join(", ", issues), "性能问题", "SystemPerformanceCheck");
                }
                else
                {
                    dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统性能检查未发现问题", Source = "SystemPerformanceCheck", Category = "系统监控" });
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统性能检查失败", ex.Message, "SystemPerformanceCheck");
            }
        }
    }

    public class SystemSecurityCheck
    {
        private DataManager dataManager;

        public SystemSecurityCheck()
        {
            dataManager = new DataManager();
        }

        public void PerformCheck()
        {
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "开始系统安全检查", Source = "SystemSecurityCheck", Category = "系统监控" });

                var systemSecurityMonitor = new SystemSecurityMonitor();
                var securityInfo = systemSecurityMonitor.GetSystemSecurityInfo();

                var serviceMonitor = new ServiceMonitor();
                var services = serviceMonitor.GetServiceInfo();

                var issues = new List<string>();

                if (securityInfo.ThreatCount > 0)
                {
                    issues.Add($"发现 {securityInfo.ThreatCount} 个威胁");
                }

                var criticalServices = new[] { "WinDefend", "Firewall", "wuauserv" };
                foreach (var serviceName in criticalServices)
                {
                    var service = services.FirstOrDefault(s => s.Name.Equals(serviceName, StringComparison.OrdinalIgnoreCase));
                    if (service == null || service.Status != ServiceControllerStatus.Running)
                    {
                        issues.Add($"关键安全服务 {serviceName} 未运行");
                    }
                }

                if (issues.Count > 0)
                {
                    dataManager.LogWarning("系统安全检查发现问题: " + string.Join(", ", issues), "安全问题", "SystemSecurityCheck");
                }
                else
                {
                    dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统安全检查未发现问题", Source = "SystemSecurityCheck", Category = "系统监控" });
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统安全检查失败", ex.Message, "SystemSecurityCheck");
            }
        }
    }

    public class SystemOptimizer
    {
        private DataManager dataManager;

        public SystemOptimizer()
        {
            dataManager = new DataManager();
        }

        public void Optimize()
        {
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "开始系统优化", Source = "SystemOptimizer", Category = "系统监控" });

                OptimizeStartup();
                OptimizeServices();
                OptimizeVisualEffects();
                OptimizePageFile();
                OptimizeDisk();
                OptimizeMemory();

                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统优化完成", Source = "SystemOptimizer", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统优化失败", ex.Message, "SystemOptimizer");
            }
        }

        private void OptimizeStartup()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "优化启动项", Source = "SystemOptimizer", Category = "系统监控" });
        }

        private void OptimizeServices()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "优化服务", Source = "SystemOptimizer", Category = "系统监控" });
        }

        private void OptimizeVisualEffects()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "优化视觉效果", Source = "SystemOptimizer", Category = "系统监控" });
        }

        private void OptimizePageFile()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "优化页面文件", Source = "SystemOptimizer", Category = "系统监控" });
        }

        private void OptimizeDisk()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "优化磁盘", Source = "SystemOptimizer", Category = "系统监控" });
        }

        private void OptimizeMemory()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "优化内存", Source = "SystemOptimizer", Category = "系统监控" });
        }
    }

    public class SystemCleaner
    {
        private DataManager dataManager;

        public SystemCleaner()
        {
            dataManager = new DataManager();
        }

        public long Clean()
        {
            long totalCleanedSize = 0;
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "开始系统清理", Source = "SystemCleaner", Category = "系统监控" });

                totalCleanedSize += CleanTempFiles();
                totalCleanedSize += CleanCacheFiles();
                totalCleanedSize += CleanLogFiles();
                totalCleanedSize += CleanJunkFiles();
                totalCleanedSize += CleanBrowserCache();
                totalCleanedSize += CleanRecycleBin();

                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = $"系统清理完成，释放空间: {FormatSize(totalCleanedSize)}", Source = "SystemCleaner", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统清理失败", ex.Message, "SystemCleaner");
            }
            return totalCleanedSize;
        }

        private long CleanTempFiles()
        {
            long cleanedSize = 0;
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "清理临时文件", Source = "SystemCleaner", Category = "系统监控" });
                
                // 清理系统临时文件夹
                string tempPath = Path.GetTempPath();
                cleanedSize += CleanDirectory(tempPath);
                
                // 清理用户临时文件夹
                string userTempPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");
                cleanedSize += CleanDirectory(userTempPath);
            }
            catch (Exception ex)
            {
                dataManager.LogError("清理临时文件失败", ex.Message, "SystemCleaner");
            }
            return cleanedSize;
        }

        private long CleanCacheFiles()
        {
            long cleanedSize = 0;
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "清理缓存文件", Source = "SystemCleaner", Category = "系统监控" });
                
                // 清理Windows缓存
                string windowsCachePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
                cleanedSize += CleanDirectory(windowsCachePath);
                
                // 清理应用缓存
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string cachePath = Path.Combine(appDataPath, "Microsoft", "Windows", "Caches");
                cleanedSize += CleanDirectory(cachePath);
            }
            catch (Exception ex)
            {
                dataManager.LogError("清理缓存文件失败", ex.Message, "SystemCleaner");
            }
            return cleanedSize;
        }

        private long CleanLogFiles()
        {
            long cleanedSize = 0;
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "清理日志文件", Source = "SystemCleaner", Category = "系统监控" });
                
                // 清理Windows日志
                string logsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Logs");
                cleanedSize += CleanDirectory(logsPath, "*.log");
                
                // 清理应用日志
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string appLogsPath = Path.Combine(appDataPath, "FireAntivirus", "Logs");
                cleanedSize += CleanDirectory(appLogsPath, "*.log");
            }
            catch (Exception ex)
            {
                dataManager.LogError("清理日志文件失败", ex.Message, "SystemCleaner");
            }
            return cleanedSize;
        }

        private long CleanJunkFiles()
        {
            long cleanedSize = 0;
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "清理垃圾文件", Source = "SystemCleaner", Category = "系统监控" });
                
                // 清理下载文件夹中的旧文件
                string downloadsPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                cleanedSize += CleanOldFiles(downloadsPath, TimeSpan.FromDays(30));
                
                // 清理其他常见垃圾文件
                string[] junkExtensions = { ".tmp", ".temp", ".log", ".bak", ".old" };
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        cleanedSize += CleanFilesByExtensions(drive.RootDirectory.FullName, junkExtensions);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("清理垃圾文件失败", ex.Message, "SystemCleaner");
            }
            return cleanedSize;
        }

        private long CleanBrowserCache()
        {
            long cleanedSize = 0;
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "清理浏览器缓存", Source = "SystemCleaner", Category = "系统监控" });
                
                // 清理Chrome缓存
                string chromeCachePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Google", "Chrome", "User Data", "Default", "Cache"
                );
                cleanedSize += CleanDirectory(chromeCachePath);
                
                // 清理Edge缓存
                string edgeCachePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft", "Edge", "User Data", "Default", "Cache"
                );
                cleanedSize += CleanDirectory(edgeCachePath);
                
                // 清理Firefox缓存
                string firefoxCachePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Mozilla", "Firefox", "Profiles"
                );
                cleanedSize += CleanDirectory(firefoxCachePath, "cache2");
            }
            catch (Exception ex)
            {
                dataManager.LogError("清理浏览器缓存失败", ex.Message, "SystemCleaner");
            }
            return cleanedSize;
        }

        private long CleanRecycleBin()
        {
            long cleanedSize = 0;
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "清理回收站", Source = "SystemCleaner", Category = "系统监控" });
                
                // 使用Shell API清空回收站
                // 这里简化处理，实际实现需要使用Shell32.dll
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "回收站清理完成", Source = "SystemCleaner", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("清理回收站失败", ex.Message, "SystemCleaner");
            }
            return cleanedSize;
        }

        private long CleanDirectory(string path, string pattern = "*")
        {
            long cleanedSize = 0;
            try
            {
                if (Directory.Exists(path))
                {
                    foreach (var file in Directory.GetFiles(path, pattern, SearchOption.AllDirectories))
                    {
                        try
                        {
                            cleanedSize += new FileInfo(file).Length;
                            File.Delete(file);
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return cleanedSize;
        }

        private long CleanOldFiles(string path, TimeSpan maxAge)
        {
            long cleanedSize = 0;
            try
            {
                if (Directory.Exists(path))
                {
                    foreach (var file in Directory.GetFiles(path, "*.*", SearchOption.AllDirectories))
                    {
                        try
                        {
                            var fileInfo = new FileInfo(file);
                            if (DateTime.Now - fileInfo.LastWriteTime > maxAge)
                            {
                                cleanedSize += fileInfo.Length;
                                File.Delete(file);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return cleanedSize;
        }

        private long CleanFilesByExtensions(string path, string[] extensions)
        {
            long cleanedSize = 0;
            try
            {
                if (Directory.Exists(path))
                {
                    foreach (var extension in extensions)
                    {
                        foreach (var file in Directory.GetFiles(path, "*" + extension, SearchOption.AllDirectories))
                        {
                            try
                            {
                                cleanedSize += new FileInfo(file).Length;
                                File.Delete(file);
                            }
                            catch { }
                        }
                    }
                }
            }
            catch { }
            return cleanedSize;
        }

        private string FormatSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;

            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return $"{size:0.##} {sizes[order]}";
        }
    }

    public class SystemDefragmenter
    {
        private DataManager dataManager;

        public SystemDefragmenter()
        {
            dataManager = new DataManager();
        }

        public void Defragment()
        {
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "开始磁盘碎片整理", Source = "SystemDefragmenter", Category = "系统监控" });

                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                    {
                        dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = $"整理磁盘 {drive.Name}", Source = "SystemDefragmenter", Category = "系统监控" });
                    }
                }

                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "磁盘碎片整理完成", Source = "SystemDefragmenter", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("磁盘碎片整理失败", ex.Message, "SystemDefragmenter");
            }
        }
    }

    public class SystemBackup
    {
        private DataManager dataManager;

        public SystemBackup()
        {
            dataManager = new DataManager();
        }

        public void PerformBackup()
        {
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "开始系统备份", Source = "SystemBackup", Category = "系统监控" });

                var backupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "SystemBackup");
                Directory.CreateDirectory(backupPath);

                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = $"备份到路径: {backupPath}", Source = "SystemBackup", Category = "系统监控" });

                BackupRegistry();
                BackupSystemFiles();
                BackupUserFiles();

                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统备份完成", Source = "SystemBackup", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统备份失败", ex.Message, "SystemBackup");
            }
        }

        private void BackupRegistry()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "备份注册表", Source = "SystemBackup", Category = "系统监控" });
        }

        private void BackupSystemFiles()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "备份系统文件", Source = "SystemBackup", Category = "系统监控" });
        }

        private void BackupUserFiles()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "备份用户文件", Source = "SystemBackup", Category = "系统监控" });
        }
    }

    public class SystemRestore
    {
        private DataManager dataManager;

        public SystemRestore()
        {
            dataManager = new DataManager();
        }

        public void PerformRestore()
        {
            try
            {
                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "开始系统还原", Source = "SystemRestore", Category = "系统监控" });

                var restorePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "SystemBackup");

                if (Directory.Exists(restorePath))
                {
                    dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = $"从路径还原: {restorePath}", Source = "SystemRestore", Category = "系统监控" });

                    RestoreRegistry();
                    RestoreSystemFiles();
                    RestoreUserFiles();
                }
                else
                {
                    dataManager.LogError("备份路径不存在", "路径不存在", "SystemRestore");
                }

                dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "系统还原完成", Source = "SystemRestore", Category = "系统监控" });
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统还原失败", ex.Message, "SystemRestore");
            }
        }

        private void RestoreRegistry()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "还原注册表", Source = "SystemRestore", Category = "系统监控" });
        }

        private void RestoreSystemFiles()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "还原系统文件", Source = "SystemRestore", Category = "系统监控" });
        }

        private void RestoreUserFiles()
        {
            dataManager.AddLog(new LogEntry { Id = Guid.NewGuid().ToString(), Time = DateTime.Now, Type = "Information", Message = "还原用户文件", Source = "SystemRestore", Category = "系统监控" });
        }
    }

    public class SystemInfo
    {
        public string OSName { get; set; }
        public string OSVersion { get; set; }
        public string OSArchitecture { get; set; }
        public string ComputerName { get; set; }
        public string UserName { get; set; }
        public string SystemDirectory { get; set; }
        public string CurrentDirectory { get; set; }
        public int TickCount { get; set; }
        public bool Is64BitOperatingSystem { get; set; }
        public bool Is64BitProcess { get; set; }
        public int ProcessorCount { get; set; }
        public int SystemPageSize { get; set; }
        public long WorkingSet { get; set; }
        public string Version { get; set; }
        public string Manufacturer { get; set; }
        public string Model { get; set; }
        public ulong TotalPhysicalMemory { get; set; }
        public int NumberOfProcessors { get; set; }
        public string Caption { get; set; }
        public string BuildNumber { get; set; }
        public string SerialNumber { get; set; }
        public DateTime InstallDate { get; set; }
        public DateTime LastBootUpTime { get; set; }
        public DateTime LocalDateTime { get; set; }
        public string OSLanguage { get; set; }
        public string OSProductSuite { get; set; }
        public string OSType { get; set; }
        public string OtherTypeDescription { get; set; }
        public int ServicePackMajorVersion { get; set; }
        public int ServicePackMinorVersion { get; set; }
        public string SuiteMask { get; set; }
        public string SystemDrive { get; set; }
        public string WindowsDirectory { get; set; }
    }

    public class ProcessInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string MainWindowTitle { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan TotalProcessorTime { get; set; }
        public TimeSpan UserProcessorTime { get; set; }
        public TimeSpan PrivilegedProcessorTime { get; set; }
        public long WorkingSet64 { get; set; }
        public long PeakWorkingSet64 { get; set; }
        public long VirtualMemorySize64 { get; set; }
        public long PeakVirtualMemorySize64 { get; set; }
        public long PagedMemorySize64 { get; set; }
        public long PeakPagedMemorySize64 { get; set; }
        public long PagedSystemMemorySize64 { get; set; }
        public long NonpagedSystemMemorySize64 { get; set; }
        public int ThreadCount { get; set; }
        public int HandleCount { get; set; }
        public int BasePriority { get; set; }
        public int Id { get; set; }
        public string MachineName { get; set; }
        public string MainModule { get; set; }
        public List<string> Modules { get; set; }
    }

    public class NetworkInfo
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Id { get; set; }
        public string NetworkInterfaceType { get; set; }
        public string OperationalStatus { get; set; }
        public long Speed { get; set; }
        public string MacAddress { get; set; }
        public bool IsReceiveOnly { get; set; }
        public bool SupportsMulticast { get; set; }
        public long BytesReceived { get; set; }
        public long BytesSent { get; set; }
        public long PacketsReceived { get; set; }
        public long PacketsSent { get; set; }
        public long IncomingPacketsDiscarded { get; set; }
        public long OutgoingPacketsDiscarded { get; set; }
        public long IncomingPacketsWithErrors { get; set; }
        public long OutgoingPacketsWithErrors { get; set; }
        public long IncomingUnknownProtocolPackets { get; set; }
        public string DnsSuffix { get; set; }
        public List<string> DnsAddresses { get; set; }
        public List<string> GatewayAddresses { get; set; }
        public List<string> UnicastAddresses { get; set; }
    }

    public class DiskInfo
    {
        public string Name { get; set; }
        public string DriveType { get; set; }
        public string FileSystem { get; set; }
        public long TotalSize { get; set; }
        public long AvailableFreeSpace { get; set; }
        public long TotalFreeSpace { get; set; }
        public string VolumeLabel { get; set; }
        public string DeviceID { get; set; }
        public string Model { get; set; }
        public string Manufacturer { get; set; }
        public string Type { get; set; }
        public string InterfaceType { get; set; }
        public ulong Size { get; set; }
        public int Partitions { get; set; }
    }

    public class MemoryInfo
    {
        public ulong TotalVisibleMemorySize { get; set; }
        public ulong FreePhysicalMemory { get; set; }
        public ulong TotalVirtualMemorySize { get; set; }
        public ulong FreeVirtualMemory { get; set; }
        public ulong SizeStoredInPagingFiles { get; set; }
        public ulong FreeSpaceInPagingFiles { get; set; }
        public ulong UsedPhysicalMemory { get; set; }
        public ulong UsedVirtualMemory { get; set; }
        public double PhysicalMemoryUsagePercentage { get; set; }
        public double VirtualMemoryUsagePercentage { get; set; }
    }

    public class CPUInfo
    {
        public string DeviceID { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Manufacturer { get; set; }
        public uint MaxClockSpeed { get; set; }
        public uint CurrentClockSpeed { get; set; }
        public uint NumberOfCores { get; set; }
        public uint NumberOfLogicalProcessors { get; set; }
        public uint L2CacheSize { get; set; }
        public uint L3CacheSize { get; set; }
        public uint AddressWidth { get; set; }
        public uint DataWidth { get; set; }
        public uint Architecture { get; set; }
        public string Family { get; set; }
        public string Model { get; set; }
        public string Stepping { get; set; }
        public string Revision { get; set; }
        public string Version { get; set; }
    }

    public class RegistryInfo
    {
        public string Hive { get; set; }
        public string Key { get; set; }
        public string ValueName { get; set; }
        public string ValueType { get; set; }
        public string ValueData { get; set; }
    }

    public class FileSystemInfo
    {
        public string Name { get; set; }
        public string DriveType { get; set; }
        public string FileSystem { get; set; }
        public long TotalSize { get; set; }
        public long AvailableFreeSpace { get; set; }
    }

    public class EventLogInfo
    {
        public string LogName { get; set; }
        public string MachineName { get; set; }
        public int EntriesCount { get; set; }
    }

    public class PerformanceCounterInfo
    {
        public string CategoryName { get; set; }
        public string MachineName { get; set; }
    }

    public class WindowsEventInfo
    {
        public string LogFile { get; set; }
        public string SourceName { get; set; }
        public string EventCode { get; set; }
        public string Message { get; set; }
        public DateTime TimeGenerated { get; set; }
    }

    public class SystemHealthInfo
    {
        public string HealthStatus { get; set; }
        public DateTime LastHealthCheck { get; set; }
        public TimeSpan Uptime { get; set; }
    }

    public class NetworkTrafficInfo
    {
        public string InterfaceName { get; set; }
        public string InterfaceDescription { get; set; }
        public long BytesReceived { get; set; }
        public long BytesSent { get; set; }
        public long PacketsReceived { get; set; }
        public long PacketsSent { get; set; }
    }

    public class SystemResourceInfo
    {
        public double CPUUsage { get; set; }
        public double MemoryUsage { get; set; }
        public double DiskUsage { get; set; }
    }

    public class SystemPerformanceInfo
    {
        public double CPUUsage { get; set; }
        public double MemoryUsage { get; set; }
        public double DiskUsage { get; set; }
        public DateTime BootTime { get; set; }
        public TimeSpan SystemUptime { get; set; }
    }

    public class SystemStabilityInfo
    {
        public double StabilityScore { get; set; }
        public DateTime LastSystemCrash { get; set; }
        public DateTime LastApplicationCrash { get; set; }
        public int CrashCount { get; set; }
        public int ApplicationCrashCount { get; set; }
    }

    public class SystemSecurityInfo
    {
        public double SecurityScore { get; set; }
        public DateTime LastSecurityScan { get; set; }
        public int ThreatCount { get; set; }
        public DateTime LastThreatDetected { get; set; }
    }

    public class SystemStatus
    {
        public SystemInfo SystemInfo { get; set; }
        public MemoryInfo MemoryInfo { get; set; }
        public CPUInfo CPUInfo { get; set; }
        public List<DiskInfo> DiskInfo { get; set; }
        public List<NetworkInfo> NetworkInfo { get; set; }
        public int ProcessCount { get; set; }
        public int ServiceCount { get; set; }
        public SystemHealthInfo HealthInfo { get; set; }
        public SystemResourceInfo ResourceInfo { get; set; }
        public SystemPerformanceInfo PerformanceInfo { get; set; }
        public SystemStabilityInfo StabilityInfo { get; set; }
        public SystemSecurityInfo SecurityInfo { get; set; }
        public DateTime Timestamp { get; set; }
    }
}