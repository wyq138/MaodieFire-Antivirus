// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;

namespace FireAntivirus.Engine.Analyzers.Performance
{
    /// <summary>
    /// 性能分析器 - 分析系统性能和资源使用
    /// </summary>
    public class PerformanceAnalyzer
    {
        private readonly Dictionary<string, List<float>> _cpuHistory;
        private readonly Dictionary<string, List<long>> _memoryHistory;
        private readonly int _historySize = 60;

        public PerformanceAnalyzer()
        {
            _cpuHistory = new Dictionary<string, List<float>>();
            _memoryHistory = new Dictionary<string, List<long>>();
        }

        public PerformanceResult Analyze()
        {
            var result = new PerformanceResult
            {
                CpuUsage = GetCpuUsage(),
                MemoryUsage = GetMemoryUsage(),
                DiskUsage = GetDiskUsage(),
                ProcessCount = Process.GetProcesses().Length,
                Warnings = new List<string>()
            };

            // 分析高CPU占用进程
            result.HighCpuProcesses = GetHighCpuProcesses();
            if (result.HighCpuProcesses.Count > 0)
            {
                result.Warnings.Add($"发现 {result.HighCpuProcesses.Count} 个高CPU占用进程");
            }

            // 分析高内存占用进程
            result.HighMemoryProcesses = GetHighMemoryProcesses();
            if (result.HighMemoryProcesses.Count > 0)
            {
                result.Warnings.Add($"发现 {result.HighMemoryProcesses.Count} 个高内存占用进程");
            }

            // 检测可疑进程行为
            result.SuspiciousProcesses = DetectSuspiciousProcesses();
            if (result.SuspiciousProcesses.Count > 0)
            {
                result.Warnings.Add($"发现 {result.SuspiciousProcesses.Count} 个可疑进程行为");
            }

            return result;
        }

        private float GetCpuUsage()
        {
            try
            {
                var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue();
                System.Threading.Thread.Sleep(100);
                return cpuCounter.NextValue();
            }
            catch
            {
                return 0;
            }
        }

        private MemoryInfo GetMemoryUsage()
        {
            var info = new MemoryInfo();
            
            try
            {
                var memCounter = new PerformanceCounter("Memory", "Available MBytes");
                info.AvailableMB = (long)memCounter.NextValue();
                
                var totalMem = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024);
                info.TotalMB = (long)totalMem;
                info.UsedMB = (long)(totalMem - info.AvailableMB);
                info.UsagePercent = info.TotalMB > 0 ? (float)info.UsedMB / info.TotalMB * 100 : 0;
            }
            catch { }

            return info;
        }

        private List<DiskInfo> GetDiskUsage()
        {
            var disks = new List<DiskInfo>();
            
            try
            {
                foreach (var drive in System.IO.DriveInfo.GetDrives())
                {
                    if (drive.IsReady)
                    {
                        disks.Add(new DiskInfo
                        {
                            Name = drive.Name,
                            TotalGB = drive.TotalSize / (1024 * 1024 * 1024),
                            FreeGB = drive.AvailableFreeSpace / (1024 * 1024 * 1024),
                            UsedGB = (drive.TotalSize - drive.AvailableFreeSpace) / (1024 * 1024 * 1024),
                            UsagePercent = (float)(drive.TotalSize - drive.AvailableFreeSpace) / drive.TotalSize * 100
                        });
                    }
                }
            }
            catch { }

            return disks;
        }

        private List<ProcessInfo> GetHighCpuProcesses()
        {
            var processes = new List<ProcessInfo>();
            
            try
            {
                var allProcesses = Process.GetProcesses();
                foreach (var proc in allProcesses)
                {
                    try
                    {
                        var cpuTime = proc.TotalProcessorTime.TotalMilliseconds;
                        if (!_cpuHistory.ContainsKey(proc.ProcessName))
                        {
                            _cpuHistory[proc.ProcessName] = new List<float>();
                        }
                        
                        _cpuHistory[proc.ProcessName].Add((float)cpuTime);
                        if (_cpuHistory[proc.ProcessName].Count > _historySize)
                        {
                            _cpuHistory[proc.ProcessName].RemoveAt(0);
                        }

                        var avgCpu = _cpuHistory[proc.ProcessName].Average();
                        
                        if (avgCpu > 500) // 高CPU阈值
                        {
                            processes.Add(new ProcessInfo
                            {
                                Id = proc.Id,
                                Name = proc.ProcessName,
                                CpuUsage = avgCpu,
                                MemoryMB = proc.WorkingSet64 / (1024 * 1024)
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return processes.OrderByDescending(p => p.CpuUsage).Take(10).ToList();
        }

        private List<ProcessInfo> GetHighMemoryProcesses()
        {
            var processes = new List<ProcessInfo>();
            
            try
            {
                var allProcesses = Process.GetProcesses();
                foreach (var proc in allProcesses)
                {
                    try
                    {
                        var memMB = proc.WorkingSet64 / (1024 * 1024);
                        if (memMB > 500) // 高内存阈值 500MB
                        {
                            processes.Add(new ProcessInfo
                            {
                                Id = proc.Id,
                                Name = proc.ProcessName,
                                MemoryMB = memMB
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return processes.OrderByDescending(p => p.MemoryMB).Take(10).ToList();
        }

        private List<SuspiciousProcessInfo> DetectSuspiciousProcesses()
        {
            var suspicious = new List<SuspiciousProcessInfo>();
            
            try
            {
                var suspiciousNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    { "mimikatz", "凭证窃取工具" },
                    { "procdump", "进程转储工具" },
                    { "lazagne", "密码提取工具" },
                    { "pwdump", "密码转储工具" },
                    { "nc", "NetCat后门" },
                    { "ncat", "NetCat后门" },
                    { "meterpreter", "Metasploit载荷" },
                    { "cobaltstrike", "渗透测试框架" },
                    { "msfvenom", "Metasploit生成器" },
                };

                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (suspiciousNames.TryGetValue(proc.ProcessName, out var threat))
                        {
                            suspicious.Add(new SuspiciousProcessInfo
                            {
                                Id = proc.Id,
                                Name = proc.ProcessName,
                                Threat = threat
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return suspicious;
        }

        public void RecordHistory(string processName, float cpu, long memory)
        {
            if (!_cpuHistory.ContainsKey(processName))
            {
                _cpuHistory[processName] = new List<float>();
                _memoryHistory[processName] = new List<long>();
            }

            _cpuHistory[processName].Add(cpu);
            _memoryHistory[processName].Add(memory);

            if (_cpuHistory[processName].Count > _historySize)
            {
                _cpuHistory[processName].RemoveAt(0);
                _memoryHistory[processName].RemoveAt(0);
            }
        }
    }

    public class PerformanceResult
    {
        public float CpuUsage { get; set; }
        public MemoryInfo MemoryUsage { get; set; }
        public List<DiskInfo> DiskUsage { get; set; }
        public int ProcessCount { get; set; }
        public List<ProcessInfo> HighCpuProcesses { get; set; }
        public List<ProcessInfo> HighMemoryProcesses { get; set; }
        public List<SuspiciousProcessInfo> SuspiciousProcesses { get; set; }
        public List<string> Warnings { get; set; }
    }

    public class MemoryInfo
    {
        public long TotalMB { get; set; }
        public long UsedMB { get; set; }
        public long AvailableMB { get; set; }
        public float UsagePercent { get; set; }
    }

    public class DiskInfo
    {
        public string Name { get; set; }
        public long TotalGB { get; set; }
        public long UsedGB { get; set; }
        public long FreeGB { get; set; }
        public float UsagePercent { get; set; }
    }

    public class ProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public float CpuUsage { get; set; }
        public long MemoryMB { get; set; }
    }

    public class SuspiciousProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Threat { get; set; }
    }
}
