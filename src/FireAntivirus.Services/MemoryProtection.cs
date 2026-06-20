using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    public class MemoryProtection : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private Dictionary<int, ProcessMemoryInfo> _processMemoryCache;
        private List<string> _suspiciousPatterns;
        private Dictionary<string, byte[]> _signatureCache;
        private DateTime _lastMemoryScan;
        
        public MemoryProtection(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _processMemoryCache = new Dictionary<int, ProcessMemoryInfo>();
            _suspiciousPatterns = new List<string>
            {
                // Shellcode和恶意软件常见特征
                "\xCC\xCC\xCC\xCC", // INT3指令
                "\x90\x90\x90\x90", // NOP指令
                "\xE8\x00\x00\x00\x00", // CALL指令
                "\xFF\xD0", // CALL EAX/RAX
                "\xFF\xD3", // CALL EBX/RBX
                "\xFF\xD1", // CALL ECX/RCX
                "\xFF\xD2", // CALL EDX/RDX
                "MZ", // PE文件头
                "This program cannot be run", // PE文件错误信息
                "kernel32.dll", "ntdll.dll", "user32.dll"
            };
            _signatureCache = new Dictionary<string, byte[]>();
            _lastMemoryScan = DateTime.MinValue;
        }
        
        public void Start()
        {
            _isRunning = true;
            _monitorThread = new Thread(MonitorMemory);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "MemoryProtectionStart",
                Message = "内存保护已启动",
                Details = "开始监控进程内存中恶意代码注入"
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
                Type = "MemoryProtectionStop",
                Message = "内存保护已停止",
                Details = string.Empty
            });
        }

        public InjectionDetectionResult DetectInjection(InjectionAttempt attempt)
        {
            return new InjectionDetectionResult { Detected = false, ThreatLevel = SecurityThreatLevel.Low };
        }
        
        private void MonitorMemory()
        {
            while (_isRunning)
            {
                try
                {
                    ScanProcessMemory();
                    DetectCodeInjections();
                    CheckHeapSpraying();
                    DetectROPChains();
                    
                    Thread.Sleep(30000); // 每30秒扫描一次
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "MemoryMonitorError",
                        Message = "内存监控错误",
                        Details = ex.Message
                    });
                    Thread.Sleep(5000);
                }
            }
        }
        
        private void ScanProcessMemory()
        {
            try
            {
                var processes = Process.GetProcesses();
                var suspiciousCount = 0;
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                            
                        if (process.HasExited)
                            continue;
                            
                        var memoryInfo = GetProcessMemoryInfo(process);
                        
                        // 检查内存中是否有可疑模式
                        var suspiciousRegions = ScanMemoryRegions(process, memoryInfo);
                        if (suspiciousRegions.Count > 0)
                        {
                            HandleSuspiciousMemory(process, suspiciousRegions);
                            suspiciousCount++;
                        }
                    }
                    catch
                    {
                        // 忽略权限不足的进程
                        continue;
                    }
                }
                
                if (suspiciousCount > 0)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "MemoryScanResult",
                        Message = "内存扫描完成",
                        Details = $"发现{suspiciousCount}个进程存在可疑内存区域"
                    });
                }
                
                _lastMemoryScan = DateTime.Now;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "MemoryScanError",
                    Message = "内存扫描错误",
                    Details = ex.Message
                });
            }
        }
        
        private ProcessMemoryInfo GetProcessMemoryInfo(Process process)
        {
            var info = new ProcessMemoryInfo
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                WorkingSet = process.WorkingSet64,
                PrivateMemory = process.PrivateMemorySize64,
                VirtualMemory = process.VirtualMemorySize64,
                ScanTime = DateTime.Now
            };
            
            try
            {
                // 获取内存区域信息
                info.MemoryRegions = GetMemoryRegions(process);
            }
            catch
            {
                // 未能获取内存区域信息
            }
            
            return info;
        }
        
        private List<MemoryRegion> GetMemoryRegions(Process process)
        {
            var regions = new List<MemoryRegion>();
            
            try
            {
                // 使用WMI或其他方法获取内存区域信息
                // 这里简化实现，实际部署时需要考虑跨平台兼容性
                var modules = process.Modules;
                foreach (ProcessModule module in modules)
                {
                    regions.Add(new MemoryRegion
                    {
                        BaseAddress = module.BaseAddress.ToInt64(),
                        Size = (ulong)module.ModuleMemorySize,
                        Name = module.ModuleName,
                        IsExecutable = true
                    });
                }
            }
            catch
            {
                // 权限不足，无法获取模块信息
            }
            
            return regions;
        }
        
        private List<MemoryRegion> ScanMemoryRegions(Process process, ProcessMemoryInfo memoryInfo)
        {
            var suspiciousRegions = new List<MemoryRegion>();
            
            try
            {
                // 简化的内存扫描实现
                // 实际部署需要更复杂的内存访问和模式匹配
                
                // 检查工作集大小的异常增长
                if (_processMemoryCache.ContainsKey(process.Id))
                {
                    var previous = _processMemoryCache[process.Id];
                    if (memoryInfo.WorkingSet > previous.WorkingSet * 2)
                    {
                        var region = new MemoryRegion
                        {
                            BaseAddress = 0,
                            Size = (ulong)(memoryInfo.WorkingSet - previous.WorkingSet),
                            Name = $"工作集异常增长: {previous.WorkingSet / 1024 / 1024}MB -> {memoryInfo.WorkingSet / 1024 / 1024}MB",
                            SuspiciousLevel = SuspiciousLevel.High
                        };
                        suspiciousRegions.Add(region);
                    }
                }
                
                _processMemoryCache[process.Id] = memoryInfo;
                
                // 检查进程模块的异常
                foreach (var region in memoryInfo.MemoryRegions)
                {
                    if (region.Name != null && IsSuspiciousModule(region.Name))
                    {
                        region.SuspiciousLevel = SuspiciousLevel.Medium;
                        suspiciousRegions.Add(region);
                    }
                }
                
            }
            catch
            {
                // 内存访问失败
            }
            
            return suspiciousRegions;
        }
        
        private bool IsSuspiciousModule(string moduleName)
        {
            var suspiciousModules = new[]
            {
                "powershell", "cmd", "wscript", "cscript", "mshta",
                "certutil", "bitsadmin", "regsvr32", "rundll32"
            };
            
            return suspiciousModules.Any(m => moduleName.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0);
        }
        
        private void DetectCodeInjections()
        {
            try
            {
                // 检测代码注入攻击
                // 这里可以集成更复杂的内存分析算法
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                            
                        if (process.HasExited)
                            continue;
                            
                        // 检查远程线程注入
                        CheckRemoteThreadInjection(process);
                        
                        // 检查反射式DLL注入
                        CheckReflectiveDLLInjection(process);
                    }
                    catch
                    {
                        // 忽略权限不足的进程
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "InjectionDetectError",
                    Message = "代码注入检测错误",
                    Details = ex.Message
                });
            }
        }
        
        private void CheckRemoteThreadInjection(Process process)
        {
            try
            {
                // 检测远程线程注入的简化实现
                // 实际实现需要更深入的进程分析
                var threads = process.Threads;
                
                foreach (ProcessThread thread in threads)
                {
                    if (thread.StartAddress.ToInt64() > 0x7FFFFFFF) // 检查是否在高位地址运行
                    {
                        HandleRemoteThreadInjection(process, thread);
                    }
                }
            }
            catch
            {
                // 权限不足或进程已退出
            }
        }
        
        private void CheckReflectiveDLLInjection(Process process)
        {
            try
            {
                // 检测反射式DLL注入的简化实现
                // 实际实现需要检查PE头部和内存映射
                var modules = process.Modules;
                
                foreach (ProcessModule module in modules)
                {
                    if (module.FileName == null || !System.IO.File.Exists(module.FileName))
                    {
                        HandleReflectiveDLLInjection(process, module);
                    }
                }
            }
            catch
            {
                // 权限不足或进程已退出
            }
        }
        
        private void CheckHeapSpraying()
        {
            try
            {
                // 检测堆喷射攻击
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                            
                        var heapSpraying = DetectHeapSprayingPatterns(process);
                        if (heapSpraying.Count > 0)
                        {
                            HandleHeapSpraying(process, heapSpraying);
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                LogHeapSprayingError(ex);
            }
        }
        
        private void DetectROPChains()
        {
            try
            {
                // ROP链检测的简化实现
                // 实际实现需要更复杂的栈分析和指令跟踪
                var criticalProcesses = Process.GetProcessesByName("explorer")
                    .Concat(Process.GetProcessesByName("lsass"))
                    .Concat(Process.GetProcessesByName("svchost"));
                    
                foreach (var process in criticalProcesses)
                {
                    try
                    {
                        CheckROPPatterns(process);
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                LogROPDetectionError(ex);
            }
        }
        
        private void HandleSuspiciousMemory(Process process, List<MemoryRegion> regions)
        {
            var message = $"进程 {process.ProcessName} (PID: {process.Id}) 发现可疑内存区域\n";
            
            foreach (var region in regions)
            {
                message += $"- {region.Name} (可疑级别: {region.SuspiciousLevel})\n";
            }
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SuspiciousMemory",
                Message = $"发现可疑内存区域",
                Details = message
            });
            
            // 高可疑级别时发出警告
            if (regions.Any(r => r.SuspiciousLevel >= SuspiciousLevel.High))
            {
                NotificationService.Instance.ShowNotification(
                    "内存威胁检测",
                    $"进程{process.ProcessName}检测到高可疑内存区域",
                    NotificationType.Error);
            }
        }
        
        private void HandleRemoteThreadInjection(Process process, ProcessThread thread)
        {
            var message = $"检测到远程线程注入\n进程: {process.ProcessName} (PID: {process.Id})\n线程ID: {thread.Id}\n起始地址: 0x{thread.StartAddress.ToInt64():X}";
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "RemoteThreadInjection",
                Message = "检测到远程线程注入",
                Details = message
            });
            
            NotificationService.Instance.ShowNotification(
                "代码注入检测",
                $"进程{process.ProcessName}检测到远程线程注入",
                NotificationType.Error);
        }
        
        private void HandleReflectiveDLLInjection(Process process, ProcessModule module)
        {
            var message = $"检测到反射式DLL注入\n进程: {process.ProcessName} (PID: {process.Id})\n模块: {module.ModuleName}\n基础地址: 0x{module.BaseAddress.ToInt64():X}";
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ReflectiveDLLInjection",
                Message = "检测到反射式DLL注入",
                Details = message
            });
            
            NotificationService.Instance.ShowNotification(
                "DLL注入检测",
                $"进程{process.ProcessName}检测到反射式DLL注入",
                NotificationType.Error);
        }
        
        private void HandleHeapSpraying(Process process, List<HeapSprayPattern> patterns)
        {
            var message = $"检测到堆喷射攻击\n进程: {process.ProcessName} (PID: {process.Id})\n模式数量: {patterns.Count}";
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "HeapSpraying",
                Message = "检测到堆喷射攻击",
                Details = message
            });
            
            NotificationService.Instance.ShowNotification(
                "堆喷射攻击检测",
                $"进程{process.ProcessName}检测到堆喷射攻击",
                NotificationType.Error);
        }
        
        private List<HeapSprayPattern> DetectHeapSprayingPatterns(Process process)
        {
            // 简化的堆喷射检测实现
            return new List<HeapSprayPattern>();
        }
        
        private void CheckROPPatterns(Process process)
        {
            // ROP模式检测的简化实现
        }
        
        private void LogHeapSprayingError(Exception ex)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "HeapSprayingError",
                Message = "堆喷射检测错误",
                Details = ex.Message
            });
        }
        
        private void LogROPDetectionError(Exception ex)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ROPDetectionError",
                Message = "ROP检测错误",
                Details = ex.Message
            });
        }
    }
    
    public class ProcessMemoryInfo
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public long WorkingSet { get; set; }
        public long PrivateMemory { get; set; }
        public long VirtualMemory { get; set; }
        public List<MemoryRegion> MemoryRegions { get; set; }
        public DateTime ScanTime { get; set; }
        public long WorkingSetMB { get; set; }
        public long PrivateMemoryMB { get; set; }
    }
    
    public class MemoryRegion
    {
        public long BaseAddress { get; set; }
        public ulong Size { get; set; }
        public string Name { get; set; }
        public bool IsExecutable { get; set; }
        public SuspiciousLevel SuspiciousLevel { get; set; }
        public byte[] ContentHash { get; set; }
    }
    
    public class HeapSprayPattern
    {
        public string PatternType { get; set; }
        public int Occurrences { get; set; }
        public long BaseAddress { get; set; }
        public ulong RegionSize { get; set; }
    }
    
    public enum SuspiciousLevel
    {
        Normal = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public class InjectionDetectionResult
    {
        public bool Detected { get; set; }
        public SecurityThreatLevel ThreatLevel { get; set; }
    }

    public class InjectionAttempt
    {
        public string TargetProcess { get; set; }
        public string SourceProcess { get; set; }
        public string InjectionMethod { get; set; }
    }
}