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
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);

        private List<MemoryRegion> GetMemoryRegions(Process process)
        {
            var regions = new List<MemoryRegion>();

            // 真实枚举：使用 VirtualQueryEx 遍历进程已提交的内存区域
            const uint PROCESS_QUERY_INFORMATION = 0x0400;
            const uint PROCESS_VM_READ = 0x0010;
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);

            if (hProcess == IntPtr.Zero)
            {
                // 无法打开进程时回退到模块列表（模块映像区域是已知的可执行内存）
                try
                {
                    foreach (ProcessModule module in process.Modules)
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

            try
            {
                long address = 0;
                const long maxAddress = 0x7FFFFFFEFFFF;
                int mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

                // 模块地址范围表用于判断区域归属
                var moduleRanges = new List<(long Start, long End, string Name)>();
                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        moduleRanges.Add((module.BaseAddress.ToInt64(),
                            module.BaseAddress.ToInt64() + module.ModuleMemorySize, module.ModuleName));
                    }
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

                const uint MEM_COMMIT = 0x1000;
                const uint PAGE_EXECUTE = 0x10;
                const uint PAGE_EXECUTE_READ = 0x20;
                const uint PAGE_EXECUTE_READWRITE = 0x40;
                const uint PAGE_EXECUTE_WRITECOPY = 0x80;

                while (address < maxAddress)
                {
                    IntPtr result = VirtualQueryEx(hProcess, (IntPtr)address, out MEMORY_BASIC_INFORMATION mbi, (IntPtr)mbiSize);
                    if (result == IntPtr.Zero) break;

                    long baseAddress = mbi.BaseAddress.ToInt64();
                    long regionSize = mbi.RegionSize.ToInt64();
                    if (regionSize <= 0) break;

                    if (mbi.State == MEM_COMMIT)
                    {
                        bool isExecutable = (mbi.Protect &
                            (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                        // 真实 RWX 判定：可写且可执行（正常模块代码段只读可执行，RWX 是注入/shellcode 典型特征）
                        bool isWritable = (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | 0x04 /*PAGE_READWRITE*/)) != 0;

                        string name = null;
                        if (isExecutable)
                        {
                            foreach (var (start, end, moduleName) in moduleRanges)
                            {
                                if (baseAddress >= start && baseAddress < end)
                                {
                                    name = moduleName;
                                    break;
                                }
                            }

                            // 无模块归属的可执行匿名区域（常见于手动映射的注入载荷）
                            name ??= "<anonymous>";
                        }

                        regions.Add(new MemoryRegion
                        {
                            BaseAddress = baseAddress,
                            Size = (ulong)regionSize,
                            Name = name,
                            IsExecutable = isExecutable,
                            IsWritable = isWritable
                        });
                    }

                    address = baseAddress + regionSize;
                }
            }
            catch
            {
                // 枚举中断时返回已收集的区域
            }
            finally
            {
                CloseHandle(hProcess);
            }

            return regions;
        }
        
        private List<MemoryRegion> ScanMemoryRegions(Process process, ProcessMemoryInfo memoryInfo)
        {
            var suspiciousRegions = new List<MemoryRegion>();
            
            try
            {
                // 真实内存区域扫描（升级自"简化实现"）：
                // 枚举目标进程已提交内存，识别"可写 + 可执行"的私有区域（shellcode/反射注入载荷典型驻留地）。
                // 正常模块代码段为只读可执行（RX），RWX 组合是可利用的强可疑特征。
                try
                {
                    var regions = GetMemoryRegions(process);
                    foreach (var region in regions)
                    {
                        if (!region.IsExecutable || !region.IsWritable) continue;
                        if (region.Size < 4096) continue; // 忽略极小的合法运行时桩

                        region.Name = (string.IsNullOrEmpty(region.Name) || region.Name == "<anonymous>"
                            ? "匿名"
                            : region.Name) + " · RWX 可写可执行区域（疑似注入/shellcode）";
                        region.SuspiciousLevel = SuspiciousLevel.High;
                        suspiciousRegions.Add(region);
                    }
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

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
            // 真实堆喷射检测（升级自"空返回"）：
            // 统计匿名"可写+可执行"区域，按大小数量级聚类；同量级区域 ≥24 个是堆喷射（等大小 shellcode 喷射）典型特征。
            var patterns = new List<HeapSprayPattern>();
            try
            {
                var rwxAnon = new List<MemoryRegion>();
                foreach (var r in GetMemoryRegions(process))
                {
                    if (!r.IsExecutable || !r.IsWritable) continue;
                    if (!string.IsNullOrEmpty(r.Name) && r.Name != "<anonymous>") continue;
                    rwxAnon.Add(r);
                }
                if (rwxAnon.Count < 24) return patterns;

                var buckets = new Dictionary<long, List<MemoryRegion>>();
                foreach (var r in rwxAnon)
                {
                    long key = (long)Math.Round(Math.Log(Math.Max(1, (double)r.Size), 2));
                    if (!buckets.TryGetValue(key, out var list))
                    {
                        list = new List<MemoryRegion>();
                        buckets[key] = list;
                    }
                    list.Add(r);
                }

                foreach (var kv in buckets)
                {
                    if (kv.Value.Count < 24) continue;
                    var first = kv.Value[0];
                    patterns.Add(new HeapSprayPattern
                    {
                        PatternType = "HeapSpray-Cluster",
                        Occurrences = kv.Value.Count,
                        BaseAddress = first.BaseAddress,
                        RegionSize = first.Size
                    });
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return patterns;
        }
        
        private void CheckROPPatterns(Process process)
        {
            try
            {
                // 真实 ROP 特征检测（升级自空实现）：
                // ROP/反射载荷常见特征为大量匿名"可写可执行"内存（JIT 页/ROP 链/解压后的 shellcode），
                // 区域数 ≥8 且总量 >64MB 触发告警（不臆造，仅依据真实内存区域统计）。
                int count = 0;
                ulong total = 0;
                foreach (var r in GetMemoryRegions(process))
                {
                    if (!r.IsExecutable || !r.IsWritable) continue;
                    if (!string.IsNullOrEmpty(r.Name) && r.Name != "<anonymous>") continue;
                    count++;
                    total += r.Size;
                }

                if (count >= 8 && total > 64UL * 1024 * 1024)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "RopPatternSuspicious",
                        Message = "检测到大量可写可执行匿名内存（疑似 ROP/反射载荷）",
                        Details = $"进程: {process.ProcessName} (PID {process.Id})，区域数: {count}，总量: {total / 1024 / 1024}MB"
                    });

                    NotificationService.Instance.ShowNotification(
                        "ROP 行为告警",
                        $"进程 {process.ProcessName} 存在大量可写可执行匿名内存（{count} 个区域 / {total / 1024 / 1024}MB）",
                        NotificationType.Warning);
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
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
        public bool IsWritable { get; set; }
        public SuspiciousLevel SuspiciousLevel { get; set; }
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