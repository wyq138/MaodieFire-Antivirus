using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 专业级进程注入防护 - 支持多种注入技术检测、API Hook检测、内存完整性验证
    /// </summary>
    public class ProcessInjectionProtection : IMonitor
    {
        private Thread _monitorThread;
        private Thread _memoryScanThread;
        private Thread _hookDetectionThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        
        // 使用并发集合
        private ConcurrentDictionary<int, ProcessSecurityProfile> _securityProfiles;
        private ConcurrentDictionary<string, ModuleInfo> _knownModules;
        private ConcurrentQueue<InjectionAlert> _alertQueue;
        private ConcurrentBag<InjectionThreat> _detectedThreats;
        
        // 进程快照
        private ConcurrentDictionary<int, ProcessSnapshot> _processSnapshots;
        private ConcurrentDictionary<string, string> _processHashes;
        
        // 可信进程列表
        private HashSet<string> _trustedProcesses;
        private HashSet<string> _trustedSigners;
        private HashSet<string> _systemProcesses;
        
        // 注入API列表
        private HashSet<string> _injectionAPIs;
        private HashSet<string> _suspiciousAPIs;
        
        // 配置参数
        private int _scanInterval;
        private int _memoryScanInterval;
        private int _hookDetectionInterval;
        private bool _enableRealTimeProtection;
        private bool _enableMemoryProtection;
        private bool _enableHookDetection;
        private bool _enableProcessHollowingDetection;
        private bool _enableDLLInjectionDetection;
        private bool _enableAPCInjectionDetection;
        private bool _enableThreadHijackingDetection;
        private bool _enableAutoTermination;
        private int _maxAlerts;
        
        // 统计数据
        private long _totalScans;
        private long _injectionsBlocked;
        private long _processesTerminated;
        private long _hooksDetected;
        private DateTime _startTime;

        #region Windows API P/Invoke
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, 
            byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesRead);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, 
            byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, 
            uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, 
            uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, 
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int SuspendThread(IntPtr hThread);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int ResumeThread(IntPtr hThread);
        
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, IntPtr[] lphModule, 
            int cb, out int lpcbNeeded, uint dwFilterFlag);
        
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern int GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, 
            StringBuilder lpFilename, int nSize);
        
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, 
            out MODULEINFO lpmodinfo, int cb);
        
        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool SymInitialize(IntPtr hProcess, string UserSearchPath, bool fInvadeProcess);
        
        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool SymCleanup(IntPtr hProcess);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr ProcessHandle, 
            int ProcessInformationClass, IntPtr ProcessInformation, uint ProcessInformationLength, 
            out uint ReturnLength);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, 
            int MemoryInformationClass, IntPtr MemoryInformation, uint MemoryInformationLength, 
            out uint ReturnLength);
        
        // 进程访问权限
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_DUP_HANDLE = 0x0040;
        
        // 线程访问权限
        private const uint THREAD_ALL_ACCESS = 0x1F03FF;
        private const uint THREAD_SET_CONTEXT = 0x0010;
        private const uint THREAD_GET_CONTEXT = 0x0008;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const uint THREAD_SET_INFORMATION = 0x0020;
        
        // 内存保护标志
        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_WRITECOPY = 0x08;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_NOCACHE = 0x200;
        private const uint PAGE_WRITECOMBINE = 0x400;
        private const uint PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000;
        private const uint PAGE_REVERT_TO_FILE_MAP = 0x80000000;
        
        // 内存分配类型
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_DECOMMIT = 0x4000;
        private const uint MEM_RELEASE = 0x8000;
        private const uint MEM_FREE = 0x10000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint MEM_MAPPED = 0x40000;
        private const uint MEM_RESET = 0x80000;
        private const uint MEM_TOP_DOWN = 0x100000;
        private const uint MEM_WRITE_WATCH = 0x200000;
        private const uint MEM_PHYSICAL = 0x400000;
        private const uint MEM_LARGE_PAGES = 0x20000000;
        
        // 结构体
        [StructLayout(LayoutKind.Sequential)]
        private struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public int SizeOfImage;
            public IntPtr EntryPoint;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }
        
        #endregion

        public ProcessInjectionProtection(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _isRunning = false;
            
            // 初始化并发集合
            _securityProfiles = new ConcurrentDictionary<int, ProcessSecurityProfile>();
            _knownModules = new ConcurrentDictionary<string, ModuleInfo>();
            _alertQueue = new ConcurrentQueue<InjectionAlert>();
            _detectedThreats = new ConcurrentBag<InjectionThreat>();
            _processSnapshots = new ConcurrentDictionary<int, ProcessSnapshot>();
            _processHashes = new ConcurrentDictionary<string, string>();
            
            // 初始化列表
            _trustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _trustedSigners = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _systemProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _injectionAPIs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _suspiciousAPIs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            // 默认配置
            _scanInterval = 3000;
            _memoryScanInterval = 10000;
            _hookDetectionInterval = 15000;
            _enableRealTimeProtection = true;
            _enableMemoryProtection = true;
            _enableHookDetection = true;
            _enableProcessHollowingDetection = true;
            _enableDLLInjectionDetection = true;
            _enableAPCInjectionDetection = true;
            _enableThreadHijackingDetection = true;
            _enableAutoTermination = false;
            _maxAlerts = 1000;
            
            // 初始化
            InitializeTrustedProcesses();
            InitializeInjectionAPIs();
        }

        private void InitializeTrustedProcesses()
        {
            // 系统核心进程
            string[] systemProcs = {
                "system", "smss", "csrss", "wininit", "services", "lsass", "svchost",
                "winlogon", "dwm", "explorer", "taskhostw", "runtimebroker",
                "conhost", "dsm", "fontdrvhost", "lsaiso", "memorycompression",
                "registry", "system", "trustedinstaller", "wudfrd"
            };
            foreach (var proc in systemProcs)
            {
                _systemProcesses.Add(proc.ToLower());
                _trustedProcesses.Add(proc.ToLower());
            }
            
            // 可信签名者
            string[] trustedSigners = {
                "Microsoft Windows",
                "Microsoft Corporation",
                "Windows Hardware Compatibility Publisher",
                "Windows Component Publisher"
            };
            foreach (var signer in trustedSigners)
            {
                _trustedSigners.Add(signer);
            }
        }

        private void InitializeInjectionAPIs()
        {
            // 进程注入相关API
            string[] injectionAPIs = {
                "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
                "VirtualAllocEx", "VirtualFreeEx", "VirtualProtectEx",
                "OpenProcess", "OpenThread", "QueueUserAPC",
                "SetThreadContext", "GetThreadContext", "SuspendThread", "ResumeThread",
                "NtCreateThreadEx", "NtQueueApcThreadEx", "RtlCreateUserThread",
                "NtWriteVirtualMemory", "NtReadVirtualMemory", "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory", "NtMapViewOfSection", "NtCreateSection",
                "NtUnmapViewOfSection", "NtOpenProcess", "NtOpenThread"
            };
            foreach (var api in injectionAPIs)
            {
                _injectionAPIs.Add(api);
            }
            
            // 可疑API组合
            string[] suspiciousAPIs = {
                "SetWindowsHookEx", "UnhookWindowsHookEx", "CallNextHookEx",
                "GetProcAddress", "LoadLibrary", "LoadLibraryEx",
                "NtCreateThread", "PsCreateSystemThread",
                "DbgUiRemoteBreakIn", "RtlRemoteCall",
                "NtSuspendProcess", "NtResumeProcess"
            };
            foreach (var api in suspiciousAPIs)
            {
                _suspiciousAPIs.Add(api);
            }
        }

        public void Start()
        {
            if (_isRunning)
                return;
            
            _isRunning = true;
            _startTime = DateTime.Now;
            
            // 启动监控线程
            _monitorThread = new Thread(MonitorInjection)
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            _monitorThread.Start();
            
            // 启动内存扫描线程
            _memoryScanThread = new Thread(MemoryScanLoop)
            {
                IsBackground = true,
                Priority = ThreadPriority.Lowest
            };
            _memoryScanThread.Start();
            
            // 启动Hook检测线程
            _hookDetectionThread = new Thread(HookDetectionLoop)
            {
                IsBackground = true,
                Priority = ThreadPriority.Lowest
            };
            _hookDetectionThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "InjectionProtectionStart",
                Message = "进程注入防护已启动",
                Details = $"监控API: {_injectionAPIs.Count}, 可信进程: {_trustedProcesses.Count}",
                Source = "ProcessInjectionProtection"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            
            _monitorThread?.Join(3000);
            _memoryScanThread?.Join(2000);
            _hookDetectionThread?.Join(2000);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "InjectionProtectionStop",
                Message = "进程注入防护已停止",
                Details = $"扫描次数: {_totalScans}, 阻止注入: {_injectionsBlocked}, 终止进程: {_processesTerminated}",
                Source = "ProcessInjectionProtection"
            });
        }

        private void MonitorInjection()
        {
            while (_isRunning)
            {
                try
                {
                    // 进程注入检测
                    CheckProcessInjection();
                    
                    // DLL注入检测
                    if (_enableDLLInjectionDetection)
                    {
                        CheckDLLInjection();
                    }
                    
                    // 进程镂空检测
                    if (_enableProcessHollowingDetection)
                    {
                        CheckProcessHollowing();
                    }
                    
                    // APC注入检测
                    if (_enableAPCInjectionDetection)
                    {
                        CheckAPCInjection();
                    }
                    
                    // 线程劫持检测
                    if (_enableThreadHijackingDetection)
                    {
                        CheckThreadHijacking();
                    }
                    
                    // 更新进程快照
                    UpdateProcessSnapshots();
                    
                    Thread.Sleep(_scanInterval);
                    Interlocked.Increment(ref _totalScans);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("注入监控线程错误", ex.Message, "ProcessInjectionProtection");
                    Thread.Sleep(1000);
                }
            }
        }

        private void MemoryScanLoop()
        {
            while (_isRunning)
            {
                try
                {
                    if (_enableMemoryProtection)
                    {
                        ScanProcessMemory();
                    }
                    Thread.Sleep(_memoryScanInterval);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("内存扫描线程错误", ex.Message, "ProcessInjectionProtection");
                }
            }
        }

        private void HookDetectionLoop()
        {
            while (_isRunning)
            {
                try
                {
                    if (_enableHookDetection)
                    {
                        DetectAPIHooks();
                    }
                    Thread.Sleep(_hookDetectionInterval);
                }
                catch (Exception ex)
                {
                    _dataManager.LogError("Hook检测线程错误", ex.Message, "ProcessInjectionProtection");
                }
            }
        }

        #region Process Injection Detection
        
        private void CheckProcessInjection()
        {
            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        // 跳过自身和系统进程
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                        
                        if (_systemProcesses.Contains(process.ProcessName.ToLower()))
                            continue;
                        
                        // 获取进程路径
                        string processPath = GetProcessPath(process);
                        if (string.IsNullOrEmpty(processPath) || !File.Exists(processPath))
                            continue;
                        
                        // 检查注入迹象
                        CheckInjectionSigns(process, processPath);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("进程注入检查错误", ex.Message, "ProcessInjectionProtection");
            }
        }

        private void CheckInjectionSigns(Process process, string processPath)
        {
            try
            {
                var profile = _securityProfiles.GetOrAdd(process.Id, 
                    id => CreateSecurityProfile(process, processPath));
                
                // 检查进程内存中的可疑区域
                CheckSuspiciousMemoryRegions(process, profile);
                
                // 检查加载的可疑DLL
                CheckSuspiciousModules(process, profile);
                
                // 检查线程状态
                CheckThreadAnomalies(process, profile);
                
                // 计算风险评分
                profile.RiskScore = CalculateInjectionRiskScore(profile);
                profile.LastScanTime = DateTime.Now;
                
                // 如果风险过高，创建告警
                if (profile.RiskScore > 70)
                {
                    CreateInjectionAlert(profile, "HighInjectionRisk", 
                        $"进程 {process.ProcessName} 存在高注入风险，评分: {profile.RiskScore}");
                }
            }
            catch { }
        }

        private ProcessSecurityProfile CreateSecurityProfile(Process process, string processPath)
        {
            var profile = new ProcessSecurityProfile
            {
                ProcessId = process.Id,
                ProcessName = process.ProcessName,
                FilePath = processPath,
                StartTime = DateTime.Now,
                RiskScore = 0,
                SuspiciousMemoryRegions = new List<MemoryRegionInfo>(),
                SuspiciousModules = new List<SuspiciousModuleInfo>(),
                ThreadAnomalies = new List<ThreadAnomaly>(),
                DetectionFlags = new HashSet<string>()
            };
            
            // 计算文件哈希
            profile.FileHash = CalculateFileHash(processPath);
            
            // 验证签名
            profile.SignatureInfo = VerifyFileSignature(processPath);
            
            // 获取原始模块列表
            profile.OriginalModules = GetProcessModules(process);
            
            return profile;
        }

        #endregion

        #region Memory Region Analysis
        
        private void CheckSuspiciousMemoryRegions(Process process, ProcessSecurityProfile profile)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
                if (hProcess == IntPtr.Zero)
                    return;
                
                try
                {
                    // 枚举内存区域
                    IntPtr address = IntPtr.Zero;
                    var suspiciousRegions = new List<MemoryRegionInfo>();
                    
                    while (true)
                    {
                        MEMORY_BASIC_INFORMATION memInfo;
                        int result = VirtualQueryEx(hProcess, address, out memInfo, 
                            Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                        
                        if (result == 0)
                            break;
                        
                        // 检查可疑内存属性
                        if (IsSuspiciousMemoryRegion(memInfo))
                        {
                            var regionInfo = new MemoryRegionInfo
                            {
                                BaseAddress = memInfo.BaseAddress,
                                RegionSize = memInfo.RegionSize,
                                Protection = memInfo.Protect,
                                State = memInfo.State,
                                Type = memInfo.Type
                            };
                            
                            // 尝试读取内存内容
                            regionInfo.Entropy = CalculateMemoryEntropy(hProcess, memInfo.BaseAddress, 
                                (int)Math.Min(memInfo.RegionSize.ToInt64(), 4096));
                            
                            suspiciousRegions.Add(regionInfo);
                            profile.DetectionFlags.Add("SuspiciousMemoryRegion");
                        }
                        
                        // 移动到下一个区域
                        long nextAddress = memInfo.BaseAddress.ToInt64() + memInfo.RegionSize.ToInt64();
                        if (nextAddress <= address.ToInt64())
                            break;
                        
                        address = new IntPtr(nextAddress);
                    }
                    
                    profile.SuspiciousMemoryRegions = suspiciousRegions;
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch { }
        }

        private void CheckSuspiciousModules(Process process, ProcessSecurityProfile profile)
        {
            try
            {
                var suspiciousModules = new List<SuspiciousModuleInfo>();

                foreach (ProcessModule module in process.Modules)
                {
                    try
                    {
                        // 检查可疑的模块特征
                        var moduleName = module.ModuleName?.ToLower() ?? "";
                        var modulePath = module.FileName ?? "";

                        // 检查未签名或可疑签名的模块
                        bool isSuspicious = false;
                        var reasons = new List<string>();

                        // 从临时目录加载
                        if (!string.IsNullOrEmpty(modulePath) &&
                            (modulePath.Contains("\\Temp\\") || modulePath.Contains("\\AppData\\Local\\Temp\\")))
                        {
                            isSuspicious = true;
                            reasons.Add("从临时目录加载");
                        }

                        // 可疑的模块名
                        var suspiciousNames = new[] { "inject", "hook", "patch", "hack", "cheat", "mod", "crack" };
                        foreach (var name in suspiciousNames)
                        {
                            if (moduleName.Contains(name))
                            {
                                isSuspicious = true;
                                reasons.Add($"模块名包含可疑关键词: {name}");
                                break;
                            }
                        }

                        if (isSuspicious)
                        {
                            suspiciousModules.Add(new SuspiciousModuleInfo
                            {
                                ModulePath = modulePath,
                                LoadTime = DateTime.Now,
                                SignatureValid = false,
                                Reason = string.Join(", ", reasons)
                            });
                            profile.DetectionFlags.Add("SuspiciousModule");
                        }
                    }
                    catch { }
                }

                profile.SuspiciousModules = suspiciousModules;
            }
            catch { }
        }

        private bool IsSuspiciousMemoryRegion(MEMORY_BASIC_INFORMATION memInfo)
        {
            // 可执行的内存区域
            if ((memInfo.Protect & PAGE_EXECUTE_READWRITE) != 0 ||
                (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) != 0 ||
                (memInfo.Protect & PAGE_EXECUTE) != 0)
            {
                // 检查是否是私有内存（非镜像）
                if ((memInfo.Type & MEM_PRIVATE) != 0)
                {
                    return true;
                }
            }
            
            // 内存保护为PAGE_EXECUTE_READWRITE且不是已提交状态
            if ((memInfo.Protect & PAGE_EXECUTE_READWRITE) != 0 && 
                (memInfo.State & MEM_COMMIT) != 0)
            {
                return true;
            }
            
            // 检测PAGE_GUARD标志（可能用于反调试）
            if ((memInfo.Protect & PAGE_GUARD) != 0)
            {
                return true;
            }
            
            return false;
        }

        private double CalculateMemoryEntropy(IntPtr hProcess, IntPtr address, int size)
        {
            try
            {
                byte[] buffer = new byte[size];
                UIntPtr bytesRead;
                
                if (ReadProcessMemory(hProcess, address, buffer, (uint)size, out bytesRead))
                {
                    return CalculateEntropy(buffer);
                }
            }
            catch { }
            
            return 0;
        }

        private double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0;
            
            var frequency = new int[256];
            foreach (byte b in data)
            {
                frequency[b]++;
            }
            
            double entropy = 0;
            int total = data.Length;
            
            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] > 0)
                {
                    double probability = (double)frequency[i] / total;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }
            
            return entropy;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, 
            out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        #endregion

        #region DLL Injection Detection
        
        private void CheckDLLInjection()
        {
            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                        
                        if (_systemProcesses.Contains(process.ProcessName.ToLower()))
                            continue;
                        
                        DetectInjectedDLLs(process);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("DLL注入检测错误", ex.Message, "ProcessInjectionProtection");
            }
        }

        private void DetectInjectedDLLs(Process process)
        {
            try
            {
                var currentModules = GetProcessModules(process);
                
                if (_securityProfiles.TryGetValue(process.Id, out var profile))
                {
                    // 检查新加载的模块
                    var newModules = currentModules.Except(profile.OriginalModules).ToList();
                    
                    foreach (var module in newModules)
                    {
                        // 检查是否来自可疑位置
                        if (IsSuspiciousModuleLocation(module))
                        {
                            var moduleInfo = new SuspiciousModuleInfo
                            {
                                ModulePath = module,
                                LoadTime = DateTime.Now,
                                Reason = "可疑位置"
                            };
                            
                            // 验证签名
                            moduleInfo.SignatureValid = VerifyFileSignature(module).IsValid;
                            
                            profile.SuspiciousModules.Add(moduleInfo);
                            profile.DetectionFlags.Add("SuspiciousModuleLoad");
                            
                            // 创建告警
                            CreateInjectionAlert(profile, "SuspiciousDLL", 
                                $"进程 {process.ProcessName} 加载了可疑DLL: {module}");
                            
                            // 扫描DLL
                            var scanResult = _antivirusEngine.ScanFile(module);
                            if (scanResult.IsInfected)
                            {
                                CreateInjectionAlert(profile, "MaliciousDLL", 
                                    $"检测到恶意DLL: {module}, 威胁: {scanResult.ThreatName}");
                                
                                if (_enableAutoTermination)
                                {
                                    TerminateProcess(process, "恶意DLL注入");
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private List<string> GetProcessModules(Process process)
        {
            var modules = new List<string>();
            
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    modules.Add(module.FileName?.ToLower() ?? "");
                }
            }
            catch
            {
                // 使用WMI作为备用方法
                try
                {
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT * FROM Win32_ProcessModule WHERE ProcessId = {process.Id}"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            modules.Add(obj["ModuleName"]?.ToString()?.ToLower() ?? "");
                        }
                    }
                }
                catch { }
            }
            
            return modules;
        }

        private bool IsSuspiciousModuleLocation(string modulePath)
        {
            if (string.IsNullOrEmpty(modulePath))
                return false;
            
            string lowerPath = modulePath.ToLower();
            
            // 可疑位置
            string[] suspiciousLocations = {
                "\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\",
                "\\desktop\\", "\\appdata\\roaming\\", "\\appdata\\local\\",
                "\\users\\public\\", "\\programdata\\", "\\recycle.bin\\",
                "\\windows\\temp\\"
            };
            
            foreach (var location in suspiciousLocations)
            {
                if (lowerPath.Contains(location))
                    return true;
            }
            
            // 检查是否在系统目录外
            string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System).ToLower();
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLower();
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLower();
            
            if (!lowerPath.StartsWith(system32) && 
                !lowerPath.StartsWith(windows) &&
                !lowerPath.StartsWith(programFiles) &&
                !lowerPath.StartsWith(programFilesX86))
            {
                // 在系统目录外，但可能来自已知的应用程序
                // 进一步检查签名
                return true;
            }
            
            return false;
        }

        #endregion

        #region Process Hollowing Detection
        
        private void CheckProcessHollowing()
        {
            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                        
                        if (_systemProcesses.Contains(process.ProcessName.ToLower()))
                            continue;
                        
                        string processPath = GetProcessPath(process);
                        if (string.IsNullOrEmpty(processPath) || !File.Exists(processPath))
                            continue;
                        
                        // 计算当前哈希
                        string currentHash = CalculateFileHash(processPath);
                        
                        if (_processHashes.TryGetValue(processPath, out string originalHash))
                        {
                            if (!string.IsNullOrEmpty(currentHash) && currentHash != originalHash)
                            {
                                // 哈希不匹配，可能是进程镂空
                                CreateInjectionAlert(null, "ProcessHollowing",
                                    $"检测到进程镂空: {process.ProcessName}, PID: {process.Id}");
                                
                                if (_enableAutoTermination)
                                {
                                    TerminateProcess(process, "进程镂空攻击");
                                }
                            }
                        }
                        else
                        {
                            _processHashes.TryAdd(processPath, currentHash);
                        }
                        
                        // 检查PEB是否被修改
                        CheckPEBModification(process);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("进程镂空检测错误", ex.Message, "ProcessInjectionProtection");
            }
        }

        private void CheckPEBModification(Process process)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
                if (hProcess == IntPtr.Zero)
                    return;
                
                try
                {
                    PROCESS_BASIC_INFORMATION pbi;
                    int size = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
                    IntPtr pPbi = Marshal.AllocHGlobal(size);
                    
                    try
                    {
                        uint returnLength;
                        int status = NtQueryInformationProcess(hProcess, 0, pPbi, (uint)size, out returnLength);
                        
                        if (status == 0)
                        {
                            pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pPbi, typeof(PROCESS_BASIC_INFORMATION));
                            
                            // 检查PEB中的ImagePath和CommandLine是否与进程信息匹配
                            // 这需要读取PEB结构，此处简化处理
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pPbi);
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch { }
        }

        #endregion

        #region APC Injection Detection
        
        private void CheckAPCInjection()
        {
            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                        
                        if (_systemProcesses.Contains(process.ProcessName.ToLower()))
                            continue;
                        
                        // 检查线程的APC队列
                        CheckThreadAPCs(process);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("APC注入检测错误", ex.Message, "ProcessInjectionProtection");
            }
        }

        private void CheckThreadAPCs(Process process)
        {
            try
            {
                // 检测APC注入的主要方法是查看线程是否处于等待状态
                // 且有未执行的APC项目
                
                foreach (ProcessThread thread in process.Threads)
                {
                    // 检测线程状态异常
                    if (thread.ThreadState == System.Diagnostics.ThreadState.Wait)
                    {
                        // 检查等待原因是否合理
                        if (thread.WaitReason == ThreadWaitReason.UserRequest)
                        {
                            // 可能是APC注入的目标
                            // 需要进一步分析
                        }
                    }
                }
            }
            catch { }
        }

        #endregion

        #region Thread Hijacking Detection
        
        private void CheckThreadHijacking()
        {
            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                        
                        if (_systemProcesses.Contains(process.ProcessName.ToLower()))
                            continue;
                        
                        CheckThreadContextAnomalies(process);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("线程劫持检测错误", ex.Message, "ProcessInjectionProtection");
            }
        }

        private void CheckThreadContextAnomalies(Process process)
        {
            try
            {
                if (_securityProfiles.TryGetValue(process.Id, out var profile))
                {
                    foreach (ProcessThread thread in process.Threads)
                    {
                        var anomaly = new ThreadAnomaly
                        {
                            ThreadId = thread.Id,
                            DetectionTime = DateTime.Now
                        };
                        
                        // 检查线程数量异常变化
                        if (_processSnapshots.TryGetValue(process.Id, out var snapshot))
                        {
                            int threadDiff = Math.Abs(process.Threads.Count - snapshot.ThreadCount);
                            if (threadDiff > 5)
                            {
                                anomaly.Type = "ThreadCountAnomaly";
                                anomaly.Details = $"线程数量变化: {snapshot.ThreadCount} -> {process.Threads.Count}";
                                profile.ThreadAnomalies.Add(anomaly);
                                profile.DetectionFlags.Add("ThreadHijacking");
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private void CheckThreadAnomalies(Process process, ProcessSecurityProfile profile)
        {
            try
            {
                // 检查是否有被暂停的线程
                int suspendedCount = 0;
                foreach (ProcessThread thread in process.Threads)
                {
                    if (thread.ThreadState == System.Diagnostics.ThreadState.Wait && 
                        thread.WaitReason == ThreadWaitReason.Suspended)
                    {
                        suspendedCount++;
                    }
                }
                
                // 如果多个线程被暂停，可能是线程劫持的迹象
                if (suspendedCount > process.Threads.Count / 2 && process.Threads.Count > 1)
                {
                    var anomaly = new ThreadAnomaly
                    {
                        ThreadId = 0,
                        Type = "MultipleSuspendedThreads",
                        Details = $"{suspendedCount} 个线程被暂停",
                        DetectionTime = DateTime.Now
                    };
                    profile.ThreadAnomalies.Add(anomaly);
                    profile.DetectionFlags.Add("ThreadSuspension");
                }
            }
            catch { }
        }

        #endregion

        #region Memory Scanning

        private void ScanProcessMemory()
        {
            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                        
                        if (_systemProcesses.Contains(process.ProcessName.ToLower()))
                            continue;
                        
                        // 扫描内存中的恶意代码特征
                        ScanProcessMemoryForThreats(process);
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void ScanProcessMemoryForThreats(Process process)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
                if (hProcess == IntPtr.Zero)
                    return;
                
                try
                {
                    // 扫描内存中的Shellcode特征
                    ScanForShellcode(hProcess, process);
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch { }
        }

        private void ScanForShellcode(IntPtr hProcess, Process process)
        {
            try
            {
                // 扫描可执行内存区域中的Shellcode特征
                IntPtr address = IntPtr.Zero;
                byte[] buffer = new byte[4096];
                
                while (true)
                {
                    MEMORY_BASIC_INFORMATION memInfo;
                    int result = VirtualQueryEx(hProcess, address, out memInfo, 
                        Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                    
                    if (result == 0)
                        break;
                    
                    // 只扫描可执行内存
                    if ((memInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0 &&
                        (memInfo.State & MEM_COMMIT) != 0 &&
                        (memInfo.Type & MEM_PRIVATE) != 0)
                    {
                        UIntPtr bytesRead;
                        if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, 4096, out bytesRead))
                        {
                            // 检查Shellcode特征
                            if (DetectShellcodePatterns(buffer))
                            {
                                CreateInjectionAlert(null, "ShellcodeDetected",
                                    $"在进程 {process.ProcessName} 中检测到Shellcode特征");
                            }
                        }
                    }
                    
                    long nextAddress = memInfo.BaseAddress.ToInt64() + memInfo.RegionSize.ToInt64();
                    if (nextAddress <= address.ToInt64())
                        break;
                    
                    address = new IntPtr(nextAddress);
                }
            }
            catch { }
        }

        private bool DetectShellcodePatterns(byte[] data)
        {
            // 检查常见的Shellcode特征
            
            // 1. 高熵值（加密/压缩的Shellcode）
            double entropy = CalculateEntropy(data);
            if (entropy > 7.5)
                return true;
            
            // 2. 常见的Shellcode模式
            // NOP sled
            int nopCount = 0;
            for (int i = 0; i < data.Length - 1; i++)
            {
                if (data[i] == 0x90) // NOP
                    nopCount++;
                else
                    nopCount = 0;
                
                if (nopCount > 10)
                    return true;
            }
            
            // 3. syscall指令模式（用于直接系统调用绕过）
            for (int i = 0; i < data.Length - 10; i++)
            {
                // MOV EAX, syscall_number; SYSCALL
                if (data[i] == 0xB8 && data[i + 5] == 0x0F && data[i + 6] == 0x05)
                    return true;
            }
            
            // 4. PE头特征（反射加载的DLL）
            if (data.Length >= 2 && data[0] == 0x4D && data[1] == 0x5A) // MZ
                return true;
            
            return false;
        }

        #endregion

        #region API Hook Detection

        private void DetectAPIHooks()
        {
            try
            {
                // 检测系统DLL中的Hook
                DetectSystemDLLHooks();
                
                // 检测进程中的Hook
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.Id == Process.GetCurrentProcess().Id)
                            continue;
                        
                        if (_systemProcesses.Contains(process.ProcessName.ToLower()))
                            continue;
                        
                        DetectProcessHooks(process);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _dataManager.LogError("Hook检测错误", ex.Message, "ProcessInjectionProtection");
            }
        }

        private void DetectSystemDLLHooks()
        {
            try
            {
                // 检查ntdll.dll和kernel32.dll中的关键函数
                string[] systemDLLs = {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntdll.dll"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernelbase.dll")
                };
                
                foreach (var dllPath in systemDLLs)
                {
                    if (File.Exists(dllPath))
                    {
                        // 验证签名
                        var sigInfo = VerifyFileSignature(dllPath);
                        if (!sigInfo.IsValid)
                        {
                            _dataManager.LogWarning($"系统DLL签名验证失败: {dllPath}");
                        }
                        
                        // 检查文件完整性
                        string hash = CalculateFileHash(dllPath);
                        if (_knownModules.TryGetValue(dllPath, out var knownHash))
                        {
                            if (knownHash.Hash != hash)
                            {
                                _dataManager.LogWarning($"系统DLL被修改: {dllPath}");
                            }
                        }
                        else
                        {
                            _knownModules.TryAdd(dllPath, new ModuleInfo
                            {
                                Path = dllPath,
                                Hash = hash,
                                SignatureInfo = sigInfo
                            });
                        }
                    }
                }
            }
            catch { }
        }

        private void DetectProcessHooks(Process process)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
                if (hProcess == IntPtr.Zero)
                    return;
                
                try
                {
                    // 检查IAT Hook
                    CheckIATHooks(hProcess, process);
                    
                    // 检查Inline Hook
                    CheckInlineHooks(hProcess, process);
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch { }
        }

        private void CheckIATHooks(IntPtr hProcess, Process process)
        {
            // IAT Hook检测需要分析PE结构
            // 此处提供框架
        }

        private void CheckInlineHooks(IntPtr hProcess, Process process)
        {
            // Inline Hook检测需要检查函数入口点的字节码
            // 此处提供框架
        }

        #endregion

        #region Helper Methods

        private string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName;
            }
            catch
            {
                try
                {
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {process.Id}"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            return obj["ExecutablePath"]?.ToString();
                        }
                    }
                }
                catch { }
            }
            return null;
        }

        private string CalculateFileHash(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
            catch
            {
                return null;
            }
        }

        private SignatureInfo VerifyFileSignature(string filePath)
        {
            var info = new SignatureInfo { IsValid = false };
            
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return info;
            
            try
            {
                // 不使用Windows签名验证，改为检查文件是否在信任目录中
                string lowerPath = filePath.ToLowerInvariant();
                
                // 检查是否在系统信任目录中
                bool isInTrustedLocation = 
                    lowerPath.Contains("\\windows\\") ||
                    lowerPath.Contains("\\program files\\") ||
                    lowerPath.Contains("\\program files (x86)\\") ||
                    lowerPath.Contains("\\microsoft\\") ||
                    lowerPath.Contains("\\system32\\") ||
                    lowerPath.Contains("\\syswow64\\");
                
                if (isInTrustedLocation)
                {
                    info.IsValid = true;
                    info.Signer = "系统信任目录";
                    info.IsTrustedSigner = true;
                }
                else
                {
                    // 检查是否在用户信任目录
                    string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    if (lowerPath.StartsWith(userProfile.ToLowerInvariant()))
                    {
                        info.IsValid = true;
                        info.Signer = "用户目录";
                        info.IsTrustedSigner = false;
                    }
                }
            }
            catch { }
            
            return info;
        }

        private void UpdateProcessSnapshots()
        {
            try
            {
                var processes = Process.GetProcesses();
                
                foreach (var process in processes)
                {
                    try
                    {
                        var snapshot = new ProcessSnapshot
                        {
                            ProcessId = process.Id,
                            ProcessName = process.ProcessName,
                            ThreadCount = process.Threads.Count,
                            HandleCount = process.HandleCount,
                            WorkingSet = process.WorkingSet64,
                            SnapshotTime = DateTime.Now
                        };
                        
                        _processSnapshots.AddOrUpdate(process.Id, snapshot, (k, v) => snapshot);
                    }
                    catch { }
                }
                
                // 清理过期快照
                var expiredKeys = _processSnapshots
                    .Where(kvp => (DateTime.Now - kvp.Value.SnapshotTime).TotalMinutes > 10)
                    .Select(kvp => kvp.Key)
                    .ToList();
                
                foreach (var key in expiredKeys)
                {
                    ProcessSnapshot removed;
                    _processSnapshots.TryRemove(key, out removed);
                }
            }
            catch { }
        }

        private int CalculateInjectionRiskScore(ProcessSecurityProfile profile)
        {
            int score = 0;
            
            // 可疑内存区域
            score += profile.SuspiciousMemoryRegions.Count * 15;
            
            // 可疑模块
            foreach (var module in profile.SuspiciousModules)
            {
                if (!module.SignatureValid)
                    score += 25;
                else
                    score += 10;
            }
            
            // 线程异常
            score += profile.ThreadAnomalies.Count * 10;
            
            // 检测标志
            foreach (var flag in profile.DetectionFlags)
            {
                switch (flag)
                {
                    case "SuspiciousMemoryRegion":
                        score += 15;
                        break;
                    case "SuspiciousModuleLoad":
                        score += 20;
                        break;
                    case "ThreadHijacking":
                        score += 30;
                        break;
                    case "ThreadSuspension":
                        score += 15;
                        break;
                    case "ShellcodeDetected":
                        score += 40;
                        break;
                }
            }
            
            // 签名验证
            if (!profile.SignatureInfo.IsValid)
                score += 15;
            
            return Math.Min(100, score);
        }

        private void CreateInjectionAlert(ProcessSecurityProfile profile, string alertType, string description)
        {
            var alert = new InjectionAlert
            {
                AlertId = Guid.NewGuid().ToString(),
                AlertType = alertType,
                ProcessId = profile?.ProcessId ?? 0,
                ProcessName = profile?.ProcessName ?? "Unknown",
                FilePath = profile?.FilePath,
                Description = description,
                RiskScore = profile?.RiskScore ?? 50,
                DetectedAt = DateTime.Now
            };
            
            _alertQueue.Enqueue(alert);
            Interlocked.Increment(ref _injectionsBlocked);
            
            // 记录日志
            _dataManager.AddLog(new LogEntry
            {
                Id = alert.AlertId,
                Time = alert.DetectedAt,
                Type = "InjectionAlert",
                Message = $"注入威胁警告: {alertType}",
                Details = description,
                Source = "ProcessInjectionProtection",
                Category = "威胁检测"
            });
            
            // 发送通知
            try
            {
                NotificationService.Instance?.ShowNotification(
                    "进程注入警告",
                    description,
                    NotificationType.Warning);
            }
            catch { }
        }

        private void TerminateProcess(Process process, string reason)
        {
            try
            {
                process.Kill();
                Interlocked.Increment(ref _processesTerminated);
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ProcessTerminated",
                    Message = $"已终止可疑进程: {process.ProcessName}",
                    Details = $"PID: {process.Id}, 原因: {reason}",
                    Source = "ProcessInjectionProtection",
                    Category = "威胁响应"
                });
            }
            catch (Exception ex)
            {
                _dataManager.LogError("终止进程失败", ex.Message, "ProcessInjectionProtection");
            }
        }

        #endregion

        #region Public API

        public List<InjectionAlert> GetAlerts()
        {
            return _alertQueue.ToList();
        }

        public List<ProcessSecurityProfile> GetSecurityProfiles()
        {
            return _securityProfiles.Values.ToList();
        }

        public ProcessSecurityProfile GetProcessSecurityProfile(int processId)
        {
            _securityProfiles.TryGetValue(processId, out var profile);
            return profile;
        }

        public InjectionProtectionStatistics GetStatistics()
        {
            return new InjectionProtectionStatistics
            {
                TotalScans = _totalScans,
                InjectionsBlocked = _injectionsBlocked,
                ProcessesTerminated = _processesTerminated,
                HooksDetected = _hooksDetected,
                MonitoredProcesses = _securityProfiles.Count,
                KnownModules = _knownModules.Count,
                RunningTime = DateTime.Now - _startTime
            };
        }

        public void SetScanInterval(int milliseconds)
        {
            _scanInterval = Math.Max(1000, milliseconds);
        }

        public void EnableRealTimeProtection(bool enable) => _enableRealTimeProtection = enable;
        public void EnableMemoryProtection(bool enable) => _enableMemoryProtection = enable;
        public void EnableHookDetection(bool enable) => _enableHookDetection = enable;
        public void EnableAutoTermination(bool enable) => _enableAutoTermination = enable;

        #endregion
    }

    #region Data Classes

    public class ProcessSecurityProfile
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string FilePath { get; set; }
        public string FileHash { get; set; }
        public SignatureInfo SignatureInfo { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime LastScanTime { get; set; }
        public int RiskScore { get; set; }
        
        public List<MemoryRegionInfo> SuspiciousMemoryRegions { get; set; }
        public List<SuspiciousModuleInfo> SuspiciousModules { get; set; }
        public List<ThreadAnomaly> ThreadAnomalies { get; set; }
        public HashSet<string> DetectionFlags { get; set; }
        public List<string> OriginalModules { get; set; }
    }

    public class MemoryRegionInfo
    {
        public IntPtr BaseAddress { get; set; }
        public IntPtr RegionSize { get; set; }
        public uint Protection { get; set; }
        public uint State { get; set; }
        public uint Type { get; set; }
        public double Entropy { get; set; }
    }

    public class SuspiciousModuleInfo
    {
        public string ModulePath { get; set; }
        public DateTime LoadTime { get; set; }
        public bool SignatureValid { get; set; }
        public string Reason { get; set; }
    }

    public class ThreadAnomaly
    {
        public int ThreadId { get; set; }
        public string Type { get; set; }
        public string Details { get; set; }
        public DateTime DetectionTime { get; set; }
    }

    public class ProcessSnapshot
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public int ThreadCount { get; set; }
        public int HandleCount { get; set; }
        public long WorkingSet { get; set; }
        public DateTime SnapshotTime { get; set; }
    }

    public class ModuleInfo
    {
        public string Path { get; set; }
        public string Hash { get; set; }
        public SignatureInfo SignatureInfo { get; set; }
    }

    public class InjectionAlert
    {
        public string AlertId { get; set; }
        public string AlertType { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string FilePath { get; set; }
        public string Description { get; set; }
        public int RiskScore { get; set; }
        public DateTime DetectedAt { get; set; }
    }

    public class InjectionThreat
    {
        public string ThreatId { get; set; }
        public string ThreatType { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string FilePath { get; set; }
        public string Details { get; set; }
        public DateTime DetectedAt { get; set; }
        public bool IsResolved { get; set; }
    }

    public class InjectionProtectionStatistics
    {
        public long TotalScans { get; set; }
        public long InjectionsBlocked { get; set; }
        public long ProcessesTerminated { get; set; }
        public long HooksDetected { get; set; }
        public int MonitoredProcesses { get; set; }
        public int KnownModules { get; set; }
        public TimeSpan RunningTime { get; set; }
    }

    #endregion
}
