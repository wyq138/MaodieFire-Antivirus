using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Engine.Scanners
{
    public static class EnumerableExtensions
    {
        // 扩展方法：将集合分批处理
        public static IEnumerable<IEnumerable<T>> Batch<T>(this IEnumerable<T> source, int size)
        {
            T[] bucket = null;
            var count = 0;
            
            foreach (var item in source)
            {
                if (bucket == null)
                {
                    bucket = new T[size];
                }
                
                bucket[count++] = item;
                
                if (count == size)
                {
                    yield return bucket;
                    bucket = null;
                    count = 0;
                }
            }
            
            if (bucket != null && count > 0)
            {
                Array.Resize(ref bucket, count);
                yield return bucket;
            }
        }
    }

    public class MemoryScanner
    {
        private DataManager dataManager;
        private Dictionary<int, List<string>> processMemoryCache;
        private Dictionary<string, List<string>> memoryPatterns;
        private Dictionary<string, List<string>> maliciousMemorySignatures;
        private Dictionary<string, List<string>> suspiciousMemorySignatures;
        private Dictionary<string, List<string>> benignMemorySignatures;
        private int maxDegreeOfParallelism;
        private int batchSize;

        public MemoryScanner(int maxThreads = 4, int batchSize = 10)
        {
            dataManager = DataManager.SharedInstance;
            processMemoryCache = new Dictionary<int, List<string>>();
            maxDegreeOfParallelism = Math.Max(1, Math.Min(Environment.ProcessorCount, maxThreads));
            this.batchSize = Math.Max(1, batchSize);
            InitializeMemoryPatterns();
            InitializeMemorySignatures();
        }

        public int MaxDegreeOfParallelism
        {
            get { return maxDegreeOfParallelism; }
            set { maxDegreeOfParallelism = Math.Max(1, Math.Min(Environment.ProcessorCount, value)); }
        }

        public int BatchSize
        {
            get { return batchSize; }
            set { batchSize = Math.Max(1, value); }
        }

        private void InitializeMemoryPatterns()
        {
            memoryPatterns = new Dictionary<string, List<string>>
            {
                { "ProcessMemory", new List<string> { "VirtualAlloc", "VirtualProtect", "RtlMoveMemory", "memcpy" } },
                { "ThreadMemory", new List<string> { "CreateThread", "CreateRemoteThread", "ResumeThread", "SuspendThread" } },
                { "ModuleMemory", new List<string> { "GetModuleHandle", "LoadLibrary", "FreeLibrary", "GetProcAddress" } },
                { "HeapMemory", new List<string> { "HeapCreate", "HeapAlloc", "HeapFree", "HeapDestroy" } },
                { "StackMemory", new List<string> { "alloca", "_alloca", "_malloca", "_freea" } },
                { "SharedMemory", new List<string> { "CreateFileMapping", "MapViewOfFile", "UnmapViewOfFile", "OpenFileMapping" } },
                { "PageMemory", new List<string> { "VirtualAllocEx", "VirtualProtectEx", "VirtualFreeEx", "ReadProcessMemory" } },
                { "ProtectedMemory", new List<string> { "VirtualProtect", "VirtualProtectEx", "GetProcessHeap", "GetProcessHandleCount" } }
            };
        }

        private void InitializeMemorySignatures()
        {
            maliciousMemorySignatures = new Dictionary<string, List<string>>
            {
                { "Injection", new List<string> { "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess" } },
                { "Hooking", new List<string> { "SetWindowsHookEx", "CallNextHookEx", "UnhookWindowsHookEx", "GetProcAddress" } },
                { "CodeExecution", new List<string> { "VirtualAlloc", "VirtualProtect", "RtlMoveMemory", "memcpy" } },
                { "MemoryManipulation", new List<string> { "ReadProcessMemory", "WriteProcessMemory", "VirtualQuery", "VirtualQueryEx" } },
                { "AntiAnalysis", new List<string> { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString", "GetThreadContext" } },
                { "PrivilegeEscalation", new List<string> { "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue", "DuplicateTokenEx" } },
                { "Persistence", new List<string> { "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue" } },
                { "DataExfiltration", new List<string> { "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest" } }
            };

            suspiciousMemorySignatures = new Dictionary<string, List<string>>
            {
                { "ProcessEnumeration", new List<string> { "EnumProcesses", "EnumProcessModules", "GetProcesses", "GetProcessById" } },
                { "ModuleEnumeration", new List<string> { "EnumProcessModulesEx", "GetModuleFileNameEx", "GetProcessModuleFileName", "EnumLoadedModules" } },
                { "ThreadEnumeration", new List<string> { "EnumThreads", "GetThreadId", "GetThreadHandleCount", "Thread32First" } },
                { "MemoryEnumeration", new List<string> { "VirtualQuery", "VirtualQueryEx", "GetProcessMemoryInfo", "GlobalMemoryStatusEx" } },
                { "SystemInformation", new List<string> { "GetSystemInfo", "GetNativeSystemInfo", "GetComputerName", "GetUserName" } },
                { "NetworkInformation", new List<string> { "GetAdaptersInfo", "GetNetworkParams", "GetIpAddrTable", "GetTcpTable" } },
                { "FileInformation", new List<string> { "FindFirstFile", "FindNextFile", "GetFileAttributes", "SetFileAttributes" } },
                { "RegistryInformation", new List<string> { "RegOpenKey", "RegQueryValue", "RegEnumKey", "RegEnumValue" } }
            };

            benignMemorySignatures = new Dictionary<string, List<string>>
            {
                { "MemoryManagement", new List<string> { "malloc", "free", "calloc", "realloc" } },
                { "StringOperations", new List<string> { "strcpy", "strcat", "strcmp", "strlen" } },
                { "MathOperations", new List<string> { "sin", "cos", "tan", "sqrt" } },
                { "InputOutput", new List<string> { "printf", "scanf", "fprintf", "fscanf" } },
                { "TimeOperations", new List<string> { "GetSystemTime", "GetLocalTime", "time", "clock" } },
                { "ErrorHandling", new List<string> { "GetLastError", "SetLastError", "FormatMessage", "GetErrorString" } },
                { "ResourceManagement", new List<string> { "LoadString", "LoadIcon", "LoadCursor", "LoadBitmap" } },
                { "UserInterface", new List<string> { "MessageBox", "CreateWindow", "ShowWindow", "UpdateWindow" } }
            };
        }

        public List<ScanResult> ScanProcessMemory(int processId)
        {
            var results = new List<ScanResult>();
            
            try
            {
                var process = Process.GetProcessById(processId);
                var memoryRegions = GetProcessMemoryRegions(processId);
                var memorySignatures = GetProcessMemorySignatures(processId);

                double memoryScore = CalculateMemoryScore(memoryRegions, memorySignatures);
                var result = CreateProcessScanResult(process, memoryScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat($"内存扫描检测到恶意进程: {process.ProcessName} (PID: {processId})", $"评分: {memoryScore:P}", "MemoryScanner");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError($"内存扫描失败: PID {processId}", ex.Message, "MemoryScanner");
            }

            return results;
        }

        public List<ScanResult> ScanAllProcessesMemory()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var processes = Process.GetProcesses();
                
                // 并行处理，提高大规模扫描效率
                var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
                var threadSafeResults = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
                
                Parallel.ForEach(processes, options, process =>
                {
                    try
                    {
                        var processResults = ScanProcessMemory(process.Id);
                        foreach (var result in processResults)
                        {
                            threadSafeResults.Add(result);
                        }
                    }
                    catch
                    {
                        // 忽略无法访问的进程
                    }
                });
                
                results.AddRange(threadSafeResults);
            }
            catch (Exception ex)
            {
                dataManager.LogError("扫描所有进程内存失败", ex.Message, "MemoryScanner");
            }

            return results;
        }

        public List<ScanResult> ScanProcessesMemoryInBatches()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var processes = Process.GetProcesses();
                var processBatches = processes.Batch(batchSize);
                
                foreach (var batch in processBatches)
                {
                    var batchResults = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
                    var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism };
                    
                    Parallel.ForEach(batch, options, process =>
                    {
                        try
                        {
                            var processResults = ScanProcessMemory(process.Id);
                            foreach (var result in processResults)
                            {
                                batchResults.Add(result);
                            }
                        }
                        catch
                        {
                            // 忽略无法访问的进程
                        }
                    });
                    
                    results.AddRange(batchResults);
                    
                    // 每批次扫描后短暂休息，减少系统负载
                    Thread.Sleep(50);
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("批量扫描进程内存失败", ex.Message, "MemoryScanner");
            }

            return results;
        }



        public List<ScanResult> ScanSystemMemory()
        {
            var results = new List<ScanResult>();
            
            try
            {
                var systemMemoryInfo = GetSystemMemoryInfo();
                var memoryModules = GetSystemMemoryModules();

                double systemMemoryScore = CalculateSystemMemoryScore(systemMemoryInfo, memoryModules);
                var result = CreateSystemScanResult(systemMemoryScore);
                results.Add(result);

                if (result.IsInfected)
                {
                    dataManager.LogThreat("内存扫描检测到系统内存异常", $"评分: {systemMemoryScore:P}", "MemoryScanner");
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("系统内存扫描失败", ex.Message, "MemoryScanner");
            }

            return results;
        }

        private List<string> GetProcessMemoryRegions(int processId)
        {
            var regions = new List<string>();
            
            try
            {
                if (processMemoryCache.TryGetValue(processId, out List<string> cachedRegions))
                {
                    return cachedRegions;
                }

                using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_PerfRawData_PerfProc_Process WHERE IDProcess = {processId}"))
                {
                    var process = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                    if (process != null)
                    {
                        regions.Add($"WorkingSet: {process["WorkingSet"]}");
                        regions.Add($"PageFileBytes: {process["PageFileBytes"]}");
                        regions.Add($"PrivateBytes: {process["PrivateBytes"]}");
                        regions.Add($"VirtualBytes: {process["VirtualBytes"]}");
                    }
                }

                processMemoryCache[processId] = regions;
            }
            catch
            {
                regions.Clear();
            }

            return regions;
        }

        private List<string> GetProcessMemorySignatures(int processId)
        {
            var signatures = new List<string>();
            
            try
            {
                var process = Process.GetProcessById(processId);
                var modules = process.Modules;

                foreach (ProcessModule module in modules)
                {
                    signatures.Add(module.FileName);
                }
            }
            catch
            {
                signatures.Clear();
            }

            return signatures;
        }

        private Dictionary<string, object> GetSystemMemoryInfo()
        {
            var info = new Dictionary<string, object>();
            
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    var os = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
                    if (os != null)
                    {
                        info["TotalVisibleMemorySize"] = os["TotalVisibleMemorySize"];
                        info["FreePhysicalMemory"] = os["FreePhysicalMemory"];
                        info["TotalVirtualMemorySize"] = os["TotalVirtualMemorySize"];
                        info["FreeVirtualMemory"] = os["FreeVirtualMemory"];
                        info["SizeStoredInPagingFiles"] = os["SizeStoredInPagingFiles"];
                        info["FreeSpaceInPagingFiles"] = os["FreeSpaceInPagingFiles"];
                    }
                }
            }
            catch
            {
                info.Clear();
            }

            return info;
        }

        private List<string> GetSystemMemoryModules()
        {
            var modules = new List<string>();
            
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE '%Memory%'"))
                {
                    foreach (var module in searcher.Get())
                    {
                        modules.Add(module["Name"].ToString());
                    }
                }
            }
            catch
            {
                modules.Clear();
            }

            return modules;
        }

        private double CalculateMemoryScore(List<string> memoryRegions, List<string> memorySignatures)
        {
            double score = 0.0;

            try
            {
                score += AnalyzeMaliciousMemorySignatures(memorySignatures);
                score += AnalyzeSuspiciousMemorySignatures(memorySignatures);
                score += AnalyzeMemoryRegions(memoryRegions);
                score += AnalyzeBenignMemorySignatures(memorySignatures);
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double CalculateSystemMemoryScore(Dictionary<string, object> systemMemoryInfo, List<string> memoryModules)
        {
            double score = 0.0;

            try
            {
                if (systemMemoryInfo.ContainsKey("FreePhysicalMemory") && systemMemoryInfo.ContainsKey("TotalVisibleMemorySize"))
                {
                    ulong freeMemory = Convert.ToUInt64(systemMemoryInfo["FreePhysicalMemory"]);
                    ulong totalMemory = Convert.ToUInt64(systemMemoryInfo["TotalVisibleMemorySize"]);
                    double memoryUsage = 1.0 - (double)freeMemory / totalMemory;

                    if (memoryUsage > 0.9)
                    {
                        score += 0.1;
                    }
                }
            }
            catch
            {
                score = 0.0;
            }

            return Math.Max(0.0, Math.Min(score, 1.0));
        }

        private double AnalyzeMaliciousMemorySignatures(List<string> memorySignatures)
        {
            double score = 0.0;

            foreach (var signatureCategory in maliciousMemorySignatures)
            {
                foreach (var signature in signatureCategory.Value)
                {
                    if (memorySignatures.Any(s => s.Contains(signature, StringComparison.OrdinalIgnoreCase)))
                    {
                        score += 0.1;
                    }
                }
            }

            return score;
        }

        private double AnalyzeSuspiciousMemorySignatures(List<string> memorySignatures)
        {
            double score = 0.0;

            foreach (var signatureCategory in suspiciousMemorySignatures)
            {
                foreach (var signature in signatureCategory.Value)
                {
                    if (memorySignatures.Any(s => s.Contains(signature, StringComparison.OrdinalIgnoreCase)))
                    {
                        score += 0.05;
                    }
                }
            }

            return score;
        }

        private double AnalyzeBenignMemorySignatures(List<string> memorySignatures)
        {
            double score = 0.0;

            foreach (var signatureCategory in benignMemorySignatures)
            {
                foreach (var signature in signatureCategory.Value)
                {
                    if (memorySignatures.Any(s => s.Contains(signature, StringComparison.OrdinalIgnoreCase)))
                    {
                        score -= 0.03;
                    }
                }
            }

            return score;
        }

        private double AnalyzeMemoryRegions(List<string> memoryRegions)
        {
            double score = 0.0;

            foreach (var region in memoryRegions)
            {
                if (region.Contains("WorkingSet") && long.Parse(region.Split(':')[1].Trim()) > 1000000000)
                {
                    score += 0.05;
                }
                if (region.Contains("PrivateBytes") && long.Parse(region.Split(':')[1].Trim()) > 500000000)
                {
                    score += 0.05;
                }
            }

            return score;
        }

        private ScanResult CreateProcessScanResult(Process process, double memoryScore)
        {
            var result = new ScanResult
            {
                FilePath = process.MainModule?.FileName ?? process.ProcessName,
                IsInfected = memoryScore > 0.85,
                Confidence = memoryScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Memory"
            };

            if (result.IsInfected)
            {
                if (memoryScore > 0.95)
                {
                    result.ThreatName = "内存扫描检测到恶意进程";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "内存扫描检测到可疑进程";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"内存评分: {memoryScore:P}, 进程ID: {process.Id}, 进程名: {process.ProcessName}";
            }

            return result;
        }

        private ScanResult CreateSystemScanResult(double memoryScore)
        {
            var result = new ScanResult
            {
                FilePath = "System Memory",
                IsInfected = memoryScore > 0.85,
                Confidence = memoryScore,
                DetectionTime = DateTime.Now,
                DetectionMethod = "Memory"
            };

            if (result.IsInfected)
            {
                if (memoryScore > 0.95)
                {
                    result.ThreatName = "内存扫描检测到系统内存异常";
                    result.ThreatType = "Malware";
                    result.Severity = "High";
                }
                else
                {
                    result.ThreatName = "内存扫描检测到系统内存可疑";
                    result.ThreatType = "Suspicious";
                    result.Severity = "Medium";
                }

                result.AdditionalInfo = $"内存评分: {memoryScore:P}";
            }

            return result;
        }

        public void ClearCache()
        {
            processMemoryCache.Clear();
        }

        public int GetCacheSize()
        {
            return processMemoryCache.Count;
        }
    }
}
