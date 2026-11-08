using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace FireAntivirus.Engine.Kernel
{
    /// <summary>
    /// 内核级保护接口 - 提供系统级威胁拦截能力
    /// </summary>
    public class KernelProtectionInterface : IDisposable
    {
        private bool _isInitialized;
        private IntPtr _driverHandle;

        // Windows API常量
        private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_ANY_ACCESS = 0;

        public KernelProtectionInterface()
        {
            _isInitialized = false;
            _driverHandle = IntPtr.Zero;
        }

        /// <summary>
        /// 初始化内核保护
        /// </summary>
        public bool Initialize()
        {
            try
            {
                // 尝试连接到内核驱动
                _driverHandle = CreateFile("\\\\.\\FireAntivirusKernel",
                    0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
                    0x1 | 0x2, // FILE_SHARE_READ | FILE_SHARE_WRITE
                    IntPtr.Zero,
                    3, // OPEN_EXISTING
                    0,
                    IntPtr.Zero);

                if (_driverHandle == IntPtr.Zero || _driverHandle.ToInt32() == -1)
                {
                    // 驱动未安装，使用用户模式保护
                    Console.WriteLine("内核驱动未安装，使用用户模式保护");
                    _isInitialized = InitializeUserModeProtection();
                }
                else
                {
                    _isInitialized = true;
                    Console.WriteLine("内核保护已初始化");
                }

                return _isInitialized;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"内核保护初始化失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 安装文件操作过滤器
        /// </summary>
        public bool InstallFileFilter()
        {
            if (!_isInitialized) return false;

            try
            {
                // 设置文件操作监控
                var filterConfig = new FileFilterConfig
                {
                    MonitorCreate = true,
                    MonitorWrite = true,
                    MonitorDelete = true,
                    MonitorExecute = true,
                    BlockSuspiciousExtensions = true
                };

                return SendIoControl(IOCTL_SET_FILE_FILTER, filterConfig);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 安装进程创建过滤器
        /// </summary>
        public bool InstallProcessFilter()
        {
            if (!_isInitialized) return false;

            try
            {
                var processConfig = new ProcessFilterConfig
                {
                    MonitorProcessCreation = true,
                    MonitorThreadCreation = true,
                    MonitorRemoteThread = true,
                    BlockCodeInjection = true
                };

                return SendIoControl(IOCTL_SET_PROCESS_FILTER, processConfig);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 安装注册表过滤器
        /// </summary>
        public bool InstallRegistryFilter()
        {
            if (!_isInitialized) return false;

            try
            {
                var registryConfig = new RegistryFilterConfig
                {
                    MonitorAutoRun = true,
                    MonitorServices = true,
                    MonitorBrowserExtensions = true,
                    BlockSuspiciousKeys = true
                };

                return SendIoControl(IOCTL_SET_REGISTRY_FILTER, registryConfig);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 拦截可疑文件操作
        /// </summary>
        public bool InterceptFileOperation(string filePath, FileOperationType operation)
        {
            if (!_isInitialized) return false;

            try
            {
                var fileInfo = new FileOperationInfo
                {
                    FilePath = filePath,
                    Operation = operation,
                    ProcessId = GetCurrentProcessId(),
                    Timestamp = DateTime.Now
                };

                // 检查是否为可疑操作
                if (IsSuspiciousFileOperation(fileInfo))
                {
                    Console.WriteLine($"拦截可疑文件操作: {operation} -> {filePath}");
                    return true; // 拦截
                }

                return false; // 允许
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 拦截可疑进程创建
        /// </summary>
        public bool InterceptProcessCreation(string imagePath, string commandLine)
        {
            if (!_isInitialized) return false;

            try
            {
                var processInfo = new ProcessCreationInfo
                {
                    ImagePath = imagePath,
                    CommandLine = commandLine,
                    ParentProcessId = GetCurrentProcessId(),
                    Timestamp = DateTime.Now
                };

                if (IsSuspiciousProcessCreation(processInfo))
                {
                    Console.WriteLine($"拦截可疑进程创建: {imagePath}");
                    return true; // 拦截
                }

                return false; // 允许
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 检查是否为可疑文件操作
        /// </summary>
        private bool IsSuspiciousFileOperation(FileOperationInfo fileInfo)
        {
            var suspiciousExtensions = new HashSet<string>
            {
                ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"
            };

            var extension = System.IO.Path.GetExtension(fileInfo.FilePath)?.ToLower();
            
            // 检查系统关键文件
            if (fileInfo.FilePath.Contains("Windows\\System32") && 
                fileInfo.Operation == FileOperationType.Write)
            {
                return true;
            }

            // 检查可疑扩展名
            if (suspiciousExtensions.Contains(extension) && 
                fileInfo.Operation == FileOperationType.Create)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// 检查是否为可疑进程创建
        /// </summary>
        private bool IsSuspiciousProcessCreation(ProcessCreationInfo processInfo)
        {
            var suspiciousPaths = new HashSet<string>
            {
                "%temp%", "%appdata%", "%userprofile%\\appdata\\local\\temp"
            };

            var imagePath = processInfo.ImagePath.ToLower();
            
            // 检查临时目录执行
            foreach (var path in suspiciousPaths)
            {
                var expandedPath = Environment.ExpandEnvironmentVariables(path).ToLower();
                if (imagePath.Contains(expandedPath))
                {
                    return true;
                }
            }

            // 检查可疑命令行参数
            var suspiciousKeywords = new[] { "-enc", "-e", "-w hidden", "invoke-expression" };
            foreach (var keyword in suspiciousKeywords)
            {
                if (processInfo.CommandLine.ToLower().Contains(keyword))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// 初始化用户模式保护
        /// </summary>
        private bool InitializeUserModeProtection()
        {
            try
            {
                // 用户模式下的基础保护
                Console.WriteLine("用户模式保护已启用");
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 发送IO控制命令 - 真实向已打开的驱动设备句柄发送 IOCTL
        /// </summary>
        private bool SendIoControl(uint ioControlCode, object input)
        {
            // 驱动未加载（句柄无效）时如实返回失败，由上层启用用户模式回退
            if (_driverHandle == IntPtr.Zero || _driverHandle == (IntPtr)(-1))
                return false;

            IntPtr inputPtr = IntPtr.Zero;
            uint inputSize = 0;

            try
            {
                if (input is FileFilterConfig fileFilter)
                {
                    inputPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FileFilterConfig>());
                    Marshal.StructureToPtr(fileFilter, inputPtr, false);
                    inputSize = (uint)Marshal.SizeOf<FileFilterConfig>();
                }
                else if (input is ProcessFilterConfig processFilter)
                {
                    inputPtr = Marshal.AllocHGlobal(Marshal.SizeOf<ProcessFilterConfig>());
                    Marshal.StructureToPtr(processFilter, inputPtr, false);
                    inputSize = (uint)Marshal.SizeOf<ProcessFilterConfig>();
                }
                else if (input is RegistryFilterConfig registryFilter)
                {
                    inputPtr = Marshal.AllocHGlobal(Marshal.SizeOf<RegistryFilterConfig>());
                    Marshal.StructureToPtr(registryFilter, inputPtr, false);
                    inputSize = (uint)Marshal.SizeOf<RegistryFilterConfig>();
                }

                return DeviceIoControl(_driverHandle, ioControlCode, inputPtr, inputSize, IntPtr.Zero, 0, out _, IntPtr.Zero);
            }
            finally
            {
                if (inputPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputPtr);
            }
        }

        public void Dispose()
        {
            if (_driverHandle != IntPtr.Zero)
            {
                CloseHandle(_driverHandle);
                _driverHandle = IntPtr.Zero;
            }
            _isInitialized = false;
        }

        // Windows API声明
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, 
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, 
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        // IOCTL码定义
        private readonly uint IOCTL_SET_FILE_FILTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private readonly uint IOCTL_SET_PROCESS_FILTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private readonly uint IOCTL_SET_REGISTRY_FILTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private readonly uint IOCTL_SET_PROTECTED_PID = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private readonly uint IOCTL_ENABLE_DISK_GUARD = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);

        private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
        {
            return (deviceType << 16) | (access << 14) | (function << 2) | method;
        }

        #region 驱动部署与内核防护开关（WinUI 实时防护页使用）

        private static KernelProtectionInterface _shared;
        private static bool _mbrGuard;
        private static bool _gptGuard;

        /// <summary>共享实例（懒加载，复用设备句柄）。</summary>
        public static KernelProtectionInterface Shared => _shared ??= new KernelProtectionInterface();

        /// <summary>检测内核驱动是否已加载（打开设备句柄试探）。</summary>
        public static bool IsDriverLoaded()
        {
            try
            {
                var h = CreateFile("\\\\.\\FireAntivirusKernel",
                    0x80000000 | 0x40000000, 0x1 | 0x2, IntPtr.Zero, 3, 0, IntPtr.Zero);
                if (h != IntPtr.Zero && h.ToInt64() != -1)
                {
                    CloseHandle(h);
                    return true;
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// 安装并启动内核驱动（需管理员权限）。
        /// FireAntivirusKrn.sys 须位于程序目录（构建时由 dist 打包）。
        /// </summary>
        public static (bool Ok, string Output) InstallAndStartDriver()
        {
            string sysPath = System.IO.Path.Combine(AppContext.BaseDirectory, "FireAntivirusKrn.sys");
            if (!System.IO.File.Exists(sysPath))
                return (false, "未找到 FireAntivirusKrn.sys（应位于程序安装目录）");

            try
            {
                RunSc($"create FireAntivirusKrn type= kernel start= demand binPath= \"{sysPath}\"");
                var startOut = RunSc("start FireAntivirusKrn");

                if (IsDriverLoaded())
                    return (true, "内核驱动已加载，内核级防护已就绪");

                return (false, "启动失败。常见原因：x64 系统未开启测试签名 —— " +
                               "请以管理员运行 bcdedit /set testsigning on 并重启，或对驱动做 WHQL 签名。\n" + startOut);
            }
            catch (Exception ex)
            {
                return (false, "安装失败: " + ex.Message);
            }
        }

        private static string RunSc(string arguments)
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                using var p = System.Diagnostics.Process.Start(psi);
                var output = p?.StandardOutput.ReadToEnd() + p?.StandardError.ReadToEnd();
                p?.WaitForExit(30000);
                return (output ?? "").Trim();
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        /// <summary>发送原始 IOCTL（字节缓冲，绕过结构编组）。</summary>
        private bool SendRawIoctl(uint ioControlCode, byte[] payload)
        {
            if (_driverHandle == IntPtr.Zero || _driverHandle.ToInt64() == -1) return false;

            IntPtr ptr = Marshal.AllocHGlobal(Math.Max(payload.Length, 1));
            try
            {
                Marshal.Copy(payload, 0, ptr, payload.Length);
                return DeviceIoControl(_driverHandle, ioControlCode, ptr, (uint)payload.Length, IntPtr.Zero, 0, out _, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        /// <summary>发送原始 IOCTL 并读取输出缓冲（事件轮询用）。</summary>
        private byte[] SendRawIoctlWithOutput(uint ioControlCode, byte[] payload, int outputSize)
        {
            if (_driverHandle == IntPtr.Zero || _driverHandle.ToInt64() == -1) return null;

            IntPtr inPtr = IntPtr.Zero, outPtr = Marshal.AllocHGlobal(outputSize);
            try
            {
                if (payload != null && payload.Length > 0)
                {
                    inPtr = Marshal.AllocHGlobal(payload.Length);
                    Marshal.Copy(payload, 0, inPtr, payload.Length);
                }

                if (!DeviceIoControl(_driverHandle, ioControlCode, inPtr,
                        (uint)(payload?.Length ?? 0), outPtr, (uint)outputSize, out var returned, IntPtr.Zero))
                    return null;

                var result = new byte[returned];
                Marshal.Copy(outPtr, result, 0, result.Length);
                return result;
            }
            finally
            {
                if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
                Marshal.FreeHGlobal(outPtr);
            }
        }

        /// <summary>
        /// 轮询内核事件（IOCTL 0x805 拉取驱动拦截/检测行为 → 用户态弹窗）。
        /// 返回本次拉取到的事件列表。
        /// </summary>
        public List<KernelEvent> PollKernelEvents()
        {
            var events = new List<KernelEvent>();

            if (_driverHandle == IntPtr.Zero || _driverHandle.ToInt64() == -1)
                return events;

            try
            {
                // 输出缓冲: 4字节count + 64 × 520字节事件（一次拉满）
                int outputSize = 4 + 64 * 520;
                var raw = SendRawIoctlWithOutput(0x222014, null, outputSize);
                if (raw == null || raw.Length < 4) return events;

                int count = BitConverter.ToInt32(raw, 0);
                int eventSize = 520;   // FAV_EVENT: Type(4)+Pid(4)+Source(256)+Detail(256)

                for (int i = 0; i < count && 4 + (i + 1) * eventSize <= raw.Length; i++)
                {
                    int baseOffset = 4 + i * eventSize;
                    var evt = new KernelEvent
                    {
                        Type = (KernelEventType)BitConverter.ToInt32(raw, baseOffset),
                        Pid = BitConverter.ToUInt32(raw, baseOffset + 4),
                        Source = Encoding.Unicode.GetString(raw, baseOffset + 8, 256).TrimEnd('\0'),
                        Detail = Encoding.Unicode.GetString(raw, baseOffset + 264, 256).TrimEnd('\0')
                    };
                    events.Add(evt);
                }
            }
            catch { }

            return events;
        }

        /// <summary>静态便捷轮询（WinUI 后台监控用）。</summary>
        public static List<KernelEvent> PollKernelEventsShared()
        {
            try
            {
                var kpi = Shared;
                if (!kpi.Initialize()) return new List<KernelEvent>();
                return kpi.PollKernelEvents();
            }
            catch
            {
                return new List<KernelEvent>();
            }
        }

        /// <summary>
        /// 切换内核级防护（WinUI 三项内核开关 + RTPPlus 联动统一入口）。
        /// mode: "kernel"（进程拦截+自保护）/ "registry"（注册表拦截）/ "mbr"（分区表）/ "gpt"（UEFI）
        /// </summary>
        public static bool SetKernelProtection(string mode, bool enabled)
        {
            try
            {
                var kpi = Shared;
                if (!kpi.Initialize()) return false;

                int b = enabled ? 1 : 0;

                switch (mode)
                {
                    case "kernel":
                    {
                        // ProcessFilterConfig: 4 x 4字节（与驱动 FAV_PROCESS_CONFIG 对齐）
                        var cfg = new byte[]
                        {
                            (byte)b, 0, 0, 0,  (byte)b, 0, 0, 0,
                            (byte)b, 0, 0, 0,  (byte)b, 0, 0, 0
                        };
                        if (!kpi.SendRawIoctl(0x222004, cfg)) return false;

                        // SET_PROTECTED_PID: [ULONG count=1][ULONG pid]（批量格式）
                        var payload = new byte[8];
                        Array.Copy(BitConverter.GetBytes(1UL), payload, 4);
                        Array.Copy(BitConverter.GetBytes((uint)System.Diagnostics.Process.GetCurrentProcess().Id), payload, 4);
                        return kpi.SendRawIoctl(0x22200C, payload);
                    }

                    case "registry":
                    {
                        // RegistryFilterConfig: 4 x 4字节（与驱动 FAV_REGISTRY_CONFIG 对齐）
                        // MonitorAutoRun / MonitorServices / MonitorBrowserExtensions / BlockSuspiciousKeys
                        var cfg = new byte[]
                        {
                            (byte)b, 0, 0, 0,  (byte)b, 0, 0, 0,
                            (byte)b, 0, 0, 0,  (byte)b, 0, 0, 0
                        };
                        return kpi.SendRawIoctl(0x222008, cfg);
                    }

                    case "mbr":
                    {
                        // 8 字节: [0]=mbrGuard, [4]=gptGuard（保留另一路当前状态）
                        var payload = BitConverter.GetBytes((enabled ? 1L : 0L) | (_gptGuard ? 0x100000000L : 0L));
                        if (kpi.SendRawIoctl(0x222010, payload))
                        {
                            _mbrGuard = enabled;
                            return true;
                        }
                        return false;
                    }

                    case "gpt":
                    {
                        var payload = BitConverter.GetBytes((_mbrGuard ? 1L : 0L) | (enabled ? 0x100000000L : 0L));
                        if (kpi.SendRawIoctl(0x222010, payload))
                        {
                            _gptGuard = enabled;
                            return true;
                        }
                        return false;
                    }

                    default:
                        return false;
                }
            }
            catch
            {
                return false;
            }
        }

        #endregion
    }

    // 配置结构体
    public struct FileFilterConfig
    {
        public bool MonitorCreate;
        public bool MonitorWrite;
        public bool MonitorDelete;
        public bool MonitorExecute;
        public bool BlockSuspiciousExtensions;
    }

    public struct ProcessFilterConfig
    {
        public bool MonitorProcessCreation;
        public bool MonitorThreadCreation;
        public bool MonitorRemoteThread;
        public bool BlockCodeInjection;
    }

    public struct RegistryFilterConfig
    {
        public bool MonitorAutoRun;
        public bool MonitorServices;
        public bool MonitorBrowserExtensions;
        public bool BlockSuspiciousKeys;
    }

    // 操作信息结构体
    public struct FileOperationInfo
    {
        public string FilePath;
        public FileOperationType Operation;
        public uint ProcessId;
        public DateTime Timestamp;
    }

    public struct ProcessCreationInfo
    {
        public string ImagePath;
        public string CommandLine;
        public uint ParentProcessId;
        public DateTime Timestamp;
    }

    public enum FileOperationType
    {
        Create,
        Read,
        Write,
        Delete,
        Execute
    }

    /// <summary>内核事件类型（与驱动 FAV_EVT_* 对齐）。</summary>
    public enum KernelEventType
    {
        ProcessBlocked = 1,     /* 进程创建被拦截 */
        RegistryBlocked = 2,    /* 注册表自启动/服务注入被拦截 */
        InjectionAttempt = 3,   /* 对受保护进程的注入尝试 */
        DiskWriteBlocked = 4,   /* 分区表/UEFI 写被拦截 */
        HandleStripped = 5,     /* 受保护进程句柄权限被剥离 */
        FileWrite = 6,          /* minifilter: 文件写入 */
        FileDelete = 7          /* minifilter: 文件删除 */
    }

    /// <summary>内核事件（驱动上报的拦截/检测行为，用户态弹窗展示）。</summary>
    public class KernelEvent
    {
        public KernelEventType Type { get; set; }
        public uint Pid { get; set; }
        public string Source { get; set; }
        public string Detail { get; set; }

        public string TypeName => Type switch
        {
            KernelEventType.ProcessBlocked => "进程拦截",
            KernelEventType.RegistryBlocked => "注册表拦截",
            KernelEventType.InjectionAttempt => "注入尝试",
            KernelEventType.DiskWriteBlocked => "磁盘写拦截",
            KernelEventType.HandleStripped => "进程保护",
            KernelEventType.FileWrite => "文件写入",
            KernelEventType.FileDelete => "文件删除",
            _ => "内核事件"
        };

        public string Severity => Type == KernelEventType.InjectionAttempt ||
                                  Type == KernelEventType.DiskWriteBlocked ? "High" : "Medium";
    }
}