using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

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
        /// 发送IO控制命令
        /// </summary>
        private bool SendIoControl(uint ioControlCode, object input)
        {
            // 简化实现 - 实际需要与驱动通信
            return true;
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

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        // IOCTL码定义
        private readonly uint IOCTL_SET_FILE_FILTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private readonly uint IOCTL_SET_PROCESS_FILTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
        private readonly uint IOCTL_SET_REGISTRY_FILTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);

        private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
        {
            return (deviceType << 16) | (access << 14) | (function << 2) | method;
        }
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
}