using System;
using System.Runtime.InteropServices;

namespace FireAntivirus.Services
{
    // 防护状态枚举
    public enum KernelProtectionStatus
    {
        Disabled,
        Enabled,
        Error
    }

    // 进程防护策略结构体
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessProtectionPolicy
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool blockUnsignedProcesses;    // 阻止未签名进程

        [MarshalAs(UnmanagedType.U1)]
        public bool blockRemoteThreads;        // 阻止远程线程注入

        [MarshalAs(UnmanagedType.U1)]
        public bool blockDllInjection;         // 阻止DLL注入

        [MarshalAs(UnmanagedType.U1)]
        public bool blockProcessHollowing;     // 阻止进程空洞攻击

        [MarshalAs(UnmanagedType.U1)]
        public bool monitorProcessCreation;    // 监控进程创建

        [MarshalAs(UnmanagedType.U1)]
        public bool monitorProcessTermination; // 监控进程终止
    }

    // C++内核防护模块的包装类
    public class FireAntivirusKernelWrapper
    {
        private const string KernelDllPath = "FireAntivirus.Kernel.dll";

        // 导出函数声明
        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        private static extern IntPtr CreateFireAntivirusKernel();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        private static extern void DestroyFireAntivirusKernel(IntPtr instance);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        private static extern KernelProtectionStatus GetProtectionStatus();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnableProtection();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DisableProtection();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetProcessProtectionPolicy(ref ProcessProtectionPolicy policy);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        private static extern void GetProcessProtectionPolicy(ref ProcessProtectionPolicy policy);

        // 内核驱动管理
        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeLoadKernelDriver([MarshalAs(UnmanagedType.LPWStr)] string driverPath, [MarshalAs(UnmanagedType.LPWStr)] string serviceName);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeUnloadKernelDriver([MarshalAs(UnmanagedType.LPWStr)] string serviceName);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeIsKernelDriverLoaded([MarshalAs(UnmanagedType.LPWStr)] string serviceName);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeIsKernelDriverTrusted([MarshalAs(UnmanagedType.LPWStr)] string driverPath);

        // 系统调用挂钩
        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeEnableSystemCallHooking();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeDisableSystemCallHooking();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeIsSystemCallHookingEnabled();

        // 内存保护
        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeProtectProcessMemory(uint processId);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeUnprotectProcessMemory(uint processId);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeIsProcessMemoryProtected(uint processId);

        // 文件系统过滤
        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeEnableFileSystemFilter();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeDisableFileSystemFilter();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeIsFileSystemFilterEnabled();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeBlockFilepath([MarshalAs(UnmanagedType.LPWStr)] string filepath);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeAllowFilepath([MarshalAs(UnmanagedType.LPWStr)] string filepath);

        // 网络过滤
        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeEnableNetworkFilter();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeDisableNetworkFilter();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeIsNetworkFilterEnabled();

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeBlockIpAddress([MarshalAs(UnmanagedType.LPStr)] string ipAddress);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeAllowIpAddress([MarshalAs(UnmanagedType.LPStr)] string ipAddress);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeBlockUrl([MarshalAs(UnmanagedType.LPWStr)] string url);

        [DllImport(KernelDllPath, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool NativeAllowUrl([MarshalAs(UnmanagedType.LPWStr)] string url);

        private IntPtr kernelInstance;
        private bool isInitialized;

        // 单例实例
        private static FireAntivirusKernelWrapper instance;
        private static readonly object lockObject = new object();

        // 私有构造函数
        private FireAntivirusKernelWrapper()
        {
            try
            {
                // 创建内核实例
                kernelInstance = CreateFireAntivirusKernel();
                isInitialized = (kernelInstance != IntPtr.Zero);
            }
            catch
            {
                isInitialized = false;
            }
        }

        // 获取单例实例
        public static FireAntivirusKernelWrapper Instance
        {
            get
            {
                if (instance == null)
                {
                    lock (lockObject)
                    {
                        if (instance == null)
                        {
                            instance = new FireAntivirusKernelWrapper();
                        }
                    }
                }
                return instance;
            }
        }

        // 检查是否已初始化
        public bool IsInitialized
        {
            get { return isInitialized; }
        }

        // 获取防护状态
        public KernelProtectionStatus GetStatus()
        {
            if (!isInitialized)
                return KernelProtectionStatus.Error;

            try
            {
                return GetProtectionStatus();
            }
            catch
            {
                return KernelProtectionStatus.Error;
            }
        }

        // 启用防护
        public bool Enable()
        {
            if (!isInitialized)
                return false;

            try
            {
                return EnableProtection();
            }
            catch
            {
                return false;
            }
        }

        // 禁用防护
        public bool Disable()
        {
            if (!isInitialized)
                return false;

            try
            {
                return DisableProtection();
            }
            catch
            {
                return false;
            }
        }

        // 设置进程防护策略
        public bool SetPolicy(ProcessProtectionPolicy policy)
        {
            if (!isInitialized)
                return false;

            try
            {
                return SetProcessProtectionPolicy(ref policy);
            }
            catch
            {
                return false;
            }
        }

        // 获取进程防护策略
        public ProcessProtectionPolicy GetPolicy()
        {
            ProcessProtectionPolicy policy = new ProcessProtectionPolicy();

            if (isInitialized)
            {
                try
                {
                    GetProcessProtectionPolicy(ref policy);
                }
                catch
                {
                    // 使用默认策略
                    policy.blockUnsignedProcesses = true;
                    policy.blockRemoteThreads = true;
                    policy.blockDllInjection = true;
                    policy.blockProcessHollowing = true;
                    policy.monitorProcessCreation = true;
                    policy.monitorProcessTermination = true;
                }
            }
            else
            {
                // 使用默认策略
                policy.blockUnsignedProcesses = true;
                policy.blockRemoteThreads = true;
                policy.blockDllInjection = true;
                policy.blockProcessHollowing = true;
                policy.monitorProcessCreation = true;
                policy.monitorProcessTermination = true;
            }

            return policy;
        }

        // 内核驱动管理
        public bool LoadKernelDriver(string driverPath, string serviceName)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeLoadKernelDriver(driverPath, serviceName);
            }
            catch
            {
                return false;
            }
        }

        public bool UnloadKernelDriver(string serviceName)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeUnloadKernelDriver(serviceName);
            }
            catch
            {
                return false;
            }
        }

        public bool IsKernelDriverLoaded(string serviceName)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeIsKernelDriverLoaded(serviceName);
            }
            catch
            {
                return false;
            }
        }

        public bool IsKernelDriverTrusted(string driverPath)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeIsKernelDriverTrusted(driverPath);
            }
            catch
            {
                return false;
            }
        }

        // 系统调用挂钩
        public bool EnableSystemCallHooking()
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeEnableSystemCallHooking();
            }
            catch
            {
                return false;
            }
        }

        public bool DisableSystemCallHooking()
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeDisableSystemCallHooking();
            }
            catch
            {
                return false;
            }
        }

        public bool IsSystemCallHookingEnabled()
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeIsSystemCallHookingEnabled();
            }
            catch
            {
                return false;
            }
        }

        // 内存保护
        public bool ProtectProcessMemory(uint processId)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeProtectProcessMemory(processId);
            }
            catch
            {
                return false;
            }
        }

        public bool UnprotectProcessMemory(uint processId)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeUnprotectProcessMemory(processId);
            }
            catch
            {
                return false;
            }
        }

        public bool IsProcessMemoryProtected(uint processId)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeIsProcessMemoryProtected(processId);
            }
            catch
            {
                return false;
            }
        }

        // 文件系统过滤
        public bool EnableFileSystemFilter()
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeEnableFileSystemFilter();
            }
            catch
            {
                return false;
            }
        }

        public bool DisableFileSystemFilter()
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeDisableFileSystemFilter();
            }
            catch
            {
                return false;
            }
        }

        public bool IsFileSystemFilterEnabled()
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeIsFileSystemFilterEnabled();
            }
            catch
            {
                return false;
            }
        }

        public bool BlockFilepath(string filepath)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeBlockFilepath(filepath);
            }
            catch
            {
                return false;
            }
        }

        public bool AllowFilepath(string filepath)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeAllowFilepath(filepath);
            }
            catch
            {
                return false;
            }
        }

        // 网络过滤
        public bool EnableNetworkFilter()
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeEnableNetworkFilter();
            }
            catch
            {
                return false;
            }
        }

        public bool DisableNetworkFilter()
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeDisableNetworkFilter();
            }
            catch
            {
                return false;
            }
        }

        public bool IsNetworkFilterEnabled()
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeIsNetworkFilterEnabled();
            }
            catch
            {
                return false;
            }
        }

        public bool BlockIpAddress(string ipAddress)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeBlockIpAddress(ipAddress);
            }
            catch
            {
                return false;
            }
        }

        public bool AllowIpAddress(string ipAddress)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeAllowIpAddress(ipAddress);
            }
            catch
            {
                return false;
            }
        }

        public bool BlockUrl(string url)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeBlockUrl(url);
            }
            catch
            {
                return false;
            }
        }

        public bool AllowUrl(string url)
        {
            if (!isInitialized)
                return false;

            try
            {
                return NativeAllowUrl(url);
            }
            catch
            {
                return false;
            }
        }

        // 清理
        public void Dispose()
        {
            if (isInitialized && kernelInstance != IntPtr.Zero)
            {
                try
                {
                    DestroyFireAntivirusKernel(kernelInstance);
                }
                catch
                {
                }
                finally
                {
                    kernelInstance = IntPtr.Zero;
                    isInitialized = false;
                }
            }
        }
    }
}
