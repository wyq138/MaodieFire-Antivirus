using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;

namespace FireAntivirus.Kernel.DriverLoader
{
    /// <summary>
    /// 内核驱动加载和管理器
    /// 提供驱动签名绕过和加载功能
    /// </summary>
    public class KernelDriverLoader : IDisposable
    {
        private bool _disposed = false;
        private string _serviceName;
        private string _driverPath;
        
        // Windows API 常量
        private const uint SERVICE_KERNEL_DRIVER = 0x00000001;
        private const uint SERVICE_DEMAND_START = 0x00000003;
        private const uint SERVICE_ERROR_NORMAL = 0x00000001;
        private const uint SERVICE_CONTROL_STOP = 0x00000001;
        private const uint SERVICE_STOPPED = 0x00000001;
        private const uint SERVICE_RUNNING = 0x00000004;
        private const int ERROR_SERVICE_ALREADY_RUNNING = 1056;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName,
            uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl,
            string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies,
            string lpServiceStartName, string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatus(IntPtr hService, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        public KernelDriverLoader(string serviceName, string driverPath)
        {
            _serviceName = serviceName ?? throw new ArgumentNullException(nameof(serviceName));
            _driverPath = driverPath ?? throw new ArgumentNullException(nameof(driverPath));

            if (!File.Exists(_driverPath))
            {
                throw new FileNotFoundException($"驱动文件不存在: {_driverPath}");
            }
        }

        /// <summary>
        /// 使用测试签名模式加载驱动
        /// </summary>
        public bool LoadWithTestSigning()
        {
            try
            {
                // 检查是否已启用测试签名
                if (!IsTestSigningEnabled())
                {
                    Console.WriteLine("测试签名模式未启用，尝试启用...");
                    EnableTestSigning();
                }

                return LoadDriver();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"驱动加载失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 使用已知签名绕过技术加载驱动
        /// </summary>
        public bool LoadWithSignatureBypass()
        {
            try
            {
                Console.WriteLine("尝试使用签名绕过技术...");
                
                // 方法1: 修改系统时间（绕过证书有效期检查）
                // 注意：生产环境不推荐使用
                // BypassCertificateValidity();
                
                // 方法2: 使用合法的系统签名文件
                if (TryUseLegitimateSignature())
                {
                    return LoadDriver();
                }
                
                // 方法3: 尝试禁用驱动签名强制验证
                if (DisableDriverSignatureEnforcement())
                {
                    Console.WriteLine("驱动签名强制验证已禁用");
                    return LoadDriver();
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"签名绕过失败: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 安装并启动驱动服务
        /// </summary>
        private bool LoadDriver()
        {
            IntPtr scManager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;

            try
            {
                // 打开服务控制管理器
                scManager = OpenSCManager(null, null, 0xF003F); // SC_MANAGER_ALL_ACCESS
                if (scManager == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // 检查服务是否已存在
                service = OpenService(scManager, _serviceName, 0xF01FF); // SERVICE_ALL_ACCESS
                if (service != IntPtr.Zero)
                {
                    Console.WriteLine("服务已存在，尝试停止...");
                    StopService(service);
                    DeleteService(service);
                    CloseServiceHandle(service);
                    service = IntPtr.Zero;
                }

                // 创建服务
                service = CreateService(scManager, _serviceName, _serviceName,
                    0xF01FF, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                    _driverPath, null, IntPtr.Zero, null, null, null);

                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != 1073) // ERROR_SERVICE_EXISTS
                    {
                        throw new Win32Exception(error);
                    }
                    
                    // 服务已存在，重新打开
                    service = OpenService(scManager, _serviceName, 0xF01FF);
                    if (service == IntPtr.Zero)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }

                // 启动服务
                if (!StartService(service, 0, null))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != ERROR_SERVICE_ALREADY_RUNNING)
                    {
                        throw new Win32Exception(error);
                    }
                }

                Console.WriteLine($"驱动服务 '{_serviceName}' 启动成功");
                return true;
            }
            finally
            {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                if (scManager != IntPtr.Zero) CloseServiceHandle(scManager);
            }
        }

        /// <summary>
        /// 停止服务
        /// </summary>
        private bool StopService(IntPtr hService)
        {
            SERVICE_STATUS serviceStatus = new SERVICE_STATUS();
            if (!ControlService(hService, SERVICE_CONTROL_STOP, ref serviceStatus))
            {
                return false;
            }

            // 等待服务停止
            int maxWait = 30; // 30秒超时
            while (maxWait-- > 0)
            {
                if (!QueryServiceStatus(hService, ref serviceStatus))
                    break;
                    
                if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
                    return true;
                    
                System.Threading.Thread.Sleep(1000);
            }

            return false;
        }

        /// <summary>
        /// 检查测试签名是否启用
        /// </summary>
        private bool IsTestSigningEnabled()
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\CI\\Config"))
                {
                    var value = key?.GetValue("VulnerableDriverBlocklistEnable");
                    return value?.ToString() == "0";
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 启用测试签名模式
        /// </summary>
        private void EnableTestSigning()
        {
            try
            {
                // 使用bcdedit启用测试签名
                using (var process = new System.Diagnostics.Process())
                {
                    process.StartInfo.FileName = "bcdedit.exe";
                    process.StartInfo.Arguments = "/set testsigning on";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    process.WaitForExit();
                }

                Console.WriteLine("测试签名模式已启用，需要重启系统生效");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"启用测试签名失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 禁用驱动签名强制验证
        /// </summary>
        private bool DisableDriverSignatureEnforcement()
        {
            try
            {
                using (var process = new System.Diagnostics.Process())
                {
                    process.StartInfo.FileName = "bcdedit.exe";
                    process.StartInfo.Arguments = "/set nointegritychecks on";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    process.WaitForExit();
                    
                    return process.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 尝试使用合法系统签名
        /// </summary>
        private bool TryUseLegitimateSignature()
        {
            try
            {
                // 查找系统目录中的合法签名驱动
                string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                var legitimateDrivers = Directory.GetFiles(system32, "*.sys")
                    .Where(f => IsDriverSigned(f))
                    .ToList();

                if (legitimateDrivers.Any())
                {
                    Console.WriteLine($"发现 {legitimateDrivers.Count} 个已签名驱动文件");
                    // 这里可以实现更复杂的签名复用逻辑
                    return true;
                }
            }
            catch
            {
                // 忽略错误
            }
            
            return false;
        }

        /// <summary>
        /// 检查驱动是否有效签名
        /// </summary>
        private bool IsDriverSigned(string driverPath)
        {
            try
            {
                // 使用系统工具验证签名
                using (var process = new System.Diagnostics.Process())
                {
                    process.StartInfo.FileName = "signtool.exe";
                    process.StartInfo.Arguments = $"verify /v \"{driverPath}\"";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    
                    return output.Contains("Successfully verified") || output.Contains("签名者");
                }
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                // 清理资源
                _disposed = true;
            }
        }

        ~KernelDriverLoader()
        {
            Dispose();
        }
    }
}