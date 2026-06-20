using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.ServiceProcess;

namespace FireAntivirus.Host.Services
{
    /// <summary>
    /// 服务自动安装器 - 自动安装Windows服务
    /// </summary>
    public class ServiceAutoInstaller
    {
        private const string ServiceName = "FireAntivirusWatchdog";
        private const string DisplayName = "耄耋杀毒 实时防护服务";
        private const string Description = "提供实时病毒防护和进程保护服务，防止杀毒程序被恶意软件终止";
        
        /// <summary>
        /// 服务状态变化事件
        /// </summary>
        public event EventHandler<string>? StatusChanged;
        
        /// <summary>
        /// 确保服务已安装并运行
        /// </summary>
        public void EnsureServiceInstalled()
        {
            try
            {
                // 检查服务是否已安装
                if (IsServiceInstalled())
                {
                    StatusChanged?.Invoke(this, "服务已安装");
                    
                    // 检查服务是否正在运行
                    if (!IsServiceRunning())
                    {
                        StartService();
                    }
                    return;
                }
                
                // 检查管理员权限
                if (!IsAdministrator())
                {
                    StatusChanged?.Invoke(this, "需要管理员权限安装服务");
                    RequestAdminPrivileges("-install-service");
                    return;
                }
                
                // 安装服务
                InstallService();
                
                // 启动服务
                StartService();
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"服务安装失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 检查服务是否已安装
        /// </summary>
        public bool IsServiceInstalled()
        {
            try
            {
                using (var sc = new ServiceController(ServiceName))
                {
                    var name = sc.ServiceName;
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// 检查服务是否正在运行
        /// </summary>
        public bool IsServiceRunning()
        {
            try
            {
                using (var sc = new ServiceController(ServiceName))
                {
                    return sc.Status == ServiceControllerStatus.Running;
                }
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// 检查是否以管理员身份运行
        /// </summary>
        public static bool IsAdministrator()
        {
            try
            {
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// 请求管理员权限
        /// </summary>
        public void RequestAdminPrivileges(string arguments)
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                var startInfo = new ProcessStartInfo
                {
                    FileName = currentProcess.MainModule?.FileName ?? Assembly.GetExecutingAssembly().Location,
                    Arguments = arguments,
                    Verb = "runas",  // 请求管理员权限
                    UseShellExecute = true
                };
                
                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"请求管理员权限失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 安装服务
        /// </summary>
        public bool InstallService()
        {
            try
            {
                // 获取服务可执行文件路径
                string? servicePath = GetServiceExecutablePath();
                if (string.IsNullOrEmpty(servicePath) || !File.Exists(servicePath))
                {
                    StatusChanged?.Invoke(this, "找不到服务程序文件");
                    return false;
                }
                
                StatusChanged?.Invoke(this, "正在安装服务...");
                
                // 使用sc.exe创建服务
                string quotedPath = $"\"{servicePath}\"";
                var startInfo = new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"create {ServiceName} binPath= {quotedPath} DisplayName= \"{DisplayName}\" start= auto",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                
                using (var process = Process.Start(startInfo))
                {
                    process?.WaitForExit();
                    if (process?.ExitCode != 0)
                    {
                        string error = process?.StandardError.ReadToEnd() ?? "Unknown error";
                        StatusChanged?.Invoke(this, $"创建服务失败: {error}");
                        return false;
                    }
                }
                
                // 设置服务描述
                startInfo.Arguments = $"description {ServiceName} \"{Description}\"";
                using (var process = Process.Start(startInfo))
                {
                    process?.WaitForExit();
                }
                
                // 设置服务失败后的恢复策略
                startInfo.Arguments = $"failure {ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000";
                using (var process = Process.Start(startInfo))
                {
                    process?.WaitForExit();
                }
                
                StatusChanged?.Invoke(this, "服务安装成功");
                return true;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"安装服务失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 卸载服务
        /// </summary>
        public bool UninstallService()
        {
            try
            {
                if (!IsServiceInstalled())
                {
                    return true;
                }
                
                // 先停止服务
                StopService();
                
                StatusChanged?.Invoke(this, "正在卸载服务...");
                
                // 使用sc.exe删除服务
                var startInfo = new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"delete {ServiceName}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                
                using (var process = Process.Start(startInfo))
                {
                    process?.WaitForExit();
                    if (process?.ExitCode != 0)
                    {
                        return false;
                    }
                }
                
                StatusChanged?.Invoke(this, "服务已卸载");
                return true;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"卸载服务失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 启动服务
        /// </summary>
        public bool StartService()
        {
            try
            {
                if (!IsServiceInstalled())
                {
                    return false;
                }
                
                using (var sc = new ServiceController(ServiceName))
                {
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        return true;
                    }
                    
                    StatusChanged?.Invoke(this, "正在启动服务...");
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    
                    StatusChanged?.Invoke(this, "服务已启动");
                    return true;
                }
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"启动服务失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 停止服务
        /// </summary>
        public bool StopService()
        {
            try
            {
                if (!IsServiceInstalled())
                {
                    return true;
                }
                
                using (var sc = new ServiceController(ServiceName))
                {
                    if (sc.Status == ServiceControllerStatus.Stopped)
                    {
                        return true;
                    }
                    
                    StatusChanged?.Invoke(this, "正在停止服务...");
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                    
                    StatusChanged?.Invoke(this, "服务已停止");
                    return true;
                }
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"停止服务失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 获取服务可执行文件路径
        /// </summary>
        private string? GetServiceExecutablePath()
        {
            try
            {
                // 优先从libs目录查找
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string servicePath = Path.Combine(baseDir, "libs", "FireAntivirus.Service.exe");
                
                if (File.Exists(servicePath))
                {
                    return servicePath;
                }
                
                // 备用：查找根目录
                servicePath = Path.Combine(baseDir, "FireAntivirus.Service.exe");
                if (File.Exists(servicePath))
                {
                    return servicePath;
                }
                
                return null;
            }
            catch
            {
                return null;
            }
        }
    }
}
