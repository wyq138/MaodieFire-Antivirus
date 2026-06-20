using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 服务管理器
    /// </summary>
    public static class ServiceManager
    {
        private const string ServiceName = "FireAntivirusService";
        private const string ServiceDisplayName = "Fire Antivirus Service";

        /// <summary>
        /// 安装服务
        /// </summary>
        /// <returns>是否安装成功</returns>
        public static bool InstallService()
        {
            try
            {
                // 获取服务可执行文件路径
                string serviceExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Service.exe");
                if (!File.Exists(serviceExePath))
                {
                    LogManager.LogError("Service executable not found: " + serviceExePath);
                    return false;
                }

                // 检查服务是否已存在
                if (IsServiceInstalled())
                {
                    LogManager.LogWarning("Service is already installed");
                    return true;
                }

                // 安装服务
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = serviceExePath;
                    process.StartInfo.Arguments = "-install";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        LogManager.LogInfo("Service installed successfully");
                        return true;
                    }
                    else
                    {
                        string errorOutput = process.StandardError.ReadToEnd();
                        LogManager.LogError("Failed to install service: " + errorOutput);
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager.LogError("Error installing service: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// 卸载服务
        /// </summary>
        /// <returns>是否卸载成功</returns>
        public static bool UninstallService()
        {
            try
            {
                // 检查服务是否存在
                if (!IsServiceInstalled())
                {
                    LogManager.LogWarning("Service is not installed");
                    return true;
                }

                // 获取服务可执行文件路径
                string serviceExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Service.exe");
                if (!File.Exists(serviceExePath))
                {
                    LogManager.LogError("Service executable not found: " + serviceExePath);
                    return false;
                }

                // 停止服务
                StopService();

                // 卸载服务
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = serviceExePath;
                    process.StartInfo.Arguments = "-uninstall";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        LogManager.LogInfo("Service uninstalled successfully");
                        return true;
                    }
                    else
                    {
                        string errorOutput = process.StandardError.ReadToEnd();
                        LogManager.LogError("Failed to uninstall service: " + errorOutput);
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager.LogError("Error uninstalling service: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// 启动服务
        /// </summary>
        /// <returns>是否启动成功</returns>
        public static bool StartService()
        {
            try
            {
                // 检查服务是否安装
                if (!IsServiceInstalled())
                {
                    LogManager.LogError("Service is not installed");
                    return false;
                }

                // 检查服务是否已启动
                if (IsServiceRunning())
                {
                    LogManager.LogWarning("Service is already running");
                    return true;
                }

                // 启动服务
                using (ServiceController serviceController = new ServiceController(ServiceName))
                {
                    serviceController.Start();
                    serviceController.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    
                    if (serviceController.Status == ServiceControllerStatus.Running)
                    {
                        LogManager.LogInfo("Service started successfully");
                        return true;
                    }
                    else
                    {
                        LogManager.LogError("Failed to start service. Current status: " + serviceController.Status);
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager.LogError("Error starting service: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// 停止服务
        /// </summary>
        /// <returns>是否停止成功</returns>
        public static bool StopService()
        {
            try
            {
                // 检查服务是否安装
                if (!IsServiceInstalled())
                {
                    LogManager.LogWarning("Service is not installed");
                    return true;
                }

                // 检查服务是否已停止
                if (!IsServiceRunning())
                {
                    LogManager.LogWarning("Service is not running");
                    return true;
                }

                // 停止服务
                using (ServiceController serviceController = new ServiceController(ServiceName))
                {
                    serviceController.Stop();
                    serviceController.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                    
                    if (serviceController.Status == ServiceControllerStatus.Stopped)
                    {
                        LogManager.LogInfo("Service stopped successfully");
                        return true;
                    }
                    else
                    {
                        LogManager.LogError("Failed to stop service. Current status: " + serviceController.Status);
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                LogManager.LogError("Error stopping service: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// 检查服务是否安装
        /// </summary>
        /// <returns>是否安装</returns>
        public static bool IsServiceInstalled()
        {
            try
            {
                using (ServiceController serviceController = new ServiceController(ServiceName))
                {
                    // 尝试获取服务状态，如果服务不存在会抛出异常
                    ServiceControllerStatus status = serviceController.Status;
                    return true;
                }
            }
            catch (InvalidOperationException)
            {
                // 服务不存在
                return false;
            }
            catch (Exception ex)
            {
                LogManager.LogError("Error checking service installation: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// 检查服务是否运行
        /// </summary>
        /// <returns>是否运行</returns>
        public static bool IsServiceRunning()
        {
            try
            {
                using (ServiceController serviceController = new ServiceController(ServiceName))
                {
                    return serviceController.Status == ServiceControllerStatus.Running;
                }
            }
            catch (Exception ex)
            {
                LogManager.LogError("Error checking service status: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// 获取服务状态
        /// </summary>
        /// <returns>服务状态</returns>
        public static ServiceControllerStatus GetServiceStatus()
        {
            try
            {
                using (ServiceController serviceController = new ServiceController(ServiceName))
                {
                    return serviceController.Status;
                }
            }
            catch (Exception ex)
            {
                LogManager.LogError("Error getting service status: " + ex.Message);
                return ServiceControllerStatus.Stopped;
            }
        }

        /// <summary>
        /// 运行服务（控制台模式）
        /// </summary>
        public static void RunServiceInConsole()
        {
            try
            {
                // 获取服务可执行文件路径
                string serviceExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Service.exe");
                if (!File.Exists(serviceExePath))
                {
                    LogManager.LogError("Service executable not found: " + serviceExePath);
                    return;
                }

                // 运行服务
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = serviceExePath;
                    process.StartInfo.Arguments = "-run";
                    process.StartInfo.UseShellExecute = true;
                    process.StartInfo.CreateNoWindow = false;
                    process.Start();
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                LogManager.LogError("Error running service in console: " + ex.Message);
            }
        }
    }
}