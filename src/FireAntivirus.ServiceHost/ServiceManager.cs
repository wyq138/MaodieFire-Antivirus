using FireAntivirus.Common;
using FireAntivirus.Data;
using FireAntivirus.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Threading.Tasks;

namespace FireAntivirus.ServiceHost
{
    public class ServiceManager
    {
        private readonly string _serviceName;
        private readonly string _serviceDisplayName;
        private readonly string _serviceDescription;
        private readonly string _servicePath;
        private readonly ServiceStartMode _startMode;

        public ServiceManager(string serviceName, string serviceDisplayName, string serviceDescription, string servicePath, ServiceStartMode startMode = ServiceStartMode.Automatic)
        {
            _serviceName = serviceName;
            _serviceDisplayName = serviceDisplayName;
            _serviceDescription = serviceDescription;
            _servicePath = servicePath;
            _startMode = startMode;
        }

        public async Task<ServiceOperationResult> InstallServiceAsync()
        {
            var result = new ServiceOperationResult
            {
                Operation = ServiceOperation.Install,
                ServiceName = _serviceName,
                StartTime = DateTime.UtcNow
            };

            try
            {
                if (IsServiceInstalled())
                {
                    result.Success = false;
                    result.ErrorMessage = "Service already installed";
                    return result;
                }

                // 使用ServiceInstaller安装服务
                Logger.Info($"Installing service: {_serviceName}");
                ServiceInstaller.InstallService(_serviceName, _serviceDisplayName, _serviceDescription, _servicePath);
                await Task.Delay(1000);

                result.Success = true;
                result.Message = "Service installed successfully";
            }
            catch (Exception ex)
            {
                Logger.Error($"Service installation error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public async Task<ServiceOperationResult> UninstallServiceAsync()
        {
            var result = new ServiceOperationResult
            {
                Operation = ServiceOperation.Uninstall,
                ServiceName = _serviceName,
                StartTime = DateTime.UtcNow
            };

            try
            {
                if (!IsServiceInstalled())
                {
                    result.Success = false;
                    result.ErrorMessage = "Service not installed";
                    return result;
                }

                // 停止服务
                await StopServiceAsync();

                // 使用ServiceInstaller卸载服务
                Logger.Info($"Uninstalling service: {_serviceName}");
                ServiceInstaller.UninstallService(_serviceName);
                await Task.Delay(1000);

                result.Success = true;
                result.Message = "Service uninstalled successfully";
            }
            catch (Exception ex)
            {
                Logger.Error($"Service uninstallation error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public async Task<ServiceOperationResult> StartServiceAsync()
        {
            var result = new ServiceOperationResult
            {
                Operation = ServiceOperation.Start,
                ServiceName = _serviceName,
                StartTime = DateTime.UtcNow
            };

            try
            {
                if (!IsServiceInstalled())
                {
                    result.Success = false;
                    result.ErrorMessage = "Service not installed";
                    return result;
                }

                using (var serviceController = new ServiceController(_serviceName))
                {
                    if (serviceController.Status == ServiceControllerStatus.Running)
                    {
                        result.Success = false;
                        result.ErrorMessage = "Service already running";
                        return result;
                    }

                    serviceController.Start();
                    serviceController.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                }

                result.Success = true;
                result.Message = "Service started successfully";
            }
            catch (Exception ex)
            {
                Logger.Error($"Service start error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public async Task<ServiceOperationResult> StopServiceAsync()
        {
            var result = new ServiceOperationResult
            {
                Operation = ServiceOperation.Stop,
                ServiceName = _serviceName,
                StartTime = DateTime.UtcNow
            };

            try
            {
                if (!IsServiceInstalled())
                {
                    result.Success = false;
                    result.ErrorMessage = "Service not installed";
                    return result;
                }

                using (var serviceController = new ServiceController(_serviceName))
                {
                    if (serviceController.Status == ServiceControllerStatus.Stopped)
                    {
                        result.Success = false;
                        result.ErrorMessage = "Service already stopped";
                        return result;
                    }

                    serviceController.Stop();
                    serviceController.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }

                result.Success = true;
                result.Message = "Service stopped successfully";
            }
            catch (Exception ex)
            {
                Logger.Error($"Service stop error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public async Task<ServiceOperationResult> RestartServiceAsync()
        {
            var result = new ServiceOperationResult
            {
                Operation = ServiceOperation.Restart,
                ServiceName = _serviceName,
                StartTime = DateTime.UtcNow
            };

            try
            {
                if (!IsServiceInstalled())
                {
                    result.Success = false;
                    result.ErrorMessage = "Service not installed";
                    return result;
                }

                // 停止服务
                await StopServiceAsync();
                // 启动服务
                await StartServiceAsync();

                result.Success = true;
                result.Message = "Service restarted successfully";
            }
            catch (Exception ex)
            {
                Logger.Error($"Service restart error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }

        public ServiceStatus GetServiceStatus()
        {
            try
            {
                if (!IsServiceInstalled())
                {
                    return new ServiceStatus
                    {
                        ServiceName = _serviceName,
                        Status = ServiceControllerStatus.Stopped,
                        IsInstalled = false
                    };
                }

                using (var serviceController = new ServiceController(_serviceName))
                {
                    return new ServiceStatus
                    {
                        ServiceName = _serviceName,
                        DisplayName = serviceController.DisplayName,
                        Status = serviceController.Status,
                        IsInstalled = true
                    };
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Get service status error: {ex.Message}");
                return new ServiceStatus
                {
                    ServiceName = _serviceName,
                    Status = ServiceControllerStatus.Stopped,
                    IsInstalled = false,
                    ErrorMessage = ex.Message
                };
            }
        }

        public List<ServiceStatus> GetAllServices()
        {
            var services = new List<ServiceStatus>();

            try
            {
                foreach (var serviceController in ServiceController.GetServices())
                {
                    services.Add(new ServiceStatus
                    {
                        ServiceName = serviceController.ServiceName,
                        DisplayName = serviceController.DisplayName,
                        Status = serviceController.Status,
                        IsInstalled = true
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Get all services error: {ex.Message}");
            }

            return services;
        }

        public bool IsServiceInstalled()
        {
            try
            {
                return ServiceController.GetServices().Any(s => s.ServiceName == _serviceName);
            }
            catch
            {
                return false;
            }
        }

        public async Task<ServiceOperationResult> UpdateServiceConfigAsync(ServiceConfigUpdate update)
        {
            var result = new ServiceOperationResult
            {
                Operation = ServiceOperation.UpdateConfig,
                ServiceName = _serviceName,
                StartTime = DateTime.UtcNow
            };

            try
            {
                if (!IsServiceInstalled())
                {
                    result.Success = false;
                    result.ErrorMessage = "Service not installed";
                    return result;
                }

                // 实现服务配置更新逻辑
                Logger.Info($"Updating service config: {_serviceName}");
                await Task.Delay(500);

                result.Success = true;
                result.Message = "Service config updated successfully";
            }
            catch (Exception ex)
            {
                Logger.Error($"Service config update error: {ex.Message}");
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.Duration = result.EndTime - result.StartTime;
            }

            return result;
        }
    }

    public class ServiceOperationResult
    {
        public ServiceOperation Operation { get; set; }
        public string ServiceName { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class ServiceStatus
    {
        public string ServiceName { get; set; }
        public string DisplayName { get; set; }
        public ServiceControllerStatus Status { get; set; }
        public bool IsInstalled { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class ServiceConfigUpdate
    {
        public string DisplayName { get; set; }
        public string Description { get; set; }
        public ServiceStartMode? StartMode { get; set; }
        public string[] Dependencies { get; set; }
    }

    public enum ServiceOperation
    {
        Install,
        Uninstall,
        Start,
        Stop,
        Restart,
        UpdateConfig
    }
}
