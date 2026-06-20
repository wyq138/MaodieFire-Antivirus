using System;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 实时防护管理器
    /// </summary>
    public class RealTimeProtectionManager : IDisposable
    {
        private readonly SecurityService _securityService;
        private bool _isInitialized;
        private bool _isRunning;
        private bool _isCoreAvailable = true;
        private readonly object _lock = new object();
        private CancellationTokenSource _cancellationTokenSource;
        private Task _monitoringTask;

        /// <summary>
        /// 威胁事件
        /// </summary>
        public event EventHandler<ThreatInfo> ThreatDetected;

        /// <summary>
        /// 状态变化事件
        /// </summary>
        public event EventHandler<ProtectionState> StatusChanged;

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="securityService">安全服务</param>
        public RealTimeProtectionManager(SecurityService securityService)
        {
            _securityService = securityService;
            _securityService.ThreatDetected += OnThreatDetected;
            _securityService.StatusChanged += OnStatusChanged;
        }

        /// <summary>
        /// 初始化实时防护
        /// </summary>
        /// <returns>是否初始化成功</returns>
        public bool Initialize()
        {
            lock (_lock)
            {
                if (_isInitialized)
                {
                    return true;
                }

                try
                {
                    // 初始化安全服务
                    if (!_securityService.IsInitialized)
                    {
                        if (!_securityService.Initialize())
                        {
                            LogManager.LogError("SecurityService initialization returned false");
                            return false;
                        }
                    }

                    // 加载配置
                    AppConfig config = ConfigManager.Config;

                    // 启用各防护模块
                    _securityService.EnableFileProtection(config.FileProtectionEnabled);
                    _securityService.EnableProcessProtection(config.ProcessProtectionEnabled);
                    _securityService.EnableDeviceProtection(config.DeviceProtectionEnabled);
                    _securityService.EnableRegistryProtection(config.RegistryProtectionEnabled);
                    _securityService.EnableBrowserProtection(config.BrowserProtectionEnabled);
                    _securityService.EnableScriptProtection(config.ScriptProtectionEnabled);
                    _securityService.EnableActiveDefense(config.ActiveDefenseEnabled);

                    _isInitialized = true;
                    LogManager.LogInfo("Real-time protection initialized");
                    return true;
                }
                catch (DllNotFoundException dllEx)
                {
                    _isCoreAvailable = false;
                    LogManager.LogError(
                        "[CRITICAL] Core DLL not found. Real-time protection is unavailable. " +
                        $"DLL: {dllEx.Message}. All protection features will be disabled.");
                    return false;
                }
                catch (Exception ex)
                {
                    LogManager.LogError("Failed to initialize real-time protection: " + ex.Message);
                    return false;
                }
            }
        }

        /// <summary>
        /// 启动实时防护
        /// </summary>
        /// <returns>是否启动成功</returns>
        public bool Start()
        {
            lock (_lock)
            {
                if (!_isCoreAvailable)
                {
                    LogManager.LogError("Cannot start protection: core DLL is not available");
                    return false;
                }

                if (!_isInitialized || _isRunning)
                {
                    return false;
                }

                try
                {
                    // 启动安全服务
                    if (!_securityService.Start())
                    {
                        return false;
                    }

                    // 启动监控任务
                    _cancellationTokenSource = new CancellationTokenSource();
                    _monitoringTask = Task.Run(() => MonitoringLoop(_cancellationTokenSource.Token), _cancellationTokenSource.Token);

                    _isRunning = true;
                    LogManager.LogInfo("Real-time protection started");
                    return true;
                }
                catch (Exception ex)
                {
                    LogManager.LogError("Failed to start real-time protection: " + ex.Message);
                    return false;
                }
            }
        }

        /// <summary>
        /// 停止实时防护
        /// </summary>
        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning)
                {
                    return;
                }

                try
                {
                    // 停止监控任务
                    if (_cancellationTokenSource != null)
                    {
                        _cancellationTokenSource.Cancel();
                        _monitoringTask?.Wait(1000);
                        _cancellationTokenSource.Dispose();
                        _cancellationTokenSource = null;
                    }

                    // 停止安全服务
                    _securityService.Stop();

                    _isRunning = false;
                    LogManager.LogInfo("Real-time protection stopped");
                }
                catch (Exception ex)
                {
                    LogManager.LogError("Failed to stop real-time protection: " + ex.Message);
                }
            }
        }

        /// <summary>
        /// 检查是否初始化
        /// </summary>
        public bool IsInitialized => _isInitialized;

        /// <summary>
        /// 检查是否运行
        /// </summary>
        public bool IsRunning => _isRunning;

        /// <summary>
        /// 检查核心 DLL 是否可用
        /// </summary>
        public bool IsCoreAvailable => _isCoreAvailable;

        /// <summary>
        /// 启用/禁用文件实时防护
        /// </summary>
        public bool EnableFileProtection(bool enable)
        {
            if (!_isCoreAvailable) return false;
            bool result = _securityService.EnableFileProtection(enable);
            if (result)
            {
                // 更新配置
                AppConfig config = ConfigManager.Config;
                config.FileProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"File protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        /// <summary>
        /// 检查文件实时防护是否启用
        /// </summary>
        public bool IsFileProtectionEnabled()
        {
            if (!_isCoreAvailable) return false;
            return _securityService.IsFileProtectionEnabled();
        }

        /// <summary>
        /// 启用/禁用进程防护
        /// </summary>
        public bool EnableProcessProtection(bool enable)
        {
            if (!_isCoreAvailable) return false;
            bool result = _securityService.EnableProcessProtection(enable);
            if (result)
            {
                // 更新配置
                AppConfig config = ConfigManager.Config;
                config.ProcessProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Process protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        /// <summary>
        /// 检查进程防护是否启用
        /// </summary>
        public bool IsProcessProtectionEnabled()
        {
            if (!_isCoreAvailable) return false;
            return _securityService.IsProcessProtectionEnabled();
        }

        /// <summary>
        /// 启用/禁用U盘防护
        /// </summary>
        public bool EnableDeviceProtection(bool enable)
        {
            if (!_isCoreAvailable) return false;
            bool result = _securityService.EnableDeviceProtection(enable);
            if (result)
            {
                // 更新配置
                AppConfig config = ConfigManager.Config;
                config.DeviceProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Device protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        /// <summary>
        /// 检查U盘防护是否启用
        /// </summary>
        public bool IsDeviceProtectionEnabled()
        {
            if (!_isCoreAvailable) return false;
            return _securityService.IsDeviceProtectionEnabled();
        }

        /// <summary>
        /// 启用/禁用注册表防护
        /// </summary>
        public bool EnableRegistryProtection(bool enable)
        {
            if (!_isCoreAvailable) return false;
            bool result = _securityService.EnableRegistryProtection(enable);
            if (result)
            {
                // 更新配置
                AppConfig config = ConfigManager.Config;
                config.RegistryProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Registry protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        /// <summary>
        /// 检查注册表防护是否启用
        /// </summary>
        public bool IsRegistryProtectionEnabled()
        {
            if (!_isCoreAvailable) return false;
            return _securityService.IsRegistryProtectionEnabled();
        }

        /// <summary>
        /// 启用/禁用浏览器防护
        /// </summary>
        public bool EnableBrowserProtection(bool enable)
        {
            if (!_isCoreAvailable) return false;
            bool result = _securityService.EnableBrowserProtection(enable);
            if (result)
            {
                // 更新配置
                AppConfig config = ConfigManager.Config;
                config.BrowserProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Browser protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        /// <summary>
        /// 检查浏览器防护是否启用
        /// </summary>
        public bool IsBrowserProtectionEnabled()
        {
            if (!_isCoreAvailable) return false;
            return _securityService.IsBrowserProtectionEnabled();
        }

        /// <summary>
        /// 启用/禁用脚本防护
        /// </summary>
        public bool EnableScriptProtection(bool enable)
        {
            if (!_isCoreAvailable) return false;
            bool result = _securityService.EnableScriptProtection(enable);
            if (result)
            {
                // 更新配置
                AppConfig config = ConfigManager.Config;
                config.ScriptProtectionEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Script protection {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        /// <summary>
        /// 检查脚本防护是否启用
        /// </summary>
        public bool IsScriptProtectionEnabled()
        {
            if (!_isCoreAvailable) return false;
            return _securityService.IsScriptProtectionEnabled();
        }

        /// <summary>
        /// 启用/禁用主动防御
        /// </summary>
        public bool EnableActiveDefense(bool enable)
        {
            if (!_isCoreAvailable) return false;
            bool result = _securityService.EnableActiveDefense(enable);
            if (result)
            {
                // 更新配置
                AppConfig config = ConfigManager.Config;
                config.ActiveDefenseEnabled = enable;
                ConfigManager.SaveConfig();
                LogManager.LogInfo($"Active defense {(enable ? "enabled" : "disabled")}");
            }
            return result;
        }

        /// <summary>
        /// 检查主动防御是否启用
        /// </summary>
        public bool IsActiveDefenseEnabled()
        {
            if (!_isCoreAvailable) return false;
            return _securityService.IsActiveDefenseEnabled();
        }

        /// <summary>
        /// 获取当前防护状态
        /// </summary>
        public ProtectionState GetProtectionStatus()
        {
            if (!_isCoreAvailable) return new ProtectionState();
            return _securityService.GetProtectionStatus();
        }

        /// <summary>
        /// 处理威胁
        /// </summary>
        /// <param name="threat">威胁信息</param>
        /// <param name="action">防护操作</param>
        public void HandleThreat(ThreatInfo threat, ProtectionAction action)
        {
            if (!_isCoreAvailable) return;
            _securityService.HandleThreat(threat, action);
        }

        /// <summary>
        /// 监控循环
        /// </summary>
        private async Task MonitoringLoop(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // 检查防护状态
                    ProtectionState status = _securityService.GetProtectionStatus();
                    
                    // 检查各防护模块是否正常运行
                    if (!_securityService.IsRunning)
                    {
                        LogManager.LogWarning("Security service is not running");
                        // 尝试重新启动
                        _securityService.Start();
                    }

                    // 休眠一段时间
                    await Task.Delay(10000, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // 任务被取消，退出循环
                    break;
                }
                catch (Exception ex)
                {
                    LogManager.LogError("Error in monitoring loop: " + ex.Message);
                    await Task.Delay(1000, cancellationToken);
                }
            }
        }

        /// <summary>
        /// 威胁检测回调
        /// </summary>
        private void OnThreatDetected(object sender, ThreatInfo threatInfo)
        {
            ThreatDetected?.Invoke(this, threatInfo);
        }

        /// <summary>
        /// 状态变化回调
        /// </summary>
        private void OnStatusChanged(object sender, ProtectionState status)
        {
            StatusChanged?.Invoke(this, status);
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            Stop();
            _securityService.ThreatDetected -= OnThreatDetected;
            _securityService.StatusChanged -= OnStatusChanged;
        }
    }
}