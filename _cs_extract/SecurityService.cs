using System;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 安全服务类
    /// </summary>
    public class SecurityService : IDisposable
    {
        private bool _isInitialized;
        private bool _isRunning;
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
        /// 初始化安全服务
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
                    // 初始化NativeSecurityCore
                    if (!NativeSecurityCoreWrapper.InitializeCore())
                    {
                        return false;
                    }

                    // 设置回调函数
                    NativeSecurityCoreWrapper.SetThreatCallbackCore(OnThreatDetected);
                    NativeSecurityCoreWrapper.SetStatusCallbackCore(OnStatusChanged);

                    _isInitialized = true;
                    return true;
                }
                catch (Exception ex)
                {
                    LogManager.LogError("Failed to initialize security service: " + ex.Message);
                    return false;
                }
            }
        }

        /// <summary>
        /// 启动安全服务
        /// </summary>
        /// <returns>是否启动成功</returns>
        public bool Start()
        {
            lock (_lock)
            {
                if (!_isInitialized || _isRunning)
                {
                    return false;
                }

                try
                {
                    // 启动NativeSecurityCore
                    if (!NativeSecurityCoreWrapper.StartProtectionCore())
                    {
                        return false;
                    }

                    // 启动监控任务
                    _cancellationTokenSource = new CancellationTokenSource();
                    _monitoringTask = Task.Run(() => MonitoringLoop(_cancellationTokenSource.Token), _cancellationTokenSource.Token);

                    _isRunning = true;
                    LogManager.LogInfo("Security service started");
                    return true;
                }
                catch (Exception ex)
                {
                    LogManager.LogError("Failed to start security service: " + ex.Message);
                    return false;
                }
            }
        }

        /// <summary>
        /// 停止安全服务
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

                    // 停止NativeSecurityCore
                    NativeSecurityCoreWrapper.StopProtectionCore();

                    _isRunning = false;
                    LogManager.LogInfo("Security service stopped");
                }
                catch (Exception ex)
                {
                    LogManager.LogError("Failed to stop security service: " + ex.Message);
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
        /// 获取当前防护状态
        /// </summary>
        public ProtectionState GetProtectionStatus()
        {
            if (!_isInitialized)
            {
                throw new InvalidOperationException("Security service is not initialized");
            }

            return NativeSecurityCoreWrapper.GetProtectionStatusCore();
        }

        /// <summary>
        /// 处理威胁
        /// </summary>
        /// <param name="threat">威胁信息</param>
        /// <param name="action">防护操作</param>
        public void HandleThreat(ThreatInfo threat, ProtectionAction action)
        {
            if (!_isInitialized || !_isRunning)
            {
                throw new InvalidOperationException("Security service is not running");
            }

            NativeSecurityCoreWrapper.HandleThreatCore(threat, action);
        }

        /// <summary>
        /// 启用/禁用文件防护
        /// </summary>
        public bool EnableFileProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableFileProtectionCore(enable);
        }

        /// <summary>
        /// 检查文件防护是否启用
        /// </summary>
        public bool IsFileProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsFileProtectionEnabledCore();
        }

        /// <summary>
        /// 启用/禁用进程防护
        /// </summary>
        public bool EnableProcessProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableProcessProtectionCore(enable);
        }

        /// <summary>
        /// 检查进程防护是否启用
        /// </summary>
        public bool IsProcessProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsProcessProtectionEnabledCore();
        }

        /// <summary>
        /// 启用/禁用U盘防护
        /// </summary>
        public bool EnableDeviceProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableDeviceProtectionCore(enable);
        }

        /// <summary>
        /// 检查U盘防护是否启用
        /// </summary>
        public bool IsDeviceProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsDeviceProtectionEnabledCore();
        }

        /// <summary>
        /// 启用/禁用注册表防护
        /// </summary>
        public bool EnableRegistryProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableRegistryProtectionCore(enable);
        }

        /// <summary>
        /// 检查注册表防护是否启用
        /// </summary>
        public bool IsRegistryProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsRegistryProtectionEnabledCore();
        }

        /// <summary>
        /// 启用/禁用浏览器防护
        /// </summary>
        public bool EnableBrowserProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableBrowserProtectionCore(enable);
        }

        /// <summary>
        /// 检查浏览器防护是否启用
        /// </summary>
        public bool IsBrowserProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsBrowserProtectionEnabledCore();
        }

        /// <summary>
        /// 启用/禁用脚本防护
        /// </summary>
        public bool EnableScriptProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableScriptProtectionCore(enable);
        }

        /// <summary>
        /// 检查脚本防护是否启用
        /// </summary>
        public bool IsScriptProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsScriptProtectionEnabledCore();
        }

        /// <summary>
        /// 启用/禁用主动防御
        /// </summary>
        public bool EnableActiveDefense(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableActiveDefenseCore(enable);
        }

        /// <summary>
        /// 检查主动防御是否启用
        /// </summary>
        public bool IsActiveDefenseEnabled()
        {
            return NativeSecurityCoreWrapper.IsActiveDefenseEnabledCore();
        }

        /// <summary>
        /// 检查勒索软件防护是否启用
        /// </summary>
        public bool IsRansomwareProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsRansomwareProtectionEnabledCore();
        }

        /// <summary>
        /// 检查网页防护是否启用
        /// </summary>
        public bool IsWebProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsWebProtectionEnabledCore();
        }

        /// <summary>
        /// 检查漏洞扫描是否启用
        /// </summary>
        public bool IsVulnerabilityScannerEnabled()
        {
            return NativeSecurityCoreWrapper.IsVulnerabilityScannerEnabledCore();
        }

        /// <summary>
        /// 检查信任区是否启用
        /// </summary>
        public bool IsTrustZoneEnabled()
        {
            return NativeSecurityCoreWrapper.IsTrustZoneEnabledCore();
        }

        /// <summary>
        /// 检查系统工具是否启用
        /// </summary>
        public bool IsSystemToolsEnabled()
        {
            return NativeSecurityCoreWrapper.IsSystemToolsEnabledCore();
        }

        /// <summary>
        /// 检查系统优化是否启用
        /// </summary>
        public bool IsSystemOptimizerEnabled()
        {
            return NativeSecurityCoreWrapper.IsSystemOptimizerEnabledCore();
        }

        /// <summary>
        /// 检查系统信息是否启用
        /// </summary>
        public bool IsSystemInfoEnabled()
        {
            return NativeSecurityCoreWrapper.IsSystemInfoEnabledCore();
        }

        /// <summary>
        /// 检查启动项管理是否启用
        /// </summary>
        public bool IsStartupManagerEnabled()
        {
            return NativeSecurityCoreWrapper.IsStartupManagerEnabledCore();
        }

        /// <summary>
        /// 检查安全评分是否启用
        /// </summary>
        public bool IsSecurityScoreEnabled()
        {
            return NativeSecurityCoreWrapper.IsSecurityScoreEnabledCore();
        }

        /// <summary>
        /// 检查安全报告是否启用
        /// </summary>
        public bool IsSecurityReportEnabled()
        {
            return NativeSecurityCoreWrapper.IsSecurityReportEnabledCore();
        }

        /// <summary>
        /// 检查隐私保护是否启用
        /// </summary>
        public bool IsPrivacyProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsPrivacyProtectionEnabledCore();
        }

        /// <summary>
        /// 检查安全浏览器是否启用
        /// </summary>
        public bool IsSecureBrowserEnabled()
        {
            return NativeSecurityCoreWrapper.IsSecureBrowserEnabledCore();
        }

        /// <summary>
        /// 检查隔离区是否启用
        /// </summary>
        public bool IsQuarantineEnabled()
        {
            return NativeSecurityCoreWrapper.IsQuarantineEnabledCore();
        }

        /// <summary>
        /// 检查弹窗拦截是否启用
        /// </summary>
        public bool IsPopupBlockerEnabled()
        {
            return NativeSecurityCoreWrapper.IsPopupBlockerEnabledCore();
        }

        /// <summary>
        /// 检查密码管理是否启用
        /// </summary>
        public bool IsPasswordManagerEnabled()
        {
            return NativeSecurityCoreWrapper.IsPasswordManagerEnabledCore();
        }

        /// <summary>
        /// 检查网络流量是否启用
        /// </summary>
        public bool IsNetworkTrafficEnabled()
        {
            return NativeSecurityCoreWrapper.IsNetworkTrafficEnabledCore();
        }

        /// <summary>
        /// 检查网络防护是否启用
        /// </summary>
        public bool IsNetworkProtectionEnabled()
        {
            return NativeSecurityCoreWrapper.IsNetworkProtectionEnabledCore();
        }

        /// <summary>
        /// 检查网络防火墙是否启用
        /// </summary>
        public bool IsNetworkFirewallEnabled()
        {
            return NativeSecurityCoreWrapper.IsNetworkFirewallEnabledCore();
        }

        /// <summary>
        /// 检查移动安全是否启用
        /// </summary>
        public bool IsMobileSecurityEnabled()
        {
            return NativeSecurityCoreWrapper.IsMobileSecurityEnabledCore();
        }

        /// <summary>
        /// 检查日志中心是否启用
        /// </summary>
        public bool IsLogCenterEnabled()
        {
            return NativeSecurityCoreWrapper.IsLogCenterEnabledCore();
        }

        /// <summary>
        /// 检查邮件安全是否启用
        /// </summary>
        public bool IsEmailSecurityEnabled()
        {
            return NativeSecurityCoreWrapper.IsEmailSecurityEnabledCore();
        }

        /// <summary>
        /// 检查云查杀是否启用
        /// </summary>
        public bool IsCloudScanEnabled()
        {
            return NativeSecurityCoreWrapper.IsCloudScanEnabledCore();
        }

        /// <summary>
        /// 检查备份恢复是否启用
        /// </summary>
        public bool IsBackupRecoveryEnabled()
        {
            return NativeSecurityCoreWrapper.IsBackupRecoveryEnabledCore();
        }

        /// <summary>
        /// 检查应用监控是否启用
        /// </summary>
        public bool IsApplicationMonitorEnabled()
        {
            return NativeSecurityCoreWrapper.IsApplicationMonitorEnabledCore();
        }

        /// <summary>
        /// 启用/禁用网页防护
        /// </summary>
        public bool EnableWebProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableWebProtectionCore(enable);
        }

        /// <summary>
        /// 启用/禁用漏洞扫描
        /// </summary>
        public bool EnableVulnerabilityScanner(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableVulnerabilityScannerCore(enable);
        }

        /// <summary>
        /// 启用/禁用信任区
        /// </summary>
        public bool EnableTrustZone(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableTrustZoneCore(enable);
        }

        /// <summary>
        /// 启用/禁用系统工具
        /// </summary>
        public bool EnableSystemTools(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableSystemToolsCore(enable);
        }

        /// <summary>
        /// 启用/禁用系统优化
        /// </summary>
        public bool EnableSystemOptimizer(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableSystemOptimizerCore(enable);
        }

        /// <summary>
        /// 启用/禁用系统信息
        /// </summary>
        public bool EnableSystemInfo(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableSystemInfoCore(enable);
        }

        /// <summary>
        /// 启用/禁用启动管理
        /// </summary>
        public bool EnableStartupManager(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableStartupManagerCore(enable);
        }

        /// <summary>
        /// 启用/禁用安全评分
        /// </summary>
        public bool EnableSecurityScore(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableSecurityScoreCore(enable);
        }

        /// <summary>
        /// 启用/禁用安全报告
        /// </summary>
        public bool EnableSecurityReport(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableSecurityReportCore(enable);
        }

        /// <summary>
        /// 启用/禁用行为分析
        /// </summary>
        public bool EnableBehaviorAnalysis(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableBehaviorAnalysisCore(enable);
        }

        /// <summary>
        /// 启用/禁用分区表防护
        /// </summary>
        public bool EnableDiskProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableDiskProtectionCore(enable);
        }

        /// <summary>
        /// 启用/禁用UEFI/BIOS防护
        /// </summary>
        public bool EnableUEFIProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableUEFIProtectionCore(enable);
        }

        /// <summary>
        /// 启用/禁用内核防护
        /// </summary>
        public bool EnableKernelProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableKernelProtectionCore(enable);
        }

        /// <summary>
        /// 启用/禁用文档防护
        /// </summary>
        public bool EnableDocumentProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableDocumentProtectionCore(enable);
        }

        /// <summary>
        /// 启用/禁用网络防护
        /// </summary>
        public bool EnableNetworkProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableNetworkProtectionCore(enable);
        }

        /// <summary>
        /// 启用/禁用弹窗拦截
        /// </summary>
        public bool EnablePopupBlocker(bool enable)
        {
            return NativeSecurityCoreWrapper.EnablePopupBlockerCore(enable);
        }

        /// <summary>
        /// 启用/禁用勒索防护
        /// </summary>
        public bool EnableRansomwareProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableRansomwareProtectionCore(enable);
        }

        /// <summary>
        /// 启用/禁用隐私保护
        /// </summary>
        public bool EnablePrivacyProtection(bool enable)
        {
            return NativeSecurityCoreWrapper.EnablePrivacyProtectionCore(enable);
        }

        /// <summary>
        /// 启用/禁用邮件安全
        /// </summary>
        public bool EnableEmailSecurity(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableEmailSecurityCore(enable);
        }

        /// <summary>
        /// 启用/禁用密码管理
        /// </summary>
        public bool EnablePasswordManager(bool enable)
        {
            return NativeSecurityCoreWrapper.EnablePasswordManagerCore(enable);
        }

        /// <summary>
        /// 启用/禁用网络防火墙
        /// </summary>
        public bool EnableNetworkFirewall(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableNetworkFirewallCore(enable);
        }

        /// <summary>
        /// 启用/禁用设备控制
        /// </summary>
        public bool EnableDeviceControl(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableDeviceControlCore(enable);
        }

        /// <summary>
        /// 启用/禁用云查杀
        /// </summary>
        public bool EnableCloudScan(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableCloudScanCore(enable);
        }

        /// <summary>
        /// 启用/禁用安全浏览器
        /// </summary>
        public bool EnableSecureBrowser(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableSecureBrowserCore(enable);
        }

        /// <summary>
        /// 启用/禁用移动安全
        /// </summary>
        public bool EnableMobileSecurity(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableMobileSecurityCore(enable);
        }

        /// <summary>
        /// 启用/禁用备份恢复
        /// </summary>
        public bool EnableBackupRecovery(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableBackupRecoveryCore(enable);
        }

        /// <summary>
        /// 启用/禁用网络流量
        /// </summary>
        public bool EnableNetworkTraffic(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableNetworkTrafficCore(enable);
        }

        /// <summary>
        /// 启用/禁用应用监控
        /// </summary>
        public bool EnableApplicationMonitor(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableApplicationMonitorCore(enable);
        }

        /// <summary>
        /// 启用/禁用隔离区
        /// </summary>
        public bool EnableQuarantine(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableQuarantineCore(enable);
        }

        /// <summary>
        /// 启用/禁用日志中心
        /// </summary>
        public bool EnableLogCenter(bool enable)
        {
            return NativeSecurityCoreWrapper.EnableLogCenterCore(enable);
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
                    // 检查服务状态
                    if (!NativeSecurityCoreWrapper.IsRunningCore())
                    {
                        LogManager.LogWarning("Native security core is not running");
                        // 尝试重新启动
                        NativeSecurityCoreWrapper.StartProtectionCore();
                    }

                    // 休眠一段时间
                    await Task.Delay(5000, cancellationToken);
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
        private void OnThreatDetected(ThreatInfo threatInfo)
        {
            LogManager.LogWarning($"Threat detected: {threatInfo.threatDescription} - {threatInfo.targetPath}");
            ThreatDetected?.Invoke(this, threatInfo);
        }

        /// <summary>
        /// 状态变化回调
        /// </summary>
        private void OnStatusChanged(ProtectionState status)
        {
            LogManager.LogInfo("Protection status changed");
            StatusChanged?.Invoke(this, status);
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            Stop();
        }
    }
}
