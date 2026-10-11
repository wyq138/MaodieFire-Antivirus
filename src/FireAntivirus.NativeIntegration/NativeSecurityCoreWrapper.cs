// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Threading;
using System.Runtime.InteropServices;
using FireAntivirus.Data;
using FireAntivirus.Common;

namespace FireAntivirus.NativeIntegration
{
    /// <summary>
    /// 原生安全核心C#封装类
    /// 提供对NativeSecurityCore C++库的安全访问
    /// </summary>
    public class NativeSecurityCoreWrapper : IDisposable
    {
        #region 私有字段
        private IntPtr _nativeInstance;
        private bool _isInitialized;
        private bool _isRunning;
        private bool _disposed;
        private readonly object _lockObject = new object();
        private Timer _statusCheckTimer;

        // 回调函数
        private ThreatDetectedCallback _threatCallback;
        private StatusChangedCallback _statusCallback;

        // 各模块启用状态
        private bool _fileProtectionEnabled;
        private bool _processProtectionEnabled;
        private bool _deviceProtectionEnabled;
        private bool _registryProtectionEnabled;
        private bool _browserProtectionEnabled;
        private bool _scriptProtectionEnabled;
        private bool _activeDefenseEnabled;
        private bool _diskProtectionEnabled;
        private bool _uefiProtectionEnabled;
        private bool _kernelProtectionEnabled;
        private bool _documentProtectionEnabled;
        private bool _networkProtectionEnabled;
        private bool _popupBlockerEnabled;
        private bool _ransomwareProtectionEnabled;
        private bool _privacyProtectionEnabled;
        private bool _webProtectionEnabled;
        private bool _emailSecurityEnabled;
        private bool _passwordManagerEnabled;
        private bool _networkFirewallEnabled;
        private bool _deviceControlEnabled;
        private bool _vulnerabilityScannerEnabled;
        private bool _cloudScanEnabled;
        private bool _secureBrowserEnabled;
        private bool _mobileSecurityEnabled;
        private bool _systemOptimizerEnabled;
        private bool _backupRecoveryEnabled;
        private bool _securityScoreEnabled;
        private bool _networkTrafficEnabled;
        private bool _applicationMonitorEnabled;
        private bool _startupManagerEnabled;
        private bool _securityReportEnabled;
        private bool _behaviorAnalysisEnabled;
        private bool _systemToolsEnabled;
        private bool _systemInfoEnabled;
        private bool _quarantineEnabled;
        private bool _trustZoneEnabled;
        private bool _logCenterEnabled;

        // 威胁历史记录
        private readonly List<NativeThreatInfo> _threatHistory = new List<NativeThreatInfo>();
        private readonly object _threatHistoryLock = new object();
        #endregion

        #region 委托定义
        public delegate void ThreatDetectedCallback(NativeThreatInfo threatInfo);
        public delegate void StatusChangedCallback(NativeProtectionStatus status);
        #endregion

        #region 构造函数和析构函数
        public NativeSecurityCoreWrapper()
        {
            try
            {
                _nativeInstance = NativeSecurityCoreLib.GetInstance();
                if (_nativeInstance != IntPtr.Zero)
                {
                    _isInitialized = NativeSecurityCoreLib.Initialize(_nativeInstance);
                }
            }
            catch (DllNotFoundException ex)
            {
                LogMessage($"无法加载NativeSecurityCore.dll: {ex.Message}");
                _isInitialized = false;
            }
            catch (Exception ex)
            {
                LogMessage($"初始化NativeSecurityCore失败: {ex.Message}");
                _isInitialized = false;
            }
        }

        ~NativeSecurityCoreWrapper()
        {
            Dispose(false);
        }
        #endregion

        #region 公共属性
        public bool IsInitialized => _isInitialized;
        public bool IsRunning => _isRunning;

        public bool FileProtectionEnabled
        {
            get => _fileProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsFileProtectionEnabled(_nativeInstance) != value)
                {
                    _fileProtectionEnabled = NativeSecurityCoreLib.EnableFileProtection(_nativeInstance, value);
                }
            }
        }

        public bool ProcessProtectionEnabled
        {
            get => _processProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsProcessProtectionEnabled(_nativeInstance) != value)
                {
                    _processProtectionEnabled = NativeSecurityCoreLib.EnableProcessProtection(_nativeInstance, value);
                }
            }
        }

        public bool DeviceProtectionEnabled
        {
            get => _deviceProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsDeviceProtectionEnabled(_nativeInstance) != value)
                {
                    _deviceProtectionEnabled = NativeSecurityCoreLib.EnableDeviceProtection(_nativeInstance, value);
                }
            }
        }

        public bool RegistryProtectionEnabled
        {
            get => _registryProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsRegistryProtectionEnabled(_nativeInstance) != value)
                {
                    _registryProtectionEnabled = NativeSecurityCoreLib.EnableRegistryProtection(_nativeInstance, value);
                }
            }
        }

        public bool BrowserProtectionEnabled
        {
            get => _browserProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsBrowserProtectionEnabled(_nativeInstance) != value)
                {
                    _browserProtectionEnabled = NativeSecurityCoreLib.EnableBrowserProtection(_nativeInstance, value);
                }
            }
        }

        public bool ScriptProtectionEnabled
        {
            get => _scriptProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsScriptProtectionEnabled(_nativeInstance) != value)
                {
                    _scriptProtectionEnabled = NativeSecurityCoreLib.EnableScriptProtection(_nativeInstance, value);
                }
            }
        }

        public bool ActiveDefenseEnabled
        {
            get => _activeDefenseEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsActiveDefenseEnabled(_nativeInstance) != value)
                {
                    _activeDefenseEnabled = NativeSecurityCoreLib.EnableActiveDefense(_nativeInstance, value);
                }
            }
        }

        public bool DiskProtectionEnabled
        {
            get => _diskProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsDiskProtectionEnabled(_nativeInstance) != value)
                {
                    _diskProtectionEnabled = NativeSecurityCoreLib.EnableDiskProtection(_nativeInstance, value);
                }
            }
        }

        public bool UEFIProtectionEnabled
        {
            get => _uefiProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsUEFIProtectionEnabled(_nativeInstance) != value)
                {
                    _uefiProtectionEnabled = NativeSecurityCoreLib.EnableUEFIProtection(_nativeInstance, value);
                }
            }
        }

        public bool KernelProtectionEnabled
        {
            get => _kernelProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsKernelProtectionEnabled(_nativeInstance) != value)
                {
                    _kernelProtectionEnabled = NativeSecurityCoreLib.EnableKernelProtection(_nativeInstance, value);
                }
            }
        }

        public bool DocumentProtectionEnabled
        {
            get => _documentProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsDocumentProtectionEnabled(_nativeInstance) != value)
                {
                    _documentProtectionEnabled = NativeSecurityCoreLib.EnableDocumentProtection(_nativeInstance, value);
                }
            }
        }

        public bool NetworkProtectionEnabled
        {
            get => _networkProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsNetworkProtectionEnabled(_nativeInstance) != value)
                {
                    _networkProtectionEnabled = NativeSecurityCoreLib.EnableNetworkProtection(_nativeInstance, value);
                }
            }
        }

        public bool PopupBlockerEnabled
        {
            get => _popupBlockerEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsPopupBlockerEnabled(_nativeInstance) != value)
                {
                    _popupBlockerEnabled = NativeSecurityCoreLib.EnablePopupBlocker(_nativeInstance, value);
                }
            }
        }

        public bool RansomwareProtectionEnabled
        {
            get => _ransomwareProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsRansomwareProtectionEnabled(_nativeInstance) != value)
                {
                    _ransomwareProtectionEnabled = NativeSecurityCoreLib.EnableRansomwareProtection(_nativeInstance, value);
                }
            }
        }

        public bool PrivacyProtectionEnabled
        {
            get => _privacyProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsPrivacyProtectionEnabled(_nativeInstance) != value)
                {
                    _privacyProtectionEnabled = NativeSecurityCoreLib.EnablePrivacyProtection(_nativeInstance, value);
                }
            }
        }

        public bool WebProtectionEnabled
        {
            get => _webProtectionEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsWebProtectionEnabled(_nativeInstance) != value)
                {
                    _webProtectionEnabled = NativeSecurityCoreLib.EnableWebProtection(_nativeInstance, value);
                }
            }
        }

        public bool EmailSecurityEnabled
        {
            get => _emailSecurityEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsEmailSecurityEnabled(_nativeInstance) != value)
                {
                    _emailSecurityEnabled = NativeSecurityCoreLib.EnableEmailSecurity(_nativeInstance, value);
                }
            }
        }

        public bool PasswordManagerEnabled
        {
            get => _passwordManagerEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsPasswordManagerEnabled(_nativeInstance) != value)
                {
                    _passwordManagerEnabled = NativeSecurityCoreLib.EnablePasswordManager(_nativeInstance, value);
                }
            }
        }

        public bool NetworkFirewallEnabled
        {
            get => _networkFirewallEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsNetworkFirewallEnabled(_nativeInstance) != value)
                {
                    _networkFirewallEnabled = NativeSecurityCoreLib.EnableNetworkFirewall(_nativeInstance, value);
                }
            }
        }

        public bool DeviceControlEnabled
        {
            get => _deviceControlEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsDeviceControlEnabled(_nativeInstance) != value)
                {
                    _deviceControlEnabled = NativeSecurityCoreLib.EnableDeviceControl(_nativeInstance, value);
                }
            }
        }

        public bool VulnerabilityScannerEnabled
        {
            get => _vulnerabilityScannerEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsVulnerabilityScannerEnabled(_nativeInstance) != value)
                {
                    _vulnerabilityScannerEnabled = NativeSecurityCoreLib.EnableVulnerabilityScanner(_nativeInstance, value);
                }
            }
        }

        public bool CloudScanEnabled
        {
            get => _cloudScanEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsCloudScanEnabled(_nativeInstance) != value)
                {
                    _cloudScanEnabled = NativeSecurityCoreLib.EnableCloudScan(_nativeInstance, value);
                }
            }
        }

        public bool SecureBrowserEnabled
        {
            get => _secureBrowserEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsSecureBrowserEnabled(_nativeInstance) != value)
                {
                    _secureBrowserEnabled = NativeSecurityCoreLib.EnableSecureBrowser(_nativeInstance, value);
                }
            }
        }

        public bool MobileSecurityEnabled
        {
            get => _mobileSecurityEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsMobileSecurityEnabled(_nativeInstance) != value)
                {
                    _mobileSecurityEnabled = NativeSecurityCoreLib.EnableMobileSecurity(_nativeInstance, value);
                }
            }
        }

        public bool SystemOptimizerEnabled
        {
            get => _systemOptimizerEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsSystemOptimizerEnabled(_nativeInstance) != value)
                {
                    _systemOptimizerEnabled = NativeSecurityCoreLib.EnableSystemOptimizer(_nativeInstance, value);
                }
            }
        }

        public bool BackupRecoveryEnabled
        {
            get => _backupRecoveryEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsBackupRecoveryEnabled(_nativeInstance) != value)
                {
                    _backupRecoveryEnabled = NativeSecurityCoreLib.EnableBackupRecovery(_nativeInstance, value);
                }
            }
        }

        public bool SecurityScoreEnabled
        {
            get => _securityScoreEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsSecurityScoreEnabled(_nativeInstance) != value)
                {
                    _securityScoreEnabled = NativeSecurityCoreLib.EnableSecurityScore(_nativeInstance, value);
                }
            }
        }

        public bool NetworkTrafficEnabled
        {
            get => _networkTrafficEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsNetworkTrafficEnabled(_nativeInstance) != value)
                {
                    _networkTrafficEnabled = NativeSecurityCoreLib.EnableNetworkTraffic(_nativeInstance, value);
                }
            }
        }

        public bool ApplicationMonitorEnabled
        {
            get => _applicationMonitorEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsApplicationMonitorEnabled(_nativeInstance) != value)
                {
                    _applicationMonitorEnabled = NativeSecurityCoreLib.EnableApplicationMonitor(_nativeInstance, value);
                }
            }
        }

        public bool StartupManagerEnabled
        {
            get => _startupManagerEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsStartupManagerEnabled(_nativeInstance) != value)
                {
                    _startupManagerEnabled = NativeSecurityCoreLib.EnableStartupManager(_nativeInstance, value);
                }
            }
        }

        public bool SecurityReportEnabled
        {
            get => _securityReportEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsSecurityReportEnabled(_nativeInstance) != value)
                {
                    _securityReportEnabled = NativeSecurityCoreLib.EnableSecurityReport(_nativeInstance, value);
                }
            }
        }

        public bool BehaviorAnalysisEnabled
        {
            get => _behaviorAnalysisEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsBehaviorAnalysisEnabled(_nativeInstance) != value)
                {
                    _behaviorAnalysisEnabled = NativeSecurityCoreLib.EnableBehaviorAnalysis(_nativeInstance, value);
                }
            }
        }

        public bool SystemToolsEnabled
        {
            get => _systemToolsEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsSystemToolsEnabled(_nativeInstance) != value)
                {
                    _systemToolsEnabled = NativeSecurityCoreLib.EnableSystemTools(_nativeInstance, value);
                }
            }
        }

        public bool SystemInfoEnabled
        {
            get => _systemInfoEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsSystemInfoEnabled(_nativeInstance) != value)
                {
                    _systemInfoEnabled = NativeSecurityCoreLib.EnableSystemInfo(_nativeInstance, value);
                }
            }
        }

        public bool QuarantineEnabled
        {
            get => _quarantineEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsQuarantineEnabled(_nativeInstance) != value)
                {
                    _quarantineEnabled = NativeSecurityCoreLib.EnableQuarantine(_nativeInstance, value);
                }
            }
        }

        public bool TrustZoneEnabled
        {
            get => _trustZoneEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsTrustZoneEnabled(_nativeInstance) != value)
                {
                    _trustZoneEnabled = NativeSecurityCoreLib.EnableTrustZone(_nativeInstance, value);
                }
            }
        }

        public bool LogCenterEnabled
        {
            get => _logCenterEnabled;
            set
            {
                if (_isInitialized && NativeSecurityCoreLib.IsLogCenterEnabled(_nativeInstance) != value)
                {
                    _logCenterEnabled = NativeSecurityCoreLib.EnableLogCenter(_nativeInstance, value);
                }
            }
        }

        public IReadOnlyList<NativeThreatInfo> ThreatHistory
        {
            get
            {
                lock (_threatHistoryLock)
                {
                    return _threatHistory.AsReadOnly();
                }
            }
        }
        #endregion

        #region 公共方法
        /// <summary>
        /// 启动所有防护
        /// </summary>
        public bool StartAllProtection()
        {
            lock (_lockObject)
            {
                if (!_isInitialized || _isRunning)
                    return false;

                try
                {
                    // 启用所有防护模块
                    FileProtectionEnabled = true;
                    ProcessProtectionEnabled = true;
                    DeviceProtectionEnabled = true;
                    RegistryProtectionEnabled = true;
                    BrowserProtectionEnabled = true;
                    ScriptProtectionEnabled = true;
                    ActiveDefenseEnabled = true;
                    DiskProtectionEnabled = true;
                    UEFIProtectionEnabled = true;
                    KernelProtectionEnabled = true;
                    DocumentProtectionEnabled = true;
                    NetworkProtectionEnabled = true;
                    PopupBlockerEnabled = true;
                    RansomwareProtectionEnabled = true;
                    PrivacyProtectionEnabled = true;
                    WebProtectionEnabled = true;
                    EmailSecurityEnabled = true;
                    NetworkFirewallEnabled = true;
                    DeviceControlEnabled = true;
                    VulnerabilityScannerEnabled = true;
                    CloudScanEnabled = true;
                    ApplicationMonitorEnabled = true;
                    BehaviorAnalysisEnabled = true;

                    // 启动核心库
                    _isRunning = NativeSecurityCoreLib.StartProtection(_nativeInstance);

                    // 启动状态检查定时器
                    if (_isRunning)
                    {
                        _statusCheckTimer = new Timer(CheckStatus, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
                    }

                    return _isRunning;
                }
                catch (Exception ex)
                {
                    LogMessage($"启动防护失败: {ex.Message}");
                    return false;
                }
            }
        }

        /// <summary>
        /// 停止所有防护
        /// </summary>
        public void StopAllProtection()
        {
            lock (_lockObject)
            {
                if (!_isRunning)
                    return;

                try
                {
                    // 停止状态检查
                    _statusCheckTimer?.Dispose();
                    _statusCheckTimer = null;

                    // 停止核心库
                    NativeSecurityCoreLib.StopProtection(_nativeInstance);

                    // 禁用所有防护模块
                    FileProtectionEnabled = false;
                    ProcessProtectionEnabled = false;
                    DeviceProtectionEnabled = false;
                    RegistryProtectionEnabled = false;
                    BrowserProtectionEnabled = false;
                    ScriptProtectionEnabled = false;
                    ActiveDefenseEnabled = false;
                    DiskProtectionEnabled = false;
                    UEFIProtectionEnabled = false;
                    KernelProtectionEnabled = false;
                    DocumentProtectionEnabled = false;
                    NetworkProtectionEnabled = false;
                    PopupBlockerEnabled = false;
                    RansomwareProtectionEnabled = false;
                    PrivacyProtectionEnabled = false;
                    WebProtectionEnabled = false;
                    EmailSecurityEnabled = false;
                    NetworkFirewallEnabled = false;
                    DeviceControlEnabled = false;
                    VulnerabilityScannerEnabled = false;
                    CloudScanEnabled = false;
                    ApplicationMonitorEnabled = false;
                    BehaviorAnalysisEnabled = false;

                    _isRunning = false;
                }
                catch (Exception ex)
                {
                    LogMessage($"停止防护失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 获取当前防护状态
        /// </summary>
        public NativeProtectionStatus GetProtectionStatus()
        {
            if (!_isInitialized || _nativeInstance == IntPtr.Zero)
                return NativeProtectionStatus.ERROR;

            try
            {
                return NativeSecurityCoreLib.GetProtectionStatus(_nativeInstance);
            }
            catch
            {
                return NativeProtectionStatus.ERROR;
            }
        }

        /// <summary>
        /// 设置威胁检测回调
        /// </summary>
        public void SetThreatCallback(ThreatDetectedCallback callback)
        {
            _threatCallback = callback;
        }

        /// <summary>
        /// 设置状态变更回调
        /// </summary>
        public void SetStatusCallback(StatusChangedCallback callback)
        {
            _statusCallback = callback;
        }

        /// <summary>
        /// 清除威胁历史记录
        /// </summary>
        public void ClearThreatHistory()
        {
            lock (_threatHistoryLock)
            {
                _threatHistory.Clear();
            }
        }
        #endregion

        #region 私有方法
        private void CheckStatus(object state)
        {
            try
            {
                var status = GetProtectionStatus();
                _statusCallback?.Invoke(status);
            }
            catch (Exception ex)
            {
                LogMessage($"检查状态失败: {ex.Message}");
            }
        }

        private void LogMessage(string message)
        {
            // 记录日志
            Console.WriteLine($"[NativeSecurityCore] {message}");
        }
        #endregion

        #region IDisposable实现
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                StopAllProtection();
            }

            _disposed = true;
        }
        #endregion
    }
}
