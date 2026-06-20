using System;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Services;

namespace FireAntivirus.Host
{
    public class UpdateManager
    {
        private static UpdateManager _instance;
        private static readonly object _lock = new object();
        private Timer _updateCheckTimer;
        private Timer _threatIntelligenceSyncTimer;
        private bool _isCheckingForUpdates;
        private bool _isSyncingThreatIntelligence;

        public static UpdateManager Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                        {
                            _instance = new UpdateManager();
                        }
                    }
                }
                return _instance;
            }
        }

        private UpdateManager()
        {
            // 初始化更新管理器
        }

        public void Start()
        {
            // 立即检查一次更新
            Task.Run(async () => await CheckForUpdatesAsync());

            // 立即同步一次威胁情报
            Task.Run(async () => await SyncThreatIntelligenceAsync());

            // 设置定期检查更新的定时器
            var updateInterval = UpdateService.GetUpdateCheckInterval();
            _updateCheckTimer = new Timer(
                async (state) => await CheckForUpdatesAsync(),
                null,
                updateInterval,
                updateInterval
            );

            // 设置定期同步威胁情报的定时器
            var threatIntelligenceInterval = TimeSpan.FromHours(6); // 每6小时同步一次
            _threatIntelligenceSyncTimer = new Timer(
                async (state) => await SyncThreatIntelligenceAsync(),
                null,
                threatIntelligenceInterval,
                threatIntelligenceInterval
            );
        }

        public void Stop()
        {
            _updateCheckTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _updateCheckTimer?.Dispose();
            _threatIntelligenceSyncTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _threatIntelligenceSyncTimer?.Dispose();
        }

        private async Task CheckForUpdatesAsync()
        {
            // 避免并发检查
            if (_isCheckingForUpdates)
                return;

            try
            {
                _isCheckingForUpdates = true;

                // 检查是否启用了自动更新
                if (UpdateService.IsAutoUpdateEnabled())
                {
                    await UpdateService.CheckForUpdatesAsync();
                }
            }
            catch (Exception ex)
            {
                // 记录错误但不影响主程序
                Console.WriteLine($"自动检查更新时出错: {ex.Message}");
            }
            finally
            {
                _isCheckingForUpdates = false;
            }
        }

        private async Task SyncThreatIntelligenceAsync()
        {
            // 避免并发同步
            if (_isSyncingThreatIntelligence)
                return;

            try
            {
                _isSyncingThreatIntelligence = true;

                // 检查是否启用了威胁情报同步
                if (UpdateService.IsThreatIntelligenceSyncEnabled())
                {
                    await UpdateService.SyncThreatIntelligenceAsync();
                }
            }
            catch (Exception ex)
            {
                // 记录错误但不影响主程序
                Console.WriteLine($"同步威胁情报时出错: {ex.Message}");
            }
            finally
            {
                _isSyncingThreatIntelligence = false;
            }
        }

        public async Task CheckForUpdatesManuallyAsync()
        {
            await CheckForUpdatesAsync();
        }

        public async Task SyncThreatIntelligenceManuallyAsync()
        {
            await SyncThreatIntelligenceAsync();
        }

        public bool IsUpdateAvailable()
        {
            return UpdateService.IsUpdateAvailable();
        }

        public string GetLatestVersion()
        {
            return UpdateService.GetLatestVersion();
        }

        public string GetCurrentVersion()
        {
            return UpdateService.GetCurrentVersion();
        }

        public async Task DownloadAndInstallUpdateAsync()
        {
            await UpdateService.DownloadAndInstallUpdateAsync();
        }

        public async Task DownloadThreatIntelligenceAsync()
        {
            await UpdateService.DownloadThreatIntelligenceAsync();
        }
    }
}
