// U盘防护：真实 WMI 监听移动磁盘接入事件，接入后自动枚举扫描可执行/脚本文件，
// 发现威胁走 QuarantineStore 处理（与实时防护同一处置管线）。
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Management;
using System.Threading.Tasks;

namespace FireAntivirus.Host.WinUI
{
    public sealed class UsbGuard
    {
        private static readonly UsbGuard _instance = new();
        public static UsbGuard Instance => _instance;

        // U盘事件（UI 订阅：360 风格弹窗由 App 层挂接）
        public event Action<string, string> UsbConnected;
        public event Action<string, int, int, int> UsbScanCompleted;

        private ManagementEventWatcher _watcher;
        private readonly ConcurrentDictionary<string, DateTime> _scannedDrives = new();

        private UsbGuard() { }

        /// <summary>启动 USB 移动盘接入监听（真实 WMI 事件订阅）。</summary>
        public void Start()
        {
            if (_watcher != null) return;

            try
            {
                // 监听逻辑磁盘创建事件（DriveType=2 为可移动磁盘）
                var query = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
                    "WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType = 2");

                _watcher = new ManagementEventWatcher(query);
                _watcher.EventArrived += (s, e) =>
                {
                    try
                    {
                        var drive = (e.NewEvent["TargetInstance"] as ManagementBaseObject)?["Name"]?.ToString();
                        if (!string.IsNullOrEmpty(drive))
                        {
                            var root = drive.EndsWith("\\") ? drive : drive + "\\";
                            UsbConnected?.Invoke(root, GetVolumeLabel(root));
                            _ = ScanRemovableDrive(root);
                        }
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                            "USB 事件处理失败: " + ex.Message);
                    }
                };
                _watcher.Start();

                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    "U盘防护已启动（监听移动磁盘接入）");
            }
            catch (Exception ex)
            {
                _watcher = null;
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"U盘防护启动失败（WMI 不可用）: {ex.Message}");
            }
        }

        public void Stop()
        {
            if (_watcher == null) return;
            try
            {
                _watcher.Stop();
                _watcher.Dispose();
            }
            catch { }
            _watcher = null;
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "U盘防护已停止");
        }

        /// <summary>读取 U 盘卷标（用于弹窗展示）。</summary>
        private static string GetVolumeLabel(string driveRoot)
        {
            try
            {
                var info = new DriveInfo(driveRoot);
                return string.IsNullOrWhiteSpace(info.VolumeLabel) ? "可移动磁盘" : info.VolumeLabel;
            }
            catch { return "可移动磁盘"; }
        }

        /// <summary>扫描整个移动盘的可执行/脚本文件（后台执行，不阻塞 UI）。</summary>
        private async Task ScanRemovableDrive(string driveRoot)
        {
            // 同一盘符 30 秒内不重复扫描
            if (_scannedDrives.TryGetValue(driveRoot, out var last) &&
                (DateTime.Now - last).TotalSeconds < 30) return;
            _scannedDrives[driveRoot] = DateTime.Now;

            // 等待系统完成挂载
            await Task.Delay(2000);
            if (!RealTimeProtection.Instance.UsbGuardEnabled || !Directory.Exists(driveRoot)) return;

            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"检测到 U 盘接入，开始自动扫描: {driveRoot}");

            var engine = new FireAntivirus.Engine.AntivirusEngine();
            int scanned = 0, threats = 0, autoQuarantined = 0;

            try
            {
                foreach (var file in Directory.EnumerateFiles(driveRoot, "*", SearchOption.AllDirectories))
                {
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext != ".exe" && ext != ".dll" && ext != ".scr" && ext != ".bat" &&
                        ext != ".cmd" && ext != ".ps1" && ext != ".vbs" && ext != ".js" && ext != ".hta")
                        continue;

                    try
                    {
                        var result = engine.ScanFile(file);
                        scanned++;
                        if (result != null && result.IsInfected)
                        {
                            threats++;
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                $"U盘防护发现威胁: {file} ({result.ThreatName})");

                            var sev = (result.Severity ?? "Medium").ToLowerInvariant();
                            if (sev == "high" || sev == "critical")
                            {
                                // U 盘威胁直接自动隔离（可恢复），防止拔盘逃逸
                                if (QuarantineStore.Quarantine(file, result.ThreatName, result.Severity, out _))
                                    autoQuarantined++;
                            }
                        }
                    }
                    catch { }
                }

                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"U盘扫描完成: {scanned} 个文件, {threats} 个威胁, 自动隔离 {autoQuarantined} 个");

                UsbScanCompleted?.Invoke(driveRoot, scanned, threats, autoQuarantined);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"U盘扫描失败: {ex.Message}");
                UsbScanCompleted?.Invoke(driveRoot, scanned, threats, autoQuarantined);
            }
        }

        /// <summary>安全弹出 U 盘（Shell COM 弹出动词，真实生效）。</summary>
        public static bool SafeEject(string driveRoot)
        {
            try
            {
                var driveLetter = driveRoot.TrimEnd('\\');
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"(New-Object -ComObject Shell.Application).Namespace(17).ParseName('{driveLetter}').InvokeVerb('Eject')\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                System.Diagnostics.Process.Start(psi);
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"已请求安全弹出 {driveRoot}");
                return true;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"安全弹出失败: {ex.Message}");
                return false;
            }
        }
    }
}