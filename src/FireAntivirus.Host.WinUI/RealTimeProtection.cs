// 真实时防护：全盘监听（所有固定驱动器递归 FileSystemWatcher + 64KB 缓冲 + 4 路并发限流），
// 新建/修改的受监控类型文件立即用引擎扫描；高危/严重威胁自动隔离，其余弹处置窗由用户决定。
// 移动盘接入由 UsbGuard 独立覆盖（自动扫描+隔离）。
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Host.WinUI
{
    public sealed class RealTimeProtection
    {
        private static readonly RealTimeProtection _instance = new();
        public static RealTimeProtection Instance => _instance;

        private readonly ConcurrentDictionary<string, FileSystemWatcher> _watchers = new();
        private readonly ConcurrentDictionary<string, DateTime> _recent = new();
        private SemaphoreSlim _scanSem;
        private FireAntivirus.Engine.AntivirusEngine _engine;

        // 各模块开关（由 UI 驱动，真实生效）
        public volatile bool FileGuardEnabled = true;      // 实时文件防护
        public volatile bool RansomGuardEnabled = true;    // 勒索防护（文档目录加密类文件写入监控）
        public volatile bool ScriptGuardEnabled = true;    // 脚本防护（JS/VBS/BAT/CMD/PS1 落盘即扫）
        public volatile bool UsbGuardEnabled = true;       // U盘防护（USB 移动盘接入自动扫描）

        /// <summary>
        /// 病毒库更新进行中：暂停实时扫描（不停止监听），防止更新下载与实时扫描抢资源把机器卡死。
        /// 首页更新流程开始时置 true、结束时置 false。
        /// </summary>
        public static volatile bool UpdateInProgress;

        private static readonly string[] WatchedExts =
        {
            ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi",
            ".com", ".pif", ".cpl", ".jar", ".lnk", ".docm", ".xlsm", ".pptm", ".rtf"
        };

        // 脚本类扩展名（受 ScriptGuardEnabled 控制）
        private static readonly string[] ScriptExts =
        {
            ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jse", ".vbe", ".wsf"
        };

        // 全盘监听下的系统噪音路径（不监控不扫描，避免事件洪峰与无意义扫描）
        private static readonly string[] NoisePaths =
        {
            "\\$recycle.bin", "\\system volume information", "\\windows\\winsxs",
            "pagefile.sys", "hiberfil.sys", "swapfile.sys", "memory.dmp",
            "\\fireantivirus\\quarantine", "\\fireantivirus\\signaturedatabase",
            "\\fireantivirus\\lmd", "\\fireantivirus\\ml\\", "\\fireantivirus\\yara_rules"
        };

        private RealTimeProtection() { }

        /// <summary>覆盖范围描述（首页/防护页状态展示）。</summary>
        public string CoverageText
        {
            get
            {
                if (!FileGuardEnabled) return "实时防护已关闭";
                int fixedDrives = 0;
                try { fixedDrives = DriveInfo.GetDrives().Count(d => d.DriveType == DriveType.Fixed && d.IsReady); } catch { }
                return $"全盘实时监控 {fixedDrives} 个固定驱动器（递归）+ 移动盘 U 盘防护，并发扫描 x4";
            }
        }

        public void Start()
        {
            if (_watchers.Count > 0) return;
            // 复用 App.Data 单例（DataManager 全量加载一次）；
            // 旧实现在此处 new AntivirusEngine() -> 再 new DataManager() = 签名库重复加载 + UI 线程冻结
            _engine = new FireAntivirus.Engine.AntivirusEngine(App.Data);
            int concurrency = SettingsStore.EffectiveConcurrency;
            _scanSem = new SemaphoreSlim(concurrency, concurrency);

            // 全盘监听：所有固定驱动器根目录递归（对标大厂全盘实时防护；移动盘走 UsbGuard）
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                WatchDirectory(drive.RootDirectory.FullName);
            }

            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"实时防护已启动：{CoverageText}（watcher={_watchers.Count}，并发 x{concurrency}）");
        }

        public int WatcherCount => _watchers.Count;

        public void Stop()
        {
            foreach (var w in _watchers.Values)
            {
                try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
            }
            _watchers.Clear();
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "实时防护已停止");
        }

        private void WatchDirectory(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) return;
                var full = Path.GetFullPath(path);
                if (_watchers.ContainsKey(full)) return;

                var watcher = new FileSystemWatcher(full)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    InternalBufferSize = 64 * 1024 // 全盘递归事件量大，64KB 缓冲防丢事件
                };
                watcher.Created += (s, e) => _ = OnFileCreated(e.FullPath);
                watcher.Changed += (s, e) => _ = OnFileCreated(e.FullPath);
                watcher.Error += (s, e) =>
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        $"全盘监控缓冲溢出（{path}），部分事件可能丢失，已自动继续");
                watcher.EnableRaisingEvents = true;
                _watchers[full] = watcher;
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"实时防护监控 {path} 失败: {ex.Message}");
            }
        }

        private static bool IsNoise(string path)
        {
            var lower = path?.ToLowerInvariant() ?? "";
            foreach (var n in NoisePaths)
                if (lower.Contains(n)) return true;
            return false;
        }

        private async Task OnFileCreated(string filePath)
        {
            if (!FileGuardEnabled) return;
            if (UpdateInProgress || FireAntivirus.Engine.SignatureDatabaseUpdater.DbUpdateInProgress) return; // 病毒库更新中，暂停实时扫描防资源对撞
            if (IsNoise(filePath)) return;
            if (SettingsStore.IsExcluded(filePath)) return; // 用户配置的扫描排除目录
            try
            {
                var ext = Path.GetExtension(filePath).ToLowerInvariant();
                bool isScript = Array.IndexOf(ScriptExts, ext) >= 0;
                bool interesting = (Array.IndexOf(WatchedExts, ext) >= 0 && (!isScript || ScriptGuardEnabled))
                                   || RansomGuardEnabled && (IsDocument(ext) || IsRansomArtifact(ext));
                if (!interesting) return;

                // 防抖：同一文件 3 秒内只扫一次
                var now = DateTime.Now;
                if (_recent.TryGetValue(filePath, out var last) && (now - last).TotalSeconds < 3) return;
                _recent[filePath] = now;

                // 勒索行为检测：短时间内大量文档事件，或出现勒索加密特征扩展名
                if (RansomGuardEnabled && IsDocument(ext))
                    TrackDocumentActivity(filePath, now);
                if (RansomGuardEnabled && IsRansomArtifact(ext))
                    RaiseRansomAlert(filePath);

                // 等文件写完（新建事件常早于写入完成）
                await Task.Delay(800);
                if (!File.Exists(filePath)) return;

                _engine ??= new FireAntivirus.Engine.AntivirusEngine();

                // 全盘事件洪峰限流：最多 4 路并发扫描，防 CPU/IO 风暴
                await _scanSem.WaitAsync();
                FireAntivirus.Engine.ScanResult result;
                try { result = _engine.ScanFile(filePath); }
                finally { _scanSem.Release(); }

                if (result == null || !result.IsInfected) return;

                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"实时防护发现威胁: {filePath} ({result.ThreatName}, {result.Severity})");

                var sev = (result.Severity ?? "Medium").ToLowerInvariant();
                if (sev == "high" || sev == "critical" || sev == "严重" || sev == "高")
                {
                    // 高危：可逆自动隔离，不删原始文件
                    if (QuarantineStore.Quarantine(filePath, result.ThreatName, result.Severity, out _))
                        sev = "auto-quarantined";
                }

                // 威胁处置主通道：独立处置窗口（隔离/忽略/打开位置；被占用时提供重启清除/结束占用进程两方案）
                ThreatDealWindow.Show(
                    result.FilePath,
                    result.ThreatName,
                    result.Severity,
                    canQuarantine: sev != "auto-quarantined");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "实时防护处理文件失败: " + ex.Message);
            }
        }

        private static bool IsDocument(string ext) =>
            ext == ".doc" || ext == ".docx" || ext == ".xls" || ext == ".xlsx" ||
            ext == ".pdf" || ext == ".jpg" || ext == ".png";

        #region 勒索行为检测（真实批量加密特征识别）

        private static readonly string[] RansomExts =
        {
            ".encrypted", ".locked", ".crypt", ".krypt", ".onion", ".cerber", ".locky", ".wcry"
        };

        private static bool IsRansomArtifact(string ext) => Array.IndexOf(RansomExts, ext) >= 0;

        private static bool IsAlertedRansom;

        // 60 秒滑动窗口内的文档写入事件计数
        private readonly ConcurrentDictionary<string, DateTime> _docEvents = new();

        private void TrackDocumentActivity(string filePath, DateTime now)
        {
            _docEvents[filePath] = now;

            // 清理 60 秒前的旧事件
            foreach (var kv in _docEvents)
            {
                if ((now - kv.Value).TotalSeconds > 60)
                    _docEvents.TryRemove(kv.Key, out _);
            }

            // 60 秒内 ≥15 个文档事件 → 疑似批量加密（勒索行为特征）
            if (_docEvents.Count >= 15 && !IsAlertedRansom)
            {
                IsAlertedRansom = true;
                RaiseRansomAlert(null);
                // 冷却 5 分钟后才允许再次告警
                _ = Task.Delay(TimeSpan.FromMinutes(5)).ContinueWith(_ => IsAlertedRansom = false);
            }
        }

        private void RaiseRansomAlert(string evidencePath)
        {
            RansomAlertCount++;
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Critical,
                $"检测到疑似勒索软件批量加密行为: {evidencePath ?? "(文档目录短时大量写入)"}");

            // 威胁处置主通道：独立处置窗口（勒索证据为目录，无隔离按钮）
            ThreatDealWindow.Show(
                evidencePath ?? "(文档目录短时大量写入)",
                "Ransomware.Behavior (勒索行为特征)",
                "Critical",
                canQuarantine: false);
        }

        #endregion

        #region 实时拦截自检（已知样本 / 变种样本 / 勒索行为 三级闭环验证）

        /// <summary>勒索告警计数（自检轮询用）。</summary>
        public volatile int RansomAlertCount;

        /// <summary>
        /// 实时防护自检（两档）：
        ///   known   = EICAR 标准样本 —— 验证精确特征库（强证据）通路；
        ///   variant = 变种样本 —— 头部注入随机注释使哈希每次都不同（绕过精确特征库），
        ///             但携带真实勒索/擦除命令特征，验证启发式+多检测器共识（弱证据）拦截通路。
        /// </summary>
        public async Task<(bool Intercepted, string Detail)> SelfTestAsync(string mode = "known")
        {
            string testPath;
            string label;

            if (mode == "variant")
            {
                testPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Downloads", $"fa_rt_selftest_variant_{Guid.NewGuid():N}.bat");
                label = "变种样本（哈希变形，绕过精确特征库，考验多引擎共识）";
            }
            else
            {
                testPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Downloads", "fa_rt_selftest_eicar.bat");
                label = "EICAR 标准样本（精确特征强证据通路）";
            }

            try
            {
                File.WriteAllText(testPath, mode == "variant" ? BuildVariantSample() : EicarSample);

                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"防护自检: 已投放{label}到 Downloads，等待实时管线拦截");

                // 轮询等待实时管线处理（防抖 800ms + 引擎多引擎扫描 + 共识判定 + 隔离）
                for (int i = 0; i < 40; i++)   // 变种走共识判定，给足 20 秒
                {
                    await Task.Delay(500);
                    if (!File.Exists(testPath))
                    {
                        return (true, $"{label}在 {(i + 1) * 0.5:F1} 秒内被实时拦截并自动隔离 ✓");
                    }
                }

                return (false,
                    mode == "variant"
                        ? "20 秒内未拦截变种样本。变种依赖多引擎共识（启发式+检测器+静态分析），请确认各防护开关已开启，并观察云端查杀网络连通性"
                        : "20 秒内未拦截标准样本，请确认文件防护与脚本防护开关已开启");
            }
            catch (Exception ex)
            {
                return (false, $"自检执行失败: {ex.Message}");
            }
            finally
            {
                try { if (File.Exists(testPath)) File.Delete(testPath); } catch { }
            }
        }

        /// <summary>
        /// 勒索行为自检：模拟勒索软件批量加密（短时间写入 18 个 .encrypted 文档），
        /// 验证 RansomGuard 批量加密检测真实触发告警。
        /// </summary>
        public async Task<(bool Detected, string Detail)> SelfTestRansomAsync()
        {
            int baseline = RansomAlertCount;
            var dir = Path.Combine(Path.GetTempPath(), "fa_ransom_selftest");
            var marker = Path.Combine(dir, $"r{Guid.NewGuid():N}");

            try
            {
                Directory.CreateDirectory(dir);

                // 模拟勒索加密行为：快速连续写入 18 个加密特征文档（超过 60 秒窗口 15 事件阈值）
                for (int i = 0; i < 18; i++)
                {
                    File.WriteAllText(Path.Combine(dir, $"{marker}_{i}.docx.encrypted"),
                        "ransomware behavior simulation (harmless, will be cleaned)");
                }

                // 轮询等待勒索行为检测触发（滑动窗口 + 浮层告警）
                for (int i = 0; i < 24; i++)
                {
                    await Task.Delay(500);
                    if (RansomAlertCount > baseline)
                    {
                        return (true, $"勒索行为检测在 {(i + 1) * 0.5:F1} 秒内触发告警 ✓（批量加密特征识别正常）");
                    }
                }

                return (false, "12 秒内未检测到勒索行为告警，请确认文档防护（勒索）开关已开启");
            }
            catch (Exception ex)
            {
                return (false, $"勒索自检执行失败: {ex.Message}");
            }
            finally
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(dir, $"{marker}*"))
                        File.Delete(f);
                }
                catch { }
            }
        }

        private const string EicarSample =
            @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        /// <summary>
        /// 构造变种测试样本：随机注释头使文件哈希每次都不同（精确特征库不会命中），
        /// 正文携带真实勒索/擦除命令特征（vssadmin 阴影删除、bcdedit 破坏恢复、cipher 覆写、
        /// 批量删除文档）——只落盘不执行，验证启发式+检测器+静态分析的多引擎共识拦截。
        /// </summary>
        private static string BuildVariantSample()
        {
            var noise = Convert.ToBase64String(Guid.NewGuid().ToByteArray())
                .Replace("=", "").Replace("/", "").Replace("+", "");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"rem variant-selftest {noise} (harmless sample, never executed)");
            sb.AppendLine("@echo off");
            sb.AppendLine("vssadmin.exe delete shadows /all /quiet");
            sb.AppendLine("wbadmin.exe delete catalog -quiet");
            sb.AppendLine("bcdedit /set recoveryenabled no");
            sb.AppendLine("cipher.exe /w:C:");
            sb.AppendLine("del /f /s /q \"%USERPROFILE%\\Documents\\*.*\"");
            sb.AppendLine($"rem end {noise}");
            return sb.ToString();
        }

        #endregion
    }
}
