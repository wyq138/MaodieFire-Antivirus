// 全局设置存储：JSON 持久化（ProgramData\FireAntivirus\Settings\app_settings.json）+ 内存缓存。
// 读取走内存（零 IO），保存时落盘并刷新缓存——实时防护/扫描的每文件热路径直接读 Current，安全。
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace FireAntivirus.Host.WinUI
{
    public static class SettingsStore
    {
        private static readonly object _lock = new object();
        private static AppSettings _cache;

        private static string FilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "Settings", "app_settings.json");

        public sealed class AppSettings
        {
            /// <summary>扫描/实时防护并发度（1-8，默认 4）。</summary>
            public int ScanConcurrency { get; set; } = 4;

            /// <summary>扫描与实时防护排除目录（精确前缀匹配，不区分大小写）。</summary>
            public List<string> ExcludedDirs { get; set; } = new List<string>();

            /// <summary>看门狗自恢复（计划任务 FireAntivirusWatchdog）开关。</summary>
            public bool WatchdogEnabled { get; set; } = true;

            /// <summary>特征库在线更新源 URL（空 = 未配置，出厂库兜底）。</summary>
            public string ThreatDataUpdateSource { get; set; } = "";

            /// <summary>弹窗拦截常驻开关（PopupBlockerService 单例随启动恢复）。</summary>
            public bool PopupBlockerEnabled { get; set; } = false;

            /// <summary>隐私访问监控随启动开启（摄像头/麦克风/敏感数据访问告警）。</summary>
            public bool PrivacyMonitorAutoStart { get; set; } = false;

            /// <summary>家长控制启用（时间限制 + 内容过滤生效）。</summary>
            public bool ParentalControlEnabled { get; set; } = false;

            /// <summary>自动沙箱验证：未签名可疑文件在 Sandboxie 中运行 60 秒行为分析，确认恶意才报（降误报）。</summary>
            public bool AutoSandboxEnabled { get; set; } = true;

            /// <summary>AMSI 脚本内容扫描（调用系统 amsi.dll，脚本检测的独立强证据源）。</summary>
            public bool AmsiEnabled { get; set; } = true;

            /// <summary>凭据访问防护（LSASS 转储 / SAM 导出 / 凭据管理器枚举等 ATT&amp;CK 技术）。</summary>
            public bool CredentialAccessEnabled { get; set; } = true;

            /// <summary>防御规避检测（卷影删除 / 日志清除 / Defender 篡改 / SafeBoot 操纵等 ATT&amp;CK 技术）。</summary>
            public bool DefenseEvasionEnabled { get; set; } = true;

            /// <summary>压缩包深度扫描（解开 zip/tar/gz/rar/7z 并对内部文件查杀）。</summary>
            public bool ScanArchives { get; set; } = true;

            /// <summary>句柄访问掩码审计（全系统句柄表 + 受保护进程，60 秒周期 + JSON 取证报告）。</summary>
            public bool HandleAuditEnabled { get; set; } = true;

            /// <summary>沙箱反沙箱对抗（识别反虚拟机/反调试痕迹并自动加固 Sandboxie 配置）。</summary>
            public bool SandboxEvasionGuardEnabled { get; set; } = true;

            /// <summary>Melix 模型数据集目录（index.jsonl 或 benign/malicious 子目录）。</summary>
            public string ModelDatasetPath { get; set; } = "";

            /// <summary>模型校准目标误报率（默认 1%）。</summary>
            public double ModelTargetFpr { get; set; } = 0.01;

            /// <summary>训练时每类样本上限（默认 200，控制训练耗时与内存）。</summary>
            public int ModelMaxSamplesPerClass { get; set; } = 200;

            // ---- 七项高级检测（实时防护 + 全盘扫描共用）----
            public bool FuzzyHashEnabled { get; set; } = true;
            public bool EntropyTimelineEnabled { get; set; } = true;
            public bool ProcessLineageEnabled { get; set; } = true;
            public bool ChainBlockEnabled { get; set; } = true;
            public bool SensitiveFlowEnabled { get; set; } = true;
            public bool VadScanEnabled { get; set; } = true;

            public bool AsrEnabled { get; set; } = true;
            public bool TimelineEnabled { get; set; } = true;

            public bool EtwEnabled { get; set; } = true;
            public bool WfpBlockEnabled { get; set; } = true;

            // 注意：VirusTotal 密钥为开发商内嵌（AntivirusEngine.DefaultVtKey，分段存储），
            // 不落设置文件、不在 UI 回填展示——这是发布给用户的软件，密钥不能暴露给终端用户。
        }

        public static AppSettings Current
        {
            get
            {
                lock (_lock)
                {
                    if (_cache == null) _cache = Load();
                    return _cache;
                }
            }
        }

        /// <summary>保存当前设置并落盘（保存即生效，消费方每次热路径读 Current 内存缓存）。</summary>
        public static void Save()
        {
            lock (_lock)
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(FilePath));
                    File.WriteAllText(FilePath,
                        JsonSerializer.Serialize(_cache, new JsonSerializerOptions { WriteIndented = true }));
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        "设置已保存: " + FilePath);
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        "设置保存失败", ex.Message);
                }
            }
        }

        /// <summary>重新从磁盘加载（导入设置备份后调用）。</summary>
        public static void Reload()
        {
            lock (_lock) { _cache = Load(); }
        }

        private static AppSettings Load()
        {
            try
            {
                if (File.Exists(FilePath))
                {
                    return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
                }
            }
            catch { }
            return new AppSettings();
        }

        /// <summary>
        /// 路径是否命中排除目录（前缀匹配，全盘实时防护与扫描枚举共用）。
        /// 排除目录自身也排除其子树；内存 O(n) 比较，热路径安全。
        /// </summary>
        public static bool IsExcluded(string path)
        {
            var dirs = Current.ExcludedDirs;
            if (dirs == null || dirs.Count == 0 || string.IsNullOrEmpty(path)) return false;
            string lower = path.ToLowerInvariant();
            foreach (var d in dirs)
            {
                if (string.IsNullOrWhiteSpace(d)) continue;
                string dd = d.Trim().TrimEnd('\\', '/').ToLowerInvariant();
                if (dd.Length == 0) continue;
                if (lower == dd || lower.StartsWith(dd + "\\", StringComparison.Ordinal)) return true;
            }
            return false;
        }

        /// <summary>并发度钳制（1-8）。</summary>
        public static int EffectiveConcurrency =>
            Math.Max(1, Math.Min(8, Current.ScanConcurrency));
    }
}