// 弹窗拦截服务（WPF 版 PopupRuleManager 真实化升级，WinUI/WPF 共用）：
//   规则管理：应用名 / 进程路径前缀 / 窗口标题关键字 三类匹配，JSON 持久化（ProgramData\FireAntivirus\PopupBlocker\rules.json）。
//   真实拦截：定时枚举可见顶层窗口（EnumWindows + 进程归属判定），命中规则后 PostMessage(WM_CLOSE) 关闭弹窗，
//             记录拦截日志（上限 1000 条）与每规则计数。
//   安全护栏：不拦本进程/系统外壳窗口（任务栏/桌面/ShellaExperience）/系统关键进程（explorer/dwm/winlogon 等），
//             无规则时不执行任何关闭动作（默认零误拦）。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace FireAntivirus.Services
{
    public class PopupRule
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string AppName { get; set; }        // 进程名（可省略 .exe）
        public string Path { get; set; }           // 进程路径前缀（可空）
        public string Rule { get; set; }           // 窗口标题关键字（可空）
        public bool Enabled { get; set; } = true;
        public long BlockedCount { get; set; }
        public DateTime? LastBlocked { get; set; }
    }

    public class PopupBlockLog
    {
        public DateTime Time { get; set; }
        public string AppName { get; set; }
        public string WindowTitle { get; set; }
        public string RuleId { get; set; }
    }

    public class PopupBlockerStats
    {
        public int RuleCount { get; set; }
        public long TotalBlocked { get; set; }
        public int LogCount { get; set; }
        public bool Running { get; set; }
    }

    public sealed class PopupBlockerService : IDisposable
    {
        /// <summary>进程级单例：页面（弹窗拦截 Tab）与设置页开关共享同一实例与同一规则/日志。</summary>
        public static PopupBlockerService Instance { get; } = new PopupBlockerService();
        private const uint WM_CLOSE = 0x0010;
        private const int MaxLogs = 1000;

        private readonly object _lock = new object();
        private readonly List<PopupRule> _rules = new List<PopupRule>();
        private readonly List<PopupBlockLog> _logs = new List<PopupBlockLog>();
        private Timer _timer;
        private volatile bool _running;
        private int _scanBusy;

        private static readonly string RulesFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "PopupBlocker", "rules.json");

        // 系统外壳/关键窗口类：永不拦截
        private static readonly HashSet<string> ProtectedClasses = new(StringComparer.OrdinalIgnoreCase)
        {
            "Shell_TrayWnd", "Shell_SecondaryTrayWnd", "Progman", "WorkerW", "Windows.UI.Core.CoreWindow",
            "ApplicationFrameWindow_System", "TaskListThumbnailWnd", "DV2ControlHost", "MsgrIMEWindowClass",
            "Windows.Internal.Shell.TabProxyWindow", "XamlExplorerHostIslandWindow"
        };

        // 系统关键进程：永不拦截
        private static readonly HashSet<string> ProtectedProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "explorer", "dwm", "winlogon", "csrss", "wininit", "services", "lsass", "smss",
            "SearchHost", "StartMenuExperienceHost", "ShellExperienceHost", "TextInputHost",
            "sihost", "taskhostw", "SecurityHealthSystray", "LockApp", "SystemSettings"
        };

        public PopupBlockerService()
        {
            LoadRules();
            LoadLogs();
        }

        public bool IsRunning => _running;
        public int ScanIntervalMs { get; set; } = 3000;

        public void Start()
        {
            if (_running) return;
            _running = true;
            _timer ??= new Timer(_ => ScanOnce(), null, 1000, ScanIntervalMs);
            _timer.Change(1000, ScanIntervalMs);
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "弹窗拦截已启动");
        }

        public void Stop()
        {
            _running = false;
            try { _timer?.Change(Timeout.Infinite, Timeout.Infinite); } catch { }
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "弹窗拦截已停止");
        }

        public void Dispose() { Stop(); _timer?.Dispose(); }

        // ---------------------------------------------------------------- 规则管理

        public List<PopupRule> GetRules()
        {
            lock (_lock) return _rules.ToList();
        }

        public bool AddRule(PopupRule rule, out string error)
        {
            error = null;
            if (rule == null) { error = "规则为空"; return false; }
            if (string.IsNullOrWhiteSpace(rule.AppName) && string.IsNullOrWhiteSpace(rule.Rule))
            {
                error = "应用名与窗口标题关键字至少填一项";
                return false;
            }

            lock (_lock)
            {
                if (_rules.Count >= 500) { error = "规则数量已达上限（500）"; return false; }

                bool dup = _rules.Any(r =>
                    string.Equals(r.AppName ?? "", rule.AppName ?? "", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.Rule ?? "", rule.Rule ?? "", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.Path ?? "", rule.Path ?? "", StringComparison.OrdinalIgnoreCase));
                if (dup) { error = "相同规则已存在"; return false; }

                rule.Id = Guid.NewGuid().ToString();
                _rules.Add(rule);
            }
            SaveRules();
            return true;
        }

        public bool RemoveRule(string id)
        {
            bool removed;
            lock (_lock)
            {
                removed = _rules.RemoveAll(r => r.Id == id) > 0;
            }
            if (removed) SaveRules();
            return removed;
        }

        public bool SetRuleEnabled(string id, bool enabled)
        {
            bool updated = false;
            lock (_lock)
            {
                var rule = _rules.FirstOrDefault(r => r.Id == id);
                if (rule != null) { rule.Enabled = enabled; updated = true; }
            }
            if (updated) SaveRules();
            return updated;
        }

        // ---------------------------------------------------------------- 拦截执行

        /// <summary>立即扫描一次（定时器调用或页面手动触发）。</summary>
        public int ScanOnce()
        {
            if (!_running && _timer == null) return 0;
            if (Interlocked.Exchange(ref _scanBusy, 1) == 1) return 0;

            int closed = 0;
            try
            {
                List<PopupRule> snapshot;
                lock (_lock) snapshot = _rules.Where(r => r.Enabled).ToList();
                if (snapshot.Count == 0) return 0; // 无规则零动作（默认零误拦）

                int selfPid = Environment.ProcessId;
                var hits = new List<(IntPtr hwnd, string title, string appName, PopupRule rule)>();

                EnumWindows((hwnd, _) =>
                {
                    try
                    {
                        if (!IsWindowVisible(hwnd)) return true;

                        string title = GetWindowTextSafe(hwnd);
                        if (string.IsNullOrWhiteSpace(title)) return true;

                        string cls = GetClassNameSafe(hwnd);
                        if (ProtectedClasses.Contains(cls)) return true;

                        GetWindowThreadProcessId(hwnd, out uint pid);
                        if (pid == 0) return true;
                        if (pid == selfPid) return true;

                        string procName;
                        string procPath = null;
                        try
                        {
                            using var proc = Process.GetProcessById((int)pid);
                            procName = proc.ProcessName;
                            try { procPath = proc.MainModule?.FileName; } catch { }
                        }
                        catch { return true; }

                        if (ProtectedProcesses.Contains(procName)) return true;

                        foreach (var rule in snapshot)
                        {
                            if (Matches(rule, procName, procPath, title))
                            {
                                hits.Add((hwnd, title, procName, rule));
                                break;
                            }
                        }
                    }
                    catch { }
                    return true;
                }, IntPtr.Zero);

                if (hits.Count == 0) return 0;

                foreach (var (hwnd, title, appName, rule) in hits)
                {
                    try
                    {
                        PostMessage(hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                        closed++;
                        rule.BlockedCount++;
                        rule.LastBlocked = DateTime.Now;
                        AddLog(new PopupBlockLog
                        {
                            Time = DateTime.Now,
                            AppName = appName,
                            WindowTitle = title,
                            RuleId = rule.Id
                        });
                    }
                    catch { }
                }

                if (closed > 0)
                {
                    SaveRules();
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        $"[弹窗拦截] 已关闭 {closed} 个弹窗窗口");
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "弹窗拦截扫描失败: " + ex.Message);
            }
            finally
            {
                Interlocked.Exchange(ref _scanBusy, 0);
            }
            return closed;
        }

        private static bool Matches(PopupRule rule, string procName, string procPath, string title)
        {
            if (!string.IsNullOrWhiteSpace(rule.AppName))
            {
                var want = rule.AppName.Trim();
                if (want.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) want = want[..^4];
                if (!procName.Equals(want, StringComparison.OrdinalIgnoreCase)) return false;
            }

            if (!string.IsNullOrWhiteSpace(rule.Path))
            {
                if (string.IsNullOrEmpty(procPath) ||
                    !procPath.StartsWith(rule.Path.Trim(), StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            if (!string.IsNullOrWhiteSpace(rule.Rule))
            {
                if (title.IndexOf(rule.Rule.Trim(), StringComparison.OrdinalIgnoreCase) < 0) return false;
            }

            return true;
        }

        // ---------------------------------------------------------------- 日志与统计

        public List<PopupBlockLog> GetLogs()
        {
            lock (_lock) return _logs.ToList();
        }

        public void ClearLogs()
        {
            lock (_lock) _logs.Clear();
            SaveLogs();
        }

        public PopupBlockerStats GetStatistics()
        {
            lock (_lock)
            {
                return new PopupBlockerStats
                {
                    RuleCount = _rules.Count,
                    TotalBlocked = _rules.Sum(r => r.BlockedCount),
                    LogCount = _logs.Count,
                    Running = _running
                };
            }
        }

        private void AddLog(PopupBlockLog log)
        {
            lock (_lock)
            {
                _logs.Insert(0, log);
                if (_logs.Count > MaxLogs) _logs.RemoveRange(MaxLogs, _logs.Count - MaxLogs);
            }
            SaveLogs();
        }

        // ---------------------------------------------------------------- 持久化

        private void LoadRules()
        {
            try
            {
                if (!File.Exists(RulesFile)) return;
                var list = JsonSerializer.Deserialize<List<PopupRule>>(File.ReadAllText(RulesFile));
                if (list == null) return;
                lock (_lock) { _rules.Clear(); _rules.AddRange(list); }
            }
            catch { }
        }

        private void SaveRules()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(RulesFile));
                List<PopupRule> snapshot;
                lock (_lock) snapshot = _rules.ToList();
                File.WriteAllText(RulesFile, JsonSerializer.Serialize(snapshot,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private static string LogsFile => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "PopupBlocker", "logs.json");

        private void LoadLogs()
        {
            try
            {
                if (!File.Exists(LogsFile)) return;
                var list = JsonSerializer.Deserialize<List<PopupBlockLog>>(File.ReadAllText(LogsFile));
                if (list == null) return;
                lock (_lock) { _logs.Clear(); _logs.AddRange(list.Take(MaxLogs)); }
            }
            catch { }
        }

        private void SaveLogs()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(LogsFile));
                List<PopupBlockLog> snapshot;
                lock (_lock) snapshot = _logs.Take(MaxLogs).ToList();
                File.WriteAllText(LogsFile, JsonSerializer.Serialize(snapshot));
            }
            catch { }
        }

        // ---------------------------------------------------------------- Win32

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
        [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        private static string GetWindowTextSafe(IntPtr hwnd)
        {
            var sb = new StringBuilder(512);
            int n = GetWindowText(hwnd, sb, sb.Capacity);
            return n > 0 ? sb.ToString() : "";
        }

        private static string GetClassNameSafe(IntPtr hwnd)
        {
            var sb = new StringBuilder(256);
            int n = GetClassName(hwnd, sb, sb.Capacity);
            return n > 0 ? sb.ToString() : "";
        }
    }
}