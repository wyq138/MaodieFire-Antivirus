using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class PopupBlocker : IMonitor
    {
        private Thread monitorThread;
        private bool isRunning;
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private HashSet<string> blockedProcesses;
        private HashSet<string> blockedWindows;
        private HashSet<string> allowedProcesses;
        private Dictionary<string, WindowInfo> windowHistory;
        private int checkInterval;
        private bool enablePopupBlocking;
        private bool enableAggressiveMode;

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);

        [DllImport("user32.dll")]
        private static extern int GetClassName(IntPtr hWnd, System.Text.StringBuilder className, int count);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        private const int SW_HIDE = 0;
        private const int SW_SHOW = 5;
        private const int SW_MINIMIZE = 6;

        public PopupBlocker(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            this.blockedProcesses = new HashSet<string>();
            this.blockedWindows = new HashSet<string>();
            this.allowedProcesses = new HashSet<string>();
            this.windowHistory = new Dictionary<string, WindowInfo>();
            this.checkInterval = 1000;
            this.enablePopupBlocking = true;
            this.enableAggressiveMode = false;
            InitializeBlockedLists();
            LoadBlockedLists();
        }

        private void InitializeBlockedLists()
        {
            allowedProcesses.Add("explorer.exe");
            allowedProcesses.Add("chrome.exe");
            allowedProcesses.Add("firefox.exe");
            allowedProcesses.Add("msedge.exe");
            allowedProcesses.Add("notepad.exe");
            allowedProcesses.Add("calc.exe");
            allowedProcesses.Add("cmd.exe");
            allowedProcesses.Add("powershell.exe");
            allowedProcesses.Add("winword.exe");
            allowedProcesses.Add("excel.exe");
            allowedProcesses.Add("powerpnt.exe");
        }

        private void LoadBlockedLists()
        {
            try
            {
                string blockedProcessesPath = Path.Combine(dataManager.GetDataDirectory(), "blocked_processes.txt");
                if (File.Exists(blockedProcessesPath))
                {
                    string[] processes = File.ReadAllLines(blockedProcessesPath);
                    foreach (string process in processes)
                    {
                        if (!string.IsNullOrWhiteSpace(process) && !process.StartsWith("#"))
                        {
                            blockedProcesses.Add(process.Trim().ToLower());
                        }
                    }
                }

                string blockedWindowsPath = Path.Combine(dataManager.GetDataDirectory(), "blocked_windows.txt");
                if (File.Exists(blockedWindowsPath))
                {
                    string[] windows = File.ReadAllLines(blockedWindowsPath);
                    foreach (string window in windows)
                    {
                        if (!string.IsNullOrWhiteSpace(window) && !window.StartsWith("#"))
                        {
                            blockedWindows.Add(window.Trim().ToLower());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("加载阻止列表失败: " + ex.Message);
            }
        }

        private void SaveBlockedLists()
        {
            try
            {
                string blockedProcessesPath = Path.Combine(dataManager.GetDataDirectory(), "blocked_processes.txt");
                File.WriteAllLines(blockedProcessesPath, blockedProcesses);

                string blockedWindowsPath = Path.Combine(dataManager.GetDataDirectory(), "blocked_windows.txt");
                File.WriteAllLines(blockedWindowsPath, blockedWindows);
            }
            catch (Exception ex)
            {
                LogError("保存阻止列表失败: " + ex.Message);
            }
        }

        public void Start()
        {
            if (isRunning) return;
            isRunning = true;
            monitorThread = new Thread(MonitorLoop);
            monitorThread.IsBackground = true;
            monitorThread.Start();
            LogInfo("弹窗拦截已启动");
        }

        public void Stop()
        {
            isRunning = false;
            if (monitorThread != null && monitorThread.IsAlive)
            {
                monitorThread.Join(5000);
            }
            LogInfo("弹窗拦截已停止");
        }

        private void MonitorLoop()
        {
            while (isRunning)
            {
                try
                {
                    if (enablePopupBlocking)
                    {
                        MonitorWindows();
                    }
                    Thread.Sleep(checkInterval);
                }
                catch (Exception ex)
                {
                    LogError("弹窗拦截监控异常: " + ex.Message);
                    Thread.Sleep(5000);
                }
            }
        }

        public void MonitorWindows()
        {
            try
            {
                IntPtr foregroundWindow = GetForegroundWindow();
                if (foregroundWindow == IntPtr.Zero) return;

                WindowInfo windowInfo = GetWindowInfo(foregroundWindow);
                if (windowInfo == null) return;

                if (IsBlockedWindow(windowInfo))
                {
                    BlockWindow(windowInfo);
                }
                else if (IsSuspiciousWindow(windowInfo))
                {
                    HandleSuspiciousWindow(windowInfo);
                }

                UpdateWindowHistory(windowInfo);
            }
            catch (Exception ex)
            {
                LogError("监控窗口失败: " + ex.Message);
            }
        }

        private WindowInfo GetWindowInfo(IntPtr hWnd)
        {
            try
            {
                if (!IsWindowVisible(hWnd)) return null;

                System.Text.StringBuilder title = new System.Text.StringBuilder(256);
                GetWindowText(hWnd, title, title.Capacity);

                System.Text.StringBuilder className = new System.Text.StringBuilder(256);
                GetClassName(hWnd, className, className.Capacity);

                string processName = GetProcessNameByWindow(hWnd);
                if (string.IsNullOrEmpty(processName)) return null;

                return new WindowInfo
                {
                    Handle = hWnd,
                    Title = title.ToString(),
                    ClassName = className.ToString(),
                    ProcessName = processName,
                    DetectedAt = DateTime.Now
                };
            }
            catch
            {
                return null;
            }
        }

        private string GetProcessNameByWindow(IntPtr hWnd)
        {
            try
            {
                uint processId;
                GetWindowThreadProcessId(hWnd, out processId);

                Process process = Process.GetProcessById((int)processId);
                return process.ProcessName.ToLower();
            }
            catch
            {
                return null;
            }
        }

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        private bool IsBlockedWindow(WindowInfo windowInfo)
        {
            if (blockedProcesses.Contains(windowInfo.ProcessName))
            {
                return true;
            }

            foreach (string blockedWindow in blockedWindows)
            {
                if (windowInfo.Title.ToLower().Contains(blockedWindow.ToLower()))
                {
                    return true;
                }
            }

            return false;
        }

        private bool IsSuspiciousWindow(WindowInfo windowInfo)
        {
            if (allowedProcesses.Contains(windowInfo.ProcessName))
            {
                return false;
            }

            string[] suspiciousKeywords = {
                "广告", "ad", "popup", "弹窗", "推广", "促销", "优惠", "中奖",
                "恭喜", "下载", "install", "update", "warning", "alert", "error",
                "病毒", "virus", "malware", "威胁", "清理", "优化", "加速"
            };

            foreach (string keyword in suspiciousKeywords)
            {
                if (windowInfo.Title.ToLower().Contains(keyword.ToLower()))
                {
                    return true;
                }
            }

            if (windowInfo.Title.Length > 0 && windowInfo.Title.Length < 10)
            {
                return true;
            }

            if (Regex.IsMatch(windowInfo.Title, @"^[\d\s]+$"))
            {
                return true;
            }

            return false;
        }

        private void BlockWindow(WindowInfo windowInfo)
        {
            try
            {
                ShowWindow(windowInfo.Handle, SW_HIDE);

                string message = $"阻止弹窗: {windowInfo.ProcessName} - {windowInfo.Title}";
                LogInfo(message);

                PopupThreatDetection detection = new PopupThreatDetection
                {
                    FilePath = windowInfo.ProcessName,
                    ThreatType = ThreatType.PopupAdvertisement.ToString(),
                    Severity = ThreatSeverity.Low.ToString(),
                    Description = "阻止弹窗广告",
                    DetectedAt = DateTime.Now,
                    Details = message
                };
                dataManager.LogThreat($"阻止弹窗广告: {windowInfo.ProcessName}", $"威胁类型: {detection.ThreatType}, 详细信息: {detection.Details}");
            }
            catch (Exception ex)
            {
                LogError("阻止窗口失败: " + ex.Message);
            }
        }

        private void HandleSuspiciousWindow(WindowInfo windowInfo)
        {
            try
            {
                if (enableAggressiveMode)
                {
                    ShowWindow(windowInfo.Handle, SW_MINIMIZE);

                    string message = $"最小化可疑窗口: {windowInfo.ProcessName} - {windowInfo.Title}";
                    LogInfo(message);
                }
                else
                {
                    string windowKey = $"{windowInfo.ProcessName}_{windowInfo.Title}";

                    if (windowHistory.ContainsKey(windowKey))
                    {
                        WindowInfo history = windowHistory[windowKey];
                        TimeSpan timeDiff = DateTime.Now - history.DetectedAt;

                        if (timeDiff.TotalSeconds < 5)
                        {
                            ShowWindow(windowInfo.Handle, SW_MINIMIZE);

                            string message = $"频繁弹窗已最小化: {windowInfo.ProcessName} - {windowInfo.Title}";
                            LogInfo(message);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("处理可疑窗口失败: " + ex.Message);
            }
        }

        private void UpdateWindowHistory(WindowInfo windowInfo)
        {
            try
            {
                string windowKey = $"{windowInfo.ProcessName}_{windowInfo.Title}";
                windowHistory[windowKey] = windowInfo;

                if (windowHistory.Count > 1000)
                {
                    var oldestEntry = windowHistory.OrderBy(kvp => kvp.Value.DetectedAt).First();
                    windowHistory.Remove(oldestEntry.Key);
                }
            }
            catch (Exception ex)
            {
                LogError("更新窗口历史失败: " + ex.Message);
            }
        }

        public bool AddBlockedProcess(string processName)
        {
            try
            {
                processName = processName.Trim().ToLower();
                if (!blockedProcesses.Contains(processName))
                {
                    blockedProcesses.Add(processName);
                    SaveBlockedLists();
                    LogInfo($"添加阻止进程: {processName}");
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"添加阻止进程异常: " + ex.Message);
                return false;
            }
        }

        public bool RemoveBlockedProcess(string processName)
        {
            try
            {
                processName = processName.Trim().ToLower();
                if (blockedProcesses.Remove(processName))
                {
                    SaveBlockedLists();
                    LogInfo($"移除阻止进程: {processName}");
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"移除阻止进程异常: " + ex.Message);
                return false;
            }
        }

        public bool AddBlockedWindow(string windowTitle)
        {
            try
            {
                windowTitle = windowTitle.Trim().ToLower();
                if (!blockedWindows.Contains(windowTitle))
                {
                    blockedWindows.Add(windowTitle);
                    SaveBlockedLists();
                    LogInfo($"添加阻止窗口: {windowTitle}");
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"添加阻止窗口异常: " + ex.Message);
                return false;
            }
        }

        public bool RemoveBlockedWindow(string windowTitle)
        {
            try
            {
                windowTitle = windowTitle.Trim().ToLower();
                if (blockedWindows.Remove(windowTitle))
                {
                    SaveBlockedLists();
                    LogInfo($"移除阻止窗口: {windowTitle}");
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                LogError($"移除阻止窗口异常: " + ex.Message);
                return false;
            }
        }

        public List<string> GetBlockedProcesses()
        {
            return blockedProcesses.ToList();
        }

        public List<string> GetBlockedWindows()
        {
            return blockedWindows.ToList();
        }

        public List<WindowInfo> GetWindowHistory()
        {
            return windowHistory.Values.ToList();
        }

        public void SetCheckInterval(int milliseconds)
        {
            checkInterval = milliseconds;
        }

        public void SetPopupBlocking(bool enabled)
        {
            enablePopupBlocking = enabled;
        }

        public void SetAggressiveMode(bool enabled)
        {
            enableAggressiveMode = enabled;
        }

        private void LogInfo(string message)
        {
            dataManager.LogInfo("[弹窗拦截] " + message);
        }

        private void LogError(string message)
        {
            dataManager.LogError("[弹窗拦截] " + message);
        }
    }

    public class WindowInfo
    {
        public IntPtr Handle { get; set; }
        public string Title { get; set; }
        public string ClassName { get; set; }
        public string ProcessName { get; set; }
        public DateTime DetectedAt { get; set; }
    }

    public class PopupThreatDetection
    {
        public string FilePath { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public string Description { get; set; }
        public DateTime DetectedAt { get; set; }
        public string Details { get; set; }
    }
}