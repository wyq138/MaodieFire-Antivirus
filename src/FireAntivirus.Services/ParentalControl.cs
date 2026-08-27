using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using FireAntivirus.Data;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 家长控制服务 - 实现真正的时间限制、内容过滤和应用阻止
    /// </summary>
    public class ParentalControl : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private Dictionary<string, UserUsageData> _userUsage;
        private ParentalControlSettings _settings;
        private DateTime _lastCheckTime;
        private string _currentProtectedUser;
        private bool _passwordVerified = false;

        public bool IsRunning => _isRunning;
        public bool IsTimeLimitEnabled => _settings?.EnableTimeLimit ?? false;
        public bool IsContentFilterEnabled => _settings?.EnableContentFilter ?? false;
        public bool IsAppBlockingEnabled => _settings?.EnableAppBlocking ?? false;

        // Windows API for session lock
        [DllImport("user32.dll")]
        private static extern bool LockWorkStation();

        [DllImport("user32.dll")]
        private static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

        private const uint EWX_LOGOFF = 0x00000000;
        private const uint EWX_FORCE = 0x00000004;

        public ParentalControl(DataManager dataManager)
        {
            _dataManager = dataManager;
            _userUsage = new Dictionary<string, UserUsageData>();
            _settings = new ParentalControlSettings();
            _lastCheckTime = DateTime.Now;
            LoadSettings();
        }

        public void Start()
        {
            if (_isRunning) return;
            
            _isRunning = true;
            _currentProtectedUser = Environment.UserName;
            _lastCheckTime = DateTime.Now;
            
            // 初始化或加载用户使用数据
            InitializeUserUsage();
            
            // 启动监控线程
            _monitorThread = new Thread(MonitorParentalControl);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ParentalControlStart",
                Message = "家长控制服务已启动",
                Details = $"受保护用户: {_currentProtectedUser}"
            });
        }

        public void Stop()
        {
            if (!_isRunning) return;
            
            _isRunning = false;
            
            // 保存使用数据
            SaveUserUsage();
            
            _monitorThread?.Join(2000);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ParentalControlStop",
                Message = "家长控制服务已停止"
            });
        }

        #region 初始化

        private void InitializeUserUsage()
        {
            try
            {
                var data = _dataManager.LoadParentalControlUsage();
                if (data != null && data.Count > 0)
                {
                    // 转换数据格式
                    foreach (var kvp in data)
                    {
                        _userUsage[kvp.Key] = new UserUsageData
                        {
                            UserName = kvp.Value.UserName,
                            DailyUsageMinutes = kvp.Value.DailyUsageMinutes,
                            SessionStartTime = DateTime.TryParse(kvp.Value.SessionStartTime, out var sTime) ? sTime : DateTime.Now,
                            LastActivity = DateTime.TryParse(kvp.Value.LastActivity, out var lTime) ? lTime : DateTime.Now,
                            LastDate = kvp.Value.LastDate ?? "",
                            AccessedApps = kvp.Value.AccessedApps ?? new List<string>(),
                            AccessedWebsites = kvp.Value.AccessedWebsites ?? new List<string>()
                        };
                    }
                    
                    // 检查是否是新的一天，如果是则重置使用时间
                    if (_userUsage.ContainsKey(_currentProtectedUser))
                    {
                        var userData = _userUsage[_currentProtectedUser];
                        if (userData.LastDate != DateTime.Today.ToString("yyyy-MM-dd"))
                        {
                            userData.DailyUsageMinutes = 0;
                            userData.LastDate = DateTime.Today.ToString("yyyy-MM-dd");
                            userData.SessionStartTime = DateTime.Now;
                        }
                    }
                }
                
                if (!_userUsage.ContainsKey(_currentProtectedUser))
                {
                    _userUsage[_currentProtectedUser] = new UserUsageData
                    {
                        UserName = _currentProtectedUser,
                        DailyUsageMinutes = 0,
                        SessionStartTime = DateTime.Now,
                        LastDate = DateTime.Today.ToString("yyyy-MM-dd")
                    };
                }
            }
            catch
            {
                _userUsage[_currentProtectedUser] = new UserUsageData
                {
                    UserName = _currentProtectedUser,
                    DailyUsageMinutes = 0,
                    SessionStartTime = DateTime.Now,
                    LastDate = DateTime.Today.ToString("yyyy-MM-dd")
                };
            }
        }

        #endregion

        #region 监控循环

        private void MonitorParentalControl()
        {
            while (_isRunning)
            {
                try
                {
                    // 计算并更新使用时间
                    UpdateUsageTime();

                    // 检查时间限制
                    if (_settings.EnableTimeLimit)
                    {
                        CheckTimeLimit();
                    }

                    // 检查允许使用时间段
                    if (_settings.EnableTimeWindow)
                    {
                        CheckTimeWindow();
                    }

                    // 检查应用程序阻止
                    if (_settings.EnableAppBlocking)
                    {
                        CheckBlockedApplications();
                    }

                    // 检查内容过滤（浏览器监控）
                    if (_settings.EnableContentFilter)
                    {
                        CheckContentFilter();
                    }

                    // 定期保存数据
                    if (DateTime.Now.Minute % 5 == 0)
                    {
                        SaveUserUsage();
                    }
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ParentalControlError",
                        Message = "家长控制服务错误",
                        Details = ex.Message
                    });
                }

                Thread.Sleep(30000); // 每30秒检查一次
            }
        }

        private void UpdateUsageTime()
        {
            var now = DateTime.Now;
            var userData = GetCurrentUserUsage();
            
            if (userData != null)
            {
                var elapsed = (now - _lastCheckTime).TotalMinutes;
                userData.DailyUsageMinutes += (int)elapsed;
                userData.LastActivity = now;
            }
            
            _lastCheckTime = now;
        }

        #endregion

        #region 时间限制

        private void CheckTimeLimit()
        {
            var userData = GetCurrentUserUsage();
            if (userData == null) return;

            var limitMinutes = _settings.DailyTimeLimitMinutes;
            var usedMinutes = userData.DailyUsageMinutes;
            var remainingMinutes = limitMinutes - usedMinutes;

            // 警告阶段
            if (remainingMinutes <= 15 && remainingMinutes > 5)
            {
                NotificationService.Instance.ShowNotification(
                    "时间限制提醒",
                    $"您今日的电脑使用时间还剩 {remainingMinutes} 分钟",
                    NotificationType.Warning
                );
            }
            
            // 最后警告
            if (remainingMinutes <= 5 && remainingMinutes > 0)
            {
                NotificationService.Instance.ShowNotification(
                    "时间限制警告",
                    $"您今日的电脑使用时间即将用完，请保存您的工作！",
                    NotificationType.Error
                );
            }

            // 超时强制措施
            if (usedMinutes >= limitMinutes)
            {
                HandleTimeLimitExceeded();
            }
        }

        private void HandleTimeLimitExceeded()
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "TimeLimitExceeded",
                Message = "今日时间限制已到",
                Details = "将强制锁定计算机"
            });

            NotificationService.Instance.ShowNotification(
                "时间限制",
                "您今日的电脑使用时间已用完，系统将锁定",
                NotificationType.Error
            );

            // 根据设置选择操作
            switch (_settings.OverLimitAction)
            {
                case OverLimitAction.LockScreen:
                    LockWorkStation();
                    break;
                case OverLimitAction.Logoff:
                    CloseAllApplications();
                    ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, 0);
                    break;
                case OverLimitAction.Shutdown:
                    Process.Start("shutdown", "/s /t 60 /c \"家长控制：今日使用时间已到\"");
                    break;
                case OverLimitAction.CloseApps:
                    CloseBlockedApplications();
                    break;
            }
        }

        private void CloseAllApplications()
        {
            // 关闭所有浏览器和游戏
            var appsToClose = new[] { "chrome", "firefox", "msedge", "iexplore", "opera", "brave" };
            foreach (var app in appsToClose)
            {
                try
                {
                    var processes = Process.GetProcessesByName(app);
                    foreach (var p in processes)
                    {
                        p.CloseMainWindow();
                        if (!p.WaitForExit(3000))
                        {
                            p.Kill();
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
            }
        }

        #endregion

        #region 时间段控制

        private void CheckTimeWindow()
        {
            var now = DateTime.Now;
            var currentTime = now.TimeOfDay;
            var currentDay = now.DayOfWeek;

            // 检查当前时间是否在允许的时间段内
            var isAllowed = IsTimeAllowed(currentTime, currentDay);

            if (!isAllowed)
            {
                HandleTimeWindowViolation();
            }
        }

        private bool IsTimeAllowed(TimeSpan currentTime, DayOfWeek day)
        {
            // 检查是否在允许的时间段内
            foreach (var window in _settings.AllowedTimeWindows)
            {
                // 检查星期是否匹配
                if (window.Days.Contains(day))
                {
                    // 检查时间是否在窗口内
                    if (currentTime >= window.StartTime && currentTime <= window.EndTime)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private void HandleTimeWindowViolation()
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "TimeWindowViolation",
                Message = "不在允许的使用时间段内",
                Details = "系统将锁定"
            });

            NotificationService.Instance.ShowNotification(
                "时间段限制",
                "当前不在允许使用电脑的时间段内，系统将锁定",
                NotificationType.Error
            );

            LockWorkStation();
        }

        #endregion

        #region 应用程序阻止

        private void CheckBlockedApplications()
        {
            foreach (var appName in _settings.BlockedApplications)
            {
                try
                {
                    var processes = Process.GetProcessesByName(appName);
                    if (processes.Length > 0)
                    {
                        foreach (var process in processes)
                        {
                            HandleBlockedApplication(process, appName);
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
            }
        }

        private void HandleBlockedApplication(Process process, string appName)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BlockedApplicationDetected",
                Message = "检测到被阻止的应用程序",
                Details = $"应用: {appName}"
            });

            NotificationService.Instance.ShowNotification(
                "应用程序被阻止",
                $"应用程序 '{appName}' 已被家长控制阻止",
                NotificationType.Warning
            );

            try
            {
                process.Kill();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
        }

        private void CloseBlockedApplications()
        {
            foreach (var appName in _settings.BlockedApplications)
            {
                try
                {
                    var processes = Process.GetProcessesByName(appName);
                    foreach (var p in processes)
                    {
                        p.CloseMainWindow();
                        if (!p.WaitForExit(2000))
                        {
                            p.Kill();
                        }
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
            }
        }

        #endregion

        #region 内容过滤

        private void CheckContentFilter()
        {
            var browserNames = new[] { "chrome", "firefox", "msedge", "iexplore", "opera", "brave" };

            foreach (var browserName in browserNames)
            {
                try
                {
                    var processes = Process.GetProcessesByName(browserName);
                    foreach (var process in processes)
                    {
                        CheckBrowserContent(process);
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
            }
        }

        private void CheckBrowserContent(Process process)
        {
            try
            {
                var commandLine = GetProcessCommandLine(process.Id);
                if (string.IsNullOrEmpty(commandLine)) return;

                // 检查成人内容关键词
                foreach (var keyword in _settings.BlockedKeywords)
                {
                    if (commandLine.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        HandleBlockedContent(process, keyword);
                        return;
                    }
                }

                // 检查被阻止的网站类别
                foreach (var category in _settings.BlockedCategories)
                {
                    if (IsCategoryMatch(commandLine, category))
                    {
                        HandleBlockedContent(process, $"类别: {category}");
                        return;
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
        }

        private bool IsCategoryMatch(string url, string category)
        {
            var categoryKeywords = GetCategoryKeywords(category);
            foreach (var keyword in categoryKeywords)
            {
                if (url.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        private List<string> GetCategoryKeywords(string category)
        {
            return category.ToLower() switch
            {
                "adult" => new List<string> { "porn", "xxx", "adult", "sex", "nude" },
                "gambling" => new List<string> { "casino", "poker", "bet", "gambling", "slot" },
                "social" => new List<string> { "facebook.com", "twitter.com", "instagram.com", "tiktok.com" },
                "gaming" => new List<string> { "steam.com", "epicgames.com", "riotgames.com" },
                "violence" => new List<string> { "gore", "violence", "weapon", "gun" },
                _ => new List<string>()
            };
        }

        private void HandleBlockedContent(Process process, string reason)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "BlockedContentDetected",
                Message = "检测到被阻止的内容",
                Details = $"原因: {reason}"
            });

            NotificationService.Instance.ShowNotification(
                "内容被阻止",
                $"此内容已被家长控制过滤",
                NotificationType.Error
            );

            try
            {
                process.Kill();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
        }

        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
                foreach (var obj in searcher.Get())
                {
                    return obj["CommandLine"] as string ?? string.Empty;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
            return string.Empty;
        }

        #endregion

        #region 设置管理

        private void LoadSettings()
        {
            try
            {
                var data = _dataManager.LoadParentalControlSettingsData();
                if (data != null)
                {
                    // 转换为基础数据类型
                    _settings.EnableTimeLimit = data.EnableTimeLimit;
                    _settings.EnableContentFilter = data.EnableContentFilter;
                    _settings.EnableAppBlocking = data.EnableAppBlocking;
                    _settings.EnableTimeWindow = data.EnableTimeWindow;
                    _settings.DailyTimeLimitMinutes = data.DailyTimeLimitMinutes;
                    _settings.OverLimitAction = (OverLimitAction)data.OverLimitAction;
                    _settings.AdminPassword = data.AdminPassword ?? "";
                    _settings.BlockedApplications = data.BlockedApplications ?? new List<string>();
                    _settings.BlockedKeywords = data.BlockedKeywords ?? new List<string>();
                    _settings.BlockedCategories = data.BlockedCategories ?? new List<string>();
                    
                    // 转换时间窗口
                    _settings.AllowedTimeWindows.Clear();
                    if (data.AllowedTimeWindows != null)
                    {
                        foreach (var tw in data.AllowedTimeWindows)
                        {
                            _settings.AllowedTimeWindows.Add(new TimeWindow
                            {
                                Days = tw.Days?.Select(d => (DayOfWeek)d).ToList() ?? new List<DayOfWeek>(),
                                StartTime = TimeSpan.TryParse(tw.StartTime, out var start) ? start : TimeSpan.Zero,
                                EndTime = TimeSpan.TryParse(tw.EndTime, out var end) ? end : TimeSpan.FromHours(23)
                            });
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
        }

        private void SaveSettings()
        {
            try
            {
                var data = new ParentalControlSettingsData
                {
                    EnableTimeLimit = _settings.EnableTimeLimit,
                    EnableContentFilter = _settings.EnableContentFilter,
                    EnableAppBlocking = _settings.EnableAppBlocking,
                    EnableTimeWindow = _settings.EnableTimeWindow,
                    DailyTimeLimitMinutes = _settings.DailyTimeLimitMinutes,
                    OverLimitAction = (int)_settings.OverLimitAction,
                    AdminPassword = _settings.AdminPassword ?? "",
                    BlockedApplications = _settings.BlockedApplications,
                    BlockedKeywords = _settings.BlockedKeywords,
                    BlockedCategories = _settings.BlockedCategories,
                    AllowedTimeWindows = _settings.AllowedTimeWindows.Select(tw => new TimeWindowData
                    {
                        Days = tw.Days.Select(d => (int)d).ToList(),
                        StartTime = tw.StartTime.ToString(),
                        EndTime = tw.EndTime.ToString()
                    }).ToList()
                };
                _dataManager.SaveParentalControlSettingsData(data);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
        }

        private void SaveUserUsage()
        {
            try
            {
                // 转换为可序列化的格式
                var data = _userUsage.ToDictionary(
                    kvp => kvp.Key,
                    kvp => new Data.UserUsageData
                    {
                        UserName = kvp.Value.UserName,
                        DailyUsageMinutes = kvp.Value.DailyUsageMinutes,
                        SessionStartTime = kvp.Value.SessionStartTime.ToString("O"),
                        LastActivity = kvp.Value.LastActivity.ToString("O"),
                        LastDate = kvp.Value.LastDate,
                        AccessedApps = kvp.Value.AccessedApps,
                        AccessedWebsites = kvp.Value.AccessedWebsites
                    });
                _dataManager.SaveParentalControlUsage(data);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControl.cs 捕获异常", ex.Message); }
        }

        private UserUsageData GetCurrentUserUsage()
        {
            if (_userUsage.ContainsKey(_currentProtectedUser))
            {
                return _userUsage[_currentProtectedUser];
            }
            return null;
        }

        #endregion

        #region 公共接口

        public ParentalControlSettings GetSettings()
        {
            return _settings;
        }

        public UserUsageData GetUsageData(string userName)
        {
            if (_userUsage.ContainsKey(userName))
            {
                return _userUsage[userName];
            }
            return null;
        }

        public Dictionary<string, UserUsageData> GetAllUsageData()
        {
            return new Dictionary<string, UserUsageData>(_userUsage);
        }

        public void UpdateSettings(ParentalControlSettings settings)
        {
            _settings = settings;
            SaveSettings();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ParentalControlSettingsUpdated",
                Message = "家长控制设置已更新",
                Details = $"时间限制: {settings.EnableTimeLimit}, 内容过滤: {settings.EnableContentFilter}"
            });
        }

        public void UpdateSettings(bool enableTimeLimit, bool enableContentFilter, int timeLimitHours, List<string> blockedWebsites)
        {
            _settings.EnableTimeLimit = enableTimeLimit;
            _settings.EnableContentFilter = enableContentFilter;
            _settings.DailyTimeLimitMinutes = timeLimitHours * 60;
            
            if (blockedWebsites != null)
            {
                _settings.BlockedKeywords = blockedWebsites;
            }
            
            SaveSettings();
        }

        public bool VerifyPassword(string password)
        {
            if (string.IsNullOrEmpty(_settings.AdminPassword))
            {
                return true; // 未设置密码时允许访问
            }

            var hash = HashPassword(password);
            _passwordVerified = hash == _settings.AdminPassword;
            return _passwordVerified;
        }

        public void SetAdminPassword(string password)
        {
            _settings.AdminPassword = HashPassword(password);
            SaveSettings();
        }

        public void SetDailyTimeLimit(int minutes)
        {
            _settings.DailyTimeLimitMinutes = minutes;
            SaveSettings();
        }

        public void AddBlockedApplication(string appName)
        {
            if (!_settings.BlockedApplications.Contains(appName))
            {
                _settings.BlockedApplications.Add(appName);
                SaveSettings();
            }
        }

        public void RemoveBlockedApplication(string appName)
        {
            _settings.BlockedApplications.Remove(appName);
            SaveSettings();
        }

        public void AddAllowedTimeWindow(DayOfWeek[] days, TimeSpan start, TimeSpan end)
        {
            _settings.AllowedTimeWindows.Add(new TimeWindow
            {
                Days = days.ToList(),
                StartTime = start,
                EndTime = end
            });
            SaveSettings();
        }

        public void ClearAllowedTimeWindows()
        {
            _settings.AllowedTimeWindows.Clear();
            SaveSettings();
        }

        public int GetRemainingMinutesToday()
        {
            var userData = GetCurrentUserUsage();
            if (userData == null || !_settings.EnableTimeLimit) return -1;
            
            return Math.Max(0, _settings.DailyTimeLimitMinutes - userData.DailyUsageMinutes);
        }

        public int GetUsedMinutesToday()
        {
            var userData = GetCurrentUserUsage();
            return userData?.DailyUsageMinutes ?? 0;
        }

        private string HashPassword(string password)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(password + "FireAntivirus_Salt");
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        #endregion
    }

    #region 数据模型

    public class ParentalControlSettings
    {
        public bool EnableTimeLimit { get; set; } = false;
        public bool EnableContentFilter { get; set; } = false;
        public bool EnableAppBlocking { get; set; } = false;
        public bool EnableTimeWindow { get; set; } = false;
        
        public int DailyTimeLimitMinutes { get; set; } = 120; // 默认2小时
        public OverLimitAction OverLimitAction { get; set; } = OverLimitAction.LockScreen;
        
        public string AdminPassword { get; set; } = "";
        
        public List<string> BlockedApplications { get; set; } = new List<string>();
        public List<string> BlockedKeywords { get; set; } = new List<string>
        {
            "porn", "xxx", "adult", "sex", "nude", "casino", "poker"
        };
        public List<string> BlockedCategories { get; set; } = new List<string>
        {
            "adult", "gambling"
        };
        
        public List<TimeWindow> AllowedTimeWindows { get; set; } = new List<TimeWindow>
        {
            new TimeWindow
            {
                Days = new List<DayOfWeek> { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday },
                StartTime = new TimeSpan(16, 0, 0), // 下午4点
                EndTime = new TimeSpan(21, 0, 0)   // 晚上9点
            },
            new TimeWindow
            {
                Days = new List<DayOfWeek> { DayOfWeek.Saturday, DayOfWeek.Sunday },
                StartTime = new TimeSpan(9, 0, 0),  // 上午9点
                EndTime = new TimeSpan(21, 0, 0)    // 晚上9点
            }
        };
    }

    public class TimeWindow
    {
        public List<DayOfWeek> Days { get; set; } = new List<DayOfWeek>();
        public TimeSpan StartTime { get; set; }
        public TimeSpan EndTime { get; set; }
    }

    public enum OverLimitAction
    {
        LockScreen,
        Logoff,
        Shutdown,
        CloseApps
    }

    public class UserUsageData
    {
        public string UserName { get; set; } = "";
        public int DailyUsageMinutes { get; set; }
        public DateTime SessionStartTime { get; set; }
        public DateTime LastActivity { get; set; }
        public string LastDate { get; set; } = "";
        public List<string> AccessedApps { get; set; } = new List<string>();
        public List<string> AccessedWebsites { get; set; } = new List<string>();
    }

    #endregion
}