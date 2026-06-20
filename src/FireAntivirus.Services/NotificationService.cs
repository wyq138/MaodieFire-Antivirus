using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using System.Drawing;
using System.IO;
using System.Diagnostics;
using System.ServiceProcess;
using FireAntivirus.Data;

namespace FireAntivirus.Services
{
    public class NotificationService
    {
        private static NotificationService _instance;
        private static readonly object _lock = new object();
        private Thread _notificationThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private NotifyIcon _notifyIcon;
        private Form _notificationForm;

        private NotificationService()
        {
            _dataManager = new DataManager();
            // 不再初始化托盘图标，避免重复图标（托盘图标由主程序MainWindow统一管理）
            // _notifyIcon 在需要时由 ShowNotification 创建，使用后立即销毁
        }

        public static NotificationService Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                        {
                            _instance = new NotificationService();
                        }
                    }
                }
                return _instance;
            }
        }

        public void Start()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _notificationThread = new Thread(RunNotificationService);
            _notificationThread.IsBackground = true;
            _notificationThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NotificationServiceStart",
                Message = "通知服务已启动",
                Details = "开始监控安全事件并显示通知"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            if (_notificationThread != null && _notificationThread.IsAlive)
            {
                _notificationThread.Join(2000);
            }

            Cleanup();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "NotificationServiceStop",
                Message = "通知服务已停止",
                Details = "已停止监控安全事件"
            });
        }

        public void ShowNotification(string title, string message, NotificationType type)
        {
            try
            {
                // 只显示自定义弹窗通知（统一风格）
                // 使用系统弹窗
                // 危险威胁弹窗通知用户
                if (type == NotificationType.Warning || type == NotificationType.Error)
                {
                    try
                    {
                        System.Windows.Forms.MessageBox.Show(message, title, System.Windows.Forms.MessageBoxButtons.OK, type == NotificationType.Warning ? System.Windows.Forms.MessageBoxIcon.Warning : System.Windows.Forms.MessageBoxIcon.Error);
                    }
                    catch { }
                }

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SecurityNotification",
                    Message = title,
                    Details = message
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NotificationError",
                    Message = "显示通知失败",
                    Details = ex.Message
                });
            }
        }

        private void RunNotificationService()
        {
            try
            {
                while (_isRunning)
                {
                    // 检查是否有未处理的安全事件
                    CheckSecurityEvents();
                    Thread.Sleep(5000); // 每5秒检查一次
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NotificationServiceError",
                    Message = "通知服务错误",
                    Details = ex.Message
                });
            }
        }

        private void CheckSecurityEvents()
        {
            try
            {
                // 只检查最近10秒内的未处理安全事件
                var allLogs = _dataManager.LoadLogs();
                var recentLogs = allLogs
                    .Where(l => l.Time > DateTime.Now.AddSeconds(-10))
                    .OrderByDescending(l => l.Time)
                    .Take(3)
                    .ToList();

                bool hasChanges = false;
                foreach (var log in recentLogs)
                {
                    // 只对真正的恶意脚本、病毒检测弹窗通知
                    if (IsRealThreat(log.Type) && !log.Details.Contains("[已通知]"))
                    {
                        // 显示通知
                        ShowNotification("安全威胁警告", log.Message + "\n" + log.Details, NotificationType.Error);

                        // 标记为已通知
                        log.Details += " [已通知]";
                        hasChanges = true;
                    }
                }

                if (hasChanges)
                {
                    // 保存所有日志
                    // _dataManager.SaveLogs(allLogs);
                }
            }
            catch { }
        }

        private bool IsRealThreat(string logType)
        {
            // 只对真正的恶意软件威胁弹窗，排除所有误报
            string[] realThreatTypes = {
                "MalwareDetected",
                "RansomwareDetected",
                "TrojanDetected",
                "WormDetected",
                "VirusDetected"
            };

// 排除所有可能的误报类型
            string[] ignoreTypes = {
                "PopupBlocked",
                "NetworkAttack",
                "NetworkAnomaly",
                "SuspiciousProcess",
                "ProcessInjection",
                "FileInjection",
                "RegistryTampering",
                "UnauthorizedAccess",
                "KernelModulesTampered",
                "SystemDllTampered",
                "NetworkHealth",
                "TrafficAnomaly",
                "ScriptDetected",
                "ScriptBlock",
                "MaliciousScript",
                "SuspiciousScript",
                "ScriptBehavior",
                "ScriptAnalysis",
                "ScriptExecution",
                "ThreatDetected",
                "BehaviorThreat",
                "AnomalyDetection",
                "SecurityAlert",
                "SuspiciousActivity",
                "SecurityEvent",
                "Alert",
                "Warning",
                "Threat",
                "NewNetworkConnection",
                "NetworkConnection",
                "SuspiciousNetworkConnection",
                "SuspiciousPortConnection",
                "UnknownProcessConnection",
                "HighNetworkTraffic",
                "SuspiciousBehavior",
                "SuspiciousProcessName",
                "SuspiciousCommandLine",
                "SuspiciousProcessPath",
                "UnsignedProcess",
                "SuspiciousProcessChain",
                "FileOperation",
                "RegistryOperation",
                "NetworkAnalyzer",
                "ConnectionLimit",
                "InterfaceDown"
            };

            if (Array.Exists(ignoreTypes, type => logType.Contains(type)))
                return false;

            return Array.Exists(realThreatTypes, type => logType.Contains(type));
        }

private void InitializeNotifyIcon()
        {
            try
            {
                // 禁用自己的托盘图标，由主程序统一管理
                _notifyIcon = new NotifyIcon
                {
                    Text = "耄耋杀毒 安全通知",
                    Visible = false // 隐藏，使用主程序的图标
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "NotifyIconInitError",
                    Message = "初始化托盘图标失败",
                    Details = ex.Message
                });
            }
        }

        private void InitializeNotificationForm()
        {
            _notificationForm = new Form
            {
                Size = new Size(380, 160),
                FormBorderStyle = FormBorderStyle.None,
                ShowInTaskbar = false,
                TopMost = true,
                BackColor = Color.FromArgb(35, 35, 45),
                ForeColor = Color.White,
                Opacity = 0.0,
                StartPosition = FormStartPosition.Manual
            };

            // 设置位置（右下角）
            UpdateNotificationPosition();

            // 添加圆角效果（通过Region）
            var path = new System.Drawing.Drawing2D.GraphicsPath();
            int radius = 12;
            Rectangle bounds = new Rectangle(0, 0, _notificationForm.Width, _notificationForm.Height);
            path.AddArc(bounds.X, bounds.Y, radius, radius, 180, 90);
            path.AddArc(bounds.X + bounds.Width - radius, bounds.Y, radius, radius, 270, 90);
            path.AddArc(bounds.X + bounds.Width - radius, bounds.Y + bounds.Height - radius, radius, radius, 0, 90);
            path.AddArc(bounds.X, bounds.Y + bounds.Height - radius, radius, radius, 90, 90);
            path.CloseAllFigures();
            _notificationForm.Region = new Region(path);

            // 主内容面板
            Panel contentPanel = new Panel
            {
                Size = new Size(380, 160),
                Location = new Point(0, 0),
                BackColor = Color.Transparent
            };

            // 左侧颜色条（根据类型变化）
            Panel colorBar = new Panel
            {
                Size = new Size(5, 160),
                Location = new Point(0, 0),
                BackColor = Color.FromArgb(255, 107, 53) // 橙色默认
            };
            contentPanel.Controls.Add(colorBar);

            // 标题栏
            Panel titlePanel = new Panel
            {
                Size = new Size(370, 40),
                Location = new Point(10, 0),
                BackColor = Color.Transparent
            };

            Label titleLabel = new Label
            {
                Text = "安全通知",
                Font = new Font("Microsoft YaHei UI", 11, FontStyle.Bold),
                Location = new Point(45, 10),
                Size = new Size(280, 24),
                ForeColor = Color.FromArgb(255, 255, 255),
                AutoEllipsis = true
            };

            // 品牌标识
            Label brandLabel = new Label
            {
                Text = "🔥 耄耋杀毒",
                Font = new Font("Microsoft YaHei UI", 8),
                Location = new Point(290, 12),
                Size = new Size(80, 20),
                ForeColor = Color.FromArgb(150, 150, 160),
                TextAlign = ContentAlignment.TopRight
            };

            titlePanel.Controls.Add(titleLabel);
            titlePanel.Controls.Add(brandLabel);
            contentPanel.Controls.Add(titlePanel);

            // 图标区域
            PictureBox iconBox = new PictureBox
            {
                Size = new Size(28, 28),
                Location = new Point(15, 12),
                BackColor = Color.Transparent,
                SizeMode = PictureBoxSizeMode.CenterImage
            };
            
            // 根据类型设置图标
            try
            {
                iconBox.Image = CreateNotificationIcon(NotificationType.Info);
            }
            catch { }
            
            titlePanel.Controls.Add(iconBox);
            iconBox.BringToFront();

            // 消息区域
            Label messageLabel = new Label
            {
                Text = "",
                Font = new Font("Microsoft YaHei UI", 9.5f),
                Location = new Point(20, 48),
                Size = new Size(340, 70),
                ForeColor = Color.FromArgb(220, 220, 225),
                AutoSize = false,
                TextAlign = ContentAlignment.TopLeft
            };
            contentPanel.Controls.Add(messageLabel);

            // 底部按钮区域
            Panel buttonPanel = new Panel
            {
                Size = new Size(370, 35),
                Location = new Point(10, 120),
                BackColor = Color.Transparent
            };

            Button closeButton = new Button
            {
                Text = "关闭",
                Size = new Size(75, 28),
                Location = new Point(285, 3),
                BackColor = Color.FromArgb(60, 60, 70),
                ForeColor = Color.FromArgb(200, 200, 200),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Font = new Font("Microsoft YaHei UI", 9)
            };
            closeButton.FlatAppearance.BorderSize = 0;
            closeButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(80, 80, 90);
            closeButton.Click += (sender, e) => 
            {
                _notificationForm.Hide();
                _notificationForm.Opacity = 0;
            };

            Button detailsButton = new Button
            {
                Text = "查看详情",
                Size = new Size(85, 28),
                Location = new Point(195, 3),
                BackColor = Color.FromArgb(255, 107, 53),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Font = new Font("Microsoft YaHei UI", 9)
            };
            detailsButton.FlatAppearance.BorderSize = 0;
            detailsButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(229, 90, 43);
            detailsButton.Click += (sender, e) =>
            {
                _notificationForm.Hide();
                _notificationForm.Opacity = 0;
                try
                {
                    string mainExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Host.exe");
                    if (!File.Exists(mainExePath))
                    {
                        mainExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.exe");
                    }
                    if (File.Exists(mainExePath))
                    {
                        Process.Start(mainExePath, "-logs");
                    }
                }
                catch { }
            };

            buttonPanel.Controls.Add(detailsButton);
            buttonPanel.Controls.Add(closeButton);
            contentPanel.Controls.Add(buttonPanel);

            _notificationForm.Controls.Add(contentPanel);

            // 保存关键控件引用（通过Tag）
            _notificationForm.Tag = new { ColorBar = colorBar, Icon = iconBox, Title = titleLabel, Message = messageLabel };
        }

        private Bitmap CreateNotificationIcon(NotificationType type)
        {
            var bitmap = new Bitmap(28, 28);
            using (var g = Graphics.FromImage(bitmap))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                Color iconColor;
                string iconText;
                
                switch (type)
                {
                    case NotificationType.Warning:
                        iconColor = Color.FromArgb(255, 180, 50);
                        iconText = "⚠";
                        break;
                    case NotificationType.Error:
                        iconColor = Color.FromArgb(255, 80, 80);
                        iconText = "✕";
                        break;
                    default:
                        iconColor = Color.FromArgb(80, 180, 255);
                        iconText = "ℹ";
                        break;
                }
                
                // 绘制圆形背景
                using (var brush = new SolidBrush(Color.FromArgb(40, iconColor)))
                {
                    g.FillEllipse(brush, 2, 2, 24, 24);
                }
                
                // 绘制图标文字
                using (var font = new Font("Segoe UI", 12, FontStyle.Bold))
                using (var brush = new SolidBrush(iconColor))
                {
                    var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                    g.DrawString(iconText, font, brush, new RectangleF(0, 0, 28, 28), sf);
                }
            }
            return bitmap;
        }

        private void UpdateNotificationPosition()
        {
            Screen screen = Screen.PrimaryScreen;
            _notificationForm.Location = new Point(
                screen.WorkingArea.Width - _notificationForm.Width - 10,
                screen.WorkingArea.Height - _notificationForm.Height - 10
            );
        }

        private void ShowNotificationForm(string title, string message, NotificationType type)
        {
            if (_notificationForm != null && !_notificationForm.IsDisposed)
            {
                try
                {
                    // 更新位置
                    UpdateNotificationPosition();

                    // 获取控件引用
                    dynamic controls = _notificationForm.Tag;
                    if (controls == null) return;

                    Panel colorBar = controls.ColorBar;
                    PictureBox iconBox = controls.Icon;
                    Label titleLabel = controls.Title;
                    Label messageLabel = controls.Message;

                    if (titleLabel != null && messageLabel != null)
                    {
                        titleLabel.Text = title;
                        messageLabel.Text = message;

                        // 根据通知类型设置颜色
                        switch (type)
                        {
                            case NotificationType.Info:
                                colorBar.BackColor = Color.FromArgb(80, 180, 255); // 蓝色
                                iconBox.Image = CreateNotificationIcon(type);
                                break;
                            case NotificationType.Warning:
                                colorBar.BackColor = Color.FromArgb(255, 180, 50); // 橙色
                                iconBox.Image = CreateNotificationIcon(type);
                                break;
                            case NotificationType.Error:
                                colorBar.BackColor = Color.FromArgb(255, 80, 80); // 红色
                                iconBox.Image = CreateNotificationIcon(type);
                                break;
                        }

                        // 显示通知窗口
                        _notificationForm.Show();
                        _notificationForm.BringToFront();

                        // 动画效果：淡入
                        ThreadPool.QueueUserWorkItem((state) =>
                        {
                            for (double i = 0; i <= 1; i += 0.15)
                            {
                                if (_notificationForm.IsDisposed) break;
                                _notificationForm.Invoke(new Action(() => _notificationForm.Opacity = i));
                                Thread.Sleep(25);
                            }

                            // 保持显示
                            Thread.Sleep(6000); // 6秒后开始淡出

                            // 动画效果：淡出
                            for (double i = 1; i >= 0; i -= 0.15)
                            {
                                if (_notificationForm.IsDisposed) break;
                                _notificationForm.Invoke(new Action(() => _notificationForm.Opacity = i));
                                Thread.Sleep(25);
                            }

                            if (!_notificationForm.IsDisposed)
                            {
                                _notificationForm.Invoke(new Action(() => _notificationForm.Hide()));
                            }
                        });
                    }
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "NotificationFormError",
                        Message = "显示通知窗口失败",
                        Details = ex.Message
                    });
                }
            }
        }

        private string GetIconPath(NotificationType type)
        {
            string iconDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Icons");
            switch (type)
            {
                case NotificationType.Info:
                    return Path.Combine(iconDir, "info.ico");
                case NotificationType.Warning:
                    return Path.Combine(iconDir, "warning.ico");
                case NotificationType.Error:
                    return Path.Combine(iconDir, "error.ico");
                default:
                    return Path.Combine(iconDir, "fireantivirus.ico");
            }
        }

        private ToolTipIcon GetToolTipIcon(NotificationType type)
        {
            switch (type)
            {
                case NotificationType.Info:
                    return ToolTipIcon.Info;
                case NotificationType.Warning:
                    return ToolTipIcon.Warning;
                case NotificationType.Error:
                    return ToolTipIcon.Error;
                default:
                    return ToolTipIcon.None;
            }
        }

        private void Cleanup()
        {
            try
            {
                if (_notifyIcon != null)
                {
                    _notifyIcon.Visible = false;
                    _notifyIcon.Dispose();
                }

                if (_notificationForm != null && !_notificationForm.IsDisposed)
                {
                    _notificationForm.Dispose();
                }
            }
            catch { }
        }
    }

    public enum NotificationType
    {
        Info,
        Warning,
        Error,
        SecurityAlert,
        PerformanceAlert,
        UpdateAvailable,
        Maintenance,
        SystemInfo
    }
}
