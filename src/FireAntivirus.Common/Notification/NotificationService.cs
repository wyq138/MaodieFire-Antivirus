using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using System.Drawing;
using System.IO;
using System.Diagnostics;
using System.ServiceProcess;

namespace FireAntivirus.Common.Notification
{
    public class NotificationService
    {
        private static NotificationService _instance;
        private static readonly object _lock = new object();
        private Thread _notificationThread;
        private bool _isRunning;
        private NotifyIcon _notifyIcon;
        private Form _notificationForm;

private NotificationService()
        {
            // 重要：后台服务绝对不能创建托盘图标
            // 这会导致显示两个图标（一个来自后台服务，一个来自主程序MainWindow）
            // 托盘图标只能由主程序MainWindow创建
            // 警告：不要在此处调用InitializeNotifyIcon()
            _notifyIcon = null; // 确保不创建托盘图标
            InitializeNotificationForm();
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

            FireAntivirus.Common.LogHelper.Info("通知服务已启动", "开始监控安全事件并显示通知");
        }

        public void Stop()
        {
            _isRunning = false;
            if (_notificationThread != null && _notificationThread.IsAlive)
            {
                _notificationThread.Join(2000);
            }

            Cleanup();

            FireAntivirus.Common.LogHelper.Info("通知服务已停止", "已停止监控安全事件");
        }

        public void ShowNotification(string title, string message, NotificationType type)
        {
            try
            {
                if (_notifyIcon == null && type != NotificationType.Risk) return;

                // 确保在正确的线程执行UI操作
                if (_notificationForm != null && !_notificationForm.IsDisposed)
                {
                    if (_notificationForm.InvokeRequired)
                    {
                        _notificationForm.Invoke(new Action(() => ShowNotificationInternal(title, message, type)));
                        return;
                    }
                }

                ShowNotificationInternal(title, message, type);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Error("显示通知失败", ex.Message);
            }
        }

        /// <summary>
        /// 显示右下角风险处理弹窗（带隔离/删除/信任/忽略等处理选项）。
        /// 需要宿主注入处理回调。
        /// </summary>
        public void ShowRisk(RiskNotificationPayload payload, string title = "检测到安全威胁")
        {
            try
            {
                if (_notificationForm != null && !_notificationForm.IsDisposed)
                {
                    if (_notificationForm.InvokeRequired)
                    {
                        _notificationForm.Invoke(new Action(() => ShowRiskInternal(payload, title)));
                        return;
                    }
                }
                ShowRiskInternal(payload, title);
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Error("显示风险通知失败", ex.Message);
            }
        }

        private void ShowRiskInternal(RiskNotificationPayload payload, string title)
        {
            try
            {
                if (_notificationForm == null || _notificationForm.IsDisposed) return;

                // 先捕获引用（移除控件后索引会移位，避免二次查找出错）
                Label messageLabel = _notificationForm.Controls[2] is Label ml ? ml : null;
                Panel titlePanel = _notificationForm.Controls[0] as Panel;
                Label titleLabel = titlePanel?.Controls[0] as Label;

                UpdateNotificationPosition();
                _notificationForm.Size = new Size(420, 220);
                _notificationForm.BackColor = Color.FromArgb(90, 30, 35);
                _notificationForm.Opacity = 0.97;

                // 标题
                if (titleLabel != null)
                {
                    titleLabel.Text = title;
                    titleLabel.Size = new Size(300, 20);
                    titlePanel.BackColor = Color.FromArgb(70, 20, 25);
                }

                // 消息正文
                if (messageLabel != null)
                {
                    string file = payload.FilePath ?? "未知文件";
                    messageLabel.Text = $"威胁: {payload.ThreatName}\n级别: {payload.Severity}\n文件: {file}";
                    messageLabel.Size = new Size(400, 95);
                }

                // 移除旧的 logo 与按钮面板，避免叠加
                foreach (Control c in _notificationForm.Controls.Cast<Control>().ToList())
                {
                    if (c is Panel p && (p != titlePanel && c != messageLabel))
                        _notificationForm.Controls.Remove(p);
                }

                // 重建处理按钮面板
                var buttonPanel = new Panel
                {
                    Size = new Size(420, 74),
                    Location = new Point(0, 140),
                    BackColor = Color.FromArgb(60, 20, 25)
                };

                int x = 10;
                var payloadCopy = payload;
                foreach (var action in payloadCopy.Actions)
                {
                    var path = payloadCopy.FilePath;
                    var b = new Button
                    {
                        Text = action.Text,
                        Size = new Size(72, 28),
                        Location = new Point(x, 5),
                        BackColor = Color.FromArgb(150, 45, 50),
                        ForeColor = Color.White,
                        FlatStyle = FlatStyle.Flat
                    };
                    b.FlatAppearance.BorderColor = Color.FromArgb(170, 70, 75);
                    b.Click += (s, e) =>
                    {
                        _notificationForm.Hide();
                        try { action.Handler?.Invoke(path); }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NotificationService.cs 捕获异常", ex.Message); }
                    };
                    buttonPanel.Controls.Add(b);
                    x += 78;
                }

                // 查看详情
                var details = new Button
                {
                    Text = "查看",
                    Size = new Size(62, 28),
                    Location = new Point(x, 5),
                    BackColor = Color.FromArgb(150, 45, 50),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat
                };
                details.FlatAppearance.BorderColor = Color.FromArgb(170, 70, 75);
                details.Click += (s, e) =>
                {
                    _notificationForm.Hide();
                    try
                    {
                        string mainExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Host.exe");
                        if (File.Exists(mainExePath)) Process.Start(mainExePath, "-logs");
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NotificationService.cs 捕获异常", ex.Message); }
                };
                buttonPanel.Controls.Add(details);
                x += 68;

                // 关闭
                var close = new Button
                {
                    Text = "关闭",
                    Size = new Size(62, 28),
                    Location = new Point(x, 5),
                    BackColor = Color.FromArgb(150, 45, 50),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat
                };
                close.FlatAppearance.BorderColor = Color.FromArgb(170, 70, 75);
                close.Click += (s, e) => _notificationForm.Hide();
                buttonPanel.Controls.Add(close);

                _notificationForm.Controls.Add(buttonPanel);

                _notificationForm.Show();
                _notificationForm.BringToFront();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Error("显示风险窗口失败", ex.Message);
            }
        }

        private void ShowNotificationInternal(string title, string message, NotificationType type)
        {
            try
            {
                // 显示托盘通知（短暂提示）
                if (_notifyIcon != null)
                {
                    string iconPath = GetIconPath(type);
                    Icon icon = null;
                    try { if (File.Exists(iconPath)) icon = new Icon(iconPath); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NotificationService.cs 捕获异常", ex.Message); }

                    _notifyIcon.BalloonTipTitle = title;
                    _notifyIcon.BalloonTipText = message;
                    _notifyIcon.BalloonTipIcon = GetToolTipIcon(type);
                    _notifyIcon.ShowBalloonTip(3000);
                }

                // 所有类型的通知都使用自定义通知窗口（显示在右下角）
                // 不再使用MessageBox.Show（会显示在屏幕中央）
                ShowNotificationForm(title, message, type);

                FireAntivirus.Common.LogHelper.Info("安全通知", $"标题: {title}\n消息: {message}");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Error("显示通知内部错误", ex.Message);
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
                FireAntivirus.Common.LogHelper.Error("通知服务错误", ex.Message);
            }
        }

        private void CheckSecurityEvents()
        {
            try
            {
                // 暂时注释掉日志检查逻辑，避免循环引用
                // 后续可以通过事件或其他方式实现安全事件的监控
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NotificationService.cs 捕获异常", ex.Message); }
        }

        private bool IsSecurityThreat(string logType)
        {
            string[] threatTypes = {
                "MalwareDetected", "SuspiciousProcess", "UnauthorizedAccess",
                "RegistryTampering", "FileInjection", "ProcessInjection",
                "NetworkAttack", "PopupBlocked", "UnsignedDriverDetected",
                "KernelModulesTampered", "SystemDllTampered"
            };

            return Array.Exists(threatTypes, type => logType.Contains(type));
        }

        private void InitializeNotifyIcon()
        {
            try
            {
                // 禁用自己的托盘图标，由主程序(MainWindow)统一管理，避免重复图标
                _notifyIcon = new NotifyIcon
                {
                    Text = "耄耋杀毒 安全通知",
                    Visible = false
                };

                // 设置图标 - 使用主程序图标 cat_icon.ico
                string[] iconPaths = new string[]
                {
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cat_icon.ico"),
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "cat_icon.ico"),
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "cat_icon.ico"),
                    Path.Combine(Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) ?? "", "cat_icon.ico")
                };
                
                bool iconSet = false;
                foreach (var iconPath in iconPaths)
                {
                    string fullPath = Path.GetFullPath(iconPath);
                    if (File.Exists(fullPath))
                    {
                        try
                        {
                            _notifyIcon.Icon = new Icon(fullPath);
                            iconSet = true;
                            break;
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NotificationService.cs 捕获异常", ex.Message); }
                    }
                }
                
                if (!iconSet)
                {
                    // 使用默认图标
                    _notifyIcon.Icon = SystemIcons.Shield;
                }

                // 添加上下文菜单
                ContextMenuStrip contextMenu = new ContextMenuStrip();
                
                // 打开主程序
                ToolStripMenuItem openMainMenuItem = new ToolStripMenuItem("打开主程序");
                openMainMenuItem.Click += (sender, e) =>
                {
                    try
                    {
                        string mainExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Host.exe");
                        if (File.Exists(mainExePath))
                        {
                            Process.Start(mainExePath);
                        }
                        else
                        {
                            ShowNotification("错误", "无法找到主程序文件", NotificationType.Error);
                        }
                    }
                    catch (Exception ex)
                    {
                        ShowNotification("错误", "启动主程序失败: " + ex.Message, NotificationType.Error);
                    }
                };
                contextMenu.Items.Add(openMainMenuItem);

                // 查看日志
                ToolStripMenuItem viewLogsMenuItem = new ToolStripMenuItem("查看日志");
                viewLogsMenuItem.Click += (sender, e) =>
                {
                    try
                    {
                        string mainExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Host.exe");
                        if (File.Exists(mainExePath))
                        {
                            Process.Start(mainExePath, "-logs");
                        }
                        else
                        {
                            // 尝试打开日志文件夹
                            string logsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Logs");
                            if (Directory.Exists(logsDir))
                            {
                                Process.Start("explorer.exe", logsDir);
                            }
                            else
                            {
                                ShowNotification("错误", "无法找到日志文件", NotificationType.Error);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        ShowNotification("错误", "打开日志失败: " + ex.Message, NotificationType.Error);
                    }
                };
                contextMenu.Items.Add(viewLogsMenuItem);

                // 分隔线
                contextMenu.Items.Add(new ToolStripSeparator());

                // 服务状态
                ToolStripMenuItem statusMenuItem = new ToolStripMenuItem("服务状态");
                statusMenuItem.Click += (sender, e) =>
                {
                    try
                    {
                        // 检查服务状态
                        ServiceController sc = new ServiceController("FireAntivirusService");
                        string status = sc.Status.ToString();
                        ShowNotification("服务状态", "耄耋杀毒防护服务当前状态: " + status, NotificationType.Info);
                    }
                    catch (Exception ex)
                    {
                        ShowNotification("错误", "获取服务状态失败: " + ex.Message, NotificationType.Error);
                    }
                };
                contextMenu.Items.Add(statusMenuItem);

                // 分隔线
                contextMenu.Items.Add(new ToolStripSeparator());

                // 退出服务
                ToolStripMenuItem exitMenuItem = new ToolStripMenuItem("退出服务");
                exitMenuItem.Click += (sender, e) =>
                {
                    // 显示确认对话框
                    DialogResult result = MessageBox.Show(
                        "确定要退出耄耋杀毒防护服务吗？\n\n退出后将失去实时保护功能。",
                        "退出服务确认",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning
                    );

                    if (result == DialogResult.Yes)
                    {
                        Cleanup();
                        Application.Exit();
                    }
                };
                contextMenu.Items.Add(exitMenuItem);

                _notifyIcon.ContextMenuStrip = contextMenu;

                // 添加双击事件
                _notifyIcon.DoubleClick += (sender, e) =>
                {
                    try
                    {
                        string mainExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Host.exe");
                        if (File.Exists(mainExePath))
                        {
                            Process.Start(mainExePath);
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NotificationService.cs 捕获异常", ex.Message); }
                };
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Error("初始化托盘图标失败", ex.Message);
            }
        }

        private void InitializeNotificationForm()
        {
            _notificationForm = new Form
            {
                Size = new Size(320, 180),
                FormBorderStyle = FormBorderStyle.None,
                ShowInTaskbar = false,
                TopMost = true,
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.White,
                Opacity = 0.95,
                StartPosition = FormStartPosition.Manual
            };

            // 设置位置（右下角）
            UpdateNotificationPosition();

            // 添加标题栏
            Panel titlePanel = new Panel
            {
                Size = new Size(320, 30),
                BackColor = Color.FromArgb(30, 30, 30),
                Location = new Point(0, 0)
            };

            Label titleLabel = new Label
            {
                Text = "安全通知",
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                Location = new Point(10, 5),
                Size = new Size(200, 20),
                ForeColor = Color.FromArgb(240, 240, 240)
            };

            Label brandLabel = new Label
            {
                Text = "耄耋杀毒",
                Font = new Font("Segoe UI", 8, FontStyle.Italic),
                Location = new Point(220, 5),
                Size = new Size(90, 20),
                ForeColor = Color.FromArgb(150, 150, 150),
                TextAlign = ContentAlignment.TopRight
            };

            titlePanel.Controls.Add(titleLabel);
            titlePanel.Controls.Add(brandLabel);

            // 添加消息标签
            Label messageLabel = new Label
            {
                Text = "",
                Font = new Font("Segoe UI", 9),
                Location = new Point(10, 40),
                Size = new Size(300, 90),
                ForeColor = Color.FromArgb(200, 200, 200),
                AutoSize = false,
                TextAlign = ContentAlignment.TopLeft
            };

            // 添加操作按钮
            Panel buttonPanel = new Panel
            {
                Size = new Size(320, 30),
                Location = new Point(0, 150),
                BackColor = Color.FromArgb(40, 40, 40)
            };

            Button closeButton = new Button
            {
                Text = "关闭",
                Size = new Size(70, 23),
                Location = new Point(240, 3),
                BackColor = Color.FromArgb(60, 60, 60),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            closeButton.FlatAppearance.BorderColor = Color.FromArgb(80, 80, 80);
            closeButton.Click += (sender, e) => _notificationForm.Hide();

            Button detailsButton = new Button
            {
                Text = "查看详情",
                Size = new Size(80, 23),
                Location = new Point(150, 3),
                BackColor = Color.FromArgb(60, 60, 60),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            detailsButton.FlatAppearance.BorderColor = Color.FromArgb(80, 80, 80);
            detailsButton.Click += (sender, e) =>
            {
                _notificationForm.Hide();
                // 这里可以打开主程序的日志页面或详情页面
                try
                {
                    // 尝试启动主程序并跳转到日志页面
                    string mainExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FireAntivirus.Host.exe");
                    if (File.Exists(mainExePath))
                    {
                        Process.Start(mainExePath, "-logs");
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NotificationService.cs 捕获异常", ex.Message); }
            };

            buttonPanel.Controls.Add(detailsButton);
            buttonPanel.Controls.Add(closeButton);

            // 添加Logo
            Panel logoPanel = new Panel
            {
                Size = new Size(40, 40),
                Location = new Point(10, 40),
                BackColor = Color.Transparent
            };

            // 创建简单的Logo
            PictureBox logoBox = new PictureBox
            {
                Size = new Size(32, 32),
                Location = new Point(4, 4),
                BackColor = Color.OrangeRed
            };
            logoPanel.Controls.Add(logoBox);

            // 调整消息标签位置
            messageLabel.Location = new Point(60, 40);
            messageLabel.Size = new Size(250, 90);

            // 添加所有控件
            _notificationForm.Controls.Add(titlePanel);
            _notificationForm.Controls.Add(logoPanel);
            _notificationForm.Controls.Add(messageLabel);
            _notificationForm.Controls.Add(buttonPanel);

            // 添加鼠标点击事件
            _notificationForm.MouseClick += (sender, e) => _notificationForm.Hide();

            // 添加动画效果
            _notificationForm.Opacity = 0;
        }

        private void UpdateNotificationPosition()
        {
            try
            {
                // 获取主显示器的工作区域
                Screen screen = Screen.PrimaryScreen;
                if (screen == null)
                {
                    // 如果无法获取主屏幕，使用默认位置
                    _notificationForm.Location = new Point(100, 100);
                    return;
                }

                // 计算右下角位置（考虑任务栏等）
                int x = screen.WorkingArea.Right - _notificationForm.Width - 10;
                int y = screen.WorkingArea.Bottom - _notificationForm.Height - 10;

                // 确保窗口在屏幕范围内
                x = Math.Max(0, x);
                y = Math.Max(0, y);

                _notificationForm.Location = new Point(x, y);
            }
            catch (Exception ex)
            {
                // 如果位置设置失败，使用默认位置
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "更新通知窗口位置失败", ex.Message);
                try
                {
                    _notificationForm.Location = new Point(100, 100);
                }
                catch { }
            }
        }

        private void ShowNotificationForm(string title, string message, NotificationType type)
        {
            if (_notificationForm != null && !_notificationForm.IsDisposed)
            {
                try
                {
                    // 更新位置
                    UpdateNotificationPosition();

                    // 更新标题和消息
                    Panel titlePanel = _notificationForm.Controls[0] as Panel;
                    Label titleLabel = titlePanel?.Controls[0] as Label;
                    Label messageLabel = _notificationForm.Controls[2] as Label;

                    if (titleLabel != null && messageLabel != null)
                    {
                        titleLabel.Text = title;
                        messageLabel.Text = message;

                        // 根据通知类型设置颜色
                        switch (type)
                        {
                            case NotificationType.Info:
                                _notificationForm.BackColor = Color.FromArgb(45, 45, 70);
                                titlePanel.BackColor = Color.FromArgb(30, 30, 50);
                                break;
                            case NotificationType.Warning:
                                _notificationForm.BackColor = Color.FromArgb(70, 55, 30);
                                titlePanel.BackColor = Color.FromArgb(50, 40, 20);
                                break;
                            case NotificationType.Error:
                                _notificationForm.BackColor = Color.FromArgb(70, 30, 30);
                                titlePanel.BackColor = Color.FromArgb(50, 20, 20);
                                break;
                        }

                        // 显示通知窗口
                        _notificationForm.Show();
                        _notificationForm.BringToFront();

                        // 动画效果：淡入
                        ThreadPool.QueueUserWorkItem((state) =>
                        {
                            for (double i = 0; i <= 1; i += 0.1)
                            {
                                if (_notificationForm.IsDisposed) break;
                                double opacity = i * 0.95;
                                _notificationForm.Invoke(new Action(() => _notificationForm.Opacity = opacity));
                                Thread.Sleep(30);
                            }

                            // 保持显示
                            Thread.Sleep(5000); // 5秒后开始淡出

                            // 动画效果：淡出
                            for (double i = 1; i >= 0; i -= 0.1)
                            {
                                if (_notificationForm.IsDisposed) break;
                                double opacity = i * 0.95;
                                _notificationForm.Invoke(new Action(() => _notificationForm.Opacity = opacity));
                                Thread.Sleep(30);
                            }

                            if (!_notificationForm.IsDisposed)
                            {
                                _notificationForm.Invoke(new Action(() => _notificationForm.Hide()));
                                _notificationForm.Invoke(new Action(() => _notificationForm.Opacity = 0));
                            }
                        });
                    }
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Error("显示通知窗口失败", ex.Message);
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
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "NotificationService.cs 捕获异常", ex.Message); }
        }
    }

    public enum NotificationType
    {
        Info,
        Warning,
        Error,
        Risk
    }

    /// <summary>
    /// 风险处理动作选项。宿主可注入真实处理回调（隔离/删除/信任/忽略/打开目录）。
    /// </summary>
    public class RiskAction
    {
        public string Text { get; set; }
        public Action<string> Handler { get; set; }
    }

    public class RiskNotificationPayload
    {
        public string FilePath { get; set; }
        public string ThreatName { get; set; }
        public string Severity { get; set; }
        public string SuggestedAction { get; set; }
        public List<RiskAction> Actions { get; set; } = new List<RiskAction>();
    }
}