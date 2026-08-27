// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using System.Collections.Generic;
using System.ServiceProcess;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host
{
    public enum Theme
    {
        Light,
        Dark
    }

    public enum ThemeColor
    {
        PrimaryColor,
        PrimaryDark,
        PrimaryLight,
        SuccessColor,
        WarningColor,
        ErrorColor,
        InfoColor,
        BgPrimary,
        BgSecondary,
        BgTertiary,
        BgHover,
        TextPrimary,
        TextSecondary,
        TextDisabled,
        BorderColor,
        CardBg
    }

    public interface IThemed
    {
        void ApplyTheme(Theme theme);
    }

    public class MainForm : Form
    {
        private Panel sidebarPanel;
        private Panel contentPanel;
        private FlowLayoutPanel navigationPanel;
        private Panel currentPagePanel;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private Button themeToggleBtn;
        private Label protectionStatusDot;
        private Label protectionStatusText;

        private Theme currentTheme = Theme.Light;
        private Dictionary<string, System.WeakReference<UserControl>> pages = new Dictionary<string, System.WeakReference<UserControl>>();
        private UserControl currentPage = null;
        private NamedPipeClient pipeClient;
        private BackgroundProtectionManager backgroundProtectionManager;
        private DateTime _lastPageLoadTime = DateTime.MinValue;
        private string _currentLoadingPage = null;
        private readonly object _pageLoadLock = new object();

        private static readonly string LogFilePath = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "app.log");
        private NotifyIcon notifyIcon;

        public MainForm()
        {
            try
            {
                // 初始化日志
                Log("Application starting...");
                
                // 只执行必要的UI初始化操作
                InitializeComponents();
                Log("UI components initialized");
                
                LoadThemeFromConfig();
                Log("Theme loaded from config");
                
                InitializeTheme();
                Log("Theme initialized");
                
                // 初始化后台防护管理器
                backgroundProtectionManager = new BackgroundProtectionManager(this);
                Log("Background protection manager initialized");
                
                // 初始化系统托盘图标
                InitializeNotifyIcon();
                Log("System tray icon initialized");
                
                // 添加窗体关闭事件处理器
                this.FormClosing += MainForm_FormClosing;
                Log("Form closing event handler added");
                
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) =>
                {
                    UpdateUI();
                };
                // 订阅全局语言变更事件
                LanguageManager.GlobalLanguageChanged += (sender, e) =>
                {
                    UpdateUI();
                };
                Log("Language changed event handlers added");
                
                // 立即返回，让UI先完全显示
                
                // 在后台线程中执行所有其他操作
                System.Threading.Tasks.Task.Run(() => {
                    try
                    {
                        // 延迟一点时间，确保UI完全初始化
                        System.Threading.Thread.Sleep(500);
                        Log("Delayed for UI initialization");
                        
                        // 加载默认页面
                        this.BeginInvoke((Action)(() => {
                            try
                            {
                                LoadPage("home");
                                Log("Default page (home) loaded");
                            }
                            catch (Exception ex)
                            {
                                Log($"Error loading home page: {ex.Message}");
                            }
                        }));
                        
                        // 初始化命名管道客户端
                        InitializePipeClient();
                        Log("Named pipe client initialized");
                        
                        // 检查并启动后台防护程序
                        System.Threading.Thread.Sleep(1000);
                        CheckAndStartBackgroundProtection();
                        Log("Background protection checked and started");

                        backgroundProtectionManager.StartStatusMonitoring();
                        Log("Background protection status monitoring started");
                        
                        // 启动更新管理器
                        System.Threading.Thread.Sleep(1500);
                        UpdateManager.Instance.Start();
                        Log("Update manager started");
                        
                        // 初始化ClamAV引擎
                        System.Threading.Thread.Sleep(2000);
                        InitializeClamAVEngine();
                        Log("ClamAV engine initialized");
                        
                        // 预加载其他常用页面（在后台）
                        System.Threading.Thread.Sleep(2500);
                        PreloadCommonPages();
                        Log("Common pages preloaded");
                    }
                    catch (Exception ex)
                    {
                        Log($"Error in background task: {ex.Message}");
                    }
                });
            }
            catch (Exception ex)
            {
                Log($"Critical error during initialization: {ex.Message}");
                MessageBox.Show($"应用启动失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Log(string message)
        {
            try
            {
                string logMessage = $"[{DateTime.Now}] {message}\n";
                System.IO.File.AppendAllText(LogFilePath, logMessage);
                Console.WriteLine(logMessage);
            }
            catch
            {
                // 静默处理日志错误
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            backgroundProtectionManager?.StopStatusMonitoring();

            if (pipeClient != null)
            {
                pipeClient.Disconnect();
            }
            
            UpdateManager.Instance.Stop();
            
            notifyIcon?.Dispose();
        }

        private void InitializeNotifyIcon()
        {
            try
            {
                // 禁用此托盘图标，由WPF主程序统一管理
                notifyIcon = new NotifyIcon
                {
                    Text = _languageManager.GetString("AppTitle"),
                    Icon = GetAntivirusIcon(),
                    Visible = false // 禁用，避免重复图标
                };
                
                // 创建右键菜单
                ContextMenuStrip contextMenu = new ContextMenuStrip();
                
                // 打开主程序菜单项
                ToolStripMenuItem openMenuItem = new ToolStripMenuItem(_languageManager.GetString("OpenMainProgram"), null, (sender, e) =>
                {
                    this.Show();
                    this.WindowState = FormWindowState.Normal;
                });
                
                // 服务状态菜单项
                ToolStripMenuItem statusMenuItem = new ToolStripMenuItem(_languageManager.GetString("ServiceStatus"), null, (sender, e) =>
                {
                    try
                    {
                        var serviceStatus = backgroundProtectionManager?.IsProtectionRunning() ?? false;
                        string statusText = serviceStatus ? _languageManager.GetString("ProtectionStatusEnabled") : "Disabled";
                        MessageBox.Show(_languageManager.GetString("ServiceStatusMessage", statusText), _languageManager.GetString("ServiceStatus"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        Log($"Error getting service status: {ex.Message}");
                    }
                });
                
                // 退出菜单项
                ToolStripMenuItem exitMenuItem = new ToolStripMenuItem(_languageManager.GetString("ExitService"), null, (sender, e) =>
                {
                    try
                    {
                        // 创建自定义退出确认弹窗
                        Form exitForm = new Form();
                        exitForm.Text = _languageManager.GetString("ExitServiceConfirmationTitle");
                        exitForm.Size = new Size(400, 150);
                        exitForm.StartPosition = FormStartPosition.Manual;
                        // 设置弹窗位置为右下角
                        exitForm.Location = new Point(
                            Screen.PrimaryScreen.WorkingArea.Width - exitForm.Width - 10,
                            Screen.PrimaryScreen.WorkingArea.Height - exitForm.Height - 10
                        );
                        exitForm.FormBorderStyle = FormBorderStyle.FixedDialog;
                        exitForm.MaximizeBox = false;
                        exitForm.MinimizeBox = false;
                        
                        // 创建UI元素
                        Label messageLabel = new Label();
                        messageLabel.Text = _languageManager.GetString("ExitServiceConfirmation");
                        messageLabel.Font = new Font("微软雅黑", 10);
                        messageLabel.Location = new Point(20, 20);
                        messageLabel.Size = new Size(360, 40);
                        messageLabel.TextAlign = ContentAlignment.MiddleCenter;
                        
                        // 创建按钮
                        Button yesButton = new Button();
                        yesButton.Text = "是";
                        yesButton.Location = new Point(100, 70);
                        yesButton.Size = new Size(80, 30);
                        yesButton.Click += (s, e2) => {
                            // 清理系统托盘图标
                            notifyIcon?.Dispose();
                            
                            // 退出应用程序
                            Application.Exit();
                        };
                        
                        Button noButton = new Button();
                        noButton.Text = "否";
                        noButton.Location = new Point(220, 70);
                        noButton.Size = new Size(80, 30);
                        noButton.Click += (s, e2) => {
                            exitForm.Close();
                        };
                        
                        // 添加控件到窗体
                        exitForm.Controls.Add(messageLabel);
                        exitForm.Controls.Add(yesButton);
                        exitForm.Controls.Add(noButton);
                        
                        // 显示弹窗
                        exitForm.ShowDialog();
                    }
                    catch (Exception ex)
                    {
                        Log($"Error exiting service: {ex.Message}");
                    }
                });
                
                // 添加菜单项到上下文菜单
                contextMenu.Items.Add(openMenuItem);
                contextMenu.Items.Add(statusMenuItem);
                contextMenu.Items.Add(new ToolStripSeparator());
                contextMenu.Items.Add(exitMenuItem);
                
                // 设置系统托盘图标的上下文菜单
                notifyIcon.ContextMenuStrip = contextMenu;
                
                // 添加双击事件
                notifyIcon.DoubleClick += (sender, e) =>
                {
                    this.Show();
                    this.WindowState = FormWindowState.Normal;
                };
            }
            catch (Exception ex)
            {
                Log($"Error initializing notify icon: {ex.Message}");
            }
        }
        
        // 当应用程序被卸载时调用的方法
        public static void UninstallCleanup()
        {
            try
            {
                string serviceName = "FireAntivirusService";
                
                // 卸载服务
                MainForm form = new MainForm();
                form.UninstallService(serviceName);
            }
            catch (Exception ex)
            {
                // 静默处理错误
            }
        }

        private void InitializePipeClient()
        {
            try
            {
                pipeClient = new NamedPipeClient("FireAntivirusPipe");
                pipeClient.Connected += PipeClient_Connected;
                pipeClient.Disconnected += PipeClient_Disconnected;
                pipeClient.MessageReceived += PipeClient_MessageReceived;
                pipeClient.Connect();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Pipe client initialization error: {ex.Message}");
            }
        }

        private void InitializeClamAVEngine()
        {
            try
            {
                var dataManager = new FireAntivirus.Data.DataManager();
                var antivirusEngine = new FireAntivirus.Engine.AntivirusEngine();
                var clamAVEngine = new FireAntivirus.Services.ClamAVEngine(dataManager, antivirusEngine);
                
                bool success = clamAVEngine.Initialize();
                if (success)
                {
                    Console.WriteLine("ClamAV engine initialized successfully");
                    Log("ClamAV engine initialized successfully");
                    
                    string version = clamAVEngine.GetClamAVVersion();
                    int databaseCount = clamAVEngine.GetVirusDatabaseCount();
                    Console.WriteLine($"ClamAV version: {version}");
                    Console.WriteLine($"Virus database count: {databaseCount}");
                    Log($"ClamAV version: {version}, Database count: {databaseCount}");
                    
                    string dbVersion = clamAVEngine.GetDatabaseVersion();
                    bool dbUpToDate = !string.IsNullOrEmpty(dbVersion) && dbVersion != "未知";
                    
                    UpdateHomePageVirusDatabaseStatus(dbVersion, dbUpToDate);
                    
                    clamAVEngine.ScheduleVirusDatabaseUpdate();
                    Console.WriteLine("Virus database auto-update scheduled");
                    Log("Virus database auto-update scheduled");
                }
                else
                {
                    Console.WriteLine("ClamAV engine initialization failed");
                    Log("ClamAV engine initialization failed");
                    UpdateHomePageVirusDatabaseStatus("未安装", false);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing ClamAV engine: {ex.Message}");
                Log($"Error initializing ClamAV engine: {ex.Message}");
                UpdateHomePageVirusDatabaseStatus("错误", false);
            }
        }

        private void UpdateHomePageVirusDatabaseStatus(string version, bool isUpToDate)
        {
            try
            {
                foreach (var kvp in pages)
                {
                    if (kvp.Key == "home" && kvp.Value.TryGetTarget(out UserControl page) && page is HomePage homePage)
                    {
                        this.BeginInvoke((Action)(() => {
                            try
                            {
                                homePage.UpdateVirusDatabaseStatus(version, isUpToDate);
                            }
                            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
                        }));
                        return;
                    }
                }

                if (currentPage is HomePage currentHome)
                {
                    this.BeginInvoke((Action)(() => {
                        try
                        {
                            currentHome.UpdateVirusDatabaseStatus(version, isUpToDate);
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
                    }));
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
        }
        
        private void CheckAndStartBackgroundProtection()
        {
            backgroundProtectionManager.CheckAndStartBackgroundProtection();
        }

        private void PipeClient_Connected(object sender, EventArgs e)
        {
            Console.WriteLine("Connected to protection service");
            // 请求防护状态
            var message = new Message();
            message.type = 1; // 状态请求消息
            pipeClient.SendMessage(message);
        }

        private void PipeClient_Disconnected(object sender, EventArgs e)
        {
            Console.WriteLine("Disconnected from protection service");
            // 尝试重新连接
            ThreadPool.QueueUserWorkItem((state) => {
                Thread.Sleep(5000);
                pipeClient.Connect();
            });
        }

        private void PipeClient_MessageReceived(object sender, MessageReceivedEventArgs e)
        {
            try
            {
                // 处理来自服务的消息
                ProcessPipeMessage(e.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Process message error: {ex.Message}");
            }
        }

        private void ProcessPipeMessage(Message message)
        {
            try
            {
                // 检查消息类型
                if (message.type == 1) // 威胁告警消息
                {
                    // 显示威胁告警弹窗
                    ShowThreatAlert(message.threatInfo);
                }
                else if (message.type == 2) // 防护状态消息
                {
                    // 这里可以处理防护状态更新
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Process message error: {ex.Message}");
            }
        }

        private void ShowThreatAlert(ThreatInfo threatInfo)
        {
            try
            {
                this.Invoke((Action)(() => {
                    // 创建威胁告警弹窗
                    Form alertForm = new Form();
                    alertForm.Text = "威胁告警"; 
                    alertForm.Size = new Size(400, 250);
                    alertForm.StartPosition = FormStartPosition.Manual;
                    // 设置弹窗位置为右下角
                    alertForm.Location = new Point(
                        Screen.PrimaryScreen.WorkingArea.Width - alertForm.Width - 10,
                        Screen.PrimaryScreen.WorkingArea.Height - alertForm.Height - 10
                    );
                    alertForm.FormBorderStyle = FormBorderStyle.FixedDialog;
                    alertForm.MaximizeBox = false;
                    alertForm.MinimizeBox = false;
                    
                    // 创建UI元素
                    Label titleLabel = new Label();
                    titleLabel.Text = "发现威胁!";
                    titleLabel.Font = new Font("微软雅黑", 14, FontStyle.Bold);
                    titleLabel.ForeColor = Color.Red;
                    titleLabel.Location = new Point(20, 20);
                    titleLabel.Size = new Size(360, 30);
                    
                    Label threatTypeLabel = new Label();
                    threatTypeLabel.Text = $"威胁类型: {threatInfo.type}";
                    threatTypeLabel.Font = new Font("微软雅黑", 10);
                    threatTypeLabel.Location = new Point(20, 60);
                    threatTypeLabel.Size = new Size(360, 20);
                    
                    Label processLabel = new Label();
                    processLabel.Text = $"进程: {threatInfo.processPath}";
                    processLabel.Font = new Font("微软雅黑", 10);
                    processLabel.Location = new Point(20, 85);
                    processLabel.Size = new Size(360, 20);
                    
                    Label targetLabel = new Label();
                    targetLabel.Text = $"目标: {threatInfo.targetPath}";
                    targetLabel.Font = new Font("微软雅黑", 10);
                    targetLabel.Location = new Point(20, 110);
                    targetLabel.Size = new Size(360, 20);
                    
                    Label descriptionLabel = new Label();
                    descriptionLabel.Text = $"描述: {threatInfo.threatDescription}";
                    descriptionLabel.Font = new Font("微软雅黑", 10);
                    descriptionLabel.Location = new Point(20, 135);
                    descriptionLabel.Size = new Size(360, 20);
                    
                    // 创建按钮
                    Button blockButton = new Button();
                    blockButton.Text = "阻止";
                    blockButton.Location = new Point(100, 170);
                    blockButton.Size = new Size(80, 30);
                    blockButton.Click += (s, e) => {
                        // 发送阻止命令到后台
                        Message response = new Message();
                        response.type = 3; // 响应消息
                        response.threatInfo = threatInfo;
                        response.action = ThreatAction.BLOCK;
                        pipeClient.SendMessage(response);
                        alertForm.Close();
                    };
                    
                    Button allowButton = new Button();
                    allowButton.Text = "允许";
                    allowButton.Location = new Point(220, 170);
                    allowButton.Size = new Size(80, 30);
                    allowButton.Click += (s, e) => {
                        // 发送允许命令到后台
                        Message response = new Message();
                        response.type = 3; // 响应消息
                        response.threatInfo = threatInfo;
                        response.action = ThreatAction.ALLOW;
                        pipeClient.SendMessage(response);
                        alertForm.Close();
                    };
                    
                    // 添加控件到窗体
                    alertForm.Controls.Add(titleLabel);
                    alertForm.Controls.Add(threatTypeLabel);
                    alertForm.Controls.Add(processLabel);
                    alertForm.Controls.Add(targetLabel);
                    alertForm.Controls.Add(descriptionLabel);
                    alertForm.Controls.Add(blockButton);
                    alertForm.Controls.Add(allowButton);
                    
                    // 显示弹窗
                    alertForm.ShowDialog();
                }));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Show threat alert error: {ex.Message}");
            }
        }



        public void UpdateProtectionStatus(Dictionary<string, bool> status)
        {
            try
            {
                bool allProtectionsEnabled = true;
                foreach (var kvp in status)
                {
                    if (!kvp.Value)
                    {
                        allProtectionsEnabled = false;
                        break;
                    }
                }

                bool serviceRunning = status.TryGetValue("Service", out bool svc) && svc;

                this.Invoke((Action)(() => {
                    if (serviceRunning && allProtectionsEnabled)
                    {
                        protectionStatusDot.ForeColor = Color.Green;
                        protectionStatusText.Text = "防护已完全启用";
                    }
                    else if (serviceRunning)
                    {
                        protectionStatusDot.ForeColor = Color.Yellow;
                        protectionStatusText.Text = "部分防护已启用";
                    }
                    else
                    {
                        protectionStatusDot.ForeColor = Color.Red;
                        protectionStatusText.Text = "防护未启动";
                    }

                    if (currentPage is ProtectionPage protectionPage)
                    {
                        try
                        {
                            protectionPage.UpdateProtectionStatus(status);
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
                    }

                    if (currentPage is HomePage homePage)
                    {
                        try
                        {
                            homePage.UpdateProtectionStatus(serviceRunning && allProtectionsEnabled);
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
                    }
                }));

                foreach (var kvp in pages)
                {
                    if (kvp.Key == "home" && kvp.Value.TryGetTarget(out UserControl page) && page is HomePage cachedHome)
                    {
                        this.BeginInvoke((Action)(() => {
                            try
                            {
                                cachedHome.UpdateProtectionStatus(serviceRunning && allProtectionsEnabled);
                            }
                            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
                        }));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Update protection status error: {ex.Message}");
            }
        }

        private void LoadThemeFromConfig()
        {
            try
            {
                string configPath = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FireAntivirus", "config.json");
                
                if (System.IO.File.Exists(configPath))
                {
                    string configContent = System.IO.File.ReadAllText(configPath);
                    if (configContent.Contains("\"theme\":\"Dark\""))
                    {
                        currentTheme = Theme.Dark;
                    }
                    else if (configContent.Contains("\"theme\":\"Light\""))
                    {
                        currentTheme = Theme.Light;
                    }
                }
                else
                {
                    // 如果配置文件不存在，默认使用白色主题
                    currentTheme = Theme.Light;
                    // 保存默认主题设置
                    SaveThemeToConfig();
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
        }

        private void SaveThemeToConfig()
        {
            try
            {
                string configDir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FireAntivirus");
                
                System.IO.Directory.CreateDirectory(configDir);
                
                string configPath = System.IO.Path.Combine(configDir, "config.json");
                string configContent = $"{{\"theme\":\"{currentTheme}\"}}";
                System.IO.File.WriteAllText(configPath, configContent);
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
        }

        private async void PreloadCommonPages()
        {
            // 预加载常用页面，避免用户点击时卡顿
            string[] commonPages = { "protection", "scan", "home" };
            
            foreach (string pageName in commonPages)
            {
                try
                {
                    // 在后台线程中创建页面实例，避免UI阻塞
                    await Task.Run(() => {
                        try
                        {
                            Log($"Preloading page: {pageName}");
                            UserControl page = CreatePageInstance(pageName);
                            
                            if (page != null)
                            {
                                // 在UI线程中应用主题并存储
                                this.Invoke((Action)(() => {
                                    try
                                    {
                                        if (page is IThemed themedPage)
                                        {
                                            themedPage.ApplyTheme(currentTheme);
                                            pages[pageName] = new System.WeakReference<UserControl>(page);
                                            Log($"Page preloaded successfully: {pageName}");
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        Log($"Error applying theme to preloaded page: {ex.Message}");
                                    }
                                }));
                            }
                        }
                        catch (Exception ex)
                        {
                            Log($"Error preloading page: {ex.Message}");
                        }
                    });
                    
                    // 延迟一点时间，避免同时创建多个页面导致CPU过载
                    await Task.Delay(100);
                }
                catch (Exception ex)
                {
                    Log($"Error in preload loop: {ex.Message}");
                }
            }
        }

        private void InitializeComponents()
        {
            try
            {
                this.Text = _languageManager.GetString("AppTitle") + " - " + _languageManager.GetString("ProfessionalProtection");
                this.Size = new Size(960, 680); // 设置固定窗口大小
                this.MinimumSize = new Size(960, 680); // 最小大小
                this.MaximumSize = new Size(960, 680); // 最大大小，防止最大化
                this.StartPosition = FormStartPosition.CenterScreen;
                this.MaximizeBox = false; // 禁用最大化按钮
                
                // 安全地获取图标
                try
                {
                    this.Icon = GetAntivirusIcon();
                    Log("Application icon loaded");
                }
                catch (Exception ex)
                {
                    Log($"Error loading application icon: {ex.Message}");
                    // 使用默认图标
                    this.Icon = SystemIcons.Application;
                }

                var mainContainer = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    ColumnCount = 2,
                    RowCount = 1
                };

                mainContainer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 220));
                mainContainer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

                sidebarPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    Padding = new Padding(10, 20, 10, 20)
                };

                var sidebarLayout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    RowCount = 3,
                    ColumnCount = 1
                };

                sidebarLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
                sidebarLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
                sidebarLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));

                var logoPanel = new Panel
                {
                    Dock = DockStyle.Fill
                };

                var logoLabel = new Label
                {
                    Text = "🛡️ 耄耋杀毒",
                    Font = new Font("微软雅黑", 14, FontStyle.Bold),
                    ForeColor = GetThemeColor(ThemeColor.PrimaryColor),
                    TextAlign = ContentAlignment.MiddleLeft,
                    Dock = DockStyle.Fill,
                    AutoSize = false
                };

                logoPanel.Controls.Add(logoLabel);
                sidebarLayout.Controls.Add(logoPanel, 0, 0);

                navigationPanel = new FlowLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    FlowDirection = FlowDirection.TopDown,
                    AutoScroll = true,
                    WrapContents = false
                };

                // 导航项分组
                var navGroups = new[]
                {
                    new { Title = "主页与扫描", Items = new[]
                        {
                            new { Page = "home", Icon = "🏠", Text = _languageManager.GetString("Home") },
                            new { Page = "scan", Icon = "🔍", Text = _languageManager.GetString("VirusScan") }
                        }
                    },
                    new { Title = "实时防护", Items = new[]
                        {
                            new { Page = "protection", Icon = "🛡️", Text = _languageManager.GetString("RealTimeProtection") },
                            new { Page = "network", Icon = "🌐", Text = _languageManager.GetString("NetworkProtection") },
                            new { Page = "popup", Icon = "📢", Text = _languageManager.GetString("PopupBlocker") },
                            new { Page = "ransomware", Icon = "💰", Text = "勒索防护" }
                        }
                    },
                    new { Title = "安全防护", Items = new[]
                        {
                            new { Page = "privacy", Icon = "🔒", Text = "隐私保护" },
                            new { Page = "parental", Icon = "👨‍👩‍👧‍👦", Text = "家长控制" },
                            new { Page = "web", Icon = "🌍", Text = "网页防护" },
                            new { Page = "email", Icon = "📧", Text = "邮件安全" },
                            new { Page = "password", Icon = "🔑", Text = "密码管理" },
                            new { Page = "firewall", Icon = "🧱", Text = "网络防火墙" },
                            new { Page = "device", Icon = "📱", Text = "设备控制" },
                            new { Page = "vulnerability", Icon = "🔓", Text = "漏洞扫描" },
                            new { Page = "cloud", Icon = "☁️", Text = "云查杀" },
                            new { Page = "browser", Icon = "🌐", Text = "安全浏览器" },
                            new { Page = "mobile", Icon = "📱", Text = "移动安全" }
                        }
                    },
                    new { Title = "系统工具", Items = new[]
                        {
                            new { Page = "optimizer", Icon = "⚡", Text = "系统优化" },
                            new { Page = "backup", Icon = "💾", Text = "备份恢复" },
                            new { Page = "score", Icon = "📊", Text = "安全评分" },
                            new { Page = "traffic", Icon = "📈", Text = "网络流量" },
                            new { Page = "app", Icon = "📱", Text = "应用监控" },
                            new { Page = "startup", Icon = "🚀", Text = "启动管理" },
                            new { Page = "report", Icon = "📋", Text = "安全报告" },
                            new { Page = "behavior", Icon = "👁️", Text = "行为分析" },
                            new { Page = "tools", Icon = "🛠️", Text = _languageManager.GetString("SystemTools") },
                            new { Page = "systeminfo", Icon = "💻", Text = _languageManager.GetString("SystemInfo") }
                        }
                    },
                    new { Title = "设置与管理", Items = new[]
                        {
                            new { Page = "quarantine", Icon = "🔒", Text = _languageManager.GetString("Quarantine") },
                            new { Page = "trust", Icon = "✅", Text = _languageManager.GetString("TrustZone") },
                            new { Page = "logs", Icon = "📋", Text = _languageManager.GetString("LogCenter") },
                            new { Page = "settings", Icon = "⚙️", Text = _languageManager.GetString("Settings") },
                            new { Page = "about", Icon = "ℹ️", Text = _languageManager.GetString("About") }
                        }
                    }
                };

                foreach (var group in navGroups)
                {
                    try
                    {
                        // 创建分组标题
                        var groupLabel = new Label
                        {
                            Text = group.Title,
                            Font = new Font("微软雅黑", 8, FontStyle.Bold),
                            ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                            AutoSize = true,
                            Margin = new Padding(0, 10, 0, 5)
                        };
                        navigationPanel.Controls.Add(groupLabel);

                        // 创建分组内的按钮
                        foreach (var item in group.Items)
                        {
                            var navBtn = CreateNavButton(item.Page, item.Icon, item.Text);
                            navigationPanel.Controls.Add(navBtn);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Error creating navigation group: {ex.Message}");
                    }
                }

                sidebarLayout.Controls.Add(navigationPanel, 0, 1);

                var statusPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    Padding = new Padding(10)
                };

                protectionStatusDot = new Label
                {
                    Text = "●",
                    Font = new Font("Arial", 12),
                    ForeColor = Color.Yellow,
                    AutoSize = true,
                    Location = new Point(0, 20)
                };

                protectionStatusText = new Label
                {
                    Text = "正在检测...",
                    Font = new Font("微软雅黑", 9),
                    ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                    AutoSize = true,
                    Location = new Point(20, 20)
                };

                statusPanel.Controls.Add(protectionStatusDot);
                statusPanel.Controls.Add(protectionStatusText);
                sidebarLayout.Controls.Add(statusPanel, 0, 2);

                sidebarPanel.Controls.Add(sidebarLayout);
                mainContainer.Controls.Add(sidebarPanel, 0, 0);

                contentPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    Padding = new Padding(20)
                };

                currentPagePanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = Color.Transparent
                };

                themeToggleBtn = new Button
                {
                    Text = "🌙",
                    Size = new Size(40, 40),
                    FlatStyle = FlatStyle.Flat,
                    BackColor = Color.Transparent,
                    ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                    Cursor = Cursors.Hand
                };
                themeToggleBtn.FlatAppearance.BorderSize = 0;
                themeToggleBtn.Click += ToggleTheme;

                contentPanel.Controls.Add(currentPagePanel);
                contentPanel.Controls.Add(themeToggleBtn);
                mainContainer.Controls.Add(contentPanel, 1, 0);

                this.Controls.Add(mainContainer);
                Log("UI components fully initialized");
            }
            catch (Exception ex)
            {
                Log($"Error initializing components: {ex.Message}");
                throw; // 重新抛出异常，因为UI初始化失败是致命的
            }
        }

        private Button CreateNavButton(string page, string icon, string text)
        {
            var btn = new Button
            {
                Text = $"{icon} {text}",
                Tag = page,
                Width = 200,
                Height = 45,
                Margin = new Padding(0, 2, 0, 2),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Transparent,
                ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                Font = new Font("微软雅黑", 9),
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(15, 0, 0, 0),
                Cursor = Cursors.Hand,
                AutoSize = false
            };
            btn.FlatAppearance.BorderSize = 0;
            btn.FlatAppearance.MouseOverBackColor = GetThemeColor(ThemeColor.BgHover);
            btn.FlatAppearance.MouseDownBackColor = GetThemeColor(ThemeColor.BgTertiary);
            
            // 添加悬停效果
            btn.MouseEnter += (s, e) => {
                btn.ForeColor = GetThemeColor(ThemeColor.PrimaryColor);
                btn.Padding = new Padding(18, 0, 0, 0); // 轻微缩进效果
            };
            
            btn.MouseLeave += (s, e) => {
                // 检查是否为当前选中页面
                if (btn.Tag.ToString() != GetCurrentPageName())
                {
                    btn.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
                }
                btn.Padding = new Padding(15, 0, 0, 0); // 恢复原始缩进
            };
            
            btn.Click += (s, e) => LoadPage(page);
            return btn;
        }
        
        private string GetCurrentPageName()
        {
            // 获取当前页面的名称
            if (currentPage == null) return string.Empty;
            
            foreach (var kvp in pages)
            {
                if (kvp.Value.TryGetTarget(out UserControl page) && page == currentPage)
                {
                    return kvp.Key;
                }
            }
            return string.Empty;
        }

        private void InitializeTheme()
        {
            ApplyTheme(currentTheme);
        }

        public async void LoadPage(string pageName)
        {
            // 快速返回如果页面名称为空
            if (string.IsNullOrEmpty(pageName))
                return;

            // 防抖机制：防止快速连续点击导致的卡死
            lock (_pageLoadLock)
            {
                if (_currentLoadingPage == pageName)
                {
                    Log($"Page {pageName} is already loading, skipping");
                    return;
                }
                
                DateTime now = DateTime.Now;
                if ((now - _lastPageLoadTime).TotalMilliseconds < 300)
                {
                    Log($"Page load debounced, too fast: {pageName}");
                    return;
                }
                
                _lastPageLoadTime = now;
                _currentLoadingPage = pageName;
            }

            try
            {
                Log($"Loading page: {pageName}");
                
                // 立即更新导航按钮样式，确保用户获得反馈
                try
                {
                    UpdateNavigationButtons(pageName);
                    Log($"Navigation buttons updated for page: {pageName}");
                }
                catch (Exception ex)
                {
                    Log($"Error updating navigation buttons: {ex.Message}");
                }

                // 快速检查页面是否已存在
                UserControl existingPage = null;
                if (pages.TryGetValue(pageName, out System.WeakReference<UserControl> pageRef))
                {
                    if (pageRef.TryGetTarget(out existingPage))
                    {
                        // 直接切换到已创建的页面
                        try
                        {
                            SwitchToPage(existingPage);
                            Log($"Switched to existing page: {pageName}");
                            return;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error switching to existing page: {ex.Message}");
                            // 页面切换失败，继续创建新页面
                            pages.Remove(pageName);
                        }
                    }
                    else
                    {
                        // 页面已被回收，移除引用
                        pages.Remove(pageName);
                        Log($"Page {pageName} was garbage collected, removing reference");
                    }
                }

                // 在后台线程中创建页面实例，避免UI阻塞
                UserControl newPage = null;
                await Task.Run(() => {
                    try
                    {
                        Log($"Creating new page instance on background thread: {pageName}");
                        newPage = CreatePageInstance(pageName);
                        if (newPage != null)
                        {
                            Log($"Page instance created successfully: {pageName}");
                        }
                        else
                        {
                            Log($"Failed to create page instance: {pageName}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Error creating page instance: {ex.Message}");
                    }
                });

                // 在UI线程中应用主题并切换页面
                this.Invoke((Action)(() => {
                    try
                    {
                        if (newPage != null)
                        {
                            // 应用主题
                            try
                            {
                                if (newPage is IThemed themedPage)
                                {
                                    themedPage.ApplyTheme(currentTheme);
                                    Log($"Theme applied to page: {pageName}");
                                }
                                // 存储页面弱引用
                                if (!pages.ContainsKey(pageName))
                                {
                                    pages[pageName] = new System.WeakReference<UserControl>(newPage);
                                    Log($"Page reference stored: {pageName}");
                                }
                                // 切换到新页面
                                SwitchToPage(newPage);
                                Log($"Switched to new page: {pageName}");
                            }
                            catch (Exception ex)
                            {
                                Log($"Error in UI thread operation: {ex.Message}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Error in UI thread page creation: {ex.Message}");
                    }
                }));
            }
            catch (Exception ex)
            {
                Log($"Error loading page: {ex.Message}");
            }
            finally
            {
                lock (_pageLoadLock)
                {
                    _currentLoadingPage = null;
                }
            }
        }
        


        private void UpdateNavigationButtons(string pageName)
        {
            // 快速更新导航按钮样式，避免任何可能的阻塞
            try
            {
                // 缓存颜色值，避免重复计算
                Color bgTertiary = GetThemeColor(ThemeColor.BgTertiary);
                Color primaryColor = GetThemeColor(ThemeColor.PrimaryColor);
                Color textSecondary = GetThemeColor(ThemeColor.TextSecondary);

                // 快速遍历并更新按钮
                foreach (Control control in navigationPanel.Controls)
                {
                    if (control is Button btn)
                    {
                        string btnPage = btn.Tag?.ToString();
                        if (btnPage == pageName)
                        {
                            // 更新选中状态
                            btn.BackColor = bgTertiary;
                            btn.ForeColor = primaryColor;
                        }
                        else
                        {
                            // 更新未选中状态
                            btn.BackColor = Color.Transparent;
                            btn.ForeColor = textSecondary;
                        }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
        }

        private UserControl CreatePageInstance(string pageName)
        {
            // 快速创建页面实例，避免任何可能的阻塞
            try
            {
                Log($"Creating page instance for: {pageName}");
                switch (pageName)
                {
                    case "home":
                        try
                        {
                            var homePage = new HomePage();
                            Log("HomePage created successfully");
                            return homePage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating HomePage: {ex.Message}");
                            return null;
                        }
                    case "scan":
                        try
                        {
                            var scanPage = new ScanPage();
                            Log("ScanPage created successfully");
                            return scanPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating ScanPage: {ex.Message}");
                            return null;
                        }
                    case "protection":
                        try
                        {
                            var protectionPage = new ProtectionPage(pipeClient);
                            Log("ProtectionPage created successfully");
                            return protectionPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating ProtectionPage: {ex.Message}");
                            return null;
                        }
                    case "network":
                        try
                        {
                            var networkPage = new NetworkPage();
                            Log("NetworkPage created successfully");
                            return networkPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating NetworkPage: {ex.Message}");
                            return null;
                        }
                    case "popup":
                        try
                        {
                            var popupPage = new PopupPage();
                            Log("PopupPage created successfully");
                            return popupPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating PopupPage: {ex.Message}");
                            return null;
                        }
                    case "parental":
                        try
                        {
                            var parentalPage = new ParentalControlPage();
                            Log("ParentalControlPage created successfully");
                            return parentalPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating ParentalControlPage: {ex.Message}");
                            return null;
                        }
                    case "web":
                        try
                        {
                            var webPage = new WebProtectionPage();
                            Log("WebProtectionPage created successfully");
                            return webPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating WebProtectionPage: {ex.Message}");
                            return null;
                        }
                    case "email":
                        try
                        {
                            var emailPage = new EmailSecurityPage();
                            Log("EmailSecurityPage created successfully");
                            return emailPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating EmailSecurityPage: {ex.Message}");
                            return null;
                        }
                    case "password":
                        try
                        {
                            var passwordPage = new PasswordManagerPage();
                            Log("PasswordManagerPage created successfully");
                            return passwordPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating PasswordManagerPage: {ex.Message}");
                            return null;
                        }
                    case "optimizer":
                        try
                        {
                            var optimizerPage = new SystemOptimizerPage();
                            Log("SystemOptimizerPage created successfully");
                            return optimizerPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating SystemOptimizerPage: {ex.Message}");
                            return null;
                        }
                    case "backup":
                        try
                        {
                            var backupPage = new BackupPage();
                            Log("BackupPage created successfully");
                            return backupPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating BackupPage: {ex.Message}");
                            return null;
                        }
                    case "firewall":
                        try
                        {
                            var firewallPage = new NetworkFirewallPage();
                            Log("NetworkFirewallPage created successfully");
                            return firewallPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating NetworkFirewallPage: {ex.Message}");
                            return null;
                        }
                    case "device":
                        try
                        {
                            var devicePage = new DeviceControlPage();
                            Log("DeviceControlPage created successfully");
                            return devicePage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating DeviceControlPage: {ex.Message}");
                            return null;
                        }
                    case "vulnerability":
                        try
                        {
                            var vulnerabilityPage = new VulnerabilityScannerPage();
                            Log("VulnerabilityScannerPage created successfully");
                            return vulnerabilityPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating VulnerabilityScannerPage: {ex.Message}");
                            return null;
                        }
                    case "ransomware":
                        try
                        {
                            var ransomwarePage = new RansomwareProtectionPage();
                            Log("RansomwareProtectionPage created successfully");
                            return ransomwarePage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating RansomwareProtectionPage: {ex.Message}");
                            return null;
                        }
                    case "cloud":
                        try
                        {
                            var cloudPage = new CloudScannerPage();
                            Log("CloudScannerPage created successfully");
                            return cloudPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating CloudScannerPage: {ex.Message}");
                            return null;
                        }
                    case "browser":
                        try
                        {
                            var browserPage = new SecureBrowserPage();
                            Log("SecureBrowserPage created successfully");
                            return browserPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating SecureBrowserPage: {ex.Message}");
                            return null;
                        }
                    case "score":
                        try
                        {
                            var scorePage = new SecurityScorePage();
                            Log("SecurityScorePage created successfully");
                            return scorePage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating SecurityScorePage: {ex.Message}");
                            return null;
                        }
                    case "traffic":
                        try
                        {
                            var trafficPage = new NetworkTrafficAnalyzerPage();
                            Log("NetworkTrafficAnalyzerPage created successfully");
                            return trafficPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating NetworkTrafficAnalyzerPage: {ex.Message}");
                            return null;
                        }
                    case "app":
                        try
                        {
                            var appPage = new ApplicationMonitorPage();
                            Log("ApplicationMonitorPage created successfully");
                            return appPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating ApplicationMonitorPage: {ex.Message}");
                            return null;
                        }
                    case "startup":
                        try
                        {
                            var startupPage = new StartupManagerPage();
                            Log("StartupManagerPage created successfully");
                            return startupPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating StartupManagerPage: {ex.Message}");
                            return null;
                        }
                    case "report":
                        try
                        {
                            var reportPage = new SecurityReportPage();
                            Log("SecurityReportPage created successfully");
                            return reportPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating SecurityReportPage: {ex.Message}");
                            return null;
                        }
                    case "behavior":
                        try
                        {
                            var behaviorPage = new BehaviorAnalysisPage();
                            Log("BehaviorAnalysisPage created successfully");
                            return behaviorPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating BehaviorAnalysisPage: {ex.Message}");
                            return null;
                        }
                    case "mobile":
                        try
                        {
                            var mobilePage = new MobileSecurityPage();
                            Log("MobileSecurityPage created successfully");
                            return mobilePage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating MobileSecurityPage: {ex.Message}");
                            return null;
                        }
                    case "privacy":
                        try
                        {
                            var privacyPage = new PrivacyProtectionPage();
                            Log("PrivacyProtectionPage created successfully");
                            return privacyPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating PrivacyProtectionPage: {ex.Message}");
                            return null;
                        }
                    case "tools":
                        try
                        {
                            var toolsPage = new ToolsPage();
                            Log("ToolsPage created successfully");
                            return toolsPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating ToolsPage: {ex.Message}");
                            return null;
                        }
                    case "systeminfo":
                        try
                        {
                            var systemInfoPage = new SystemInfoPage();
                            Log("SystemInfoPage created successfully");
                            return systemInfoPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating SystemInfoPage: {ex.Message}");
                            return null;
                        }
                    case "quarantine":
                        try
                        {
                            var quarantinePage = new QuarantinePage();
                            Log("QuarantinePage created successfully");
                            return quarantinePage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating QuarantinePage: {ex.Message}");
                            return null;
                        }
                    case "trust":
                        try
                        {
                            var trustPage = new TrustPage();
                            Log("TrustPage created successfully");
                            return trustPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating TrustPage: {ex.Message}");
                            return null;
                        }
                    case "logs":
                        try
                        {
                            var logsPage = new LogsPage();
                            Log("LogsPage created successfully");
                            return logsPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating LogsPage: {ex.Message}");
                            return null;
                        }
                    case "settings":
                        try
                        {
                            var settingsPage = new SettingsPage();
                            Log("SettingsPage created successfully");
                            return settingsPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating SettingsPage: {ex.Message}");
                            return null;
                        }
                    case "about":
                        try
                        {
                            var aboutPage = new AboutPage();
                            Log("AboutPage created successfully");
                            return aboutPage;
                        }
                        catch (Exception ex)
                        {
                            Log($"Error creating AboutPage: {ex.Message}");
                            return null;
                        }
                    default:
                        Log($"Unknown page name: {pageName}");
                        return null;
                }
            }
            catch (Exception ex)
            {
                Log($"Error in CreatePageInstance: {ex.Message}");
                return null;
            }
        }

        private async void SwitchToPage(UserControl page)
        {
            if (page == null)
                return;

            try
            {
                Log("Switching to page...");
                
                // 快速检查是否为同一页面，避免重复操作
                if (currentPage == page)
                {
                    Log("Same page, no switch needed");
                    return;
                }

                // 在UI线程中执行所有UI操作
                this.Invoke(new Action(async () => {
                    try
                    {
                        // 设置新页面的属性
                        try
                        {
                            page.Dock = DockStyle.Fill;
                            page.Visible = false;

                            currentPagePanel.Controls.Add(page);
                            Log("Page properties set and added to panel");
                        }
                        catch (Exception ex)
                        {
                            Log($"Error setting page properties: {ex.Message}");
                            return;
                        }
                        
                        // 执行淡入淡出动画
                        await AnimatePageTransition(currentPage, page);
                        
                        // 移除旧页面
                        if (currentPage != null)
                        {
                            try
                            {
                                currentPagePanel.Controls.Remove(currentPage);
                                currentPage.Dispose();
                                Log("Old page removed and disposed");
                            }
                            catch (Exception ex)
                            {
                                Log($"Error removing old page: {ex.Message}");
                            }
                        }
                        
                        // 更新当前页面引用
                        currentPage = page;
                        Log("Current page reference updated");
                        
                        // 如果是系统信息页面，调用OnPageShown方法延迟加载数据
                        if (page is SystemInfoPage systemInfoPage)
                        {
                            try
                            {
                                systemInfoPage.OnPageShown();
                                Log("SystemInfoPage.OnPageShown() called");
                            }
                            catch (Exception ex)
                            {
                                Log($"Error calling SystemInfoPage.OnPageShown(): {ex.Message}");
                            }
                        }
                        
                        Log("Page switch completed successfully");
                    }
                    catch (Exception ex)
                    {
                        Log($"Error in UI thread during page switch: {ex.Message}");
                    }
                }));
            }
            catch (Exception ex)
            {
                Log($"Error switching to page: {ex.Message}");
            }
        }
        
        private async Task AnimatePageTransition(UserControl oldPage, UserControl newPage)
        {
            // 确保新页面已添加到控件集合
            if (!currentPagePanel.Controls.Contains(newPage))
            {
                currentPagePanel.Controls.Add(newPage);
            }
            
            // 隐藏旧页面
            oldPage?.Invoke((Action)(() => {
                oldPage.Visible = false;
            }));
            
            // 设置新页面的初始状态
            newPage.Invoke((Action)(() => {
                newPage.Size = new Size(currentPagePanel.Width, currentPagePanel.Height);
                newPage.Location = new Point(0, 0);
                newPage.Visible = true;
                newPage.BringToFront();
            }));
            
            // 使用简单的延迟来确保UI更新
            await Task.Delay(30);
        }

        private void ToggleTheme(object sender, EventArgs e)
        {
            currentTheme = currentTheme == Theme.Dark ? Theme.Light : Theme.Dark;
            themeToggleBtn.Text = currentTheme == Theme.Dark ? "🌙" : "☀️";
            ApplyTheme(currentTheme);
        }
        
        private void UpdateUI()
        {
            // 更新窗口标题
            this.Text = _languageManager.GetString("AppTitle") + " - " + _languageManager.GetString("ProfessionalProtection");
            
            // 清空导航面板并重新添加按钮
            navigationPanel.Controls.Clear();
            var navItems = new[]
            {
                new { Page = "home", Icon = "🏠", Text = _languageManager.GetString("Home") },
                new { Page = "scan", Icon = "🔍", Text = _languageManager.GetString("VirusScan") },
                new { Page = "protection", Icon = "🛡️", Text = _languageManager.GetString("RealTimeProtection") },
                new { Page = "network", Icon = "🌐", Text = _languageManager.GetString("NetworkProtection") },
                new { Page = "popup", Icon = "📢", Text = _languageManager.GetString("PopupBlocker") },
                new { Page = "parental", Icon = "👨‍👩‍👧‍👦", Text = "家长控制" },
                new { Page = "web", Icon = "🌍", Text = "网页防护" },
                new { Page = "email", Icon = "📧", Text = "邮件安全" },
                new { Page = "password", Icon = "🔑", Text = "密码管理" },
                new { Page = "optimizer", Icon = "⚡", Text = "系统优化" },
                new { Page = "backup", Icon = "💾", Text = "备份恢复" },
                new { Page = "firewall", Icon = "🧱", Text = "网络防火墙" },
                new { Page = "device", Icon = "📱", Text = "设备控制" },
                new { Page = "vulnerability", Icon = "🔓", Text = "漏洞扫描" },
                new { Page = "ransomware", Icon = "💰", Text = "勒索防护" },
                new { Page = "cloud", Icon = "☁️", Text = "云查杀" },
                new { Page = "browser", Icon = "🌐", Text = "安全浏览器" },
                new { Page = "score", Icon = "📊", Text = "安全评分" },
                new { Page = "traffic", Icon = "📈", Text = "网络流量" },
                new { Page = "app", Icon = "📱", Text = "应用监控" },
                new { Page = "startup", Icon = "🚀", Text = "启动管理" },
                new { Page = "report", Icon = "📋", Text = "安全报告" },
                new { Page = "behavior", Icon = "👁️", Text = "行为分析" },
                new { Page = "mobile", Icon = "📱", Text = "移动安全" },
                new { Page = "privacy", Icon = "🔒", Text = "隐私保护" },
                new { Page = "tools", Icon = "🛠️", Text = _languageManager.GetString("SystemTools") },
                new { Page = "systeminfo", Icon = "💻", Text = _languageManager.GetString("SystemInfo") },
                new { Page = "quarantine", Icon = "🔒", Text = _languageManager.GetString("Quarantine") },
                new { Page = "trust", Icon = "✅", Text = _languageManager.GetString("TrustZone") },
                new { Page = "logs", Icon = "📋", Text = _languageManager.GetString("LogCenter") },
                new { Page = "settings", Icon = "⚙️", Text = _languageManager.GetString("Settings") },
                new { Page = "about", Icon = "ℹ️", Text = _languageManager.GetString("About") }
            };

            foreach (var item in navItems)
            {
                try
                {
                    var navBtn = CreateNavButton(item.Page, item.Icon, item.Text);
                    navigationPanel.Controls.Add(navBtn);
                }
                catch (Exception ex)
                {
                    Log($"Error creating navigation button for {item.Page}: {ex.Message}");
                }
            }
            
            // 重新加载当前页面
            if (currentPage != null)
            {
                string currentPageName = GetCurrentPageName();
                if (!string.IsNullOrEmpty(currentPageName))
                {
                    LoadPage(currentPageName);
                }
            }
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            if (themeToggleBtn != null)
            {
                themeToggleBtn.Location = new Point(contentPanel.Width - 60, 10);
            }
        }

        public void ApplyTheme(Theme theme)
        {
            // 更新当前主题
            currentTheme = theme;
            
            // 保存主题设置到配置文件
            SaveThemeToConfig();
            
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            sidebarPanel.BackColor = GetThemeColor(ThemeColor.BgSecondary);
            contentPanel.BackColor = GetThemeColor(ThemeColor.BgPrimary);

            foreach (Control control in sidebarPanel.Controls)
            {
                UpdateControlTheme(control);
            }

            themeToggleBtn.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
            themeToggleBtn.Text = currentTheme == Theme.Dark ? "🌙" : "☀️";
            // 确保主题切换按钮使用微软雅黑字体
            if (themeToggleBtn.Font.Name != "微软雅黑")
            {
                themeToggleBtn.Font = new Font("微软雅黑", themeToggleBtn.Font.Size, themeToggleBtn.Font.Style);
            }

            foreach (var pageRef in pages.Values)
            {
                if (pageRef.TryGetTarget(out UserControl page))
                {
                    if (page is IThemed themedPage)
                    {
                        themedPage.ApplyTheme(theme);
                    }
                }
            }

            // 设置滚动条颜色
            SetScrollBarColor();

            this.Invalidate();
        }

        private void UpdateControlTheme(Control control)
        {
            if (control is Label label)
            {
                label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                // 确保使用微软雅黑字体
                if (label.Font.Name != "微软雅黑")
                {
                    label.Font = new Font("微软雅黑", label.Font.Size, label.Font.Style);
                }
            }
            else if (control is Button button)
            {
                button.BackColor = Color.Transparent;
                button.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
                button.FlatAppearance.MouseOverBackColor = GetThemeColor(ThemeColor.BgHover);
                // 确保使用微软雅黑字体
                if (button.Font.Name != "微软雅黑")
                {
                    button.Font = new Font("微软雅黑", button.Font.Size, button.Font.Style);
                }
            }
            else if (control is TableLayoutPanel tableLayoutPanel)
            {
                foreach (Control childControl in tableLayoutPanel.Controls)
                {
                    UpdateControlTheme(childControl);
                }
            }
            else if (control is FlowLayoutPanel flowLayoutPanel)
            {
                foreach (Control navControl in flowLayoutPanel.Controls)
                {
                    UpdateControlTheme(navControl);
                }
            }
        }

        // 设置滚动条颜色
        private void SetScrollBarColor()
        {
            try
            {
                if (currentTheme == Theme.Dark)
                {
                    // 黑色主题下使用深色滚动条
                    SetDarkScrollBarColor();
                }
                else
                {
                    // 白色主题下使用默认滚动条
                    SetLightScrollBarColor();
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
        }

        // P/Invoke 声明
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern int SetSysColors(int cElements, int[] lpaElements, int[] lpaRgbValues);

        // SCROLLBAR 常量
        private const int COLOR_SCROLLBAR = 0;
        private const int COLOR_WINDOW = 5;
        private const int COLOR_WINDOWTEXT = 8;

        private void SetDarkScrollBarColor()
        {
            try
            {
                // 设置滚动条颜色
                int[] elements = { COLOR_SCROLLBAR };
                // 深色滚动条颜色 (RGB: 50, 50, 50)
                int[] colors = { System.Drawing.Color.FromArgb(50, 50, 50).ToArgb() };
                SetSysColors(1, elements, colors);
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
        }

        private void SetLightScrollBarColor()
        {
            try
            {
                // 设置滚动条颜色
                int[] elements = { COLOR_SCROLLBAR };
                // 默认滚动条颜色 (RGB: 240, 240, 240)
                int[] colors = { System.Drawing.Color.FromArgb(240, 240, 240).ToArgb() };
                SetSysColors(1, elements, colors);
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
        }

        // 缓存主题颜色，避免频繁计算
        private Dictionary<Theme, Dictionary<ThemeColor, Color>> themeColorCache = new Dictionary<Theme, Dictionary<ThemeColor, Color>>();

        private Color GetThemeColor(ThemeColor colorType)
        {
            // 检查缓存是否存在
            if (!themeColorCache.ContainsKey(currentTheme))
            {
                // 初始化缓存
                themeColorCache[currentTheme] = new Dictionary<ThemeColor, Color>();
            }

            // 检查颜色是否已缓存
            if (themeColorCache[currentTheme].TryGetValue(colorType, out Color cachedColor))
            {
                return cachedColor;
            }

            // 计算颜色
            Color color;
            if (currentTheme == Theme.Dark)
            {
                switch (colorType)
                {
                    case ThemeColor.PrimaryColor:
                        color = Color.FromArgb(0, 212, 255);
                        break;
                    case ThemeColor.PrimaryDark:
                        color = Color.FromArgb(0, 163, 204);
                        break;
                    case ThemeColor.PrimaryLight:
                        color = Color.FromArgb(102, 229, 255);
                        break;
                    case ThemeColor.SuccessColor:
                        color = Color.FromArgb(0, 255, 136);
                        break;
                    case ThemeColor.WarningColor:
                        color = Color.FromArgb(255, 193, 7);
                        break;
                    case ThemeColor.ErrorColor:
                        color = Color.FromArgb(255, 72, 72);
                        break;
                    case ThemeColor.InfoColor:
                        color = Color.FromArgb(0, 177, 255);
                        break;
                    case ThemeColor.BgPrimary:
                        color = Color.FromArgb(30, 30, 30);
                        break;
                    case ThemeColor.BgSecondary:
                        color = Color.FromArgb(40, 40, 40);
                        break;
                    case ThemeColor.BgTertiary:
                        color = Color.FromArgb(50, 50, 50);
                        break;
                    case ThemeColor.BgHover:
                        color = Color.FromArgb(60, 60, 60);
                        break;
                    case ThemeColor.TextPrimary:
                        color = Color.White;
                        break;
                    case ThemeColor.TextSecondary:
                        color = Color.Gray;
                        break;
                    case ThemeColor.TextDisabled:
                        color = Color.DarkGray;
                        break;
                    case ThemeColor.BorderColor:
                        color = Color.FromArgb(60, 60, 60);
                        break;
                    case ThemeColor.CardBg:
                        color = Color.FromArgb(45, 45, 45);
                        break;
                    default:
                        color = Color.Black;
                        break;
                }
            }
            else
            {
                switch (colorType)
                {
                    case ThemeColor.PrimaryColor:
                        color = Color.FromArgb(37, 99, 235);
                        break;
                    case ThemeColor.PrimaryDark:
                        color = Color.FromArgb(29, 78, 216);
                        break;
                    case ThemeColor.PrimaryLight:
                        color = Color.FromArgb(96, 165, 250);
                        break;
                    case ThemeColor.SuccessColor:
                        color = Color.FromArgb(16, 185, 129);
                        break;
                    case ThemeColor.WarningColor:
                        color = Color.FromArgb(245, 158, 11);
                        break;
                    case ThemeColor.ErrorColor:
                        color = Color.FromArgb(239, 68, 68);
                        break;
                    case ThemeColor.InfoColor:
                        color = Color.FromArgb(59, 130, 246);
                        break;
                    case ThemeColor.BgPrimary:
                        color = Color.White;
                        break;
                    case ThemeColor.BgSecondary:
                        color = Color.FromArgb(249, 250, 251);
                        break;
                    case ThemeColor.BgTertiary:
                        color = Color.FromArgb(243, 244, 246);
                        break;
                    case ThemeColor.BgHover:
                        color = Color.FromArgb(229, 231, 235);
                        break;
                    case ThemeColor.TextPrimary:
                        color = Color.Black;
                        break;
                    case ThemeColor.TextSecondary:
                        color = Color.Gray;
                        break;
                    case ThemeColor.TextDisabled:
                        color = Color.LightGray;
                        break;
                    case ThemeColor.BorderColor:
                        color = Color.FromArgb(229, 231, 235);
                        break;
                    case ThemeColor.CardBg:
                        color = Color.White;
                        break;
                    default:
                        color = Color.White;
                        break;
                }
            }

            // 缓存颜色
            themeColorCache[currentTheme][colorType] = color;
            return color;
        }

        private System.Drawing.Icon GetAntivirusIcon()
        {
            try
            {
                // 尝试从内嵌资源加载图片
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                // 修正资源路径，使用正确的命名空间
                string resourceName = "FireAntivirus.Host.Resources.cat_icon.png";
                
                using (var stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream != null)
                    {
                        using (var bitmap = new Bitmap(stream))
                        {
                            // 调整图片大小为32x32
                            var resizedBitmap = new Bitmap(bitmap, new Size(32, 32));
                            return Icon.FromHandle(resizedBitmap.GetHicon());
                        }
                    }
                }

                // 尝试其他可能的资源路径
                string[] possibleResourceNames = {
                    "FireAntivirus.Resources.cat_icon.png",
                    "Resources.cat_icon.png",
                    "cat_icon.png"
                };
                
                foreach (var name in possibleResourceNames)
                {
                    using (var stream = assembly.GetManifestResourceStream(name))
                    {
                        if (stream != null)
                        {
                            using (var bitmap = new Bitmap(stream))
                            {
                                var resizedBitmap = new Bitmap(bitmap, new Size(32, 32));
                                return Icon.FromHandle(resizedBitmap.GetHicon());
                            }
                        }
                    }
                }

                // 如果找不到图标文件，创建一个自定义图标
                using (var bitmap = new Bitmap(32, 32))
                using (var graphics = Graphics.FromImage(bitmap))
                {
                    // 绘制一个蓝色背景
                    graphics.Clear(Color.FromArgb(37, 99, 235));
                    // 绘制一个白色的盾牌图标
                    using (var pen = new Pen(Color.White, 2))
                    {
                        // 绘制盾牌轮廓
                        graphics.DrawPolygon(pen, new Point[] {
                            new Point(16, 5),
                            new Point(27, 15),
                            new Point(27, 27),
                            new Point(5, 27),
                            new Point(5, 15)
                        });
                        // 绘制盾牌内部
                        graphics.FillPolygon(new SolidBrush(Color.White), new Point[] {
                            new Point(16, 8),
                            new Point(24, 16),
                            new Point(24, 24),
                            new Point(8, 24),
                            new Point(8, 16)
                        });
                    }
                    return Icon.FromHandle(bitmap.GetHicon());
                }
            }
            catch (Exception ex)
            {
                // 记录错误
                Log($"Error loading antivirus icon: {ex.Message}");
                // 如果获取图标失败，返回系统默认图标
                return SystemIcons.Shield;
            }
        }
        
        #region 服务管理方法
        
        private void CheckAndStartService()
        {
            try
            {
                string serviceName = "FireAntivirusService";
                
                // 检查是否需要提权安装服务
                if (!IsServiceInstalled(serviceName) && !IsRunningAsAdmin())
                {
                    // 需要管理员权限安装服务
                    RequestAdminPrivileges();
                    return;
                }
                
                // 记录开始检查服务
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_check.log"),
                    $"[{DateTime.Now}] 开始检查服务状态\n");
                
                // 检查服务是否存在
                if (!IsServiceInstalled(serviceName))
                {
                    System.IO.File.AppendAllText(
                        System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_check.log"),
                        $"[{DateTime.Now}] 服务不存在，开始安装\n");
                    
                    // 安装服务
                    InstallService(serviceName);
                    
                    // 等待服务安装完成
                    System.Threading.Thread.Sleep(2000);
                }
                else
                {
                    System.IO.File.AppendAllText(
                        System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_check.log"),
                        $"[{DateTime.Now}] 服务已存在\n");
                }
                
                // 检查服务是否正在运行
                if (!IsServiceRunning(serviceName))
                {
                    System.IO.File.AppendAllText(
                        System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_check.log"),
                        $"[{DateTime.Now}] 服务未运行，开始启动\n");
                    
                    // 启动服务
                    StartService(serviceName);
                    
                    // 等待服务启动完成
                    System.Threading.Thread.Sleep(3000);
                }
                else
                {
                    System.IO.File.AppendAllText(
                        System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_check.log"),
                        $"[{DateTime.Now}] 服务已运行\n");
                }
                
                // 更新防护状态显示
                UpdateProtectionStatus();
                
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_check.log"),
                    $"[{DateTime.Now}] 服务检查完成\n");
            }
            catch (Exception ex)
            {
                // 记录错误
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_check_error.log"),
                    $"[{DateTime.Now}] 错误: {ex.ToString()}\n");
            }
        }
        
        public void InstallService(string serviceName)
        {
            try
            {
                // 构建服务程序路径 - 使用当前目录下的服务程序
                string serviceExePath = System.IO.Path.Combine(
                    System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location),
                    "FireAntivirus.Service.exe"
                );
                
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install.log"),
                    $"[{DateTime.Now}] 服务程序路径: {serviceExePath}\n"
                );
                
                // 检查服务程序是否存在
                if (!System.IO.File.Exists(serviceExePath))
                {
                    // 尝试其他可能的路径
                    string alternativePath = System.IO.Path.Combine(
                        System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location),
                        "FireAntivirus.Service.exe"
                    );
                    
                    if (System.IO.File.Exists(alternativePath))
                    {
                        serviceExePath = alternativePath;
                        System.IO.File.AppendAllText(
                            System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install.log"),
                            $"[{DateTime.Now}] 使用替代路径: {serviceExePath}\n"
                        );
                    }
                    else
                    {
                        System.IO.File.AppendAllText(
                            System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install.log"),
                            $"[{DateTime.Now}] 服务程序不存在: {serviceExePath}\n"
                        );
                        return;
                    }
                }
                
                // 停止并删除现有服务
                ExecuteScCommand($"stop {serviceName}");
                ExecuteScCommand($"delete {serviceName}");
                
                // 等待服务删除完成
                System.Threading.Thread.Sleep(2000);
                
                // 安装新服务
                string installCommand = $"create {serviceName} binPath= \"{serviceExePath}\" start= auto displayname= \"耄耋杀毒防护服务\"";
                ExecuteScCommand(installCommand);
                
                // 设置服务描述
                string descriptionCommand = $"description {serviceName} \"耄耋杀毒软件实时防护服务，提供实时病毒防护和安全监控功能\"";
                ExecuteScCommand(descriptionCommand);
                
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install.log"),
                    $"[{DateTime.Now}] 服务安装完成\n"
                );
            }
            catch (Exception ex)
            {
                // 记录错误
                System.IO.File.WriteAllText(
                    System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install_error.log"),
                    $"[{DateTime.Now}] 错误: {ex.ToString()}\n"
                );
            }
        }
        
        private void ExecuteScCommand(string arguments)
        {
            try
            {
                System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
                psi.FileName = "sc";
                psi.Arguments = arguments;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                
                using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    
                    System.IO.File.AppendAllText(
                        System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install.log"),
                        $"[{DateTime.Now}] 执行命令: sc {arguments}\n"
                    );
                    
                    if (!string.IsNullOrEmpty(output))
                    {
                        System.IO.File.AppendAllText(
                            System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install.log"),
                            $"[{DateTime.Now}] 输出: {output}\n"
                        );
                    }
                    
                    if (!string.IsNullOrEmpty(error))
                    {
                        System.IO.File.AppendAllText(
                            System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install.log"),
                            $"[{DateTime.Now}] 错误: {error}\n"
                        );
                    }
                }
            }
            catch (Exception ex)
            {
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install_error.log"),
                    $"[{DateTime.Now}] 执行命令时出错: {ex.ToString()}\n"
                );
            }
        }
        

        
        private void UninstallService(string serviceName)
        {
            try
            {
                // 检查服务是否存在
                if (IsServiceInstalled(serviceName))
                {
                    // 停止服务
                    if (IsServiceRunning(serviceName))
                    {
                        ServiceController service = new ServiceController(serviceName);
                        service.Stop();
                        service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                    }
                    
                    // 使用sc命令卸载服务
                    System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
                    psi.FileName = "sc";
                    psi.Arguments = $"delete \"{serviceName}\"";
                    psi.UseShellExecute = true;
                    psi.Verb = "runas";
                    psi.CreateNoWindow = true;
                    
                    using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(psi))
                    {
                        process.WaitForExit(10000);
                    }
                }
            }
            catch (Exception ex)
            {
                // 静默处理错误，避免干扰用户
            }
        }
        
        public bool IsServiceInstalled(string serviceName)
        {
            ServiceController[] services = ServiceController.GetServices();
            foreach (ServiceController service in services)
            {
                if (service.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }
        
        private bool IsServiceRunning(string serviceName)
        {
            ServiceController[] services = ServiceController.GetServices();
            foreach (ServiceController service in services)
            {
                if (service.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase))
                {
                    return service.Status == ServiceControllerStatus.Running;
                }
            }
            return false;
        }
        
        public void StartService(string serviceName)
        {
            try
            {
                ServiceController service = new ServiceController(serviceName);
                if (service.Status != ServiceControllerStatus.Running)
                {
                    service.Start();
                    // 不再等待服务启动，避免阻塞线程
                }
            }
            catch (Exception ex)
            {
                // 静默处理错误，避免干扰用户
            }
        }
        
        private bool IsRunningAsAdmin()
        {
            try
            {
                System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                System.Security.Principal.WindowsPrincipal principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private void RequestAdminPrivileges()
        {
            try
            {
                // 重新启动程序并请求管理员权限
                System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
                psi.FileName = System.Reflection.Assembly.GetExecutingAssembly().Location;
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.Arguments = "--install-service";
                
                System.Diagnostics.Process.Start(psi);
                
                // 关闭当前实例
                this.BeginInvoke((Action)(() => {
                    this.Close();
                }));
            }
            catch
            {
                // 用户拒绝了管理员权限，静默处理
            }
        }

        private void UpdateProtectionStatus()
        {
            try
            {
                bool isRunning = backgroundProtectionManager.IsProtectionRunning();
                
                this.Invoke((Action)(() => {
                    if (isRunning)
                    {
                        protectionStatusDot.ForeColor = Color.Green;
                        protectionStatusText.Text = "防护已启用";
                    }
                    else
                    {
                        protectionStatusDot.ForeColor = Color.Red;
                        protectionStatusText.Text = "防护未启动";
                    }

                    if (currentPage is HomePage homePage)
                    {
                        try
                        {
                            homePage.UpdateProtectionStatus(isRunning);
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MainForm.cs exception", ex.Message);  }
                    }
                }));
            }
            catch
            {
                this.Invoke((Action)(() => {
                    protectionStatusDot.ForeColor = Color.Yellow;
                    protectionStatusText.Text = "防护状态未知";
                }));
            }
        }
        
        #endregion
    }
}