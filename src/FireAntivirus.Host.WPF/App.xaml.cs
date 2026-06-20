using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows;
using FireAntivirus.Host.Services;
using FireAntivirus.Host.WPF;
using FireAntivirus.Common;

namespace FireAntivirus.Host
{
    public partial class App : Application
    {
        private ServiceAutoInstaller? _serviceInstaller;
        public static WatchdogClient? WatchdogClient { get; private set; }
        
        // 单实例互斥体
        private static Mutex? _singleInstanceMutex;
        private const string MutexName = "FireAntivirus_SingleInstance_Mutex";
        
        protected override void OnStartup(StartupEventArgs e)
        {
            // 单实例检查
            bool createdNew;
            _singleInstanceMutex = new Mutex(true, MutexName, out createdNew);
            
            if (!createdNew)
            {
                // 已经有实例在运行，直接退出
                MessageBox.Show("耄耋安全软件已经在运行中！", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown();
                return;
            }
            
            base.OnStartup(e);
            
            // 记录启动信息
            LogHelper.Info("应用程序启动", $"版本: {Assembly.GetExecutingAssembly().GetName().Version}");
            
            // 预加载libs目录下的DLL
            PreloadLibsDlls();
            
            // 注册DLL解析事件
            AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;
            
            LogHelper.Info("OnStartup完成", "DLL解析器已注册");
            
            // 处理命令行参数
            if (e.Args.Length > 0)
            {
                LogHelper.Info("命令行参数", string.Join(", ", e.Args));
                HandleCommandLineArgs(e.Args);
                return;
            }
            
            // 初始化服务并显示主窗口
            LogHelper.Info("开始初始化服务", "");
            InitializeServices();
        }
        
        /// <summary>
        /// DLL解析器 - 从libs目录加载DLL
        /// </summary>
        private Assembly? OnAssemblyResolve(object? sender, ResolveEventArgs args)
        {
            try
            {
                var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                var assemblyName = new AssemblyName(args.Name).Name + ".dll";
                
                // 优先从libs目录加载
                var libsPath = Path.Combine(baseDir, "libs", assemblyName);
                if (File.Exists(libsPath))
                {
                    LogHelper.Debug("DLL解析", $"从libs加载: {assemblyName}");
                    return Assembly.LoadFrom(libsPath);
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("DLL解析错误", ex.Message);
            }
            
            return null;
        }
        
        /// <summary>
        /// 预加载libs目录下的DLL
        /// </summary>
        private void PreloadLibsDlls()
        {
            try
            {
                var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                var libsDir = Path.Combine(baseDir ?? ".", "libs");
                
                if (!Directory.Exists(libsDir))
                {
                    LogHelper.Warning("预加载DLL", "libs目录不存在");
                    return;
                }
                
                var dlls = Directory.GetFiles(libsDir, "*.dll");
                LogHelper.Info("预加载DLL", $"找到 {dlls.Length} 个DLL");
                
                int loadedCount = 0;
                foreach (var dll in dlls)
                {
                    try
                    {
                        Assembly.LoadFrom(dll);
                        loadedCount++;
                    }
                    catch (Exception ex)
                    {
                        LogHelper.Debug("加载DLL", $"失败: {Path.GetFileName(dll)} - {ex.Message}");
                    }
                }
                
                LogHelper.Info("预加载DLL", $"成功加载 {loadedCount}/{dlls.Length} 个DLL");
            }
            catch (Exception ex)
            {
                LogHelper.Error("预加载DLL异常", ex.Message);
            }
        }
        
        /// <summary>
        /// 处理命令行参数
        /// </summary>
        private void HandleCommandLineArgs(string[] args)
        {
            string arg = args[0].ToLower();
            LogHelper.Info("处理命令行", arg);
            
            switch (arg)
            {
                case "-install-service":
                    InstallServiceAndExit();
                    break;
                    
                case "-uninstall-service":
                    UninstallServiceAndExit();
                    break;
                    
                case "-watchdog":
                    RunAsWatchdog();
                    break;
                    
                default:
                    InitializeServices();
                    break;
            }
        }
        
        /// <summary>
        /// 初始化服务
        /// </summary>
        private void InitializeServices()
        {
            LogHelper.Info("InitializeServices", "开始初始化服务");
            
            try
            {
                // 创建看门狗客户端
                WatchdogClient = new WatchdogClient();
                LogHelper.Debug("InitializeServices", "WatchdogClient已创建");
                
                // 初始化服务安装器
                _serviceInstaller = new ServiceAutoInstaller();
                _serviceInstaller.StatusChanged += OnServiceStatusChanged;
                LogHelper.Debug("InitializeServices", "ServiceAutoInstaller已创建");
                
                // 创建并显示主窗口
                LogHelper.Info("InitializeServices", "创建主窗口");
                var mainWindow = new MainWindow();
                mainWindow.Show();
                LogHelper.Info("InitializeServices", "主窗口已显示");
            }
            catch (Exception ex)
            {
                LogHelper.Error("InitializeServices错误", ex.Message);
                MessageBox.Show($"初始化服务错误: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        /// <summary>
        /// 服务状态变化事件处理
        /// </summary>
        private void OnServiceStatusChanged(object? sender, string status)
        {
            LogHelper.Info("服务状态变化", status);
        }
        
        /// <summary>
        /// 安装服务并退出
        /// </summary>
        private void InstallServiceAndExit()
        {
            LogHelper.Info("InstallServiceAndExit", "开始安装服务");
            
            try
            {
                var installer = new ServiceAutoInstaller();
                installer.StatusChanged += (s, msg) => LogHelper.Debug("安装服务", msg);
                
                if (installer.InstallService())
                {
                    installer.StartService();
                    LogHelper.Info("安装服务", "成功");
                    MessageBox.Show("服务安装成功！", "耄耋安全软件", 
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    LogHelper.Warning("安装服务", "失败");
                    MessageBox.Show("服务安装失败，请以管理员权限运行。", "耄耋安全软件", 
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("安装服务异常", ex.Message);
                MessageBox.Show($"安装服务异常: {ex.Message}", "耄耋安全软件", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            
            Shutdown();
        }
        
        /// <summary>
        /// 卸载服务并退出
        /// </summary>
        private void UninstallServiceAndExit()
        {
            LogHelper.Info("UninstallServiceAndExit", "开始卸载服务");
            
            try
            {
                var installer = new ServiceAutoInstaller();
                installer.StatusChanged += (s, msg) => LogHelper.Debug("卸载服务", msg);
                
                if (installer.UninstallService())
                {
                    LogHelper.Info("卸载服务", "成功");
                    MessageBox.Show("服务已卸载。", "耄耋安全软件", 
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    LogHelper.Warning("卸载服务", "失败");
                    MessageBox.Show("服务卸载失败。", "耄耋安全软件", 
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                LogHelper.Error("卸载服务异常", ex.Message);
                MessageBox.Show($"卸载服务异常: {ex.Message}", "耄耋安全软件", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            
            Shutdown();
        }
        
        /// <summary>
        /// 以看门狗模式运行
        /// </summary>
        private void RunAsWatchdog()
        {
            LogHelper.Info("RunAsWatchdog", "以看门狗模式运行");
            Debug.WriteLine("Watchdog mode should be handled by background service");
            Shutdown();
        }
        
        protected override void OnExit(ExitEventArgs e)
        {
            LogHelper.Info("应用程序退出", $"ExitCode: {e.ApplicationExitCode}");
            
            // 释放看门狗客户端
            WatchdogClient?.Dispose();
            
            // 释放单实例互斥体
            _singleInstanceMutex?.ReleaseMutex();
            _singleInstanceMutex?.Dispose();
            
            base.OnExit(e);
        }
    }
}