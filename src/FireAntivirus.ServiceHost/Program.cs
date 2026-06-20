using System;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using FireAntivirus.Services;

namespace FireAntivirus.ServiceHost
{
    public class FireAntivirusService : ServiceBase
    {
        private ProtectionService _protectionService;
        private Thread _notificationThread;
        private string _logPath;

        public FireAntivirusService()
        {
            ServiceName = "FireAntivirusService";
            CanStop = true;
            CanPauseAndContinue = false;
            CanShutdown = true;
            AutoLog = true;
            
            _logPath = Path.Combine(
                Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? ".",
                "service.log");
        }

        private void Log(string message)
        {
            try
            {
                File.AppendAllText(_logPath, $"[{DateTime.Now}] {message}\n");
            }
            catch { }
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                Log("服务正在启动...");
                
                // 启动保护服务
                _protectionService = new ProtectionService();
                _protectionService.Start();
                Log("保护服务已启动");

                // 启动通知服务线程
                _notificationThread = new Thread(RunNotificationService);
                _notificationThread.IsBackground = true;
                _notificationThread.Start();
                Log("通知服务线程已启动");

                EventLog.WriteEntry("FireAntivirusService", "服务已启动", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                Log($"启动失败: {ex.Message}\n{ex.StackTrace}");
                EventLog.WriteEntry("FireAntivirusService", $"启动失败: {ex.Message}", EventLogEntryType.Error);
            }
        }

        protected override void OnStop()
        {
            try
            {
                Log("服务正在停止...");
                
                // 停止保护服务
                if (_protectionService != null)
                {
                    _protectionService.Stop();
                }

                // 停止通知服务线程
                if (_notificationThread != null && _notificationThread.IsAlive)
                {
                    _notificationThread.Join(2000);
                }

                EventLog.WriteEntry("FireAntivirusService", "服务已停止", EventLogEntryType.Information);
                Log("服务已停止");
            }
            catch (Exception ex)
            {
                Log($"停止失败: {ex.Message}");
                EventLog.WriteEntry("FireAntivirusService", $"停止失败: {ex.Message}", EventLogEntryType.Error);
            }
        }

        protected override void OnShutdown()
        {
            OnStop();
        }

        private void RunNotificationService()
        {
            try
            {
                // 启动通知服务
                NotificationService.Instance.Start();
                Log("通知服务已启动");

                // 保持线程运行
                while (true)
                {
                    Thread.Sleep(1000);
                }
            }
            catch (Exception ex)
            {
                Log($"通知服务错误: {ex.Message}");
                EventLog.WriteEntry("FireAntivirusService", $"通知服务错误: {ex.Message}", EventLogEntryType.Error);
            }
        }
    }

    internal static class Program
    {
        private static string _mainProcessPath;
        private static bool _isRunning = true;
        
        public static void Main(string[] args)
        {
            string baseDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? ".";
            _mainProcessPath = Path.Combine(baseDir, "FireAntivirus.exe");
            
            string logPath = Path.Combine(baseDir, "service.log");
            
            void Log(string message)
            {
                try { File.AppendAllText(logPath, $"[{DateTime.Now}] {message}\n"); } catch { }
            }

            // 检查是否以控制台模式运行
            if (args.Length > 0 && args[0] == "-console")
            {
                RunAsConsole(Log);
            }
            else if (args.Length > 0 && args[0] == "-run")
            {
                // 独立运行模式（无窗口）
                RunStandalone(Log);
            }
            else
            {
                // 作为Windows服务运行
                Log("作为Windows服务启动");
                ServiceBase.Run(new FireAntivirusService());
            }
        }
        
        private static void RunStandalone(Action<string> log)
        {
            log("=== 独立运行模式启动 ===");
            
            ProtectionService protectionService = null;
            NamedPipeServer pipeServer = null;
            
            try
            {
                // 创建保护服务实例
                protectionService = new ProtectionService();
                protectionService.Start();
                log("保护服务已启动");

                // 启动命名管道服务用于通信
                pipeServer = new NamedPipeServer("FireAntivirus_Watchdog");
                pipeServer.Start();
                log("命名管道服务已启动");

                // 启动进程守护
                Task.Run(() => MonitorMainProcess(log));
                log("进程守护已启动");

                // 保持运行
                while (_isRunning)
                {
                    Thread.Sleep(5000);
                    log("服务运行中 - 心跳");
                }
            }
            catch (Exception ex)
            {
                log($"运行出错: {ex.Message}");
            }
            finally
            {
                protectionService?.Stop();
                pipeServer?.Stop();
            }
        }
        
        private static async Task MonitorMainProcess(Action<string> log)
        {
            while (_isRunning)
            {
                try
                {
                    await Task.Delay(5000);  // 每5秒检查一次
                    
                    // 检查退出标志
                    string exitFlagFile = Path.Combine(
                        Path.GetDirectoryName(_mainProcessPath) ?? ".",
                        "exit_flag.dat");
                    
                    if (File.Exists(exitFlagFile))
                    {
                        log("检测到退出标志，停止进程守护");
                        _isRunning = false;
                        break;
                    }
                    
                    var processes = Process.GetProcessesByName("FireAntivirus");
                    if (processes.Length == 0 && File.Exists(_mainProcessPath))
                    {
                        log("主进程不存在，尝试启动...");
                        
                        try
                        {
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = _mainProcessPath,
                                UseShellExecute = true,
                                WindowStyle = ProcessWindowStyle.Normal
                            });
                            log("主进程已启动");
                        }
                        catch (Exception ex)
                        {
                            log($"启动主进程失败: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    log($"进程守护错误: {ex.Message}");
                }
            }
        }

        private static void RunAsConsole(Action<string> log)
        {
            log("=== 控制台模式启动 ===");
            Console.WriteLine("=== FireAntivirus 防护服务 (控制台模式) ===");
            Console.WriteLine("服务已启动，退出主程序后依然保持防护...");
            Console.WriteLine("按 Ctrl+C 手动停止防护服务...");
            Console.WriteLine();

            ProtectionService protectionService = null;
            
            try
            {
                log("正在初始化保护服务...");
                
                // 创建保护服务实例
                protectionService = new ProtectionService();
                log("保护服务实例创建成功");
                
                // 启动保护服务
                protectionService.Start();
                log("保护服务已启动");
                Console.WriteLine("[OK] 保护服务已启动");

                // 启动命名管道服务用于通信
                try
                {
                    var pipeServer = new NamedPipeServer("FireAntivirus_Watchdog");
                    pipeServer.Start();
                    log("命名管道服务已启动 (FireAntivirus_Watchdog)");
                    Console.WriteLine("[OK] 通信服务已启动");
                }
                catch (Exception ex)
                {
                    log($"命名管道服务启动失败: {ex.Message}");
                    Console.WriteLine($"[WARN] 通信服务启动失败: {ex.Message}");
                }

                // 启动进程守护
                Task.Run(() => MonitorMainProcess(log));
                log("进程守护已启动");
                Console.WriteLine("[OK] 进程守护已启动");

                Console.WriteLine();
                Console.WriteLine("防护服务正在运行中...");
                Console.WriteLine();

                // 等待退出信号
                var exitEvent = new ManualResetEvent(false);
                Console.CancelKeyPress += (sender, e) =>
                {
                    e.Cancel = true;
                    exitEvent.Set();
                    Console.WriteLine("\n收到退出信号...");
                };

                // 保持运行，定期输出状态
                int counter = 0;
                while (!exitEvent.WaitOne(1000))
                {
                    counter++;
                    if (counter % 60 == 0) // 每分钟输出一次状态
                    {
                        log("服务运行中 - 心跳");
                    }
                }

                Console.WriteLine();
                Console.WriteLine("正在停止防护服务...");
                log("正在停止防护服务...");
                
                protectionService.Stop();
                log("防护服务已停止");
                Console.WriteLine("防护服务已停止。");
            }
            catch (Exception ex)
            {
                log($"防护服务运行出错: {ex.Message}\n{ex.StackTrace}");
                Console.WriteLine($"[ERROR] 防护服务运行出错: {ex.Message}");
                Console.WriteLine($"堆栈跟踪: {ex.StackTrace}");
                Console.WriteLine("按任意键退出...");
                Console.ReadKey(true);
            }
            finally
            {
                // 确保服务停止
                protectionService?.Stop();
            }
        }
    }
}
