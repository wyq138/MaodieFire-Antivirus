using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host
{
    public class BackgroundProtectionManager
    {
        private MainWindow mainForm;
        private bool hasShownMissingWarning = false;

        public BackgroundProtectionManager(MainWindow form)
        {
            mainForm = form;
        }

        public bool IsProtectionRunning()
        {
            Process[] processes = Process.GetProcessesByName("FireAntivirus.Service");
            bool isRunning = processes.Length > 0;
            foreach (var p in processes) p.Dispose();
            return isRunning;
        }

        public bool StartBackgroundProtection()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (string.IsNullOrEmpty(baseDir))
                {
                    baseDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                }
                
                string[] possiblePaths = new string[]
                {
                    Path.Combine(baseDir, "libs", "FireAntivirus.Service.exe"),
                    Path.Combine(baseDir, "FireAntivirus.Service.exe"),
                    Path.Combine(baseDir, "..", "FireAntivirus.Service.exe"),
                    Path.Combine(baseDir, "..", "libs", "FireAntivirus.Service.exe"),
                    Path.Combine(baseDir, "x64", "Debug", "FireAntivirus.Service.exe"),
                    Path.Combine(baseDir, "x64", "Release", "FireAntivirus.Service.exe"),
                };

                string protectionExePath = null;
                foreach (var path in possiblePaths)
                {
                    string fullPath = Path.GetFullPath(path);
                    if (File.Exists(fullPath))
                    {
                        protectionExePath = fullPath;
                        File.AppendAllText(
                            Path.Combine(baseDir, "protection_start.log"),
                            $"[{DateTime.Now}] 找到防护程序: {protectionExePath}\n"
                        );
                        break;
                    }
                }

                if (protectionExePath == null)
                {
                    File.AppendAllText(
                        Path.Combine(baseDir, "protection_start.log"),
                        $"[{DateTime.Now}] 防护程序不存在\n"
                    );

                    hasShownMissingWarning = true;
                    return false;
                }

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = protectionExePath;
                psi.UseShellExecute = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.WorkingDirectory = Path.GetDirectoryName(protectionExePath);
                psi.Arguments = "-console";

                Process.Start(psi);
                
                File.AppendAllText(
                    Path.Combine(baseDir, "protection_start.log"),
                    $"[{DateTime.Now}] 防护程序已启动（独立进程模式）\n"
                );
                return true;
            }
            catch (Exception ex)
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                File.AppendAllText(
                    Path.Combine(baseDir, "protection_start_error.log"),
                    $"[{DateTime.Now}] 错误: {ex.ToString()}\n"
                );
                return false;
            }
        }

        public async Task CheckAndStartBackgroundProtectionAsync()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                
                File.AppendAllText(
                    Path.Combine(baseDir, "protection_check.log"),
                    $"[{DateTime.Now}] 开始检查防护程序状态\n"
                );

                if (!IsProtectionRunning())
                {
                    File.AppendAllText(
                        Path.Combine(baseDir, "protection_check.log"),
                        $"[{DateTime.Now}] 防护程序未运行，开始启动\n"
                    );

                    bool started = StartBackgroundProtection();

                    if (started)
                    {
                        await Task.Delay(3000);
                    }
                }
                else
                {
                    File.AppendAllText(
                        Path.Combine(baseDir, "protection_check.log"),
                        $"[{DateTime.Now}] 防护程序已运行\n"
                    );
                }

                mainForm.Dispatcher.BeginInvoke(new Action(() => {
                    mainForm.CheckProtectionStatus();
                }));

                File.AppendAllText(
                    Path.Combine(baseDir, "protection_check.log"),
                    $"[{DateTime.Now}] 防护程序检查完成\n"
                );
            }
            catch (Exception ex)
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                File.AppendAllText(
                    Path.Combine(baseDir, "protection_check_error.log"),
                    $"[{DateTime.Now}] 错误: {ex.ToString()}\n"
                );
            }
        }

        // 同步版本，供外部调用
        public void CheckAndStartBackgroundProtection()
        {
            _ = CheckAndStartBackgroundProtectionAsync();
        }

        public static void StopBackgroundProtection()
        {
            try
            {
                // 自家服务，走守护的安全终止入口
                FireAntivirus.Common.TrustedProcessGuard.SafeTerminateByName("FireAntivirus.Service");
            }
            catch
            {
            }
        }
    }
}
