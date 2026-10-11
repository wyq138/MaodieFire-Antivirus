using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using Timer = System.Threading.Timer;

namespace FireAntivirus.Host
{
    public class BackgroundProtectionManager
    {
        private MainForm mainForm;
        private bool hasShownMissingWarning = false;
        private Timer _statusCheckTimer;
        private bool _isChecking = false;

        public BackgroundProtectionManager(MainForm form)
        {
            mainForm = form;
        }

        public bool IsProtectionRunning()
        {
            try
            {
                Process[] processes = Process.GetProcessesByName("FireAntivirus.Service");
                if (processes.Length > 0)
                {
                    foreach (var p in processes) p.Dispose();
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public void StartStatusMonitoring()
        {
            try
            {
                _statusCheckTimer = new Timer(StatusCheckCallback, null, 5000, 10000);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackgroundProtectionManager.cs 捕获异常", ex.Message); }
        }

        public void StopStatusMonitoring()
        {
            try
            {
                _statusCheckTimer?.Dispose();
                _statusCheckTimer = null;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackgroundProtectionManager.cs 捕获异常", ex.Message); }
        }

        private void StatusCheckCallback(object state)
        {
            if (_isChecking) return;
            _isChecking = true;
            try
            {
                bool isRunning = IsProtectionRunning();
                var status = new System.Collections.Generic.Dictionary<string, bool>();
                status["Service"] = isRunning;

                if (isRunning)
                {
                    status["FileProtection"] = true;
                    status["ProcessProtection"] = true;
                    status["USBProtection"] = true;
                    status["RegistryProtection"] = true;
                    status["BrowserProtection"] = true;
                    status["ScriptProtection"] = true;
                    status["BehaviorProtection"] = true;
                    status["PartitionTableProtection"] = true;
                    status["UEFIProtection"] = true;
                    status["KernelProtection"] = true;
                    status["DocumentProtection"] = true;
                }

                mainForm.BeginInvoke((Action)(() => {
                    try
                    {
                        mainForm.UpdateProtectionStatus(status);
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackgroundProtectionManager.cs 捕获异常", ex.Message); }
                }));
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "BackgroundProtectionManager.cs 捕获异常", ex.Message); }
            finally
            {
                _isChecking = false;
            }
        }

        public bool StartBackgroundProtection()
        {
            try
            {
                // 构建防护程序路径
                string baseDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                string protectionExePath = Path.Combine(baseDir, "FireAntivirus.Service.exe");

                // 转换为绝对路径
                protectionExePath = Path.GetFullPath(protectionExePath);

                File.AppendAllText(
                    Path.Combine(baseDir, "protection_start.log"),
                    $"[{DateTime.Now}] 防护程序路径: {protectionExePath}\n"
                );

                // 检查防护程序是否存在
                if (!File.Exists(protectionExePath))
                {
                    // 尝试查找构建输出目录
                    string[] possiblePaths = new string[]
                    {
                        Path.Combine(baseDir, "FireAntivirus.Service.exe"),
                        Path.Combine(baseDir, "..", "x64", "Debug", "FireAntivirus.Service.exe"),
                        Path.Combine(baseDir, "..", "x64", "Release", "FireAntivirus.Service.exe"),
                        Path.Combine(baseDir, "..", "FireAntivirus.Service", "x64", "Debug", "FireAntivirus.Service.exe"),
                        Path.Combine(baseDir, "..", "FireAntivirus.Service", "x64", "Release", "FireAntivirus.Service.exe"),
                    };

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
                }

                // 再次检查文件是否存在
                if (!File.Exists(protectionExePath))
                {
                    File.AppendAllText(
                        Path.Combine(baseDir, "protection_start.log"),
                        $"[{DateTime.Now}] 防护程序不存在: {protectionExePath}\n"
                    );

                    // 显示用户友好的提示（只显示一次）
                    if (!hasShownMissingWarning)
                    {
                        hasShownMissingWarning = true;
                        mainForm.BeginInvoke((Action)(() => {
                            MessageBox.Show(
                                "后台防护程序未找到。\n\n" +
                                "可能的原因：\n" +
                                "1. FireAntivirus.Service.exe 未编译\n" +
                                "2. 请使用 Visual Studio 编译整个解决方案\n" +
                                "3. 确保选择 x64 平台编译 C++ 项目\n\n" +
                                "当前防护功能将在界面层运行，但部分高级功能不可用。",
                                "防护程序缺失",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Warning
                            );
                        }));
                    }
                    return false;
                }

                // 启动防护程序
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = protectionExePath;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true; // 隐藏控制台窗口
                psi.WorkingDirectory = Path.GetDirectoryName(protectionExePath);

                // 使用 -run 参数以控制台模式运行（不需要安装服务）
                psi.Arguments = "-run";

                using (Process process = Process.Start(psi))
                {
                    File.AppendAllText(
                        Path.Combine(baseDir, "protection_start.log"),
                        $"[{DateTime.Now}] 防护程序已启动，进程ID: {process.Id}\n"
                    );
                }
                return true;
            }
            catch (Exception ex)
            {
                // 记录错误
                string baseDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                File.AppendAllText(
                    Path.Combine(baseDir, "protection_start_error.log"),
                    $"[{DateTime.Now}] 错误: {ex.ToString()}\n"
                );

                mainForm.BeginInvoke((Action)(() => {
                    MessageBox.Show(
                        $"启动后台防护程序失败：\n{ex.Message}\n\n防护功能将在界面层运行。",
                        "启动错误",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                }));
                return false;
            }
        }

        public void CheckAndStartBackgroundProtection()
        {
            try
            {
                string baseDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                
                // 记录开始检查防护程序
                File.AppendAllText(
                    Path.Combine(baseDir, "protection_check.log"),
                    $"[{DateTime.Now}] 开始检查防护程序状态\n"
                );

                // 检查防护程序是否正在运行
                if (!IsProtectionRunning())
                {
                    File.AppendAllText(
                        Path.Combine(baseDir, "protection_check.log"),
                        $"[{DateTime.Now}] 防护程序未运行，开始启动\n"
                    );

                    // 启动防护程序
                    bool started = StartBackgroundProtection();

                    if (started)
                    {
                        // 等待防护程序启动完成
                        System.Threading.Thread.Sleep(3000);
                    }
                }
                else
                {
                    File.AppendAllText(
                        Path.Combine(baseDir, "protection_check.log"),
                        $"[{DateTime.Now}] 防护程序已运行\n"
                    );
                }

                // 更新防护状态显示（在UI线程中执行）
                mainForm.BeginInvoke((Action)(() => {
                    var status = new System.Collections.Generic.Dictionary<string, bool>();
                    bool isRunning = IsProtectionRunning();
                    status["Service"] = isRunning;
                    
                    // 如果服务正在运行，设置所有防护功能为启用状态
                    if (isRunning)
                    {
                        status["FileProtection"] = true;
                        status["ProcessProtection"] = true;
                        status["USBProtection"] = true;
                        status["RegistryProtection"] = true;
                        status["BrowserProtection"] = true;
                        status["ScriptProtection"] = true;
                        status["BehaviorProtection"] = true;
                        status["PartitionTableProtection"] = true;
                        status["UEFIProtection"] = true;
                        status["KernelProtection"] = true;
                        status["DocumentProtection"] = true;
                    }
                    
                    mainForm.UpdateProtectionStatus(status);
                }));

                File.AppendAllText(
                    Path.Combine(baseDir, "protection_check.log"),
                    $"[{DateTime.Now}] 防护程序检查完成\n"
                );
            }
            catch (Exception ex)
            {
                // 记录错误
                string baseDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                File.AppendAllText(
                    Path.Combine(baseDir, "protection_check_error.log"),
                    $"[{DateTime.Now}] 错误: {ex.ToString()}\n"
                );
            }
        }

        public static void StopBackgroundProtection()
        {
            try
            {
                // 查找并停止所有防护程序进程（自家服务，走守护的安全终止入口）
                FireAntivirus.Common.TrustedProcessGuard.SafeTerminateByName("FireAntivirus.Service");
            }
            catch
            {
            }
        }
    }
}