// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Windows.Forms;

namespace FireAntivirus.Host
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                // 输出启动信息到控制台
                Console.WriteLine("Starting FireAntivirus...");
                
                // 检查命令行参数
                if (args.Length > 0 && args[0] == "--install-service")
                {
                    // 以管理员权限启动，直接安装服务
                    Console.WriteLine("Installing service...");
                    InstallServiceAsAdmin();
                    return;
                }

                Console.WriteLine("Creating MainForm...");
                var mainForm = new MainForm();
                Console.WriteLine("Running application...");
                Application.Run(mainForm);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting application: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                MessageBox.Show($"启动程序失败: {ex.Message}\n\n详细信息: {ex.StackTrace}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void InstallServiceAsAdmin()
        {
            try
            {
                // 创建MainForm实例以使用其服务管理方法
                var mainForm = new MainForm();
                
                // 直接安装服务
                mainForm.InstallService("FireAntivirusService");
                
                // 等待服务安装完成
                System.Threading.Thread.Sleep(3000);
                
                // 启动服务
                if (mainForm.IsServiceInstalled("FireAntivirusService"))
                {
                    mainForm.StartService("FireAntivirusService");
                }
            }
            catch (Exception ex)
            {
                // 记录错误但不显示UI
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "service_install_error.log"),
                    $"[{DateTime.Now}] 安装服务时出错: {ex.ToString()}\n"
                );
            }
        }
    }
}