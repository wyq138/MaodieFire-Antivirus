using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace FireAntivirus.Launcher
{
    class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);

        static int Main(string[] args)
        {
            try
            {
                var exeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                var libsDir = Path.Combine(exeDir ?? ".", "libs");

                // 设置DLL搜索路径 - 这个是关键！
                SetDllDirectory(libsDir);

                // 获取主程序路径
                var mainExe = Path.Combine(libsDir, "FireAntivirus.Host.exe");
                if (!File.Exists(mainExe))
                {
                    mainExe = Path.Combine(exeDir ?? ".", "FireAntivirus.Host.exe");
                }

                Console.WriteLine($"Launcher: Starting {mainExe}");
                Console.WriteLine($"Launcher: DLL path set to {libsDir}");

                // 使用Process.Start启动主程序
                var startInfo = new ProcessStartInfo
                {
                    FileName = mainExe,
                    UseShellExecute = true,
                    Arguments = string.Join(" ", args)
                };

                Process.Start(startInfo);

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Launcher error: {ex}");
                return 1;
            }
        }
    }
}
