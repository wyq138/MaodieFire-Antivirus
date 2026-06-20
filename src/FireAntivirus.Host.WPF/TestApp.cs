using System;
using System.IO;
using System.Reflection;
using System.Windows;

namespace FireAntivirus.Host
{
    public class TestApp : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            
            string logPath = Path.Combine(
                Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".",
                "test.log");
            
            try
            {
                File.AppendAllText(logPath, "[1] TestApp.OnStartup started\r\n");
                
                // 注册DLL解析器
                AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;
                File.AppendAllText(logPath, "[2] AssemblyResolve registered\r\n");
                
                var w = new Window();
                w.Title = "Test Window";
                w.Width = 400;
                w.Height = 300;
                w.Show();
                
                File.AppendAllText(logPath, "[3] Window shown\r\n");
            }
            catch (Exception ex)
            {
                File.AppendAllText(logPath, "[ERROR] " + ex.Message + "\r\n" + ex.StackTrace + "\r\n");
                MessageBox.Show(ex.Message, "Test Error");
            }
        }
        
        private Assembly OnAssemblyResolve(object sender, ResolveEventArgs args)
        {
            try
            {
                var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                var assemblyName = new AssemblyName(args.Name).Name + ".dll";
                
                string[] paths = {
                    Path.Combine(baseDir, "libs", assemblyName),
                    Path.Combine(baseDir, assemblyName)
                };
                
                foreach (var path in paths)
                {
                    if (File.Exists(path))
                    {
                        File.AppendAllText("d:\\desktop\\所有文件\\项目文件\\激活工具\\develop\\fireantivirus\\src\\fireantivirus.host.wpf\\bin\\final\\test.log", 
                            "[AssemblyResolve] Loading: " + path + "\r\n");
                        return Assembly.LoadFrom(path);
                    }
                }
            }
            catch (Exception ex)
            {
                File.AppendAllText("d:\\desktop\\所有文件\\项目文件\\激活工具\\develop\\fireantivirus\\src\\fireantivirus.host.wpf\\bin\\final\\test.log", 
                    "[AssemblyResolve ERROR] " + ex.Message + "\r\n");
            }
            return null;
        }
    }
}
