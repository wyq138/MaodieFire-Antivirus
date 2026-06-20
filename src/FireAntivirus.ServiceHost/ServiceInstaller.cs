using System.ServiceProcess;

namespace FireAntivirus.ServiceHost
{
    public class ServiceInstaller
    {
        public static void InstallService(string serviceName, string displayName, string description, string executablePath)
        {
            using (ServiceController sc = new ServiceController())
            {
                sc.ServiceName = serviceName;
                try
                {
                    var status = sc.Status;
                }
                catch
                {
                    // 服务不存在，创建服务
                    System.Diagnostics.Process process = new System.Diagnostics.Process();
                    process.StartInfo.FileName = "sc.exe";
                    process.StartInfo.Arguments = $"create {serviceName} binPath= \"{executablePath}\" displayname= \"{displayName}\" start= auto";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.Start();
                    process.WaitForExit();
                }
            }
        }

        public static void UninstallService(string serviceName)
        {
            using (ServiceController sc = new ServiceController())
            {
                sc.ServiceName = serviceName;
                try
                {
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped);
                    }
                    System.Diagnostics.Process process = new System.Diagnostics.Process();
                    process.StartInfo.FileName = "sc.exe";
                    process.StartInfo.Arguments = $"delete {serviceName}";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.Start();
                    process.WaitForExit();
                }
                catch
                {
                    // 服务不存在，忽略
                }
            }
        }
    }
}