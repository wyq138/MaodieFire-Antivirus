// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.SystemMonitor
{
    public class SystemMonitorManager
    {
        private bool _isMonitoring;
        private CancellationTokenSource _cancellationTokenSource;
        private List<Process> _processes;
        private List<ConnectionInfo> _connections;
        private List<FileOperationInfo> _fileOperations;
        
        public event EventHandler<ProcessCreatedEventArgs> ProcessCreated;
        public event EventHandler<ConnectionEstablishedEventArgs> ConnectionEstablished;
        public event EventHandler<FileOperationEventArgs> FileOperation;

        public SystemMonitorManager()
        {
            _isMonitoring = false;
            _processes = new List<Process>();
            _connections = new List<ConnectionInfo>();
            _fileOperations = new List<FileOperationInfo>();
        }

        /// <summary>
        /// 开始监控
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring)
                return;

            _isMonitoring = true;
            _cancellationTokenSource = new CancellationTokenSource();
            
            // 初始化当前进程列表
            _processes = Process.GetProcesses().ToList();
            
            // 初始化当前网络连接
            _connections = GetCurrentConnections();
            
            // 启动监控任务
            Task.Run(() => MonitorProcesses(), _cancellationTokenSource.Token);
            Task.Run(() => MonitorNetwork(), _cancellationTokenSource.Token);
            Task.Run(() => MonitorFileOperations(), _cancellationTokenSource.Token);
        }

        /// <summary>
        /// 停止监控
        /// </summary>
        public void StopMonitoring()
        {
            if (!_isMonitoring)
                return;

            _cancellationTokenSource.Cancel();
            _isMonitoring = false;
        }

        /// <summary>
        /// 监控进程创建
        /// </summary>
        private async Task MonitorProcesses()
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    var currentProcesses = Process.GetProcesses().ToList();
                    
                    // 检测新进程
                    var newProcesses = currentProcesses.Where(p => !_processes.Any(op => op.Id == p.Id)).ToList();
                    
                    foreach (var process in newProcesses)
                    {
                        try
                        {
                            var processInfo = new ProcessInfo
                            {
                                Id = process.Id,
                                Name = process.ProcessName,
                                Path = GetProcessPath(process),
                                CommandLine = GetProcessCommandLine(process),
                                StartTime = process.StartTime
                            };
                            
                            // 触发进程创建事件
                            OnProcessCreated(new ProcessCreatedEventArgs { Process = processInfo });
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"获取进程信息失败: {ex.Message}");
                        }
                    }
                    
                    // 更新进程列表
                    _processes = currentProcesses;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"监控进程失败: {ex.Message}");
                }
                
                await Task.Delay(1000, _cancellationTokenSource.Token);
            }
        }

        /// <summary>
        /// 监控网络连接
        /// </summary>
        private async Task MonitorNetwork()
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    var currentConnections = GetCurrentConnections();
                    
                    // 检测新连接
                    var newConnections = currentConnections.Where(c => !_connections.Any(oc => 
                        oc.LocalAddress == c.LocalAddress && 
                        oc.LocalPort == c.LocalPort && 
                        oc.RemoteAddress == c.RemoteAddress && 
                        oc.RemotePort == c.RemotePort)).ToList();
                    
                    foreach (var connection in newConnections)
                    {
                        // 触发连接建立事件
                        OnConnectionEstablished(new ConnectionEstablishedEventArgs { Connection = connection });
                    }
                    
                    // 更新连接列表
                    _connections = currentConnections;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"监控网络连接失败: {ex.Message}");
                }
                
                await Task.Delay(2000, _cancellationTokenSource.Token);
            }
        }

        /// <summary>
        /// 监控文件操作
        /// </summary>
        private async Task MonitorFileOperations()
        {
            // 这里可以使用文件系统监视器或其他方法来监控文件操作
            // 为了简单起见，我们使用一个模拟实现
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                await Task.Delay(5000, _cancellationTokenSource.Token);
            }
        }

        /// <summary>
        /// 获取当前网络连接
        /// </summary>
        /// <returns>网络连接列表</returns>
        private List<ConnectionInfo> GetCurrentConnections()
        {
            var connections = new List<ConnectionInfo>();
            
            try
            {
                var ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = ipGlobalProperties.GetActiveTcpConnections();
                
                foreach (var connection in tcpConnections)
                {
                    if (connection.RemoteEndPoint != null)
                    {
                        connections.Add(new ConnectionInfo
                        {
                            LocalAddress = connection.LocalEndPoint.Address.ToString(),
                            LocalPort = connection.LocalEndPoint.Port,
                            RemoteAddress = connection.RemoteEndPoint.Address.ToString(),
                            RemotePort = connection.RemoteEndPoint.Port,
                            State = connection.State.ToString()
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取网络连接失败: {ex.Message}");
            }
            
            return connections;
        }

        /// <summary>
        /// 获取进程路径
        /// </summary>
        /// <param name="process">进程</param>
        /// <returns>进程路径</returns>
        private string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName;
            }
            catch
            {
                return "未知";
            }
        }

        /// <summary>
        /// 获取进程命令行
        /// </summary>
        /// <param name="process">进程</param>
        /// <returns>进程命令行</returns>
        private string GetProcessCommandLine(Process process)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}"))
                {
                    using (var collection = searcher.Get())
                    {
                        foreach (var obj in collection)
                        {
                            return obj["CommandLine"]?.ToString();
                        }
                    }
                }
            }
            catch
            {
                // 忽略异常
            }
            
            return "未知";
        }

        /// <summary>
        /// 触发进程创建事件
        /// </summary>
        /// <param name="e">事件参数</param>
        protected virtual void OnProcessCreated(ProcessCreatedEventArgs e)
        {
            ProcessCreated?.Invoke(this, e);
        }

        /// <summary>
        /// 触发连接建立事件
        /// </summary>
        /// <param name="e">事件参数</param>
        protected virtual void OnConnectionEstablished(ConnectionEstablishedEventArgs e)
        {
            ConnectionEstablished?.Invoke(this, e);
        }

        /// <summary>
        /// 触发文件操作事件
        /// </summary>
        /// <param name="e">事件参数</param>
        protected virtual void OnFileOperation(FileOperationEventArgs e)
        {
            FileOperation?.Invoke(this, e);
        }
    }

    public class ProcessInfo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string CommandLine { get; set; }
        public DateTime StartTime { get; set; }
    }

    public class ConnectionInfo
    {
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
    }

    public class FileOperationInfo
    {
        public string Path { get; set; }
        public string Operation { get; set; }
        public string ProcessName { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class ProcessCreatedEventArgs : EventArgs
    {
        public ProcessInfo Process { get; set; }
    }

    public class ConnectionEstablishedEventArgs : EventArgs
    {
        public ConnectionInfo Connection { get; set; }
    }

    public class FileOperationEventArgs : EventArgs
    {
        public FileOperationInfo Operation { get; set; }
    }
}
