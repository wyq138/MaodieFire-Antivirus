using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Host.Models;
using Newtonsoft.Json;

namespace FireAntivirus.Host.Services
{
    /// <summary>
    /// 看门狗客户端 - 负责与守护进程通信并发送心跳
    /// </summary>
    public class WatchdogClient : IDisposable
    {
        private const string PipeName = "FireAntivirus_Watchdog";
        private const int HeartbeatIntervalMs = 3000;
        private const int ConnectTimeoutMs = 5000;
        private const int MaxReconnectAttempts = 3;
        
        private NamedPipeClientStream? _pipeClient;
        private Timer? _heartbeatTimer;
        private readonly string _exitFlagFile;
        private readonly string _mainProcessPath;
        private readonly object _lockObj = new object();
        private bool _isConnected;
        private bool _isExiting;
        private int _reconnectAttempts;
        
        /// <summary>
        /// 连接状态变化事件
        /// </summary>
        public event EventHandler<bool>? ConnectionStateChanged;
        
        /// <summary>
        /// 是否已连接到守护进程
        /// </summary>
        public bool IsConnected => _isConnected;
        
        /// <summary>
        /// 是否正在退出
        /// </summary>
        public bool IsExiting => _isExiting;
        
        public WatchdogClient()
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            _exitFlagFile = Path.Combine(baseDir, "exit_flag.dat");
            _mainProcessPath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
            
            // 清除旧的退出标志
            ClearExitFlag();
        }
        
        /// <summary>
        /// 启动看门狗客户端
        /// </summary>
        public void Start()
        {
            // 连接守护进程
            _ = ConnectAsync();
            
            // 启动心跳定时器
            _heartbeatTimer = new Timer(OnHeartbeatTimer, null, 
                HeartbeatIntervalMs, HeartbeatIntervalMs);
        }
        
        /// <summary>
        /// 连接到守护进程
        /// </summary>
        private async Task ConnectAsync()
        {
            for (int attempt = 0; attempt < MaxReconnectAttempts; attempt++)
            {
                try
                {
                    _pipeClient = new NamedPipeClientStream(".", PipeName, 
                        PipeDirection.InOut, PipeOptions.Asynchronous);
                    
                    await _pipeClient.ConnectAsync(ConnectTimeoutMs);
                    
                    lock (_lockObj)
                    {
                        _isConnected = true;
                        _reconnectAttempts = 0;
                    }
                    
                    // 注册主进程
                    await SendMessageAsync(new WatchdogMessage
                    {
                        ProcessType = "Main",
                        ProcessId = Process.GetCurrentProcess().Id,
                        Action = "Register",
                        MainProcessPath = _mainProcessPath
                    });
                    
                    ConnectionStateChanged?.Invoke(this, true);
                    Debug.WriteLine("[WatchdogClient] Connected to guardian process");
                    return;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[WatchdogClient] Connect attempt {attempt + 1} failed: {ex.Message}");
                    
                    _pipeClient?.Dispose();
                    _pipeClient = null;
                    
                    await Task.Delay(1000);
                }
            }
            
            lock (_lockObj)
            {
                _isConnected = false;
            }
            
            ConnectionStateChanged?.Invoke(this, false);
            Debug.WriteLine("[WatchdogClient] Failed to connect to guardian process");
        }
        
        /// <summary>
        /// 心跳定时器回调
        /// </summary>
        private async void OnHeartbeatTimer(object? state)
        {
            if (_isExiting)
                return;
            
            // 检查退出标志
            if (CheckExitFlag())
            {
                Debug.WriteLine("[WatchdogClient] Exit flag detected, stopping heartbeat");
                return;
            }
            
            if (!_isConnected || _pipeClient == null)
            {
                // 尝试重连
                if (_reconnectAttempts < MaxReconnectAttempts)
                {
                    Interlocked.Increment(ref _reconnectAttempts);
                    await ConnectAsync();
                }
                return;
            }
            
            try
            {
                await SendMessageAsync(new WatchdogMessage
                {
                    ProcessType = "Main",
                    ProcessId = Process.GetCurrentProcess().Id,
                    Action = "Heartbeat",
                    MainProcessPath = _mainProcessPath
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WatchdogClient] Heartbeat failed: {ex.Message}");
                
                lock (_lockObj)
                {
                    _isConnected = false;
                }
                
                _pipeClient?.Dispose();
                _pipeClient = null;
                
                ConnectionStateChanged?.Invoke(this, false);
            }
        }
        
        /// <summary>
        /// 发送消息到守护进程
        /// </summary>
        private async Task SendMessageAsync(WatchdogMessage message)
        {
            if (_pipeClient == null || !_pipeClient.IsConnected)
                throw new InvalidOperationException("Pipe not connected");
            
            string json = JsonConvert.SerializeObject(message);
            byte[] buffer = Encoding.UTF8.GetBytes(json);
            
            // 先发送长度
            byte[] lengthBytes = BitConverter.GetBytes(buffer.Length);
            await _pipeClient.WriteAsync(lengthBytes, 0, 4);
            
            // 再发送内容
            await _pipeClient.WriteAsync(buffer, 0, buffer.Length);
            await _pipeClient.FlushAsync();
        }
        
        /// <summary>
        /// 请求退出 - 创建退出标志并通知守护进程
        /// </summary>
        public void RequestExit()
        {
            lock (_lockObj)
            {
                _isExiting = true;
            }
            
            // 创建退出标志文件
            CreateExitFlag();
            
            // 停止心跳
            _heartbeatTimer?.Dispose();
            _heartbeatTimer = null;
            
            // 发送退出消息
            try
            {
                if (_pipeClient != null && _pipeClient.IsConnected)
                {
                    SendMessageAsync(new WatchdogMessage
                    {
                        ProcessType = "Main",
                        ProcessId = Process.GetCurrentProcess().Id,
                        Action = "Exit"
                    }).Wait(3000);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WatchdogClient.cs 捕获异常", ex.Message); }
            
            // 关闭连接
            _pipeClient?.Dispose();
            _pipeClient = null;
            
            Debug.WriteLine("[WatchdogClient] Exit requested");
        }
        
        /// <summary>
        /// 检查退出标志文件
        /// </summary>
        public bool CheckExitFlag()
        {
            return File.Exists(_exitFlagFile);
        }
        
        /// <summary>
        /// 创建退出标志文件
        /// </summary>
        private void CreateExitFlag()
        {
            try
            {
                File.WriteAllText(_exitFlagFile, DateTime.Now.ToString("O"));
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WatchdogClient] Failed to create exit flag: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 清除退出标志文件
        /// </summary>
        public void ClearExitFlag()
        {
            try
            {
                if (File.Exists(_exitFlagFile))
                {
                    File.Delete(_exitFlagFile);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WatchdogClient.cs 捕获异常", ex.Message); }
        }
        
        public void Dispose()
        {
            _heartbeatTimer?.Dispose();
            _pipeClient?.Dispose();
        }
    }
}