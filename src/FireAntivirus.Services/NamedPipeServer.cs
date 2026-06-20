using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Collections.Concurrent;

namespace FireAntivirus.Services
{
    public class NamedPipeServer
    {
        private string pipeName;
        private bool isRunning;
        private ConcurrentDictionary<string, PipeClient> clients;
        private Thread listenerThread;
        private NamedPipeServerStream currentPipeServer;
        private readonly object pipeLock = new object();

        public event EventHandler<MessageReceivedEventArgs> MessageReceived;
        public event EventHandler<ClientConnectedEventArgs> ClientConnected;
        public event EventHandler<ClientDisconnectedEventArgs> ClientDisconnected;

        public NamedPipeServer(string pipeName)
        {
            this.pipeName = pipeName;
            this.clients = new ConcurrentDictionary<string, PipeClient>();
        }

        public void Start()
        {
            if (isRunning) return;
            
            isRunning = true;
            listenerThread = new Thread(ListenForClients);
            listenerThread.IsBackground = true;
            listenerThread.Start();
        }

        public void Stop()
        {
            isRunning = false;
            
            // 关闭当前等待的管道
            lock (pipeLock)
            {
                if (currentPipeServer != null)
                {
                    try
                    {
                        currentPipeServer.Close();
                    }
                    catch { }
                }
            }
            
            // 关闭所有客户端连接
            foreach (var client in clients.Values)
            {
                client.Close();
            }
            
            clients.Clear();
            
            // 等待监视线程结束
            if (listenerThread != null && listenerThread.IsAlive)
            {
                listenerThread.Join(2000);
            }
        }

        public void SendMessage(string clientId, string message)
        {
            if (clients.TryGetValue(clientId, out PipeClient client))
            {
                client.SendMessage(message);
            }
        }

        public void BroadcastMessage(string message)
        {
            foreach (var client in clients.Values)
            {
                client.SendMessage(message);
            }
        }

        private void ListenForClients()
        {
            while (isRunning)
            {
                NamedPipeServerStream pipeServer = null;
                try
                {
                    pipeServer = new NamedPipeServerStream(
                        pipeName,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Message,
                        PipeOptions.Asynchronous);
                    
                    lock (pipeLock)
                    {
                        currentPipeServer = pipeServer;
                    }
                    
                    // 同步等待连接（更可靠）
                    pipeServer.WaitForConnection();
                    
                    if (!isRunning)
                    {
                        pipeServer.Close();
                        break;
                    }
                    
                    // 创建新的客户端实例
                    var client = new PipeClient(Guid.NewGuid().ToString(), pipeServer);
                    client.MessageReceived += (s, e) => OnMessageReceived(client.Id, e.Message);
                    client.Disconnected += (s, e) => OnClientDisconnected(client.Id);
                    
                    clients.TryAdd(client.Id, client);
                    
                    // 触发客户端连接事件
                    OnClientConnected(client.Id);
                    
                    // 开始接收消息
                    client.StartReceiving();
                }
                catch (ObjectDisposedException)
                {
                    // 正常关闭时会发生
                    break;
                }
                catch (Exception ex)
                {
                    // 记录错误但不中断监听
                    Console.WriteLine($"NamedPipeServer error: {ex.Message}");
                    pipeServer?.Dispose();
                    Thread.Sleep(100);
                }
            }
        }

        private void OnMessageReceived(string clientId, string message)
        {
            MessageReceived?.Invoke(this, new MessageReceivedEventArgs(clientId, message));
        }

        private void OnClientConnected(string clientId)
        {
            ClientConnected?.Invoke(this, new ClientConnectedEventArgs(clientId));
        }

        private void OnClientDisconnected(string clientId)
        {
            clients.TryRemove(clientId, out _);
            ClientDisconnected?.Invoke(this, new ClientDisconnectedEventArgs(clientId));
        }
    }

    public class PipeClient
    {
        public string Id { get; }
        private NamedPipeServerStream pipeStream;
        private Thread readThread;
        private bool isConnected;
        private readonly object lockObj = new object();

        public event EventHandler<MessageReceivedEventArgs> MessageReceived;
        public event EventHandler Disconnected;

        public PipeClient(string id, NamedPipeServerStream pipeStream)
        {
            Id = id;
            this.pipeStream = pipeStream;
            isConnected = true;
        }

        public void StartReceiving()
        {
            readThread = new Thread(ReadMessages);
            readThread.IsBackground = true;
            readThread.Start();
        }

        public void SendMessage(string message)
        {
            lock (lockObj)
            {
                try
                {
                    if (isConnected && pipeStream != null && pipeStream.CanWrite)
                    {
                        byte[] buffer = Encoding.UTF8.GetBytes(message + "\n");
                        pipeStream.Write(buffer, 0, buffer.Length);
                        pipeStream.Flush();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Send message error: {ex.Message}");
                    Close();
                }
            }
        }

        public void Close()
        {
            lock (lockObj)
            {
                if (!isConnected) return;
                
                isConnected = false;
                try
                {
                    pipeStream?.Close();
                    pipeStream?.Dispose();
                }
                catch { }
            }
            
            if (readThread != null && readThread.IsAlive)
            {
                readThread.Join(500);
            }
            
            Disconnected?.Invoke(this, EventArgs.Empty);
        }

        private void ReadMessages()
        {
            try
            {
                // 不使用using，因为pipeStream由外部管理
                var buffer = new byte[4096];
                var messageBuilder = new StringBuilder();
                
                while (isConnected)
                {
                    try
                    {
                        int bytesRead = pipeStream.Read(buffer, 0, buffer.Length);
                        if (bytesRead == 0)
                        {
                            // 客户端断开连接
                            break;
                        }
                        
                        string data = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        messageBuilder.Append(data);
                        
                        // 检查是否有完整消息（以换行符结尾）
                        string accumulated = messageBuilder.ToString();
                        int newlineIndex;
                        while ((newlineIndex = accumulated.IndexOf('\n')) >= 0)
                        {
                            string message = accumulated.Substring(0, newlineIndex).Trim();
                            if (!string.IsNullOrEmpty(message))
                            {
                                MessageReceived?.Invoke(this, new MessageReceivedEventArgs(Id, message));
                            }
                            accumulated = accumulated.Substring(newlineIndex + 1);
                        }
                        messageBuilder.Clear();
                        messageBuilder.Append(accumulated);
                    }
                    catch (IOException)
                    {
                        // 连接断开
                        break;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Read error: {ex.Message}");
                        break;
                    }
                }
            }
            finally
            {
                Close();
            }
        }
    }

    public class MessageReceivedEventArgs : EventArgs
    {
        public string ClientId { get; }
        public string Message { get; }

        public MessageReceivedEventArgs(string clientId, string message)
        {
            ClientId = clientId;
            Message = message;
        }
    }

    public class ClientConnectedEventArgs : EventArgs
    {
        public string ClientId { get; }

        public ClientConnectedEventArgs(string clientId)
        {
            ClientId = clientId;
        }
    }

    public class ClientDisconnectedEventArgs : EventArgs
    {
        public string ClientId { get; }

        public ClientDisconnectedEventArgs(string clientId)
        {
            ClientId = clientId;
        }
    }
}
