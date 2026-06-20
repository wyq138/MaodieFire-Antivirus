using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;
using FireAntivirus.Services;

namespace FireAntivirus.Host
{
    // 威胁操作枚举
    public enum ThreatAction
    {
        ALLOW,
        BLOCK
    }

    // 威胁类型枚举
    public enum ThreatType
    {
        Unknown,
        Ransomware,
        Trojan,
        Virus,
        Spyware,
        Adware,
        Keylogger,
        Backdoor,
        Worm,
        Miner,
        PUP,
        Exploit,
        FILE_MALICIOUS,
        PROCESS_MALICIOUS,
        DEVICE_UNAUTHORIZED,
        REGISTRY_TAMPERING,
        SCRIPT_MALICIOUS,
        BEHAVIOR_MALICIOUS,
        DOCUMENT_ENCRYPTION
    }

    // 威胁信息结构体
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ThreatInfo
    {
        public ThreatType type;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string processPath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string targetPath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string threatDescription;
        public int processId;
        public int threadId;
    }

    // 消息结构体
    [StructLayout(LayoutKind.Sequential)]
    public struct Message
    {
        public int type;
        public ThreatInfo threatInfo;
        public ThreatAction action;
    }

    public class NamedPipeClient
    {
        private string pipeName;
        private NamedPipeClientStream pipeClient;
        private Thread readThread;
        private bool isConnected;

        public event EventHandler<MessageReceivedEventArgs> MessageReceived;
        public event EventHandler Connected;
        public event EventHandler Disconnected;

        public bool IsConnected => isConnected;

        public NamedPipeClient(string pipeName)
        {
            this.pipeName = pipeName;
        }

        public void Connect()
        {
            try
            {
                pipeClient = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                pipeClient.Connect(2000);
                isConnected = true;
                
                // 启动读取线程
                readThread = new Thread(ReadMessages);
                readThread.Start();
                
                Connected?.Invoke(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Pipe connection error: {ex.Message}");
                isConnected = false;
            }
        }

        public void Disconnect()
        {
            try
            {
                isConnected = false;
                if (pipeClient != null)
                {
                    pipeClient.Close();
                    pipeClient.Dispose();
                }
                if (readThread != null && readThread.IsAlive)
                {
                    readThread.Join(1000);
                }
                Disconnected?.Invoke(this, EventArgs.Empty);
            }
            catch { }
        }

        public void SendMessage(Message message)
        {
            try
            {
                if (isConnected && pipeClient != null && pipeClient.CanWrite)
                {
                    // 序列化消息
                    int size = Marshal.SizeOf(message);
                    byte[] buffer = new byte[size];
                    IntPtr ptr = Marshal.AllocHGlobal(size);
                    Marshal.StructureToPtr(message, ptr, true);
                    Marshal.Copy(ptr, buffer, 0, size);
                    Marshal.FreeHGlobal(ptr);

                    // 发送消息
                    pipeClient.Write(buffer, 0, size);
                    pipeClient.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Send message error: {ex.Message}");
                Disconnect();
            }
        }

        private void ReadMessages()
        {
            try
            {
                while (isConnected)
                {
                    // 读取消息
                    int size = Marshal.SizeOf(typeof(Message));
                    byte[] buffer = new byte[size];
                    int bytesRead = pipeClient.Read(buffer, 0, size);
                    
                    if (bytesRead == size)
                    {
                        // 反序列化消息
                        IntPtr ptr = Marshal.AllocHGlobal(size);
                        Marshal.Copy(buffer, 0, ptr, size);
                        Message message = (Message)Marshal.PtrToStructure(ptr, typeof(Message));
                        Marshal.FreeHGlobal(ptr);

                        // 触发事件
                        MessageReceived?.Invoke(this, new MessageReceivedEventArgs(message));
                    }
                    else if (bytesRead == 0)
                    {
                        // 服务器断开连接
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Read message error: {ex.Message}");
            }
            finally
            {
                isConnected = false;
                Disconnected?.Invoke(this, EventArgs.Empty);
            }
        }

        public Message SendMessageAndWaitForResponse(Message message, int timeout = 5000)
        {
            Message response = new Message();
            AutoResetEvent responseEvent = new AutoResetEvent(false);

            // 临时事件处理程序
            EventHandler<MessageReceivedEventArgs> tempHandler = (s, e) => {
                response = e.Message;
                responseEvent.Set();
            };

            try
            {
                MessageReceived += tempHandler;
                SendMessage(message);
                
                // 等待响应
                if (!responseEvent.WaitOne(timeout))
                {
                    throw new TimeoutException("Response timeout");
                }
            }
            finally
            {
                MessageReceived -= tempHandler;
            }

            return response;
        }
    }

    public class MessageReceivedEventArgs : EventArgs
    {
        public Message Message { get; }

        public MessageReceivedEventArgs(Message message)
        {
            Message = message;
        }
    }
}
