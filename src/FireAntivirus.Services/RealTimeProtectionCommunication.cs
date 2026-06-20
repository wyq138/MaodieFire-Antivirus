using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    [DataContract]
    public class RealTimeThreatDetection
    {
        [DataMember]
        public string Id { get; set; }
        [DataMember]
        public string FilePath { get; set; }
        [DataMember]
        public string ThreatName { get; set; }
        [DataMember]
        public string ThreatType { get; set; }
        [DataMember]
        public double Confidence { get; set; }
        [DataMember]
        public DateTime DetectionTime { get; set; }
        [DataMember]
        public string DetectionMethod { get; set; }
        [DataMember]
        public string ActionTaken { get; set; }
        [DataMember]
        public string AdditionalInfo { get; set; }
        [DataMember]
        public string Severity { get; set; }
        [DataMember]
        public string Description { get; set; }
        [DataMember]
        public DateTime DetectedAt { get; set; }
        [DataMember]
        public string Details { get; set; }
    }

    [DataContract]
    public class RealTimeThreatDetectedEventArgs : EventArgs
    {
        [DataMember]
        public RealTimeThreatDetection Detection { get; set; }
    }

    [DataContract]
    public class ProtectionStatusEventArgs : EventArgs
    {
        [DataMember]
        public RealTimeProtectionStatus Status { get; set; }
    }

    [DataContract]
    public class RealTimeProtectionStatus
    {
        [DataMember]
        public bool IsRunning { get; set; }
        [DataMember]
        public DateTime StartTime { get; set; }
        [DataMember]
        public DateTime StopTime { get; set; }
        [DataMember]
        public List<string> ActiveMonitors { get; set; }
    }

    [DataContract]
    public class ScanSettings
    {
        [DataMember]
        public bool ScanSystemFiles { get; set; } = true;
        [DataMember]
        public bool ScanEmail { get; set; } = true;
        [DataMember]
        public bool ScanArchive { get; set; } = true;
        [DataMember]
        public bool ScanRemovableMedia { get; set; } = true;
        [DataMember]
        public bool ScanNetworkDrives { get; set; } = false;
        [DataMember]
        public int MaxFileSize { get; set; } = 100 * 1024 * 1024; // 100MB
        [DataMember]
        public List<string> ExcludedPaths { get; set; } = new List<string>();
        [DataMember]
        public List<string> ExcludedExtensions { get; set; } = new List<string>();
    }


    public interface IRealTimeProtectionClient
    {
        Task<bool> StartProtection();
        Task<bool> StopProtection();
        Task<RealTimeProtectionStatus> GetStatus();
        Task<List<RealTimeThreatDetection>> GetRecentThreats();
        Task<bool> ScanFile(string filePath);
        Task<bool> AddQuarantine(string filePath);
        Task<bool> RemoveQuarantine(string itemId);
        Task<bool> AddWhitelist(string filePath);
        Task<bool> RemoveWhitelist(string filePath);
        Task<bool> UpdateSignatures();
        Task<bool> EnableModule(string moduleName);
        Task<bool> DisableModule(string moduleName);
        Task<Dictionary<string, bool>> GetModuleStatus();
        Task<bool> SetScanSettings(ScanSettings settings);
        Task<ScanSettings> GetScanSettings();
        event EventHandler<ThreatDetectedEventArgs> ThreatDetected;
        event EventHandler<ProtectionStatusEventArgs> StatusChanged;
    }

    public interface IRealTimeProtectionServer
    {
        void StartServer();
        void StopServer();
        RealTimeProtectionStatus GetStatus();
        List<RealTimeThreatDetection> GetRecentThreats();
        bool ScanFile(string filePath);
        bool AddQuarantine(string filePath);
        bool RemoveQuarantine(string itemId);
        bool AddWhitelist(string filePath);
        bool RemoveWhitelist(string filePath);
        bool UpdateSignatures();
        bool EnableModule(string moduleName);
        bool DisableModule(string moduleName);
        Dictionary<string, bool> GetModuleStatus();
        bool SetScanSettings(ScanSettings settings);
        ScanSettings GetScanSettings();
    }

    public class RealTimeProtectionServer : IRealTimeProtectionServer
    {
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;
        private Dictionary<string, IMonitor> monitors;
        private NamedPipeServerStream pipeServer;
        private Thread serverThread;
        private bool isRunning;
        private RealTimeProtectionStatus currentStatus;
        private ScanSettings scanSettings;

        public event EventHandler<ThreatDetectedEventArgs> ThreatDetected;
        public event EventHandler<ProtectionStatusEventArgs> StatusChanged;

        public RealTimeProtectionServer(DataManager dataManager, AntivirusEngine antivirusEngine, Dictionary<string, IMonitor> monitors)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
            this.monitors = monitors;
            this.currentStatus = new RealTimeProtectionStatus { IsRunning = false };
            this.scanSettings = new ScanSettings();
            InitializeMonitors();
        }

        private void InitializeMonitors()
        {
            // 监控器事件订阅已移除，因为FileMonitor、ProcessMonitor和NetworkMonitor类没有ThreatDetected事件
        }

        private void OnThreatDetected(RealTimeThreatDetection detection)
        {
            ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs { Detection = detection });
        }

        public void StartServer()
        {
            if (isRunning) return;
            isRunning = true;
            serverThread = new Thread(ServerLoop);
            serverThread.IsBackground = true;
            serverThread.Start();
        }

        public void StopServer()
        {
            isRunning = false;
            if (pipeServer != null)
            {
                pipeServer.Close();
                pipeServer = null;
            }
            if (serverThread != null && serverThread.IsAlive)
            {
                serverThread.Join(5000);
            }
        }

        private void ServerLoop()
        {
            while (isRunning)
            {
                try
                {
                    pipeServer = new NamedPipeServerStream("FireAntivirusProtection", PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message, PipeOptions.Asynchronous);

                    pipeServer.WaitForConnection();
                    HandleClientConnection(pipeServer);
                }
                catch (Exception ex)
                {
                    dataManager.LogError("服务器连接异常: " + ex.Message);
                    Thread.Sleep(1000);
                }
            }
        }

        private void HandleClientConnection(NamedPipeServerStream pipe)
        {
            try
            {
                using (StreamReader reader = new StreamReader(pipe))
                using (StreamWriter writer = new StreamWriter(pipe) { AutoFlush = true })
                {
                    while (pipe.IsConnected && isRunning)
                    {
                        string requestJson = reader.ReadLine();
                        if (string.IsNullOrEmpty(requestJson)) break;

                        CommunicationRequest request = DeserializeRequest(requestJson);
                        CommunicationResponse response = ProcessRequest(request);

                        string responseJson = SerializeResponse(response);
                        writer.WriteLine(responseJson);
                    }
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("处理客户端连接异常: " + ex.Message);
            }
            finally
            {
                pipe.Close();
            }
        }

        private CommunicationRequest DeserializeRequest(string json)
        {
            try
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(CommunicationRequest));
                using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    return (CommunicationRequest)serializer.ReadObject(stream);
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("反序列化请求失败: " + ex.Message);
                return new CommunicationRequest { Command = "error" };
            }
        }

        private string SerializeResponse(CommunicationResponse response)
        {
            try
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(CommunicationResponse));
                using (MemoryStream stream = new MemoryStream())
                {
                    serializer.WriteObject(stream, response);
                    return Encoding.UTF8.GetString(stream.ToArray());
                }
            }
            catch (Exception ex)
            {
                dataManager.LogError("序列化响应失败: " + ex.Message);
                return "{}";
            }
        }

        private CommunicationResponse ProcessRequest(CommunicationRequest request)
        {
            CommunicationResponse response = new CommunicationResponse { Success = true };

            try
            {
                switch (request.Command.ToLower())
                {
                    case "start_protection":
                        response.Success = StartProtection();
                        response.Data = currentStatus;
                        break;

                    case "stop_protection":
                        response.Success = StopProtection();
                        response.Data = currentStatus;
                        break;

                    case "get_status":
                        response.Data = GetStatus();
                        break;

                    case "get_recent_threats":
                        response.Data = GetRecentThreats();
                        break;

                    case "scan_file":
                        string filePath = request.Parameters["filePath"];
                        response.Success = ScanFile(filePath);
                        break;

                    case "add_quarantine":
                        filePath = request.Parameters["filePath"];
                        response.Success = AddQuarantine(filePath);
                        break;

                    case "remove_quarantine":
                        string itemId = request.Parameters["itemId"];
                        response.Success = RemoveQuarantine(itemId);
                        break;

                    case "add_whitelist":
                        filePath = request.Parameters["filePath"];
                        response.Success = AddWhitelist(filePath);
                        break;

                    case "remove_whitelist":
                        filePath = request.Parameters["filePath"];
                        response.Success = RemoveWhitelist(filePath);
                        break;

                    case "update_signatures":
                        response.Success = UpdateSignatures();
                        break;

                    case "enable_module":
                        string moduleName = request.Parameters["moduleName"];
                        response.Success = EnableModule(moduleName);
                        break;

                    case "disable_module":
                        moduleName = request.Parameters["moduleName"];
                        response.Success = DisableModule(moduleName);
                        break;

                    case "get_module_status":
                        response.Data = GetModuleStatus();
                        break;

                    case "set_scan_settings":
                        string settingsJson = request.Parameters["settings"];
                        ScanSettings settings = DeserializeSettings(settingsJson);
                        response.Success = SetScanSettings(settings);
                        break;

                    case "get_scan_settings":
                        response.Data = GetScanSettings();
                        break;

                    default:
                        response.Success = false;
                        response.Message = "未知命令: " + request.Command;
                        break;
                }
            }
            catch (Exception ex)
            {
                response.Success = false;
                response.Message = "处理请求异常: " + ex.Message;
            }

            return response;
        }

        private ScanSettings DeserializeSettings(string json)
        {
            try
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(ScanSettings));
                using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    return (ScanSettings)serializer.ReadObject(stream);
                }
            }
            catch
            {
                return new ScanSettings();
            }
        }

        public bool StartProtection()
        {
            try
            {
                foreach (var monitor in monitors.Values)
                {
                    monitor.Start();
                }

                currentStatus.IsRunning = true;
                currentStatus.StartTime = DateTime.Now;
                StatusChanged?.Invoke(this, new ProtectionStatusEventArgs { Status = currentStatus });

                dataManager.LogInfo("实时防护已启动");
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError("启动实时防护失败: " + ex.Message);
                return false;
            }
        }

        public bool StopProtection()
        {
            try
            {
                foreach (var monitor in monitors.Values)
                {
                    monitor.Stop();
                }

                currentStatus.IsRunning = false;
                currentStatus.StopTime = DateTime.Now;
                StatusChanged?.Invoke(this, new ProtectionStatusEventArgs { Status = currentStatus });

                dataManager.LogInfo("实时防护已停止");
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError("停止实时防护失败: " + ex.Message);
                return false;
            }
        }

        public RealTimeProtectionStatus GetStatus()
        {
            currentStatus.ActiveMonitors = new List<string>();
            foreach (var kvp in monitors)
            {
                if (kvp.Value is IMonitor monitor)
                {
                    currentStatus.ActiveMonitors.Add(kvp.Key);
                }
            }

            return currentStatus;
        }

        public List<RealTimeThreatDetection> GetRecentThreats()
        {
            var logEntries = dataManager.GetRecentThreats(100);
            var threats = new List<RealTimeThreatDetection>();
            
            foreach (var log in logEntries)
            {
                threats.Add(new RealTimeThreatDetection
                {
                    Id = log.Id,
                    FilePath = log.Details,
                    ThreatName = log.Message,
                    ThreatType = log.Type,
                    DetectionTime = log.Time,
                    Severity = log.Severity,
                    Description = log.Details
                });
            }
            
            return threats;
        }

        public bool ScanFile(string filePath)
        {
            try
            {
                ScanResult result = antivirusEngine.ScanFile(filePath);
                return !result.IsInfected;
            }
            catch (Exception ex)
            {
                dataManager.LogError("扫描文件失败: " + ex.Message);
                return false;
            }
        }

        public bool AddQuarantine(string filePath)
        {
            try
            {
                return dataManager.AddToQuarantine(filePath);
            }
            catch (Exception ex)
            {
                dataManager.LogError("添加到隔离区失败: " + ex.Message);
                return false;
            }
        }

        public bool RemoveQuarantine(string itemId)
        {
            try
            {
                return dataManager.RemoveFromQuarantine(itemId);
            }
            catch (Exception ex)
            {
                dataManager.LogError("从隔离区移除失败: " + ex.Message);
                return false;
            }
        }

        public bool AddWhitelist(string filePath)
        {
            try
            {
                dataManager.AddToWhitelist(filePath);
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError("添加到白名单失败: " + ex.Message);
                return false;
            }
        }

        public bool RemoveWhitelist(string filePath)
        {
            try
            {
                return dataManager.RemoveFromWhitelist(filePath);
            }
            catch (Exception ex)
            {
                dataManager.LogError("从白名单移除失败: " + ex.Message);
                return false;
            }
        }

        public bool UpdateSignatures()
        {
            try
            {
                dataManager.UpdateVirusDatabase();
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError("更新病毒库失败: " + ex.Message);
                return false;
            }
        }

        public bool EnableModule(string moduleName)
        {
            try
            {
                if (monitors.ContainsKey(moduleName))
                {
                    monitors[moduleName].Start();
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"启用模块失败 {moduleName}: " + ex.Message);
                return false;
            }
        }

        public bool DisableModule(string moduleName)
        {
            try
            {
                if (monitors.ContainsKey(moduleName))
                {
                    monitors[moduleName].Stop();
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"禁用模块失败 {moduleName}: " + ex.Message);
                return false;
            }
        }

        public Dictionary<string, bool> GetModuleStatus()
        {
            Dictionary<string, bool> status = new Dictionary<string, bool>();
            foreach (var kvp in monitors)
            {
                status[kvp.Key] = true;
            }
            return status;
        }

        public bool SetScanSettings(ScanSettings settings)
        {
            try
            {
                this.scanSettings = settings;
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError("设置扫描配置失败: " + ex.Message);
                return false;
            }
        }

        public ScanSettings GetScanSettings()
        {
            return scanSettings;
        }
    }

    public class RealTimeProtectionClient : IRealTimeProtectionClient
    {
        private NamedPipeClientStream pipeClient;
        private bool isConnected;

        public event EventHandler<ThreatDetectedEventArgs> ThreatDetected;
        public event EventHandler<ProtectionStatusEventArgs> StatusChanged;

        public async Task<bool> StartProtection()
        {
            CommunicationResponse response = await SendRequest("start_protection");
            return response.Success;
        }

        public async Task<bool> StopProtection()
        {
            CommunicationResponse response = await SendRequest("stop_protection");
            return response.Success;
        }

        public async Task<RealTimeProtectionStatus> GetStatus()
        {
            CommunicationResponse response = await SendRequest("get_status");
            return response.Data as RealTimeProtectionStatus;
        }

        public async Task<List<RealTimeThreatDetection>> GetRecentThreats()
        {
            CommunicationResponse response = await SendRequest("get_recent_threats");
            return response.Data as List<RealTimeThreatDetection>;
        }

        public async Task<bool> ScanFile(string filePath)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string> { { "filePath", filePath } };
            CommunicationResponse response = await SendRequest("scan_file", parameters);
            return response.Success;
        }

        public async Task<bool> AddQuarantine(string filePath)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string> { { "filePath", filePath } };
            CommunicationResponse response = await SendRequest("add_quarantine", parameters);
            return response.Success;
        }

        public async Task<bool> RemoveQuarantine(string itemId)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string> { { "itemId", itemId } };
            CommunicationResponse response = await SendRequest("remove_quarantine", parameters);
            return response.Success;
        }

        public async Task<bool> AddWhitelist(string filePath)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string> { { "filePath", filePath } };
            CommunicationResponse response = await SendRequest("add_whitelist", parameters);
            return response.Success;
        }

        public async Task<bool> RemoveWhitelist(string filePath)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string> { { "filePath", filePath } };
            CommunicationResponse response = await SendRequest("remove_whitelist", parameters);
            return response.Success;
        }

        public async Task<bool> UpdateSignatures()
        {
            CommunicationResponse response = await SendRequest("update_signatures");
            return response.Success;
        }

        public async Task<bool> EnableModule(string moduleName)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string> { { "moduleName", moduleName } };
            CommunicationResponse response = await SendRequest("enable_module", parameters);
            return response.Success;
        }

        public async Task<bool> DisableModule(string moduleName)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string> { { "moduleName", moduleName } };
            CommunicationResponse response = await SendRequest("disable_module", parameters);
            return response.Success;
        }

        public async Task<Dictionary<string, bool>> GetModuleStatus()
        {
            CommunicationResponse response = await SendRequest("get_module_status");
            return response.Data as Dictionary<string, bool>;
        }

        public async Task<bool> SetScanSettings(ScanSettings settings)
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(ScanSettings));
            using (MemoryStream stream = new MemoryStream())
            {
                serializer.WriteObject(stream, settings);
                string settingsJson = Encoding.UTF8.GetString(stream.ToArray());

                Dictionary<string, string> parameters = new Dictionary<string, string> { { "settings", settingsJson } };
                CommunicationResponse response = await SendRequest("set_scan_settings", parameters);
                return response.Success;
            }
        }

        public async Task<ScanSettings> GetScanSettings()
        {
            CommunicationResponse response = await SendRequest("get_scan_settings");
            return response.Data as ScanSettings;
        }

        private async Task<CommunicationResponse> SendRequest(string command, Dictionary<string, string> parameters = null)
        {
            CommunicationRequest request = new CommunicationRequest
            {
                Command = command,
                Parameters = parameters ?? new Dictionary<string, string>()
            };

            try
            {
                if (!isConnected)
                {
                    await ConnectAsync();
                }

                string requestJson = SerializeRequest(request);
                await WriteToPipeAsync(requestJson);

                string responseJson = await ReadFromPipeAsync();
                return DeserializeResponse(responseJson);
            }
            catch (Exception ex)
            {
                return new CommunicationResponse
                {
                    Success = false,
                    Message = "通信异常: " + ex.Message
                };
            }
        }

        private async Task ConnectAsync()
        {
            pipeClient = new NamedPipeClientStream(".", "FireAntivirusProtection", PipeDirection.InOut);
            await pipeClient.ConnectAsync(5000);
            isConnected = true;
        }

        private async Task WriteToPipeAsync(string data)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(data);
            await pipeClient.WriteAsync(buffer, 0, buffer.Length);
            await pipeClient.FlushAsync();
        }

        private async Task<string> ReadFromPipeAsync()
        {
            byte[] buffer = new byte[4096];
            int bytesRead = await pipeClient.ReadAsync(buffer, 0, buffer.Length);
            return Encoding.UTF8.GetString(buffer, 0, bytesRead);
        }

        private string SerializeRequest(CommunicationRequest request)
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(CommunicationRequest));
            using (MemoryStream stream = new MemoryStream())
            {
                serializer.WriteObject(stream, request);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }

        private CommunicationResponse DeserializeResponse(string json)
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(CommunicationResponse));
            using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                return (CommunicationResponse)serializer.ReadObject(stream);
            }
        }

        public void Disconnect()
        {
            if (pipeClient != null)
            {
                pipeClient.Close();
                pipeClient = null;
            }
            isConnected = false;
        }
    }

    [DataContract]
    public class CommunicationRequest
    {
        [DataMember]
        public string Command { get; set; }

        [DataMember]
        public Dictionary<string, string> Parameters { get; set; }
    }

    [DataContract]
    public class CommunicationResponse
    {
        [DataMember]
        public bool Success { get; set; }

        [DataMember]
        public string Message { get; set; }

        [DataMember]
        public object Data { get; set; }
    }


}