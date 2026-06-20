using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Data;
using System.Data.SQLite;

namespace FireAntivirus.Services
{
    public class EnterpriseManager
    {
        private string _databasePath;
        private string _serverUrl;
        private bool _enabled;
        private object _managerLock = new object();
        private HttpClient _httpClient;

        public event EventHandler<EnterpriseEventArgs> EnterpriseEvent;

        public EnterpriseManager(string databasePath = null, string serverUrl = null)
        {
            _databasePath = databasePath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Enterprise", "enterprise.db");
            _serverUrl = serverUrl ?? "http://localhost:8080";
            _enabled = true;
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            try
            {
                var directory = Path.GetDirectoryName(_databasePath);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    
                    // 创建设备表
                    string createDevicesTable = @"
                    CREATE TABLE IF NOT EXISTS Devices (
                        DeviceId TEXT PRIMARY KEY,
                        DeviceName TEXT,
                        IPAddress TEXT,
                        OSVersion TEXT,
                        LastSeen DATETIME,
                        Status TEXT,
                        GroupId TEXT
                    );
                    ";
                    using (var command = new SQLiteCommand(createDevicesTable, connection))
                    {
                        command.ExecuteNonQuery();
                    }

                    // 创建扫描记录表
                    string createScanRecordsTable = @"
                    CREATE TABLE IF NOT EXISTS ScanRecords (
                        RecordId TEXT PRIMARY KEY,
                        DeviceId TEXT,
                        ScanType TEXT,
                        StartTime DATETIME,
                        EndTime DATETIME,
                        Status TEXT,
                        DetectedThreats INTEGER,
                        QuarantinedItems INTEGER,
                        FOREIGN KEY (DeviceId) REFERENCES Devices(DeviceId)
                    );
                    ";
                    using (var command = new SQLiteCommand(createScanRecordsTable, connection))
                    {
                        command.ExecuteNonQuery();
                    }

                    // 创建威胁表
                    string createThreatsTable = @"
                    CREATE TABLE IF NOT EXISTS Threats (
                        ThreatId TEXT PRIMARY KEY,
                        DeviceId TEXT,
                        ScanRecordId TEXT,
                        FilePath TEXT,
                        ThreatName TEXT,
                        ThreatType TEXT,
                        Severity TEXT,
                        Status TEXT,
                        DetectionTime DATETIME,
                        FOREIGN KEY (DeviceId) REFERENCES Devices(DeviceId),
                        FOREIGN KEY (ScanRecordId) REFERENCES ScanRecords(RecordId)
                    );
                    ";
                    using (var command = new SQLiteCommand(createThreatsTable, connection))
                    {
                        command.ExecuteNonQuery();
                    }

                    // 创建策略表
                    string createPoliciesTable = @"
                    CREATE TABLE IF NOT EXISTS Policies (
                        PolicyId TEXT PRIMARY KEY,
                        PolicyName TEXT,
                        Description TEXT,
                        Settings TEXT,
                        CreatedDate DATETIME,
                        LastModifiedDate DATETIME
                    );
                    ";
                    using (var command = new SQLiteCommand(createPoliciesTable, connection))
                    {
                        command.ExecuteNonQuery();
                    }

                    // 创建设备组表
                    string createGroupsTable = @"
                    CREATE TABLE IF NOT EXISTS Groups (
                        GroupId TEXT PRIMARY KEY,
                        GroupName TEXT,
                        Description TEXT,
                        PolicyId TEXT,
                        FOREIGN KEY (PolicyId) REFERENCES Policies(PolicyId)
                    );
                    ";
                    using (var command = new SQLiteCommand(createGroupsTable, connection))
                    {
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to initialize enterprise database: " + ex.Message));
            }
        }

        public async Task<DeviceInfo> RegisterDeviceAsync(DeviceInfo deviceInfo, CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Registering device: " + deviceInfo.Name));

                // 生成设备ID
                if (string.IsNullOrEmpty(deviceInfo.DeviceId))
                {
                    deviceInfo.DeviceId = Guid.NewGuid().ToString();
                }
                deviceInfo.LastSeen = DateTime.Now;

                // 保存到数据库
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = @"
                    INSERT OR REPLACE INTO Devices (DeviceId, Name, IPAddress, OSVersion, LastSeen, Status, GroupId)
                    VALUES (@DeviceId, @Name, @IPAddress, @OSVersion, @LastSeen, @Status, @GroupId);
                    ";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@DeviceId", deviceInfo.DeviceId);
                        command.Parameters.AddWithValue("@Name", deviceInfo.Name);
                        command.Parameters.AddWithValue("@IPAddress", deviceInfo.IPAddress);
                        command.Parameters.AddWithValue("@OSVersion", deviceInfo.OSVersion);
                        command.Parameters.AddWithValue("@LastSeen", deviceInfo.LastSeen);
                        command.Parameters.AddWithValue("@Status", deviceInfo.Status);
                        command.Parameters.AddWithValue("@GroupId", deviceInfo.GroupId);
                        command.ExecuteNonQuery();
                    }
                }

                // 同步到服务器
                await SyncDeviceToServerAsync(deviceInfo, cancellationToken);

                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Device registered successfully: " + deviceInfo.Name));
                return deviceInfo;
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to register device: " + ex.Message));
                throw;
            }
        }

        public async Task<ScanRecord> AddScanRecordAsync(ScanRecord scanRecord, CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Adding scan record for device: " + scanRecord.DeviceId));

                // 生成记录ID
                if (string.IsNullOrEmpty(scanRecord.RecordId))
                {
                    scanRecord.RecordId = Guid.NewGuid().ToString();
                }

                // 保存到数据库
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = @"
                    INSERT INTO ScanRecords (RecordId, DeviceId, ScanType, StartTime, EndTime, Status, DetectedThreats, QuarantinedItems)
                    VALUES (@RecordId, @DeviceId, @ScanType, @StartTime, @EndTime, @Status, @DetectedThreats, @QuarantinedItems);
                    ";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@RecordId", scanRecord.RecordId);
                        command.Parameters.AddWithValue("@DeviceId", scanRecord.DeviceId);
                        command.Parameters.AddWithValue("@ScanType", scanRecord.ScanType);
                        command.Parameters.AddWithValue("@StartTime", scanRecord.StartTime);
                        command.Parameters.AddWithValue("@EndTime", scanRecord.EndTime);
                        command.Parameters.AddWithValue("@Status", scanRecord.Status);
                        command.Parameters.AddWithValue("@DetectedThreats", scanRecord.DetectedThreats);
                        command.Parameters.AddWithValue("@QuarantinedItems", scanRecord.QuarantinedItems);
                        command.ExecuteNonQuery();
                    }
                }

                // 同步到服务器
                await SyncScanRecordToServerAsync(scanRecord, cancellationToken);

                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Scan record added successfully: " + scanRecord.RecordId));
                return scanRecord;
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to add scan record: " + ex.Message));
                throw;
            }
        }

        public async Task<Threat> AddThreatAsync(Threat threat, CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Adding threat for device: " + threat.DeviceId));

                // 生成威胁ID
                if (string.IsNullOrEmpty(threat.ThreatId))
                {
                    threat.ThreatId = Guid.NewGuid().ToString();
                }
                threat.DetectionTime = DateTime.Now;

                // 保存到数据库
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = @"
                    INSERT INTO Threats (ThreatId, DeviceId, ScanRecordId, FilePath, ThreatName, ThreatType, Severity, Status, DetectionTime)
                    VALUES (@ThreatId, @DeviceId, @ScanRecordId, @FilePath, @ThreatName, @ThreatType, @Severity, @Status, @DetectionTime);
                    ";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@ThreatId", threat.ThreatId);
                        command.Parameters.AddWithValue("@DeviceId", threat.DeviceId);
                        command.Parameters.AddWithValue("@ScanRecordId", threat.ScanRecordId);
                        command.Parameters.AddWithValue("@FilePath", threat.FilePath);
                        command.Parameters.AddWithValue("@ThreatName", threat.ThreatName);
                        command.Parameters.AddWithValue("@ThreatType", threat.ThreatType);
                        command.Parameters.AddWithValue("@Severity", threat.Severity);
                        command.Parameters.AddWithValue("@Status", threat.Status);
                        command.Parameters.AddWithValue("@DetectionTime", threat.DetectionTime);
                        command.ExecuteNonQuery();
                    }
                }

                // 同步到服务器
                await SyncThreatToServerAsync(threat, cancellationToken);

                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Threat added successfully: " + threat.ThreatId));
                return threat;
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to add threat: " + ex.Message));
                throw;
            }
        }

        public async Task<Policy> CreatePolicyAsync(Policy policy, CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Creating policy: " + policy.PolicyName));

                // 生成策略ID
                if (string.IsNullOrEmpty(policy.PolicyId))
                {
                    policy.PolicyId = Guid.NewGuid().ToString();
                }
                policy.CreatedDate = DateTime.Now;
                policy.LastModifiedDate = DateTime.Now;

                // 保存到数据库
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = @"
                    INSERT INTO Policies (PolicyId, PolicyName, Description, Settings, CreatedDate, LastModifiedDate)
                    VALUES (@PolicyId, @PolicyName, @Description, @Settings, @CreatedDate, @LastModifiedDate);
                    ";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@PolicyId", policy.PolicyId);
                        command.Parameters.AddWithValue("@PolicyName", policy.PolicyName);
                        command.Parameters.AddWithValue("@Description", policy.Description);
                        command.Parameters.AddWithValue("@Settings", policy.Settings);
                        command.Parameters.AddWithValue("@CreatedDate", policy.CreatedDate);
                        command.Parameters.AddWithValue("@LastModifiedDate", policy.LastModifiedDate);
                        command.ExecuteNonQuery();
                    }
                }

                // 同步到服务器
                await SyncPolicyToServerAsync(policy, cancellationToken);

                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Policy created successfully: " + policy.PolicyName));
                return policy;
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to create policy: " + ex.Message));
                throw;
            }
        }

        public async Task<Group> CreateGroupAsync(Group group, CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Creating group: " + group.GroupName));

                // 生成组ID
                if (string.IsNullOrEmpty(group.GroupId))
                {
                    group.GroupId = Guid.NewGuid().ToString();
                }

                // 保存到数据库
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = @"
                    INSERT INTO Groups (GroupId, GroupName, Description, PolicyId)
                    VALUES (@GroupId, @GroupName, @Description, @PolicyId);
                    ";
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@GroupId", group.GroupId);
                        command.Parameters.AddWithValue("@GroupName", group.GroupName);
                        command.Parameters.AddWithValue("@Description", group.Description);
                        command.Parameters.AddWithValue("@PolicyId", group.PolicyId);
                        command.ExecuteNonQuery();
                    }
                }

                // 同步到服务器
                await SyncGroupToServerAsync(group, cancellationToken);

                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Group created successfully: " + group.GroupName));
                return group;
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to create group: " + ex.Message));
                throw;
            }
        }

        public List<DeviceInfo> GetDevices()
        {
            var devices = new List<DeviceInfo>();
            try
            {
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = "SELECT * FROM Devices ORDER BY LastSeen DESC";
                    using (var command = new SQLiteCommand(query, connection))
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            devices.Add(new DeviceInfo
                            {
                                DeviceId = reader["DeviceId"].ToString(),
                                Name = reader["Name"].ToString(),
                                IPAddress = reader["IPAddress"].ToString(),
                                OSVersion = reader["OSVersion"].ToString(),
                                LastSeen = Convert.ToDateTime(reader["LastSeen"]),
                                Status = reader["Status"].ToString(),
                                GroupId = reader["GroupId"]?.ToString()
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to get devices: " + ex.Message));
            }
            return devices;
        }

        public List<ScanRecord> GetScanRecords(string deviceId = null)
        {
            var records = new List<ScanRecord>();
            try
            {
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = deviceId != null
                        ? "SELECT * FROM ScanRecords WHERE DeviceId = @DeviceId ORDER BY StartTime DESC"
                        : "SELECT * FROM ScanRecords ORDER BY StartTime DESC";
                    
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        if (deviceId != null)
                        {
                            command.Parameters.AddWithValue("@DeviceId", deviceId);
                        }
                        
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                records.Add(new ScanRecord
                                {
                                    RecordId = reader["RecordId"].ToString(),
                                    DeviceId = reader["DeviceId"].ToString(),
                                    ScanType = reader["ScanType"].ToString(),
                                    StartTime = Convert.ToDateTime(reader["StartTime"]),
                                    EndTime = Convert.ToDateTime(reader["EndTime"]),
                                    Status = reader["Status"].ToString(),
                                    DetectedThreats = Convert.ToInt32(reader["DetectedThreats"]),
                                    QuarantinedItems = Convert.ToInt32(reader["QuarantinedItems"])
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to get scan records: " + ex.Message));
            }
            return records;
        }

        public List<Threat> GetThreats(string deviceId = null, string scanRecordId = null)
        {
            var threats = new List<Threat>();
            try
            {
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = "SELECT * FROM Threats WHERE 1=1";
                    if (!string.IsNullOrEmpty(deviceId))
                    {
                        query += " AND DeviceId = @DeviceId";
                    }
                    if (!string.IsNullOrEmpty(scanRecordId))
                    {
                        query += " AND ScanRecordId = @ScanRecordId";
                    }
                    query += " ORDER BY DetectionTime DESC";
                    
                    using (var command = new SQLiteCommand(query, connection))
                    {
                        if (!string.IsNullOrEmpty(deviceId))
                        {
                            command.Parameters.AddWithValue("@DeviceId", deviceId);
                        }
                        if (!string.IsNullOrEmpty(scanRecordId))
                        {
                            command.Parameters.AddWithValue("@ScanRecordId", scanRecordId);
                        }
                        
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                threats.Add(new Threat
                                {
                                    ThreatId = reader["ThreatId"].ToString(),
                                    DeviceId = reader["DeviceId"].ToString(),
                                    ScanRecordId = reader["ScanRecordId"].ToString(),
                                    FilePath = reader["FilePath"].ToString(),
                                    ThreatName = reader["ThreatName"].ToString(),
                                    ThreatType = reader["ThreatType"].ToString(),
                                    Severity = reader["Severity"].ToString(),
                                    Status = reader["Status"].ToString(),
                                    DetectionTime = Convert.ToDateTime(reader["DetectionTime"])
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to get threats: " + ex.Message));
            }
            return threats;
        }

        public List<Policy> GetPolicies()
        {
            var policies = new List<Policy>();
            try
            {
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = "SELECT * FROM Policies ORDER BY LastModifiedDate DESC";
                    using (var command = new SQLiteCommand(query, connection))
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            policies.Add(new Policy
                            {
                                PolicyId = reader["PolicyId"].ToString(),
                                PolicyName = reader["PolicyName"].ToString(),
                                Description = reader["Description"].ToString(),
                                Settings = reader["Settings"].ToString(),
                                CreatedDate = Convert.ToDateTime(reader["CreatedDate"]),
                                LastModifiedDate = Convert.ToDateTime(reader["LastModifiedDate"])
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to get policies: " + ex.Message));
            }
            return policies;
        }

        public List<Group> GetGroups()
        {
            var groups = new List<Group>();
            try
            {
                using (var connection = new SQLiteConnection($"Data Source={_databasePath};Version=3;"))
                {
                    connection.Open();
                    string query = "SELECT * FROM Groups ORDER BY GroupName";
                    using (var command = new SQLiteCommand(query, connection))
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            groups.Add(new Group
                            {
                                GroupId = reader["GroupId"].ToString(),
                                GroupName = reader["GroupName"].ToString(),
                                Description = reader["Description"].ToString(),
                                PolicyId = reader["PolicyId"]?.ToString()
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to get groups: " + ex.Message));
            }
            return groups;
        }

        public async Task<Report> GenerateReportAsync(ReportOptions options, CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Generating report..."));

                var report = new Report
                {
                    ReportId = Guid.NewGuid().ToString(),
                    ReportName = options.ReportName,
                    ReportType = options.ReportType,
                    GeneratedDate = DateTime.Now,
                    Devices = new List<DeviceReport>()
                };

                // 获取设备列表
                var devices = GetDevices();
                if (!string.IsNullOrEmpty(options.GroupId))
                {
                    devices = devices.Where(d => d.GroupId == options.GroupId).ToList();
                }

                foreach (var device in devices)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    var deviceReport = new DeviceReport
                    {
                        DeviceId = device.DeviceId,
                        Name = device.Name,
                        IPAddress = device.IPAddress,
                        OSVersion = device.OSVersion,
                        Status = device.Status,
                        ScanRecords = GetScanRecords(device.DeviceId).Take(10).ToList(),
                        Threats = GetThreats(device.DeviceId).Take(20).ToList()
                    };
                    report.Devices.Add(deviceReport);
                }

                // 计算统计信息
                report.TotalDevices = devices.Count;
                report.TotalScans = report.Devices.Sum(d => d.ScanRecords.Count);
                report.TotalThreats = report.Devices.Sum(d => d.Threats.Count);
                report.CriticalThreats = report.Devices.Sum(d => d.Threats.Count(t => t.Severity == "Critical"));
                report.HighThreats = report.Devices.Sum(d => d.Threats.Count(t => t.Severity == "High"));
                report.MediumThreats = report.Devices.Sum(d => d.Threats.Count(t => t.Severity == "Medium"));
                report.LowThreats = report.Devices.Sum(d => d.Threats.Count(t => t.Severity == "Low"));

                // 保存报告
                string reportPath = Path.Combine(Path.GetDirectoryName(_databasePath), "Reports", $"report_{report.ReportId}.json");
                var reportDirectory = Path.GetDirectoryName(reportPath);
                if (!Directory.Exists(reportDirectory))
                {
                    Directory.CreateDirectory(reportDirectory);
                }
                File.WriteAllText(reportPath, Newtonsoft.Json.JsonConvert.SerializeObject(report, Newtonsoft.Json.Formatting.Indented));

                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Report generated successfully: " + report.ReportName));
                return report;
            }
            catch (Exception ex)
            {
                RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Error, "Failed to generate report: " + ex.Message));
                throw;
            }
        }

        private async Task SyncDeviceToServerAsync(DeviceInfo deviceInfo, CancellationToken cancellationToken = default)
        {
            try
            {
                var content = new StringContent(
                    Newtonsoft.Json.JsonConvert.SerializeObject(deviceInfo),
                    Encoding.UTF8,
                    "application/json"
                );
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/devices", content, cancellationToken);
                response.EnsureSuccessStatusCode();
            }
            catch { }
        }

        private async Task SyncScanRecordToServerAsync(ScanRecord scanRecord, CancellationToken cancellationToken = default)
        {
            try
            {
                var content = new StringContent(
                    Newtonsoft.Json.JsonConvert.SerializeObject(scanRecord),
                    Encoding.UTF8,
                    "application/json"
                );
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/scanrecords", content, cancellationToken);
                response.EnsureSuccessStatusCode();
            }
            catch { }
        }

        private async Task SyncThreatToServerAsync(Threat threat, CancellationToken cancellationToken = default)
        {
            try
            {
                var content = new StringContent(
                    Newtonsoft.Json.JsonConvert.SerializeObject(threat),
                    Encoding.UTF8,
                    "application/json"
                );
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/threats", content, cancellationToken);
                response.EnsureSuccessStatusCode();
            }
            catch { }
        }

        private async Task SyncPolicyToServerAsync(Policy policy, CancellationToken cancellationToken = default)
        {
            try
            {
                var content = new StringContent(
                    Newtonsoft.Json.JsonConvert.SerializeObject(policy),
                    Encoding.UTF8,
                    "application/json"
                );
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/policies", content, cancellationToken);
                response.EnsureSuccessStatusCode();
            }
            catch { }
        }

        private async Task SyncGroupToServerAsync(Group group, CancellationToken cancellationToken = default)
        {
            try
            {
                var content = new StringContent(
                    Newtonsoft.Json.JsonConvert.SerializeObject(group),
                    Encoding.UTF8,
                    "application/json"
                );
                var response = await _httpClient.PostAsync($"{_serverUrl}/api/groups", content, cancellationToken);
                response.EnsureSuccessStatusCode();
            }
            catch { }
        }

        public void Enable()
        {
            _enabled = true;
            RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Enterprise manager enabled"));
        }

        public void Disable()
        {
            _enabled = false;
            RaiseEnterpriseEvent(new EnterpriseEventArgs(EnterpriseEventType.Info, "Enterprise manager disabled"));
        }

        public bool IsEnabled()
        {
            return _enabled;
        }

        public void SetServerUrl(string url)
        {
            _serverUrl = url;
        }

        public string GetServerUrl()
        {
            return _serverUrl;
        }

        private void RaiseEnterpriseEvent(EnterpriseEventArgs e)
        {
            EnterpriseEvent?.Invoke(this, e);
        }
    }

    public class ScanRecord
    {
        public string RecordId { get; set; }
        public string DeviceId { get; set; }
        public string ScanType { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string Status { get; set; }
        public int DetectedThreats { get; set; }
        public int QuarantinedItems { get; set; }
    }

    public class Threat
    {
        public string ThreatId { get; set; }
        public string DeviceId { get; set; }
        public string ScanRecordId { get; set; }
        public string FilePath { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public string Status { get; set; }
        public DateTime DetectionTime { get; set; }
    }

    public class Policy
    {
        public string PolicyId { get; set; }
        public string PolicyName { get; set; }
        public string Description { get; set; }
        public string Settings { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime LastModifiedDate { get; set; }
    }

    public class Group
    {
        public string GroupId { get; set; }
        public string GroupName { get; set; }
        public string Description { get; set; }
        public string PolicyId { get; set; }
    }

    public class Report
    {
        public string ReportId { get; set; }
        public string ReportName { get; set; }
        public string ReportType { get; set; }
        public DateTime GeneratedDate { get; set; }
        public int TotalDevices { get; set; }
        public int TotalScans { get; set; }
        public int TotalThreats { get; set; }
        public int CriticalThreats { get; set; }
        public int HighThreats { get; set; }
        public int MediumThreats { get; set; }
        public int LowThreats { get; set; }
        public List<DeviceReport> Devices { get; set; } = new List<DeviceReport>();
    }

    public class DeviceReport
    {
        public string DeviceId { get; set; }
        public string Name { get; set; }
        public string IPAddress { get; set; }
        public string OSVersion { get; set; }
        public string Status { get; set; }
        public List<ScanRecord> ScanRecords { get; set; } = new List<ScanRecord>();
        public List<Threat> Threats { get; set; } = new List<Threat>();
    }

    public class ReportOptions
    {
        public string ReportName { get; set; }
        public string ReportType { get; set; }
        public string GroupId { get; set; }
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
    }

    public class EnterpriseEventArgs : EventArgs
    {
        public EnterpriseEventType EventType { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }

        public EnterpriseEventArgs(EnterpriseEventType eventType, string message)
        {
            EventType = eventType;
            Message = message;
            Timestamp = DateTime.Now;
        }
    }

    public enum EnterpriseEventType
    {
        Info,
        Warning,
        Error,
        DeviceRegistered,
        ScanRecordAdded,
        ThreatDetected,
        PolicyCreated,
        GroupCreated,
        ReportGenerated
    }
}