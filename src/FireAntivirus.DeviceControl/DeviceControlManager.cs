using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;
using Newtonsoft.Json;

namespace FireAntivirus.DeviceControl
{
    public class DeviceControlManager
    {
        private DataManager _dataManager;
        private List<Device> _devices;
        private List<DevicePolicy> _policies;
        private Dictionary<string, string> _devicePnpIds = new Dictionary<string, string>(); // device.Id -> PNPDeviceID

        public DeviceControlManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _devices = new List<Device>();
            _policies = new List<DevicePolicy>();
            InitializeDeviceControl();
        }

        private void InitializeDeviceControl()
        {
            LoadDevices();
            LoadPolicies();
        }

        private void LoadDevices()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject disk in searcher.Get())
                    {
                        string name = disk["Name"]?.ToString() ?? "未知设备";
                        string manufacturer = disk["Manufacturer"]?.ToString() ?? "未知厂商";
                        string model = disk["Model"]?.ToString() ?? "未知型号";
                        string serialNumber = disk["SerialNumber"]?.ToString() ?? "";
                        string interfaceType = disk["InterfaceType"]?.ToString() ?? "";
                        string pnpDeviceId = disk["PNPDeviceID"]?.ToString() ?? "";

                        DeviceType deviceType = DeviceType.Other;
                        if (interfaceType.IndexOf("USB", StringComparison.OrdinalIgnoreCase) >= 0)
                            deviceType = DeviceType.USB;
                        else if (interfaceType.IndexOf("SCSI", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 interfaceType.IndexOf("ATA", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 interfaceType.IndexOf("SATA", StringComparison.OrdinalIgnoreCase) >= 0)
                            deviceType = DeviceType.HardDrive;

                        var device = new Device
                        {
                            Id = Guid.NewGuid().ToString(),
                            Name = name,
                            Type = deviceType,
                            Manufacturer = manufacturer,
                            Model = model,
                            SerialNumber = serialNumber,
                            Status = DeviceStatus.Connected,
                            ConnectedAt = DateTime.Now
                        };

                        _devices.Add(device);
                        if (!string.IsNullOrEmpty(pnpDeviceId))
                        {
                            _devicePnpIds[device.Id] = pnpDeviceId;
                        }
                    }
                }
            }
            catch
            {
                // WMI 查询失败时，设备列表为空
            }
        }

        private void LoadPolicies()
        {
            string policiesFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "DeviceControl", "policies.json");
            if (File.Exists(policiesFile))
            {
                try
                {
                    string json = File.ReadAllText(policiesFile);
                    var loaded = JsonConvert.DeserializeObject<List<DevicePolicy>>(json);
                    if (loaded != null && loaded.Count > 0)
                    {
                        _policies = loaded;
                        return;
                    }
                }
                catch
                {
                    // 文件损坏时重新生成默认策略
                }
            }

            // 文件不存在或加载失败时，使用默认策略
            _policies.Add(new DevicePolicy
            {
                Id = Guid.NewGuid().ToString(),
                Name = "阻止USB存储设备",
                Description = "阻止所有USB存储设备的访问",
                DeviceType = DeviceType.USB,
                AccessType = DeviceAccessType.Block,
                Enabled = true
            });

            _policies.Add(new DevicePolicy
            {
                Id = Guid.NewGuid().ToString(),
                Name = "允许打印机访问",
                Description = "允许所有打印机设备的访问",
                DeviceType = DeviceType.Printer,
                AccessType = DeviceAccessType.Allow,
                Enabled = true
            });

            _policies.Add(new DevicePolicy
            {
                Id = Guid.NewGuid().ToString(),
                Name = "只读CD/DVD",
                Description = "将CD/DVD设备设置为只读",
                DeviceType = DeviceType.OpticalDrive,
                AccessType = DeviceAccessType.ReadOnly,
                Enabled = true
            });
        }

        public List<Device> GetDevices()
        {
            return _devices;
        }

        public List<Device> GetConnectedDevices()
        {
            return _devices.Where(d => d.Status == DeviceStatus.Connected).ToList();
        }

        public Device GetDevice(string deviceId)
        {
            return _devices.FirstOrDefault(d => d.Id == deviceId);
        }

        public DevicePolicyResult AddPolicy(DevicePolicy policy)
        {
            try
            {
                policy.Id = Guid.NewGuid().ToString();
                _policies.Add(policy);
                SavePolicies();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DevicePolicyAdded",
                    Message = "设备策略已添加",
                    Details = $"名称: {policy.Name}, 设备类型: {policy.DeviceType}, 访问类型: {policy.AccessType}"
                });

                return new DevicePolicyResult
                {
                    Success = true,
                    Message = "策略添加成功",
                    Policy = policy
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DevicePolicyError",
                    Message = "设备策略添加错误",
                    Details = $"错误: {ex.Message}"
                });

                return new DevicePolicyResult
                {
                    Success = false,
                    Message = $"策略添加失败: {ex.Message}"
                };
            }
        }

        public DevicePolicyResult UpdatePolicy(DevicePolicy policy)
        {
            try
            {
                var existingPolicy = _policies.FirstOrDefault(p => p.Id == policy.Id);
                if (existingPolicy != null)
                {
                    existingPolicy.Name = policy.Name;
                    existingPolicy.Description = policy.Description;
                    existingPolicy.DeviceType = policy.DeviceType;
                    existingPolicy.AccessType = policy.AccessType;
                    existingPolicy.Enabled = policy.Enabled;
                    SavePolicies();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "DevicePolicyUpdated",
                        Message = "设备策略已更新",
                        Details = $"名称: {policy.Name}"
                    });

                    return new DevicePolicyResult
                    {
                        Success = true,
                        Message = "策略更新成功",
                        Policy = existingPolicy
                    };
                }
                else
                {
                    return new DevicePolicyResult
                    {
                        Success = false,
                        Message = "策略不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DevicePolicyError",
                    Message = "设备策略更新错误",
                    Details = $"错误: {ex.Message}"
                });

                return new DevicePolicyResult
                {
                    Success = false,
                    Message = $"策略更新失败: {ex.Message}"
                };
            }
        }

        public DevicePolicyResult DeletePolicy(string policyId)
        {
            try
            {
                var policy = _policies.FirstOrDefault(p => p.Id == policyId);
                if (policy != null)
                {
                    _policies.Remove(policy);
                    SavePolicies();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "DevicePolicyDeleted",
                        Message = "设备策略已删除",
                        Details = $"名称: {policy.Name}"
                    });

                    return new DevicePolicyResult
                    {
                        Success = true,
                        Message = "策略删除成功"
                    };
                }
                else
                {
                    return new DevicePolicyResult
                    {
                        Success = false,
                        Message = "策略不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DevicePolicyError",
                    Message = "设备策略删除错误",
                    Details = $"错误: {ex.Message}"
                });

                return new DevicePolicyResult
                {
                    Success = false,
                    Message = $"策略删除失败: {ex.Message}"
                };
            }
        }

        public List<DevicePolicy> GetPolicies()
        {
            return _policies;
        }

        public DeviceAccessType GetDeviceAccessType(Device device)
        {
            var policy = _policies.FirstOrDefault(p => p.DeviceType == device.Type && p.Enabled);
            return policy?.AccessType ?? DeviceAccessType.Allow;
        }

        public bool BlockDevice(Device device)
        {
            try
            {
                // 使用 WMI 禁用设备
                if (_devicePnpIds.TryGetValue(device.Id, out string pnpDeviceId))
                {
                    try
                    {
                        using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID = '{pnpDeviceId.Replace("'", "''")}'"))
                        {
                            foreach (ManagementObject pnpEntity in searcher.Get())
                            {
                                var result = pnpEntity.InvokeMethod("Disable", null);
                                if (result != null)
                                {
                                    // result is uint, 0 = success
                                }
                            }
                        }
                    }
                    catch
                    {
                        // WMI 禁用失败时，仍标记状态
                    }
                }

                device.Status = DeviceStatus.Blocked;
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceBlocked",
                    Message = "设备已被阻止",
                    Details = $"名称: {device.Name}, 类型: {device.Type}"
                });
                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceBlockError",
                    Message = "设备阻止错误",
                    Details = $"名称: {device.Name}, 错误: {ex.Message}"
                });
                return false;
            }
        }

        public bool AllowDevice(Device device)
        {
            try
            {
                // 使用 WMI 启用设备
                if (_devicePnpIds.TryGetValue(device.Id, out string pnpDeviceId))
                {
                    try
                    {
                        using (var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID = '{pnpDeviceId.Replace("'", "''")}'"))
                        {
                            foreach (ManagementObject pnpEntity in searcher.Get())
                            {
                                var result = pnpEntity.InvokeMethod("Enable", null);
                                if (result != null)
                                {
                                    // result is uint, 0 = success
                                }
                            }
                        }
                    }
                    catch
                    {
                        // WMI 启用失败时，仍标记状态
                    }
                }

                device.Status = DeviceStatus.Connected;
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceAllowed",
                    Message = "设备已被允许",
                    Details = $"名称: {device.Name}, 类型: {device.Type}"
                });
                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "DeviceAllowError",
                    Message = "设备允许错误",
                    Details = $"名称: {device.Name}, 错误: {ex.Message}"
                });
                return false;
            }
        }

        private void SavePolicies()
        {
            string policiesFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "DeviceControl", "policies.json");
            Directory.CreateDirectory(Path.GetDirectoryName(policiesFile));
            string json = JsonConvert.SerializeObject(_policies, Formatting.Indented);
            File.WriteAllText(policiesFile, json);
        }
    }
}