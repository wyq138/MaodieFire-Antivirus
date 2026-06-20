using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.DeviceControl
{
    public class DeviceControlManager
    {
        private DataManager _dataManager;
        private List<Device> _devices;
        private List<DevicePolicy> _policies;

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
            // 模拟加载设备列表
            _devices.Add(new Device
            {
                Id = Guid.NewGuid().ToString(),
                Name = "USB Flash Drive",
                Type = DeviceType.USB,
                Manufacturer = "Kingston",
                Model = "DataTraveler",
                SerialNumber = "1234567890",
                Status = DeviceStatus.Connected,
                ConnectedAt = DateTime.Now.AddHours(-2)
            });

            _devices.Add(new Device
            {
                Id = Guid.NewGuid().ToString(),
                Name = "External Hard Drive",
                Type = DeviceType.HardDrive,
                Manufacturer = "Seagate",
                Model = "Backup Plus",
                SerialNumber = "0987654321",
                Status = DeviceStatus.Connected,
                ConnectedAt = DateTime.Now.AddDays(-1)
            });

            _devices.Add(new Device
            {
                Id = Guid.NewGuid().ToString(),
                Name = "Printer",
                Type = DeviceType.Printer,
                Manufacturer = "HP",
                Model = "LaserJet Pro",
                SerialNumber = "ABC123",
                Status = DeviceStatus.Disconnected,
                ConnectedAt = DateTime.Now.AddDays(-3),
                DisconnectedAt = DateTime.Now.AddDays(-2)
            });
        }

        private void LoadPolicies()
        {
            // 模拟加载设备策略
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
                // 模拟阻止设备
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
                // 模拟允许设备
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
            // 模拟保存策略到文件
            string policiesFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "DeviceControl", "policies.json");
            Directory.CreateDirectory(Path.GetDirectoryName(policiesFile));
            // 实际实现中应该序列化策略到文件
        }
    }
}