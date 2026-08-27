using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;
using Newtonsoft.Json;

namespace FireAntivirus.NetworkFirewall
{
    public class NetworkFirewallManager
    {
        private DataManager _dataManager;
        private List<FirewallRule> _rules;
        private List<NetworkConnection> _connections;
        private bool _isEnabled;

        public NetworkFirewallManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _rules = new List<FirewallRule>();
            _connections = new List<NetworkConnection>();
            _isEnabled = true;
            InitializeFirewall();
        }

        private void InitializeFirewall()
        {
            LoadRules();
            LoadConnections();
        }

        private void LoadRules()
        {
            string rulesFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Firewall", "rules.json");
            if (File.Exists(rulesFile))
            {
                try
                {
                    string json = File.ReadAllText(rulesFile);
                    var loaded = JsonConvert.DeserializeObject<List<FirewallRule>>(json);
                    if (loaded != null && loaded.Count > 0)
                    {
                        _rules = loaded;
                        return;
                    }
                }
                catch
                {
                    // 文件损坏时重新生成默认规则
                }
            }

            // 文件不存在或加载失败时，使用默认规则
            _rules.Add(new FirewallRule
            {
                Id = Guid.NewGuid().ToString(),
                Name = "允许本地连接",
                Description = "允许本地网络连接",
                Action = FirewallAction.Allow,
                Protocol = FirewallProtocol.All,
                LocalPort = "0",
                RemotePort = "0",
                Direction = FirewallDirection.Inbound,
                Enabled = true
            });

            _rules.Add(new FirewallRule
            {
                Id = Guid.NewGuid().ToString(),
                Name = "阻止远程访问",
                Description = "阻止远程访问本地服务",
                Action = FirewallAction.Block,
                Protocol = FirewallProtocol.TCP,
                LocalPort = "3389",
                RemotePort = "0",
                Direction = FirewallDirection.Inbound,
                Enabled = true
            });

            _rules.Add(new FirewallRule
            {
                Id = Guid.NewGuid().ToString(),
                Name = "允许HTTP流量",
                Description = "允许HTTP和HTTPS流量",
                Action = FirewallAction.Allow,
                Protocol = FirewallProtocol.TCP,
                LocalPort = "80,443",
                RemotePort = "0",
                Direction = FirewallDirection.Both,
                Enabled = true
            });
        }

        private void LoadConnections()
        {
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();
                var pidMapping = GetTcpConnectionPidMapping();

                foreach (var conn in tcpConnections)
                {
                    string processName = "System";
                    if (pidMapping.TryGetValue(conn.LocalEndPoint, out int pid))
                    {
                        try
                        {
                            var proc = Process.GetProcessById(pid);
                            processName = proc.ProcessName;
                        }
                        catch
                        {
                            // 进程可能已退出
                        }
                    }

                    _connections.Add(new NetworkConnection
                    {
                        Id = Guid.NewGuid().ToString(),
                        ProcessName = processName,
                        LocalAddress = conn.LocalEndPoint.Address.ToString(),
                        LocalPort = conn.LocalEndPoint.Port,
                        RemoteAddress = conn.RemoteEndPoint.Address.ToString(),
                        RemotePort = conn.RemoteEndPoint.Port,
                        Protocol = "TCP",
                        State = conn.State.ToString(),
                        CreatedAt = DateTime.Now
                    });
                }
            }
            catch
            {
                // 获取连接失败时不加载任何连接
            }
        }

        public FirewallRuleResult AddRule(FirewallRule rule)
        {
            try
            {
                rule.Id = Guid.NewGuid().ToString();
                _rules.Add(rule);
                SaveRules();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FirewallRuleAdded",
                    Message = "防火墙规则已添加",
                    Details = $"名称: {rule.Name}, 动作: {rule.Action}"
                });

                return new FirewallRuleResult
                {
                    Success = true,
                    Message = "规则添加成功",
                    Rule = rule
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FirewallRuleError",
                    Message = "防火墙规则添加错误",
                    Details = $"错误: {ex.Message}"
                });

                return new FirewallRuleResult
                {
                    Success = false,
                    Message = $"规则添加失败: {ex.Message}"
                };
            }
        }

        public FirewallRuleResult UpdateRule(FirewallRule rule)
        {
            try
            {
                var existingRule = _rules.FirstOrDefault(r => r.Id == rule.Id);
                if (existingRule != null)
                {
                    existingRule.Name = rule.Name;
                    existingRule.Description = rule.Description;
                    existingRule.Action = rule.Action;
                    existingRule.Protocol = rule.Protocol;
                    existingRule.LocalPort = rule.LocalPort;
                    existingRule.RemotePort = rule.RemotePort;
                    existingRule.Direction = rule.Direction;
                    existingRule.Enabled = rule.Enabled;
                    SaveRules();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "FirewallRuleUpdated",
                        Message = "防火墙规则已更新",
                        Details = $"名称: {rule.Name}"
                    });

                    return new FirewallRuleResult
                    {
                        Success = true,
                        Message = "规则更新成功",
                        Rule = existingRule
                    };
                }
                else
                {
                    return new FirewallRuleResult
                    {
                        Success = false,
                        Message = "规则不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FirewallRuleError",
                    Message = "防火墙规则更新错误",
                    Details = $"错误: {ex.Message}"
                });

                return new FirewallRuleResult
                {
                    Success = false,
                    Message = $"规则更新失败: {ex.Message}"
                };
            }
        }

        public FirewallRuleResult DeleteRule(string ruleId)
        {
            try
            {
                var rule = _rules.FirstOrDefault(r => r.Id == ruleId);
                if (rule != null)
                {
                    _rules.Remove(rule);
                    SaveRules();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "FirewallRuleDeleted",
                        Message = "防火墙规则已删除",
                        Details = $"名称: {rule.Name}"
                    });

                    return new FirewallRuleResult
                    {
                        Success = true,
                        Message = "规则删除成功"
                    };
                }
                else
                {
                    return new FirewallRuleResult
                    {
                        Success = false,
                        Message = "规则不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "FirewallRuleError",
                    Message = "防火墙规则删除错误",
                    Details = $"错误: {ex.Message}"
                });

                return new FirewallRuleResult
                {
                    Success = false,
                    Message = $"规则删除失败: {ex.Message}"
                };
            }
        }

        public List<FirewallRule> GetRules()
        {
            return _rules;
        }

        public List<NetworkConnection> GetConnections()
        {
            return _connections;
        }

        public void EnableFirewall()
        {
            _isEnabled = true;
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "FirewallEnabled",
                Message = "防火墙已启用"
            });
        }

        public void DisableFirewall()
        {
            _isEnabled = false;
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "FirewallDisabled",
                Message = "防火墙已禁用"
            });
        }

        public bool IsFirewallEnabled()
        {
            return _isEnabled;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public byte localPort1;
            public byte localPort2;
            public byte localPort3;
            public byte localPort4;
            public uint remoteAddr;
            public byte remotePort1;
            public byte remotePort2;
            public byte remotePort3;
            public byte remotePort4;
            public uint owningPid;
        }

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TCP_TABLE_CLASS TableClass, int reserved);

        private void SaveRules()
        {
            string rulesFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Firewall", "rules.json");
            Directory.CreateDirectory(Path.GetDirectoryName(rulesFile));
            string json = JsonConvert.SerializeObject(_rules, Formatting.Indented);
            File.WriteAllText(rulesFile, json);
        }

        private Dictionary<IPEndPoint, int> GetTcpConnectionPidMapping()
        {
            var mapping = new Dictionary<IPEndPoint, int>();
            int bufferSize = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0 && ret != 122) // ERROR_INSUFFICIENT_BUFFER
                return mapping;

            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                ret = GetExtendedTcpTable(buffer, ref bufferSize, false, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0)
                    return mapping;

                int tableSize = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                IntPtr rowPtr = buffer + 4;

                for (int i = 0; i < tableSize; i++)
                {
                    var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    rowPtr += rowSize;

                    var localEndPoint = new IPEndPoint(
                        new IPAddress((long)row.localAddr),
                        (row.localPort1 << 8) | row.localPort2);

                    if (!mapping.ContainsKey(localEndPoint))
                    {
                        mapping[localEndPoint] = (int)row.owningPid;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return mapping;
        }
    }
}