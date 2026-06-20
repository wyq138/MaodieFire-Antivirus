using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

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
            // 模拟加载防火墙规则
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
            // 模拟加载网络连接
            _connections.Add(new NetworkConnection
            {
                Id = Guid.NewGuid().ToString(),
                ProcessName = "chrome.exe",
                LocalAddress = "127.0.0.1",
                LocalPort = 54321,
                RemoteAddress = "192.168.1.1",
                RemotePort = 80,
                Protocol = "TCP",
                State = "Established",
                CreatedAt = DateTime.Now.AddMinutes(-5)
            });

            _connections.Add(new NetworkConnection
            {
                Id = Guid.NewGuid().ToString(),
                ProcessName = "firefox.exe",
                LocalAddress = "127.0.0.1",
                LocalPort = 65432,
                RemoteAddress = "192.168.1.2",
                RemotePort = 443,
                Protocol = "TCP",
                State = "Established",
                CreatedAt = DateTime.Now.AddMinutes(-3)
            });
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

        private void SaveRules()
        {
            // 模拟保存规则到文件
            string rulesFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Firewall", "rules.json");
            Directory.CreateDirectory(Path.GetDirectoryName(rulesFile));
            // 实际实现中应该序列化规则到文件
        }
    }
}