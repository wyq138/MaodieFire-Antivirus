using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace FireAntivirus.Engine.Analyzers.Protection
{
    /// <summary>
    /// 防火墙分析器 - 分析防火墙规则和网络连接
    /// </summary>
    public class FirewallAnalyzer
    {
        private readonly List<FirewallRule> _rules;
        private readonly List<FirewallRule> _suspiciousRules;

        public FirewallAnalyzer()
        {
            _rules = new List<FirewallRule>();
            _suspiciousRules = new List<FirewallRule>();
            InitializeSuspiciousPatterns();
        }

        private void InitializeSuspiciousPatterns()
        {
            // 可疑端口列表
            _suspiciousPorts = new HashSet<int>
            {
                4444, 5555, 6666, 7777, 8888, 9999,  // 常见后门端口
                31337, 12345, 54321,  // 知名后门端口
                1337, 23, 21,  // 常见攻击目标
            };

            // 可疑程序路径
            _suspiciousPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "\\temp\\",
                "\\tmp\\",
                "\\appdata\\local\\temp\\",
                "\\public\\",
                "\\programdata\\",
                "\\downloads\\"
            };
        }

        private HashSet<int> _suspiciousPorts;
        private HashSet<string> _suspiciousPaths;

        public FirewallResult Analyze()
        {
            var result = new FirewallResult
            {
                Rules = new List<FirewallRuleInfo>(),
                SuspiciousRules = new List<FirewallRuleInfo>(),
                Warnings = new List<string>()
            };

            try
            {
                // 分析入站规则
                var inboundRules = AnalyzeInboundRules();
                result.InboundRulesCount = inboundRules.Count;
                result.Rules.AddRange(inboundRules);

                // 分析出站规则
                var outboundRules = AnalyzeOutboundRules();
                result.OutboundRulesCount = outboundRules.Count;
                result.Rules.AddRange(outboundRules);

                // 检查可疑规则
                foreach (var rule in result.Rules)
                {
                    if (IsSuspiciousRule(rule))
                    {
                        rule.IsSuspicious = true;
                        result.SuspiciousRules.Add(rule);
                    }
                }

                result.TotalRules = result.Rules.Count;
                result.SuspiciousCount = result.SuspiciousRules.Count;

                if (result.SuspiciousCount > 0)
                {
                    result.Warnings.Add($"发现 {result.SuspiciousCount} 条可疑防火墙规则");
                }
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"防火墙分析错误: {ex.Message}");
            }

            return result;
        }

        private List<FirewallRuleInfo> AnalyzeInboundRules()
        {
            var rules = new List<FirewallRuleInfo>();
            
            try
            {
                // 使用netsh获取防火墙规则
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "advfirewall firewall show rule name=all dir=in",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    rules = ParseFirewallRules(output, "Inbound");
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "FirewallAnalyzer.cs 捕获异常", ex.Message); }

            return rules;
        }

        private List<FirewallRuleInfo> AnalyzeOutboundRules()
        {
            var rules = new List<FirewallRuleInfo>();
            
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "advfirewall firewall show rule name=all dir=out",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = System.Diagnostics.Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    rules = ParseFirewallRules(output, "Outbound");
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "FirewallAnalyzer.cs 捕获异常", ex.Message); }

            return rules;
        }

        private List<FirewallRuleInfo> ParseFirewallRules(string output, string direction)
        {
            var rules = new List<FirewallRuleInfo>();
            
            try
            {
                var lines = output.Split('\n');
                FirewallRuleInfo currentRule = null;

                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    
                    if (trimmed.StartsWith("规则名:") || trimmed.StartsWith("Rule Name:"))
                    {
                        if (currentRule != null)
                            rules.Add(currentRule);
                        
                        currentRule = new FirewallRuleInfo
                        {
                            Direction = direction,
                            Name = trimmed.Split(new[] { ':', '=' }, 2).Last().Trim()
                        };
                    }
                    else if (currentRule != null)
                    {
                        if (trimmed.StartsWith("已启用:") || trimmed.StartsWith("Enabled:"))
                        {
                            currentRule.Enabled = trimmed.Contains("是") || trimmed.Contains("Yes");
                        }
                        else if (trimmed.StartsWith("操作:") || trimmed.StartsWith("Action:"))
                        {
                            currentRule.Action = trimmed.Contains("允许") || trimmed.Contains("Allow") ? "Allow" : "Block";
                        }
                        else if (trimmed.StartsWith("协议:") || trimmed.StartsWith("Protocol:"))
                        {
                            currentRule.Protocol = trimmed.Split(new[] { ':', '=' }, 2).Last().Trim();
                        }
                        else if (trimmed.StartsWith("本地端口:") || trimmed.StartsWith("LocalPort:"))
                        {
                            currentRule.LocalPorts = trimmed.Split(new[] { ':', '=' }, 2).Last().Trim();
                        }
                        else if (trimmed.StartsWith("远程端口:") || trimmed.StartsWith("RemotePort:"))
                        {
                            currentRule.RemotePorts = trimmed.Split(new[] { ':', '=' }, 2).Last().Trim();
                        }
                        else if (trimmed.StartsWith("程序:") || trimmed.StartsWith("Program:"))
                        {
                            currentRule.ProgramPath = trimmed.Split(new[] { ':', '=' }, 2).Last().Trim();
                        }
                    }
                }

                if (currentRule != null)
                    rules.Add(currentRule);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "FirewallAnalyzer.cs 捕获异常", ex.Message); }

            return rules;
        }

        private bool IsSuspiciousRule(FirewallRuleInfo rule)
        {
            // 检查可疑端口
            if (!string.IsNullOrEmpty(rule.LocalPorts))
            {
                foreach (var port in rule.LocalPorts.Split(','))
                {
                    if (int.TryParse(port.Trim(), out var portNum) && _suspiciousPorts.Contains(portNum))
                    {
                        return true;
                    }
                }
            }

            // 检查可疑程序路径
            if (!string.IsNullOrEmpty(rule.ProgramPath))
            {
                foreach (var path in _suspiciousPaths)
                {
                    if (rule.ProgramPath.Contains(path, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            // 检查开放的危险端口
            if (rule.Action == "Allow" && rule.Direction == "Inbound")
            {
                if (!string.IsNullOrEmpty(rule.LocalPorts))
                {
                    var dangerousPorts = new[] { "23", "21", "3389", "445", "139", "135" };
                    foreach (var port in rule.LocalPorts.Split(','))
                    {
                        if (dangerousPorts.Contains(port.Trim()))
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        public FirewallRuleInfo CreateBlockRule(string name, int port, string direction = "Inbound")
        {
            return new FirewallRuleInfo
            {
                Name = name,
                Direction = direction,
                Action = "Block",
                Enabled = true,
                Protocol = "TCP",
                LocalPorts = port.ToString()
            };
        }
    }

    public class FirewallResult
    {
        public List<FirewallRuleInfo> Rules { get; set; }
        public List<FirewallRuleInfo> SuspiciousRules { get; set; }
        public List<string> Warnings { get; set; }
        public int TotalRules { get; set; }
        public int InboundRulesCount { get; set; }
        public int OutboundRulesCount { get; set; }
        public int SuspiciousCount { get; set; }
    }

    public class FirewallRuleInfo
    {
        public string Name { get; set; }
        public string Direction { get; set; }
        public bool Enabled { get; set; }
        public string Action { get; set; }
        public string Protocol { get; set; }
        public string LocalPorts { get; set; }
        public string RemotePorts { get; set; }
        public string ProgramPath { get; set; }
        public bool IsSuspicious { get; set; }
    }

    public class FirewallRule
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string ApplicationPath { get; set; }
    }
}