// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Firewall
{
    public class FirewallManager
    {
        private bool _isEnabled;
        private List<FirewallRule> _rules;
        private TcpListener _listener;
        private CancellationTokenSource _cancellationTokenSource;

        public event EventHandler<FirewallBlockEventArgs> Blocked;

        public FirewallManager()
        {
            _isEnabled = false;
            _rules = new List<FirewallRule>();
            InitializeDefaultRules();
        }

        /// <summary>
        /// 启用防火墙
        /// </summary>
        public void Enable()
        {
            if (_isEnabled)
                return;

            _isEnabled = true;
            _cancellationTokenSource = new CancellationTokenSource();
            
            // 启动网络监控
            Task.Run(() => MonitorNetwork(), _cancellationTokenSource.Token);
        }

        /// <summary>
        /// 禁用防火墙
        /// </summary>
        public void Disable()
        {
            if (!_isEnabled)
                return;

            _cancellationTokenSource.Cancel();
            _isEnabled = false;
        }

        /// <summary>
        /// 添加防火墙规则
        /// </summary>
        /// <param name="rule">防火墙规则</param>
        public void AddRule(FirewallRule rule)
        {
            _rules.Add(rule);
        }

        /// <summary>
        /// 删除防火墙规则
        /// </summary>
        /// <param name="rule">防火墙规则</param>
        public void RemoveRule(FirewallRule rule)
        {
            _rules.Remove(rule);
        }

        /// <summary>
        /// 清除所有防火墙规则
        /// </summary>
        public void ClearRules()
        {
            _rules.Clear();
            InitializeDefaultRules();
        }

        /// <summary>
        /// 监控网络流量
        /// </summary>
        private async Task MonitorNetwork()
        {
            while (!_cancellationTokenSource.Token.IsCancellationRequested)
            {
                try
                {
                    // 这里可以实现更复杂的网络监控逻辑
                    // 为了简单起见，我们使用一个模拟实现
                    await Task.Delay(1000, _cancellationTokenSource.Token);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"监控网络失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 检查连接是否应该被阻止
        /// </summary>
        /// <param name="ipAddress">IP地址</param>
        /// <param name="port">端口</param>
        /// <returns>是否应该被阻止</returns>
        public bool ShouldBlockConnection(string ipAddress, int port)
        {
            foreach (var rule in _rules)
            {
                if (rule.Matches(ipAddress, port))
                {
                    return rule.Action == FirewallAction.Block;
                }
            }
            return false;
        }

        /// <summary>
        /// 初始化默认防火墙规则
        /// </summary>
        private void InitializeDefaultRules()
        {
            // 添加默认规则
            _rules.Add(new FirewallRule { Name = "Block Known Malicious IPs", IpAddress = "192.168.1.100", Port = 0, Action = FirewallAction.Block });
            _rules.Add(new FirewallRule { Name = "Allow Localhost", IpAddress = "127.0.0.1", Port = 0, Action = FirewallAction.Allow });
            _rules.Add(new FirewallRule { Name = "Block Common Malware Ports", IpAddress = "*", Port = 4444, Action = FirewallAction.Block });
            _rules.Add(new FirewallRule { Name = "Block Remote Desktop", IpAddress = "*", Port = 3389, Action = FirewallAction.Block });
            _rules.Add(new FirewallRule { Name = "Block SQL Injection", IpAddress = "*", Port = 1433, Action = FirewallAction.Block });
        }

        /// <summary>
        /// 触发阻止事件
        /// </summary>
        /// <param name="e">事件参数</param>
        protected virtual void OnBlocked(FirewallBlockEventArgs e)
        {
            Blocked?.Invoke(this, e);
        }
    }

    public class FirewallRule
    {
        public string Name { get; set; }
        public string IpAddress { get; set; }
        public int Port { get; set; }
        public FirewallAction Action { get; set; }
        public string Description { get; set; }

        /// <summary>
        /// 检查规则是否匹配
        /// </summary>
        /// <param name="ipAddress">IP地址</param>
        /// <param name="port">端口</param>
        /// <returns>是否匹配</returns>
        public bool Matches(string ipAddress, int port)
        {
            bool ipMatch = (IpAddress == "*" || IpAddress == ipAddress);
            bool portMatch = (Port == 0 || Port == port);
            return ipMatch && portMatch;
        }
    }

    public enum FirewallAction
    {
        Allow,
        Block
    }

    public class FirewallBlockEventArgs : EventArgs
    {
        public string IpAddress { get; set; }
        public int Port { get; set; }
        public string RuleName { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
