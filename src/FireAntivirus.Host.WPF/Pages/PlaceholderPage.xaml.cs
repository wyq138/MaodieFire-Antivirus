using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 占位符页面 - 用于尚未完全实现的页面
    /// </summary>
    public partial class PlaceholderPage : Page, IThemed
    {
        private string pageName;
        
        public PlaceholderPage(string name)
        {
            pageName = name;
            InitializeComponent();
            PageNameText.Text = GetPageDisplayName(name);
        }
        
        private string GetPageDisplayName(string name)
        {
            var names = new System.Collections.Generic.Dictionary<string, string>
            {
                { "home", "主页" },
                { "scan", "病毒扫描" },
                { "protection", "实时防护" },
                { "network", "网络防护" },
                { "ransomware", "勒索防护" },
                { "privacy", "隐私保护" },
                { "parental", "家长控制" },
                { "web", "网页防护" },
                { "email", "邮件安全" },
                { "password", "密码管理" },
                { "firewall", "网络防火墙" },
                { "device", "设备控制" },
                { "vulnerability", "漏洞扫描" },
                { "cloud", "云查杀" },
                { "browser", "安全浏览器" },
                { "mobile", "移动安全" },
                { "optimizer", "系统优化" },
                { "backup", "备份恢复" },
                { "score", "安全评分" },
                { "traffic", "网络流量" },
                { "app", "应用监控" },
                { "startup", "启动管理" },
                { "report", "安全报告" },
                { "behavior", "行为分析" },
                { "tools", "系统工具" },
                { "systeminfo", "系统信息" },
                { "quarantine", "隔离区" },
                { "trust", "信任区" },
                { "logs", "日志中心" },
                { "settings", "设置" },
                { "about", "关于" },
                { "popup", "弹窗拦截" }
            };
            
            return names.TryGetValue(name, out string displayName) ? displayName : name;
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            }
            else
            {
                Background = new SolidColorBrush(Color.FromRgb(255, 255, 255));
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(255, 255, 255));
            }
        }
    }
}
