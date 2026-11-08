// 安全中心（聚合页）：安全报告 + 安全评分 合并入口（TabView 容器，复用现有页面实例）。
using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class SecurityCenterPage : Page
    {
        public SecurityCenterPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                var tabs = new TabView { IsAddTabButtonVisible = false };
                tabs.TabItems.Add(new TabViewItem { Header = "安全报告", Content = new ReportPage(), IsClosable = false });
                tabs.TabItems.Add(new TabViewItem { Header = "安全评分", Content = new SecurityScorePage(), IsClosable = false });
                Content = tabs;
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("安全中心", ex);
            }
        }
    }
}