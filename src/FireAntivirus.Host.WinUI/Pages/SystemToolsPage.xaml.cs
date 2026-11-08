// 系统工具（聚合页）：系统优化 + 垃圾清理 + 启动项管理 合并入口。
using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class SystemToolsPage : Page
    {
        public SystemToolsPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                var tabs = new TabView { IsAddTabButtonVisible = false };
                tabs.TabItems.Add(new TabViewItem { Header = "系统优化", Content = new OptimizePage(), IsClosable = false });
                tabs.TabItems.Add(new TabViewItem { Header = "垃圾清理", Content = new CleanPage(), IsClosable = false });
                tabs.TabItems.Add(new TabViewItem { Header = "启动项管理", Content = new StartupPage(), IsClosable = false });
                Content = tabs;
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("系统工具", ex);
            }
        }
    }
}