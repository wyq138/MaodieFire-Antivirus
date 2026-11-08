// 隔离与信任（聚合页）：隔离区 + 信任区 合并入口。
using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class QuarantineCenterPage : Page
    {
        public QuarantineCenterPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                var tabs = new TabView { IsAddTabButtonVisible = false };
                tabs.TabItems.Add(new TabViewItem { Header = "隔离区", Content = new QuarantinePage(), IsClosable = false });
                tabs.TabItems.Add(new TabViewItem { Header = "信任区", Content = new TrustZonePage(), IsClosable = false });
                Content = tabs;
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("隔离与信任", ex);
            }
        }
    }
}