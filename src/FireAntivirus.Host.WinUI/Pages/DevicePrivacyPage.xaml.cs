// 设备与隐私（聚合页）：设备控制 + 隐私保护 + 家长控制。
// 独立容错：每个 Tab 单独 try-catch，单个子页失败不影响其他 Tab。
using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class DevicePrivacyPage : Page
    {
        public DevicePrivacyPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                var tabs = new TabView { IsAddTabButtonVisible = false };
                AddTabSafe(tabs, "设备控制", () => new DeviceControlPage());
                AddTabSafe(tabs, "隐私保护", () => new PrivacyProtectionPage());
                AddTabSafe(tabs, "家长控制", () => new ParentalControlPage());
                Content = tabs;
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("设备与隐私", ex);
            }
        }

        private static void AddTabSafe(TabView tabs, string header, Func<Page> factory)
        {
            Page page = null;
            try { page = factory(); }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    $"[聚合页] {header} 初始化失败: {ex}");
                page = new Page
                {
                    Content = new TextBlock
                    {
                        Text = $"「{header}」初始化失败：{ex.Message}\n\n详细信息已写入日志，其余标签页不受影响。",
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(24)
                    }
                };
            }
            tabs.TabItems.Add(new TabViewItem { Header = header, Content = page, IsClosable = false });
        }
    }
}