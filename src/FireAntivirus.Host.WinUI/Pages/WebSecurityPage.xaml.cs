// 网页与邮件安全（聚合页）：网页防护 + 弹窗拦截 + 邮件安全。
// 独立容错：每个 Tab 单独 try-catch，单个子页初始化失败只影响该 Tab，不再整页"加载失败"。
using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class WebSecurityPage : Page
    {
        public WebSecurityPage()
        {
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;
            try
            {
                var tabs = new TabView { IsAddTabButtonVisible = false };
                AddTabSafe(tabs, "网页防护", () => new WebProtectionPage());
                AddTabSafe(tabs, "弹窗拦截", () => new PopupBlockerPage());
                AddTabSafe(tabs, "邮件安全", () => new EmailSecurityPage());
                Content = tabs;
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("网页与邮件安全", ex);
            }
        }

        private static void AddTabSafe(TabView tabs, string header, Func<Page> factory)
        {
            Page page = null;
            string error = null;
            try { page = factory(); }
            catch (Exception ex)
            {
                error = ex.Message;
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