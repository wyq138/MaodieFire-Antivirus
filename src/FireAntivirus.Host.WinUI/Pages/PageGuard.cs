// 页面初始化兜底：管理器构造/模板解析失败时展示真实错误信息，保证页面永不闪退
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    internal static class PageGuard
    {
        public static UIElement BuildError(string pageTitle, System.Exception ex)
        {
            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                $"页面初始化失败 [{pageTitle}]: {ex}");

            var root = new StackPanel { Margin = new Thickness(24, 20, 24, 20), Spacing = 12 };
            root.Children.Add(new TextBlock
            {
                Text = pageTitle,
                FontSize = 24,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            });
            root.Children.Add(new InfoBar
            {
                IsOpen = true,
                IsClosable = false,
                Severity = InfoBarSeverity.Error,
                Title = "页面初始化失败",
                Message = $"{ex.Message}\n\n详细信息已写入日志，重试请切换页面后返回。"
            });
            return root;
        }
    }
}