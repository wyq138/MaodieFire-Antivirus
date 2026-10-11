// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace FireAntivirus.Host.WinUI
{
    public sealed partial class ThreatOverlayHost : UserControl
    {
        public sealed class ThreatItem
        {
            public string FilePath { get; set; }
            public string ThreatName { get; set; }
            public string Severity { get; set; }
            public string Confidence { get; set; }
        }

        // 处理动作回调（由页面注入，指向引擎真实隔离/删除/信任实现）
        public Action<string> OnQuarantine { get; set; }
        public Action<string> OnDelete { get; set; }
        public Action<string> OnTrust { get; set; }

        private readonly List<ThreatItem> _pending = new();
        private const int MaxVisible = 4;

        public ThreatOverlayHost()
        {
            InitializeComponent();
        }

        public void Show(ThreatItem threat)
        {
            if (threat == null) return;
            DispatcherQueue.TryEnqueue(() => AddCard(threat));
        }

        private void AddCard(ThreatItem threat)
        {
            try
            {
                while (ThreatStack.Children.Count >= MaxVisible)
                    ThreatStack.Children.RemoveAt(0);

                var severity = threat.Severity ?? "Medium";
                var accent = severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ||
                             severity.Equals("High", StringComparison.OrdinalIgnoreCase)
                    ? new SolidColorBrush(Windows.UI.Color.FromArgb(255, 239, 68, 68))
                    : new SolidColorBrush(Windows.UI.Color.FromArgb(255, 245, 158, 11));

                var pathBlock = new TextBlock
                {
                    Text = threat.FilePath ?? "",
                    Opacity = 0.75,
                    FontSize = 12,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    MaxLines = 2
                };

                var nameBlock = new TextBlock
                {
                    Text = threat.ThreatName ?? "未知威胁",
                    FontSize = 15,
                    FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                    Foreground = accent
                };

                var infoBlock = new TextBlock
                {
                    Text = $"严重性: {severity}    置信度: {threat.Confidence ?? "-"}",
                    Opacity = 0.65,
                    FontSize = 12,
                    Margin = new Thickness(0, 4, 0, 0)
                };

                var card = new Border
                {
                    Background = new SolidColorBrush(Windows.UI.Color.FromArgb(242, 28, 28, 30)),
                    BorderBrush = accent,
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(12),
                    Padding = new Thickness(16),
                    VerticalAlignment = VerticalAlignment.Bottom
                };

                var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 12, 0, 0) };

                Button Mk(string text, Action<string> handler)
                {
                    var b = new Button { Content = text, MinWidth = 72 };
                    b.Click += (s, e) =>
                    {
                        try { handler?.Invoke(threat.FilePath); } finally { RemoveCard(card); }
                    };
                    return b;
                }

                var del = Mk("删除", OnDelete);
                del.Background = accent;
                del.Foreground = new SolidColorBrush(Microsoft.UI.Colors.White);

                var panel = new StackPanel();
                panel.Children.Add(nameBlock);
                panel.Children.Add(pathBlock);
                panel.Children.Add(infoBlock);
                buttons.Children.Add(Mk("隔离", OnQuarantine));
                buttons.Children.Add(del);
                buttons.Children.Add(Mk("信任", OnTrust));
                buttons.Children.Add(Mk("忽略", _ => { }));
                panel.Children.Add(buttons);
                card.Child = panel;

                // 入场：轻量淡入（避免低配机卡顿的复杂动画）
                card.Opacity = 0;
                ThreatStack.Children.Add(card);
                var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(16) };
                double opacity = 0;
                timer.Tick += (s, e) =>
                {
                    opacity += 0.2;
                    card.Opacity = Math.Min(1.0, opacity);
                    if (opacity >= 1.0) timer.Stop();
                };
                timer.Start();
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "威胁弹窗显示失败: " + ex.Message);
            }
        }

        private void RemoveCard(Border card)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                try { ThreatStack.Children.Remove(card); }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WinUI 移除威胁卡片失败: " + ex.Message);
                }
            });
        }
    }
}


