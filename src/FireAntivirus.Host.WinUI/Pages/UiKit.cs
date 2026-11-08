// UiKit —— 全局简洁风组件库（所有页面统一视觉语言）：
//   单色图标 / 半透明卡片 / 细边框 / 克制留白 / 单一强调色
// 规则：不放彩色渐变、不用彩色图标容器；强调色仅用于主按钮与状态点。
using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;

namespace FireAntivirus.Host.WinUI.Pages
{
    internal static class UiKit
    {
        /// <summary>
        /// 从输出目录 Assets 加载图片（unpackaged WinUI 不依赖 ms-appx：
        /// 直接读文件 → InMemoryRandomAccessStream → BitmapImage，任何启动方式都可靠）。
        /// </summary>
        public static async System.Threading.Tasks.Task<ImageSource> LoadAssetAsync(string fileName)
        {
            try
            {
                string path = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", fileName);
                if (!System.IO.File.Exists(path)) return null;

                byte[] bytes = System.IO.File.ReadAllBytes(path);
                var stream = new Windows.Storage.Streams.InMemoryRandomAccessStream();
                using (var writer = new Windows.Storage.Streams.DataWriter(stream))
                {
                    writer.WriteBytes(bytes);
                    await writer.StoreAsync();
                    await writer.FlushAsync();
                    writer.DetachStream();
                }
                stream.Seek(0);

                var bitmap = new Microsoft.UI.Xaml.Media.Imaging.BitmapImage();
                await bitmap.SetSourceAsync(stream);
                return bitmap;
            }
            catch { return null; }
        }
        // ---- 简洁风调色板（真正跟随系统明暗主题的中性色，仅主按钮/状态点用强调色） ----
        private static bool IsDark =>
            Application.Current.RequestedTheme == ApplicationTheme.Dark;

        // 主文字：深色主题白系，浅色主题深灰系（标准 WinUI 前景色对齐）
        public static SolidColorBrush TextPrimary => IsDark
            ? new(Windows.UI.Color.FromArgb(235, 255, 255, 255))
            : new(Windows.UI.Color.FromArgb(235, 32, 33, 36));

        // 次要文字
        public static SolidColorBrush TextSecondary => IsDark
            ? new(Windows.UI.Color.FromArgb(150, 255, 255, 255))
            : new(Windows.UI.Color.FromArgb(150, 60, 62, 66));

        // 图标前景
        public static SolidColorBrush IconFg => IsDark
            ? new(Windows.UI.Color.FromArgb(140, 128, 128, 128))
            : new(Windows.UI.Color.FromArgb(140, 96, 97, 100));

        // 卡片底/边框/分隔线：半透明中性色在两个主题下都成立
        public static SolidColorBrush CardBg =>
            new(Windows.UI.Color.FromArgb(8, 128, 128, 128));
        public static SolidColorBrush CardBorder =>
            new(Windows.UI.Color.FromArgb(22, 128, 128, 128));
        public static SolidColorBrush Accent = new(Windows.UI.Color.FromArgb(255, 99, 102, 241)); // 靛蓝 #6366F1
        public static readonly SolidColorBrush Ok = new(Windows.UI.Color.FromArgb(255, 34, 197, 94));
        public static readonly SolidColorBrush Warn = new(Windows.UI.Color.FromArgb(255, 234, 179, 8));
        public static readonly SolidColorBrush Danger = new(Windows.UI.Color.FromArgb(255, 239, 68, 68));

        /// <summary>页面大标题。</summary>
        public static TextBlock PageTitle(string text) => new()
        {
            Text = text,
            FontSize = 22,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            Foreground = TextPrimary
        };

        /// <summary>分节小标题（字距 + 半透明）。</summary>
        public static TextBlock Section(string text) => new()
        {
            Text = text,
            FontSize = 12,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            Opacity = 0.5,
            Margin = new Thickness(2, 4, 0, -4)
        };

        /// <summary>简洁卡片（单色半透明底 + 细边框 + 圆角 10）。</summary>
        public static Border Card(UIElement content, Thickness? padding = null) => new()
        {
            Background = CardBg,
            BorderBrush = CardBorder,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(10),
            Padding = padding ?? new Thickness(14, 12, 14, 12),
            Child = content
        };

        /// <summary>
        /// 简洁行：单色图标 + 标题/描述 + 右侧元素（开关/按钮/徽章）。
        /// </summary>
        public static Grid Row(string glyph, string title, string subtitle, FrameworkElement trailing = null)
        {
            var grid = new Grid { ColumnSpacing = 14 };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            if (trailing != null)
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            grid.Children.Add(new FontIcon
            {
                Glyph = glyph,
                FontSize = 18,
                Foreground = IconFg,
                VerticalAlignment = VerticalAlignment.Center
            });

            var text = new StackPanel { Spacing = 2, VerticalAlignment = VerticalAlignment.Center };
            text.Children.Add(new TextBlock
            {
                Text = title,
                FontSize = 14,
                FontWeight = Microsoft.UI.Text.FontWeights.Normal,
                Foreground = TextPrimary
            });
            if (!string.IsNullOrEmpty(subtitle))
            {
                text.Children.Add(new TextBlock
                {
                    Text = subtitle,
                    FontSize = 12,
                    Foreground = TextSecondary,
                    TextWrapping = TextWrapping.Wrap
                });
            }
            Grid.SetColumn(text, 1);
            grid.Children.Add(text);

            if (trailing != null)
            {
                trailing.VerticalAlignment = VerticalAlignment.Center;
                Grid.SetColumn(trailing, 2);
                grid.Children.Add(trailing);
            }

            return grid;
        }

        /// <summary>简洁分隔线（卡片内行间）。</summary>
        public static FrameworkElement Divider() => new Border
        {
            Height = 1,
            Background = IsDark
                ? new SolidColorBrush(Windows.UI.Color.FromArgb(14, 128, 128, 128))
                : new SolidColorBrush(Windows.UI.Color.FromArgb(18, 60, 62, 66)),
            Margin = new Thickness(0, 4, 0, 4)
        };

        /// <summary>主按钮（唯一强调色使用者）。</summary>
        public static Button Primary(string text) => new()
        {
            Content = text,
            MinWidth = 108,
            Style = (Style)Application.Current.Resources["AccentButtonStyle"],
            CornerRadius = new CornerRadius(6)
        };

        /// <summary>次按钮（默认样式 + 圆角）。</summary>
        public static Button Secondary(string text) => new()
        {
            Content = text,
            MinWidth = 96,
            CornerRadius = new CornerRadius(6)
        };

        /// <summary>状态徽章（小圆点 + 文本）。</summary>
        public static StackPanel StatusBadge(bool ok, string text)
        {
            var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, VerticalAlignment = VerticalAlignment.Center };
            panel.Children.Add(new Ellipse
            {
                Width = 7,
                Height = 7,
                Fill = ok ? Ok : Warn,
                VerticalAlignment = VerticalAlignment.Center
            });
            panel.Children.Add(new TextBlock
            {
                Text = text,
                FontSize = 12,
                Foreground = TextSecondary,
                VerticalAlignment = VerticalAlignment.Center
            });
            return panel;
        }

        /// <summary>主开关（简洁尺寸）。</summary>
        public static ToggleSwitch Toggle(bool isOn, RoutedEventHandler onToggled) => new()
        {
            OnContent = "",
            OffContent = "",
            IsOn = isOn,
            Margin = new Thickness(0, 0, -60, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
    }
}