// U盘防护悬浮窗（360 风格）：右下角贴边、无边框圆角悬浮卡、置顶、可拖动、主题感知。
// U 盘接入时弹出，实时展示自动扫描进度与结果；无威胁 10 秒自动关闭（有威胁保持等待用户处理）。
// 支持"安全弹出"（Shell COM 弹出动词，真实生效）。纯代码构建 UI。
using System;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;

namespace FireAntivirus.Host.WinUI
{
    public sealed class UsbGuardToast : Window
    {
        private static UsbGuardToast _current;

        private readonly string _driveRoot;
        private readonly DispatcherTimer _autoCloseTimer;
        private ProgressBar _progress;
        private TextBlock _status;
        private TextBlock _result;
        private TextBlock _closeGlyph;

        // 悬浮卡拖动状态（无边框窗口需自实现）
        private bool _dragging;
        private PointInt32 _dragStartWinPos;
        private Windows.Foundation.Point _dragStartPointer;

        public UsbGuardToast(string driveRoot, string volumeLabel)
        {
            _driveRoot = driveRoot;
            Title = "耄耋安全 - U盘防护";
            Closed += (_, _) => { if (_current == this) _current = null; };
            BuildUi(volumeLabel);
            ConfigureFloatingCard();

            // 无威胁时 10 秒自动关闭（有威胁保持等待用户处理）
            _autoCloseTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
            _autoCloseTimer.Tick += (_, _) => CloseToast();
        }

        /// <summary>无边框圆角悬浮卡：右下角贴边 + 置顶 + 去标题栏。</summary>
        private void ConfigureFloatingCard()
        {
            try
            {
                var area = DisplayArea.Primary.WorkArea;
                var size = new SizeInt32(380, 236);
                AppWindow.Resize(size);
                AppWindow.Move(new PointInt32(
                    area.Width - size.Width - 18,
                    area.Height - size.Height - 18));

                if (AppWindow.Presenter is OverlappedPresenter presenter)
                {
                    presenter.SetBorderAndTitleBar(false, false); // 360 式无边框悬浮卡
                    presenter.IsAlwaysOnTop = true;
                    presenter.IsResizable = false;
                    presenter.IsMaximizable = false;
                    presenter.IsMinimizable = false;
                }
            }
            catch { }
        }

        /// <summary>显示悬浮卡（同盘重复接入时复用现有窗口）。</summary>
        public static void Show(string driveRoot, string volumeLabel)
        {
            if (_current != null && _current._driveRoot == driveRoot)
            {
                return; // 已在展示中
            }

            try { _current?.Close(); } catch { }
            _current = new UsbGuardToast(driveRoot, volumeLabel);
            _current.Activate();
            _current._autoCloseTimer.Start();
        }

        /// <summary>后台线程通知扫描结果（切回 UI 线程更新）。</summary>
        public static void UpdateResult(string driveRoot, int scanned, int threats, int autoQuarantined)
        {
            var toast = _current;
            if (toast == null || toast._driveRoot != driveRoot) return;

            toast.DispatcherQueue.TryEnqueue(() =>
            {
                toast._autoCloseTimer.Stop(); // 已出结果，主计时器停：无威胁 8s 自动关，有威胁等用户
                toast.ShowResult(scanned, threats, autoQuarantined);
                if (threats == 0)
                {
                    var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(8) };
                    t.Tick += (_, _) => { t.Stop(); toast.CloseToast(); };
                    t.Start();
                }
            });
        }

        private void BuildUi(string volumeLabel)
        {
            var root = new Border
            {
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(18, 12, 18, 14)
            };
            // 主题感知（Window 无 ActualTheme，从根元素取）：深色深底浅字，浅色浅底
            bool dark = root.ActualTheme == ElementTheme.Dark;
            root.Background = new SolidColorBrush(dark
                ? Windows.UI.Color.FromArgb(255, 32, 32, 36)
                : Windows.UI.Color.FromArgb(255, 250, 250, 252));
            root.BorderBrush = new SolidColorBrush(dark
                ? Windows.UI.Color.FromArgb(120, 70, 130, 220)
                : Windows.UI.Color.FromArgb(90, 0, 122, 204));

            var panel = new StackPanel { Spacing = 9 };

            // 标题行：盾牌图标 + "U盘防护" + 关闭按钮（此行可拖动整卡）
            var titleRow = new Grid { ColumnSpacing = 8 };
            titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleStack = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            titleStack.Children.Add(new FontIcon
            {
                Glyph = "\uE72E",
                Foreground = new SolidColorBrush(Colors.DodgerBlue),
                FontSize = 18
            });
            titleStack.Children.Add(new TextBlock
            {
                Text = "U盘防护",
                FontSize = 15,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            });
            Grid.SetColumn(titleStack, 0);
            titleRow.Children.Add(titleStack);

            _closeGlyph = new TextBlock
            {
                Text = "\uE711", // ChromeClose
                FontSize = 12,
                Opacity = 0.6,
                VerticalAlignment = VerticalAlignment.Center
            };
            var closeBtn = new Button
            {
                Content = _closeGlyph,

                Padding = new Thickness(6, 2, 6, 2),
                MinWidth = 0,
                MinHeight = 0,
                BorderThickness = new Thickness(0)
            };
            closeBtn.Click += (_, _) => CloseToast();
            Grid.SetColumn(closeBtn, 1);
            titleRow.Children.Add(closeBtn);

            // 标题行整行可拖动悬浮卡
            titleRow.PointerPressed += TitleRow_PointerPressed;
            titleRow.PointerMoved += TitleRow_PointerMoved;
            titleRow.PointerReleased += TitleRow_PointerReleased;

            panel.Children.Add(titleRow);

            // 检测信息
            panel.Children.Add(new TextBlock
            {
                Text = $"检测到 U 盘已接入：{volumeLabel} ({_driveRoot})",
                FontSize = 13,
                TextWrapping = TextWrapping.Wrap
            });

            _status = new TextBlock
            {
                Text = "正在自动扫描 U 盘中的可执行与脚本文件...",
                FontSize = 12,
                Opacity = 0.7,
                TextWrapping = TextWrapping.Wrap
            };
            panel.Children.Add(_status);

            _progress = new ProgressBar { IsIndeterminate = true, Height = 3 };
            panel.Children.Add(_progress);

            _result = new TextBlock
            {
                FontSize = 13,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap,
                Visibility = Visibility.Collapsed
            };
            panel.Children.Add(_result);

            // 按钮行
            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, Margin = new Thickness(0, 4, 0, 0) };

            var ejectBtn = new Button { Content = "安全弹出", MinWidth = 100 };
            ejectBtn.Click += (_, _) =>
            {
                UsbGuard.SafeEject(_driveRoot);
                CloseToast();
            };
            btnRow.Children.Add(ejectBtn);

            var okBtn = new Button { Content = "知道了", MinWidth = 90, Style = (Style)Application.Current.Resources["AccentButtonStyle"] };
            okBtn.Click += (_, _) => CloseToast();
            btnRow.Children.Add(okBtn);

            panel.Children.Add(btnRow);
            root.Child = panel;
            Content = root;
        }

        // ---- 悬浮卡拖动 ----

        private void TitleRow_PointerPressed(object sender, PointerRoutedEventArgs e)
        {
            if (e.GetCurrentPoint((UIElement)sender).Properties.IsLeftButtonPressed)
            {
                _dragging = true;
                _dragStartPointer = e.GetCurrentPoint(null).Position;
                _dragStartWinPos = AppWindow.Position;
                ((UIElement)sender).CapturePointer(e.Pointer);
            }
        }

        private void TitleRow_PointerMoved(object sender, PointerRoutedEventArgs e)
        {
            if (!_dragging) return;
            var p = e.GetCurrentPoint(null).Position;
            AppWindow.Move(new PointInt32(
                _dragStartWinPos.X + (int)(p.X - _dragStartPointer.X),
                _dragStartWinPos.Y + (int)(p.Y - _dragStartPointer.Y)));
        }

        private void TitleRow_PointerReleased(object sender, PointerRoutedEventArgs e)
        {
            _dragging = false;
            try { ((UIElement)sender).ReleasePointerCapture(e.Pointer); } catch { }
        }

        private void ShowResult(int scanned, int threats, int autoQuarantined)
        {
            _progress.IsIndeterminate = false;
            _progress.Visibility = Visibility.Collapsed;

            _status.Text = "扫描完成";
            _result.Visibility = Visibility.Visible;

            if (threats == 0)
            {
                _result.Text = $"✓ 扫描完成：{scanned} 个文件，未发现威胁，U 盘安全";
                _result.Foreground = new SolidColorBrush(Colors.ForestGreen);
            }
            else
            {
                _result.Text = $"⚠ 发现 {threats} 个威胁（已自动隔离 {autoQuarantined} 个），详见隔离区";
                _result.Foreground = new SolidColorBrush(Colors.OrangeRed);
            }
        }

        private void CloseToast()
        {
            try { _autoCloseTimer.Stop(); } catch { }
            try { Close(); } catch { }
        }
    }
}