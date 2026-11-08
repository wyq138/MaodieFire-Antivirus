// 威胁处置窗口（对标 XIGUASecurity 10x 的独立处置窗口，用户明确要求不再用系统 Toast/应用内浮层）：
//   · 独立无边框窗口：置顶、不占任务栏、右下角、可拖动标题行、主题感知（参照其 420x240/无装饰/透明阴影/置顶属性）
//   · 预创建复用：首次 Show 创建，隐藏不销毁；静态 pending 数据兜底（对应西瓜的 PENDING_*_DATA）
//   · 真实按钮：隔离（QuarantineStore 落库）/ 忽略（白名单入库）/ 打开位置
//   · 文件被活动进程占用（隔离失败）时，追加两方案（照搬其 active_threat 机制）：
//       重启时清除（MoveFileEx DELAY_UNTIL_REBOOT / PendingFileRenameOperations 回退）
//       结束占用进程并清除（Restart Manager 定位 → 终止 → 重试删除）
using System;
using System.Diagnostics;
using System.IO;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;

namespace FireAntivirus.Host.WinUI
{
    public sealed class ThreatDealWindow : Window
    {
        private static ThreatDealWindow _instance;
        private static readonly object _sync = new object();
        private static (string Path, string Name, string Severity, bool CanQuarantine)? _pending;

        private readonly TextBlock _titleText;
        private readonly TextBlock _detailText;
        private readonly TextBlock _stateText;
        private readonly StackPanel _lockPanel;
        private readonly Button _quarantineBtn;
        private string _currentPath;
        private string _currentName;
        private string _currentSeverity;

        private bool _dragging;
        private PointInt32 _dragStartWinPos;
        private Windows.Foundation.Point _dragStartPointer;

        /// <summary>显示威胁处置窗口（线程安全；可在任意线程调用）。</summary>
        public static void Show(string filePath, string threatName, string severity, bool canQuarantine = true)
        {
            lock (_sync)
            {
                _pending = (filePath ?? "", string.IsNullOrWhiteSpace(threatName) ? "未知威胁" : threatName,
                            string.IsNullOrWhiteSpace(severity) ? "High" : severity, canQuarantine);
                try
                {
                    if (_instance == null)
                    {
                        _instance = new ThreatDealWindow();
                        _instance.Closed += (_, _) => { lock (_sync) { _instance = null; } };
                    }
                    _instance.Activate();
                    _instance.FillFromPending();
                    _instance.PlaceBottomRight();
                }
                catch { }
            }
        }

        private ThreatDealWindow()
        {
            Title = "威胁处置";
            try
            {
                if (AppWindow.Presenter is OverlappedPresenter p)
                {
                    p.SetBorderAndTitleBar(false, false);   // 无边框
                    p.IsAlwaysOnTop = true;                  // 置顶
                    p.IsResizable = false;
                    p.IsMaximizable = false;
                    p.IsMinimizable = false;
                }
                AppWindow.Resize(new SizeInt32(440, 300));
            }
            catch { }

            var root = new Border
            {
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(20, 14, 20, 16)
            };
            bool dark = root.ActualTheme == ElementTheme.Dark;
            root.Background = new SolidColorBrush(dark
                ? Windows.UI.Color.FromArgb(255, 30, 30, 34)
                : Windows.UI.Color.FromArgb(255, 250, 250, 252));
            root.BorderBrush = new SolidColorBrush(Windows.UI.Color.FromArgb(110, 220, 60, 40));

            var panel = new StackPanel { Spacing = 10 };

            // 标题行（可拖动）
            var titleRow = new Grid { ColumnSpacing = 8 };
            titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            titleRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleStack = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            titleStack.Children.Add(new FontIcon
            {
                Glyph = "\uE7BA",
                Foreground = new SolidColorBrush(Colors.OrangeRed),
                FontSize = 18
            });
            _titleText = new TextBlock
            {
                Text = "发现威胁",
                FontSize = 15,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                TextWrapping = TextWrapping.Wrap
            };
            titleStack.Children.Add(_titleText);
            Grid.SetColumn(titleStack, 0);
            titleRow.Children.Add(titleStack);

            var closeBtn = new Button
            {
                Content = new TextBlock { Text = "\uE711", FontSize = 12, Opacity = 0.6 },
                Padding = new Thickness(6, 2, 6, 2), MinWidth = 0, MinHeight = 0,
                BorderThickness = new Thickness(0)
            };
            closeBtn.Click += (_, _) => CloseToast();
            Grid.SetColumn(closeBtn, 1);
            titleRow.Children.Add(closeBtn);

            titleRow.PointerPressed += TitleRow_PointerPressed;
            titleRow.PointerMoved += TitleRow_PointerMoved;
            titleRow.PointerReleased += TitleRow_PointerReleased;
            panel.Children.Add(titleRow);

            // 详情（威胁名 + 路径 + 等级）
            _detailText = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12, Opacity = 0.85 };
            panel.Children.Add(_detailText);

            _stateText = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12, Opacity = 0.7 };
            panel.Children.Add(_stateText);

            // 处置按钮行
            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            _quarantineBtn = new Button { Content = "隔离", MinWidth = 88 };
            _quarantineBtn.Click += (_, _) => DoQuarantine();
            btnRow.Children.Add(_quarantineBtn);

            var ignoreBtn = new Button { Content = "忽略", MinWidth = 88 };
            ignoreBtn.Click += (_, _) => DoIgnore();
            btnRow.Children.Add(ignoreBtn);

            var openBtn = new Button { Content = "打开位置", MinWidth = 96 };
            openBtn.Click += (_, _) => DoOpenLocation();
            btnRow.Children.Add(openBtn);

            var okBtn = new Button { Content = "关闭", MinWidth = 76 };
            okBtn.Click += (_, _) => CloseToast();
            btnRow.Children.Add(okBtn);
            panel.Children.Add(btnRow);

            // 被占用时的两方案（默认隐藏，隔离失败时显示）
            _lockPanel = new StackPanel { Spacing = 8, Visibility = Visibility.Collapsed };
            _lockPanel.Children.Add(new TextBlock
            {
                Text = "文件被活动进程占用，无法直接隔离/删除。请选择清除方案：",
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Opacity = 0.85
            });
            var lockBtnRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            var rebootBtn = new Button { Content = "重启时清除", MinWidth = 110 };
            rebootBtn.Click += (_, _) => DoScheduleRebootDelete();
            lockBtnRow.Children.Add(rebootBtn);
            var killBtn = new Button { Content = "结束占用进程并清除", MinWidth = 160 };
            killBtn.Click += (_, _) => DoKillLocksAndDelete();
            lockBtnRow.Children.Add(killBtn);
            _lockPanel.Children.Add(lockBtnRow);
            panel.Children.Add(_lockPanel);

            root.Child = panel;
            Content = root;
        }

        private void FillFromPending()
        {
            (string Path, string Name, string Severity, bool CanQuarantine)? data;
            lock (_sync) data = _pending;
            if (data == null) return;

            var d = data.Value;
            _currentPath = d.Path;
            _currentName = d.Name;
            _currentSeverity = d.Severity;

            _titleText.Text = $"发现威胁（{d.Severity}）：{d.Name}";
            _detailText.Text = "路径: " + (string.IsNullOrEmpty(d.Path) ? "-" : d.Path);
            _stateText.Text = "请选择处置方式";
            _stateText.Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 140, 140, 140));
            _quarantineBtn.IsEnabled = d.CanQuarantine && !string.IsNullOrEmpty(d.Path) && File.Exists(d.Path);
            _lockPanel.Visibility = Visibility.Collapsed;
        }

        private void PlaceBottomRight()
        {
            try
            {
                var area = DisplayArea.Primary.WorkArea;
                AppWindow.Move(new PointInt32(area.Width - 440 - 18, area.Height - 300 - 18));
            }
            catch { }
        }

        // ---- 真实处置动作 ----

        private void DoQuarantine()
        {
            if (string.IsNullOrEmpty(_currentPath)) return;
            if (QuarantineStore.Quarantine(_currentPath, _currentName, _currentSeverity, out var err))
            {
                SetState("已隔离（可在隔离区查看与还原）", success: true);
                HideAfterDelay();
                return;
            }

            // 失败：若为占用/拒绝访问 → 展示两方案（真实系统机制，非假装成功）
            SetState("隔离失败：" + err, success: false);
            if (File.Exists(_currentPath))
                _lockPanel.Visibility = Visibility.Visible;
        }

        private void DoIgnore()
        {
            if (string.IsNullOrEmpty(_currentPath)) { CloseToast(); return; }
            FireAntivirus.Engine.WhitelistStore.RememberFile(_currentPath);
            SetState("已忽略：文件已加入清白哈希库，此后不再告警", success: true);
            HideAfterDelay();
        }

        private void DoOpenLocation()
        {
            try
            {
                if (string.IsNullOrEmpty(_currentPath)) return;
                if (File.Exists(_currentPath))
                {
                    Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + _currentPath + "\"")
                    { UseShellExecute = true });
                }
                else
                {
                    var dir = Path.GetDirectoryName(_currentPath);
                    if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                        Process.Start(new ProcessStartInfo(dir) { UseShellExecute = true });
                }
            }
            catch { }
        }

        private void DoScheduleRebootDelete()
        {
            if (string.IsNullOrEmpty(_currentPath)) return;
            if (FireAntivirus.Engine.ActiveThreatHandler.ScheduleDeleteOnReboot(_currentPath, out var err))
            {
                SetState("已标记为“下次重启时删除”（重启后由系统在早期清除，不会再次被占用）", success: true);
                _lockPanel.Visibility = Visibility.Collapsed;
                HideAfterDelay();
            }
            else
            {
                SetState("重启清除标记失败: " + err, success: false);
            }
        }

        private void DoKillLocksAndDelete()
        {
            if (string.IsNullOrEmpty(_currentPath)) return;
            SetState("正在通过 Restart Manager 定位占用进程并清除...", success: true);
            _ = System.Threading.Tasks.Task.Run(() =>
            {
                bool ok = FireAntivirus.Engine.ActiveThreatHandler.KillLocksAndDelete(_currentPath, out var err);
                DispatcherQueue.TryEnqueue(() =>
                {
                    if (ok)
                    {
                        SetState("已结束占用进程并彻底清除该文件", success: true);
                        _lockPanel.Visibility = Visibility.Collapsed;
                        HideAfterDelay();
                    }
                    else
                    {
                        SetState("清除失败: " + err, success: false);
                    }
                });
            });
        }

        private void SetState(string text, bool success)
        {
            _stateText.Text = text;
            _stateText.Foreground = new SolidColorBrush(success
                ? Windows.UI.Color.FromArgb(255, 34, 139, 34)
                : Windows.UI.Color.FromArgb(255, 220, 60, 40));
        }

        private void HideAfterDelay()
        {
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            timer.Tick += (_, _) => { timer.Stop(); CloseToast(); };
            timer.Start();
        }

        private void CloseToast()
        {
            try { AppWindow.Hide(); }
            catch { try { Close(); } catch { } }
        }

        // ---- 拖动 ----
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
    }
}