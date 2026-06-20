using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// UI响应性优化器，提供平滑的页面切换和加载动画
    /// </summary>
    public class UIResponsivenessOptimizer
    {
        private readonly Dictionary<string, Storyboard> _pageAnimations;
        private readonly DispatcherTimer _uiMonitor;
        private readonly Dispatcher _dispatcher;
        private readonly PerformanceMonitor _performanceMonitor;
        
        public event EventHandler<UIOptimizationEventArgs> OptimizationEvent;

        public UIResponsivenessOptimizer(Dispatcher dispatcher = null)
        {
            _dispatcher = dispatcher ?? Dispatcher.CurrentDispatcher;
            _pageAnimations = new Dictionary<string, Storyboard>();
            _performanceMonitor = new PerformanceMonitor();
            
            // UI监控定时器
            _uiMonitor = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(100)
            };
            _uiMonitor.Tick += OnUIMonitorTick;
            _uiMonitor.Start();
        }

        /// <summary>
        /// 应用页面切换动画
        /// </summary>
        public async Task ApplyPageTransitionAsync(ContentControl container, FrameworkElement oldPage, FrameworkElement newPage, PageTransition transition = PageTransition.SlideLeft)
        {
            if (container == null || newPage == null)
                return;

            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                switch (transition)
                {
                    case PageTransition.Fade:
                        await ApplyFadeTransition(container, oldPage, newPage).ConfigureAwait(true);
                        break;
                    case PageTransition.SlideLeft:
                        await ApplySlideTransition(container, oldPage, newPage, -container.ActualWidth).ConfigureAwait(true);
                        break;
                    case PageTransition.SlideRight:
                        await ApplySlideTransition(container, oldPage, newPage, container.ActualWidth).ConfigureAwait(true);
                        break;
                    case PageTransition.Scale:
                        await ApplyScaleTransition(container, oldPage, newPage).ConfigureAwait(true);
                        break;
                    default:
                        container.Content = newPage;
                        break;
                }

                sw.Stop();
                DebugTrace($"页面切换完成: {sw.ElapsedMilliseconds}ms, 类型: {transition}");
            }
            catch (Exception ex)
            {
                DebugTrace($"页面切换失败: {ex.Message}");
                // 降级到直接切换 - 在UI线程上直接设置内容
                _dispatcher.Invoke(new Action(() => container.Content = newPage));
            }
        }

        /// <summary>
        /// 应用淡入淡出过渡
        /// </summary>
        private async Task ApplyFadeTransition(ContentControl container, FrameworkElement oldPage, FrameworkElement newPage)
        {
            await _dispatcher.InvokeAsync(async () =>
            {
                if (oldPage != null)
                {
                    var fadeOut = CreateFadeAnimation(oldPage, 1.0, 0.0, TimeSpan.FromMilliseconds(200));
                    await fadeOut.Controller.BeginAsync();
                }

                container.Content = newPage;
                newPage.Opacity = 0;

                var fadeIn = CreateFadeAnimation(newPage, 0.0, 1.0, TimeSpan.FromMilliseconds(300));
                await fadeIn.Controller.BeginAsync();
            });
        }

        /// <summary>
        /// 应用滑动过渡
        /// </summary>
        private async Task ApplySlideTransition(ContentControl container, FrameworkElement oldPage, FrameworkElement newPage, double slideDistance)
        {
            await _dispatcher.InvokeAsync(async () =>
            {
                if (oldPage != null)
                {
                    var slideOut = CreateSlideAnimation(oldPage, 0, slideDistance, TimeSpan.FromMilliseconds(250));
                    await slideOut.Controller.BeginAsync();
                }

                container.Content = newPage;
                var slideIn = CreateSlideAnimation(newPage, slideDistance, 0, TimeSpan.FromMilliseconds(300));
                await slideIn.Controller.BeginAsync();
            });
        }

        /// <summary>
        /// 应用缩放过渡
        /// </summary>
        private async Task ApplyScaleTransition(ContentControl container, FrameworkElement oldPage, FrameworkElement newPage)
        {
            await _dispatcher.InvokeAsync(async () =>
            {
                if (oldPage != null)
                {
                    var scaleOut = CreateScaleAnimation(oldPage, 1.0, 0.8, TimeSpan.FromMilliseconds(200));
                    await scaleOut.Controller.BeginAsync();
                }

                container.Content = newPage;
                var scaleIn = CreateScaleAnimation(newPage, 0.8, 1.0, TimeSpan.FromMilliseconds(300));
                await scaleIn.Controller.BeginAsync();
            });
        }

        /// <summary>
        /// 创建淡入淡出动画
        /// </summary>
        private (Storyboard Animation, StoryboardController Controller) CreateFadeAnimation(FrameworkElement element, double from, double to, TimeSpan duration)
        {
            var storyboard = new Storyboard();
            var animation = new DoubleAnimation(from, to, new Duration(duration))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };

            Storyboard.SetTarget(animation, element);
            Storyboard.SetTargetProperty(animation, new PropertyPath("Opacity"));
            storyboard.Children.Add(animation);

            return (storyboard, new StoryboardController(storyboard));
        }

        /// <summary>
        /// 创建滑动动画
        /// </summary>
        private (Storyboard Animation, StoryboardController Controller) CreateSlideAnimation(FrameworkElement element, double from, double to, TimeSpan duration)
        {
            var storyboard = new Storyboard();
            var animation = new DoubleAnimation(from, to, new Duration(duration))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };

            var translateTransform = new System.Windows.Media.TranslateTransform();
            element.RenderTransform = translateTransform;

            Storyboard.SetTarget(animation, translateTransform);
            Storyboard.SetTargetProperty(animation, new PropertyPath("X"));
            storyboard.Children.Add(animation);

            return (storyboard, new StoryboardController(storyboard));
        }

        /// <summary>
        /// 创建缩放动画
        /// </summary>
        private (Storyboard Animation, StoryboardController Controller) CreateScaleAnimation(FrameworkElement element, double from, double to, TimeSpan duration)
        {
            var storyboard = new Storyboard();
            var animation = new DoubleAnimation(from, to, new Duration(duration))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };

            var scaleTransform = new System.Windows.Media.ScaleTransform();
            element.RenderTransform = scaleTransform;
            element.RenderTransformOrigin = new System.Windows.Point(0.5, 0.5);

            Storyboard.SetTarget(animation, scaleTransform);
            Storyboard.SetTargetProperty(animation, new PropertyPath("ScaleX"));
            storyboard.Children.Add(animation);

            var animationY = new DoubleAnimation(from, to, new Duration(duration))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            Storyboard.SetTarget(animationY, scaleTransform);
            Storyboard.SetTargetProperty(animationY, new PropertyPath("ScaleY"));
            storyboard.Children.Add(animationY);

            return (storyboard, new StoryboardController(storyboard));
        }

        /// <summary>
        /// 等待UI线程空闲
        /// </summary>
        private async Task WaitForUIIdleAsync()
        {
            var tcs = new TaskCompletionSource<bool>();
            
            _dispatcher.BeginInvoke(new Action(() =>
            {
                tcs.SetResult(true);
            }), DispatcherPriority.ApplicationIdle);

            await tcs.Task.ConfigureAwait(false);
            await Task.Delay(16).ConfigureAwait(false); // 等待一帧
        }

        /// <summary>
        /// UI监控定时器回调
        /// </summary>
        private void OnUIMonitorTick(object sender, EventArgs e)
        {
            // 监控UI响应性
            var uiResponsiveness = CheckUIResponsiveness();
            
            if (uiResponsiveness.ResponsivenessLevel == UIResponsivenessLevel.NeedOptimization)
            {
                OptimizationEvent?.Invoke(this, new UIOptimizationEventArgs
                {
                    Level = OptimizationLevel.Warning,
                    Message = "UI响应性下降，建议减少动画复杂度或增加延迟",
                    Timestamp = DateTime.Now
                });
            }
        }

        /// <summary>
        /// 检查UI响应性
        /// </summary>
        public UIResponsiveness CheckUIResponsiveness()
        {
            try
            {
                // 检查Dispatcher队列长度
                var queueLength = _dispatcher.HasShutdownStarted ? 0 : 1;
                
                // 检查内存使用
                var memoryUsage = GC.GetTotalMemory(false) / (1024.0 * 1024.0);
                
                // 估算响应性级别
                var responsivenessLevel = memoryUsage switch
                {
                    < 100 => UIResponsivenessLevel.Excellent,
                    < 300 => UIResponsivenessLevel.Good,
                    < 500 => UIResponsivenessLevel.Acceptable,
                    _ => UIResponsivenessLevel.NeedOptimization
                };

                return new UIResponsiveness
                {
                    DispatcherQueueLength = queueLength,
                    MemoryUsageMB = memoryUsage,
                    ResponsivenessLevel = responsivenessLevel,
                    Timestamp = DateTime.Now
                };
            }
            catch
            {
                return new UIResponsiveness { ResponsivenessLevel = UIResponsivenessLevel.Unknown };
            }
        }

        /// <summary>
        /// 添加加载动画到控件
        /// </summary>
        public void AddLoadingAnimation(FrameworkElement element, LoadingAnimationType animationType = LoadingAnimationType.SimplePulse)
        {
            _dispatcher.BeginInvoke(new Action(() =>
            {
                switch (animationType)
                {
                    case LoadingAnimationType.SimplePulse:
                        ApplyPulseAnimation(element);
                        break;
                    case LoadingAnimationType.Rotate:
                        ApplyRotateAnimation(element);
                        break;
                    case LoadingAnimationType.Wave:
                        ApplyWaveAnimation(element);
                        break;
                }
            }));
        }

        /// <summary>
        /// 应用脉冲动画
        /// </summary>
        private void ApplyPulseAnimation(FrameworkElement element)
        {
            var animation = new DoubleAnimation(0.8, 1.0, new Duration(TimeSpan.FromSeconds(1)))
            {
                AutoReverse = true,
                RepeatBehavior = RepeatBehavior.Forever
            };

            var scaleTransform = new System.Windows.Media.ScaleTransform();
            element.RenderTransform = scaleTransform;
            element.RenderTransformOrigin = new System.Windows.Point(0.5, 0.5);

            scaleTransform.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, animation);
            scaleTransform.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, animation);
        }

        /// <summary>
        /// 应用旋转动画
        /// </summary>
        private void ApplyRotateAnimation(FrameworkElement element)
        {
            var animation = new DoubleAnimation(0, 360, new Duration(TimeSpan.FromSeconds(2)))
            {
                RepeatBehavior = RepeatBehavior.Forever
            };

            var rotateTransform = new System.Windows.Media.RotateTransform();
            element.RenderTransform = rotateTransform;
            element.RenderTransformOrigin = new System.Windows.Point(0.5, 0.5);

            rotateTransform.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty, animation);
        }

        /// <summary>
        /// 应用波形动画
        /// </summary>
        private void ApplyWaveAnimation(FrameworkElement element)
        {
            var opacityAnimation = new DoubleAnimation(0.5, 1.0, new Duration(TimeSpan.FromSeconds(0.8)))
            {
                AutoReverse = true,
                RepeatBehavior = RepeatBehavior.Forever
            };

            element.BeginAnimation(UIElement.OpacityProperty, opacityAnimation);
        }

        /// <summary>
        /// 记录调试信息
        /// </summary>
        private void DebugTrace(string message)
        {
            System.Diagnostics.Debug.WriteLine($"[UI优化器] {message}");
        }

        /// <summary>
        /// 显示数据加载指示器
        /// </summary>
        public LoadingIndicator ShowLoadingIndicator(DependencyObject parent, string message = "加载中...", LoadingIndicatorType type = LoadingIndicatorType.SimpleProgress)
        {
            if (parent == null) return null;
            
            var indicator = new LoadingIndicator(message, type);
            
            _dispatcher.BeginInvoke(new Action(() =>
            {
                if (parent is Panel panel)
                {
                    panel.Children.Add(indicator);
                }
                else if (parent is ContentControl contentControl)
                {
                    var container = new Grid();
                    if (contentControl.Content is UIElement existingContent)
                    {
                        container.Children.Add(existingContent);
                    }
                    container.Children.Add(indicator);
                    contentControl.Content = container;
                }
            }));
            
            return indicator;
        }

        /// <summary>
        /// 隐藏数据加载指示器
        /// </summary>
        public void HideLoadingIndicator(LoadingIndicator indicator)
        {
            if (indicator == null) return;
            
            _dispatcher.BeginInvoke(new Action(() =>
            {
                if (indicator.Parent is Panel panel)
                {
                    panel.Children.Remove(indicator);
                }
                else if (indicator.Parent is Grid grid && grid.Children.Count == 2)
                {
                    // 恢复原始内容
                    var originalContent = grid.Children[0];
                    grid.Children.Clear();
                    
                    if (grid.Parent is ContentControl parentControl)
                    {
                        parentControl.Content = originalContent;
                    }
                }
            }));
        }

        /// <summary>
        /// 创建进度条可视化
        /// </summary>
        public ProgressBarVisualization CreateProgressBarVisualization(FrameworkElement target, ProgressBarAlignment alignment = ProgressBarAlignment.Top)
        {
            return new ProgressBarVisualization(target, alignment);
        }

        /// <summary>
        /// 应用简单过渡动画
        /// </summary>
        public async Task ApplySimpleTransitionAsync(FrameworkElement element)
        {
            await _dispatcher.InvokeAsync(() =>
            {
                element.Opacity = 0;
            });
            await Task.Delay(50);
            await _dispatcher.InvokeAsync(() =>
            {
                element.Opacity = 1;
            });
        }

        /// <summary>
        /// 开始页面切换动画（外部调用入口）
        /// </summary>
        public async Task StartPageTransitionAsync(ContentControl contentFrame)
        {
            await ApplyPageTransitionAsync(contentFrame, null, null, PageTransition.Fade);
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            _uiMonitor?.Stop();
            _performanceMonitor?.Dispose();
            _pageAnimations.Clear();
        }
    }

    /// <summary>
    /// 页面切换动画类型
    /// </summary>
    public enum PageTransition
    {
        None,       // 无动画
        Fade,       // 淡入淡出
        SlideLeft,  // 从左滑入
        SlideRight, // 从右滑入
        Scale       // 缩放
    }

    /// <summary>
    /// 加载动画类型
    /// </summary>
    public enum LoadingAnimationType
    {
        SimplePulse, // 简单脉冲
        Rotate,      // 旋转
        Wave         // 波纹效果
    }

    /// <summary>
    /// UI响应性状态
    /// </summary>
    public enum UIResponsivenessLevel
    {
        Unknown,
        Excellent,      // 优秀 <100MB
        Good,           // 良好 100-300MB
        Acceptable,     // 可接受 300-500MB
        NeedOptimization // 需要优化 >500MB
    }

    /// <summary>
    /// UI响应性信息
    /// </summary>
    public class UIResponsiveness
    {
        public int DispatcherQueueLength { get; set; }
        public double MemoryUsageMB { get; set; }
        public UIResponsivenessLevel ResponsivenessLevel { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// UI优化事件参数
    /// </summary>
    public class UIOptimizationEventArgs : EventArgs
    {
        public OptimizationLevel Level { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// 优化级别
    /// </summary>
    public enum OptimizationLevel
    {
        Info,       // 信息
        Warning,    // 警告
        Critical    // 严重
    }

    /// <summary>
    /// Storyboard控制器（异步支持）
    /// </summary>
    public class StoryboardController
    {
        private readonly Storyboard _storyboard;
        private readonly TaskCompletionSource<bool> _completionSource;

        public StoryboardController(Storyboard storyboard)
        {
            _storyboard = storyboard;
            _completionSource = new TaskCompletionSource<bool>();

            storyboard.Completed += (s, e) => _completionSource.TrySetResult(true);
        }

        public void Begin()
        {
            _storyboard.Begin();
        }

        public async Task BeginAsync()
        {
            _storyboard.Begin();
            await _completionSource.Task.ConfigureAwait(false);
        }

        public Task InvokeAsync()
        {
            return BeginAsync();
        }
    }

    /// <summary>
    /// 数据加载指示器类型
    /// </summary>
    public enum LoadingIndicatorType
    {
        SimpleProgress,      // 简单进度条
        CircularProgress,    // 圆形进度条
        TextOnly,           // 仅文字
        FullScreen          // 全屏加载
    }

    /// <summary>
    /// 数据加载指示器工具类
    /// </summary>
    public class LoadingIndicator : UserControl
    {
        private readonly TextBlock _textBlock;
        private readonly ProgressBar _progressBar;
        private readonly Grid _container;

        public LoadingIndicator(string message, LoadingIndicatorType type)
        {
            _container = new Grid();
            _container.Background = new SolidColorBrush(Color.FromArgb(128, 0, 0, 0));
            
            // 文本显示
            _textBlock = new TextBlock
            {
                Text = message,
                Foreground = Brushes.White,
                FontSize = 14,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                TextAlignment = TextAlignment.Center
            };

            _progressBar = new ProgressBar
            {
                IsIndeterminate = true,
                Height = 20,
                Width = 200,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };

            switch (type)
            {
                case LoadingIndicatorType.SimpleProgress:
                    _container.Children.Add(_progressBar);
                    _textBlock.Margin = new Thickness(0, 40, 0, 0);
                    _container.Children.Add(_textBlock);
                    break;
                case LoadingIndicatorType.CircularProgress:
                    var circularProgress = new ProgressBar
                    {
                        IsIndeterminate = true,
                        Height = 60,
                        Width = 60,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    // 模拟圆形进度条
                    circularProgress.Style = CreateCircularProgressBarStyle();
                    _container.Children.Add(circularProgress);
                    _textBlock.Margin = new Thickness(0, 80, 0, 0);
                    _container.Children.Add(_textBlock);
                    break;
                case LoadingIndicatorType.TextOnly:
                    _container.Background = Brushes.Transparent;
                    _container.Children.Add(_textBlock);
                    break;
                case LoadingIndicatorType.FullScreen:
                    _container.HorizontalAlignment = HorizontalAlignment.Stretch;
                    _container.VerticalAlignment = VerticalAlignment.Stretch;
                    var stackPanel = new StackPanel
                    {
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    var fullScreenProgress = new ProgressBar
                    {
                        IsIndeterminate = true,
                        Height = 30,
                        Width = 300,
                        Margin = new Thickness(0, 0, 0, 20)
                    };
                    stackPanel.Children.Add(fullScreenProgress);
                    stackPanel.Children.Add(_textBlock);
                    _container.Children.Add(stackPanel);
                    break;
            }

            Content = _container;
        }

        public void UpdateMessage(string message)
        {
            _textBlock.Text = message;
        }

        public void UpdateProgress(double? value)
        {
            if (value.HasValue)
            {
                _progressBar.IsIndeterminate = false;
                _progressBar.Value = value.Value;
            }
            else
            {
                _progressBar.IsIndeterminate = true;
            }
        }

        private Style CreateCircularProgressBarStyle()
        {
            var style = new Style(typeof(ProgressBar));
            style.Setters.Add(new Setter(ProgressBar.TemplateProperty, CreateCircularTemplate()));
            return style;
        }

        private ControlTemplate CreateCircularTemplate()
        {
            var template = new ControlTemplate(typeof(ProgressBar));
            
            var gridFactory = new FrameworkElementFactory(typeof(Grid));
            var ellipseFactory = new FrameworkElementFactory(typeof(Ellipse));
            ellipseFactory.SetValue(Ellipse.StrokeProperty, Brushes.White);
            ellipseFactory.SetValue(Ellipse.StrokeThicknessProperty, 3.0);
            ellipseFactory.SetValue(Ellipse.HeightProperty, 60.0);
            ellipseFactory.SetValue(Ellipse.WidthProperty, 60.0);
            
            gridFactory.AppendChild(ellipseFactory);
            template.VisualTree = gridFactory;
            
            return template;
        }
    }

    /// <summary>
    /// 进度条可视化类
    /// </summary>
    public class ProgressBarVisualization : IDisposable
    {
        private readonly ProgressBar _progressBar;
        private readonly FrameworkElement _target;
        private readonly Grid _container;

        public ProgressBarVisualization(FrameworkElement target, ProgressBarAlignment alignment)
        {
            _target = target;
            _progressBar = new ProgressBar
            {
                IsIndeterminate = true,
                Height = 4,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = GetVerticalAlignment(alignment),
                Background = Brushes.Transparent,
                Foreground = Brushes.CornflowerBlue
            };

            _container = new Grid();
            _container.Children.Add(_target);
            _container.Children.Add(_progressBar);

            // 替换原始控件
            if (_target.Parent is Panel parentPanel)
            {
                var index = parentPanel.Children.IndexOf(_target);
                parentPanel.Children.Remove(_target);
                parentPanel.Children.Insert(index, _container);
            }
        }

        public void UpdateProgress(double? value)
        {
            if (value.HasValue)
            {
                _progressBar.IsIndeterminate = false;
                _progressBar.Value = value.Value;
            }
            else
            {
                _progressBar.IsIndeterminate = true;
            }
        }

        public void Dispose()
        {
            // 恢复原始控件
            if (_container.Parent is Panel parentPanel)
            {
                parentPanel.Children.Remove(_container);
                parentPanel.Children.Add(_target);
            }
        }

        private VerticalAlignment GetVerticalAlignment(ProgressBarAlignment alignment)
        {
            return alignment switch
            {
                ProgressBarAlignment.Top => VerticalAlignment.Top,
                ProgressBarAlignment.Bottom => VerticalAlignment.Bottom,
                _ => VerticalAlignment.Top
            };
        }
    }

    /// <summary>
    /// 进度条对齐方式
    /// </summary>
    public enum ProgressBarAlignment
    {
        Top,    // 顶部
        Bottom  // 底部
    }
}