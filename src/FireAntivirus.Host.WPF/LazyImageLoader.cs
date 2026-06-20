using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// 图像懒加载器 - 专为WPF优化设计的图像异步加载组件
    /// </summary>
    public class LazyImageLoader : IDisposable
    {
        private static readonly LazyImageLoader _instance = new LazyImageLoader();
        public static LazyImageLoader Instance => _instance;

        private readonly ConcurrentDictionary<string, LazyImageInfo> _imageCache;
        private readonly ConcurrentQueue<ImageLoadTask> _loadQueue;
        private readonly Dispatcher _dispatcher;
        private readonly object _queueLock = new object();
        private bool _isLoading = false;
        private bool _disposed = false;

        // 加载任务优先级
        public enum LoadPriority
        {
            Low = 0,
            Normal = 1,
            High = 2,
            Critical = 3
        }

        public LazyImageLoader()
        {
            _imageCache = new ConcurrentDictionary<string, LazyImageInfo>();
            _loadQueue = new ConcurrentQueue<ImageLoadTask>();
            _dispatcher = Dispatcher.CurrentDispatcher;
            
            // 启动队列处理器
            StartQueueProcessor();
        }

        /// <summary>
        /// 异步懒加载图像
        /// </summary>
        public async Task LoadImageAsync(Image imageControl, string imagePath, 
            LazyImageOptions options = null)
        {
            if (imageControl == null || string.IsNullOrEmpty(imagePath) || _disposed)
                return;

            options ??= new LazyImageOptions();

            // 检查缓存
            if (await TryLoadFromCacheAsync(imageControl, imagePath, options))
                return;

            // 添加到加载队列
            var loadTask = new ImageLoadTask
            {
                ImageControl = imageControl,
                ImagePath = imagePath,
                Options = options,
                Priority = options.Priority
            };

            _loadQueue.Enqueue(loadTask);
            
            // 显示加载占位符
            await ShowLoadingPlaceholderAsync(imageControl, options);
        }

        /// <summary>
        /// 预加载图像到缓存
        /// </summary>
        public async Task PreloadImageAsync(string imagePath, BitmapCompressionOptions compressionOptions = null)
        {
            if (string.IsNullOrEmpty(imagePath) || _disposed)
                return;

            compressionOptions ??= new BitmapCompressionOptions();

            // 如果已经在缓存中，直接返回
            if (_imageCache.ContainsKey(imagePath))
                return;

            // 异步预加载
            await Task.Run(() => PreloadImageInternal(imagePath, compressionOptions));
        }

        /// <summary>
        /// 预加载图像集合
        /// </summary>
        public async Task PreloadImagesAsync(string[] imagePaths, Action<int, int> progressCallback = null)
        {
            if (imagePaths == null || _disposed)
                return;

            var total = imagePaths.Length;
            var completed = 0;

            foreach (var path in imagePaths)
            {
                if (_disposed) break;

                try
                {
                    await PreloadImageAsync(path);
                    completed++;
                    progressCallback?.Invoke(completed, total);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"预加载图像失败 {path}: {ex.Message}");
                }

                // 防止过度占用资源
                await Task.Delay(5);
            }
        }

        /// <summary>
        /// 清除缓存
        /// </summary>
        public void ClearCache(ImageCacheClearMode mode = ImageCacheClearMode.Normal)
        {
            switch (mode)
            {
                case ImageCacheClearMode.Normal:
                    // 清除长时间未使用的缓存项
                    var currentTime = DateTime.Now;
                    foreach (var kvp in _imageCache)
                    {
                        if ((currentTime - kvp.Value.LastAccessTime).TotalMinutes > 30)
                        {
                            _imageCache.TryRemove(kvp.Key, out _);
                        }
                    }
                    break;
                
                case ImageCacheClearMode.Aggressive:
                    _imageCache.Clear();
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    break;
                
                case ImageCacheClearMode.All:
                    _imageCache.Clear();
                    // 强制垃圾回收
                    for (int i = 0; i < 3; i++)
                    {
                        GC.Collect();
                        GC.WaitForPendingFinalizers();
                    }
                    break;
            }
        }

        /// <summary>
        /// 获取缓存统计信息
        /// </summary>
        public ImageCacheStatistics GetCacheStatistics()
        {
            var stats = new ImageCacheStatistics();

            foreach (var kvp in _imageCache)
            {
                stats.TotalCachedImages++;
                stats.TotalMemoryBytes += kvp.Value.MemorySize;
                
                if (kvp.Value.HitCount > stats.MostAccessedHitCount)
                {
                    stats.MostAccessedImage = kvp.Key;
                    stats.MostAccessedHitCount = kvp.Value.HitCount;
                }
                
                if (DateTime.Now - kvp.Value.LastAccessTime > TimeSpan.FromHours(1))
                {
                    stats.LeastRecentlyUsedCount++;
                }
            }

            stats.TotalMemoryMB = stats.TotalMemoryBytes / (1024.0 * 1024.0);
            return stats;
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;
            
            _disposed = true;
            _imageCache.Clear();
            _loadQueue.Clear();
        }

        #region 私有实现方法

        private void StartQueueProcessor()
        {
            // 异步处理加载队列
            _ = Task.Run(async () =>
            {
                while (!_disposed)
                {
                    if (_loadQueue.TryDequeue(out var loadTask))
                    {
                        await ProcessLoadTaskAsync(loadTask);
                    }
                    else
                    {
                        await Task.Delay(50); // 避免CPU占用过高
                    }
                }
            });
        }

        private async Task ProcessLoadTaskAsync(ImageLoadTask loadTask)
        {
            try
            {
                _isLoading = true;
                await LoadImageFromSourceAsync(loadTask.ImageControl, loadTask.ImagePath, loadTask.Options);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"处理图像加载任务失败 {loadTask.ImagePath}: {ex.Message}");
                await ShowErrorImageAsync(loadTask.ImageControl, loadTask.Options);
            }
            finally
            {
                _isLoading = false;
            }
        }

        private async Task<bool> TryLoadFromCacheAsync(Image imageControl, string imagePath, LazyImageOptions options)
        {
            if (_imageCache.TryGetValue(imagePath, out var cachedImage))
            {
                cachedImage.HitCount++;
                cachedImage.LastAccessTime = DateTime.Now;

                await _dispatcher.BeginInvoke(new Action(() =>
                {
                    imageControl.Source = cachedImage.BitmapImage;
                    
                    if (options.EnableFadeIn)
                    {
                        ApplyFadeInAnimation(imageControl);
                    }
                }));

                return true;
            }
            
            return false;
        }

        private async Task LoadImageFromSourceAsync(Image imageControl, string imagePath, LazyImageOptions options)
        {
            await Task.Run(async () =>
            {
                try
                {
                    // 使用优化设置加载图像
                    var bitmapImage = ResourceOptimizationManager.Instance.CompressBitmapImage(
                        imagePath, options.CompressionOptions);
                    
                    if (bitmapImage != null)
                    {
                        var imageInfo = new LazyImageInfo
                        {
                            BitmapImage = bitmapImage,
                            MemorySize = EstimateMemorySize(bitmapImage),
                            HitCount = 1,
                            LastAccessTime = DateTime.Now
                        };

                        // 添加到缓存
                        _imageCache[imagePath] = imageInfo;

                        // 在UI线程设置图像
                        await _dispatcher.BeginInvoke(new Action(() =>
                        {
                            imageControl.Source = bitmapImage;
                            
                            if (options.EnableFadeIn)
                            {
                                ApplyFadeInAnimation(imageControl);
                            }
                        }));
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"加载图像失败 {imagePath}: {ex.Message}");
                    await ShowErrorImageAsync(imageControl, options);
                }
            });
        }

        private async Task ShowLoadingPlaceholderAsync(Image imageControl, LazyImageOptions options)
        {
            await _dispatcher.BeginInvoke(new Action(() =>
            {
                if (options.ShowLoadingIndicator)
                {
                    var placeholder = CreateLoadingIndicator();
                    imageControl.Source = placeholder;
                }
            }));
        }

        private async Task ShowErrorImageAsync(Image imageControl, LazyImageOptions options)
        {
            await _dispatcher.BeginInvoke(new Action(() =>
            {
                if (!string.IsNullOrEmpty(options.ErrorImagePath))
                {
                    var errorImage = ResourceOptimizationManager.Instance.CompressBitmapImage(
                        options.ErrorImagePath);
                    
                    if (errorImage != null)
                    {
                        imageControl.Source = errorImage;
                        return;
                    }
                }
                
                // 显示默认错误图标
                imageControl.Source = CreateErrorIcon();
            }));
        }

        private DrawingImage CreateLoadingIndicator()
        {
            var geometry = new EllipseGeometry(new Point(16, 16), 8, 8);
            var drawing = new GeometryDrawing(
                new SolidColorBrush(Color.FromRgb(240, 240, 240)),
                new Pen(new SolidColorBrush(Color.FromRgb(200, 200, 200)), 1),
                geometry);
            
            return new DrawingImage(drawing);
        }

        private DrawingImage CreateErrorIcon()
        {
            var geometry = Geometry.Parse("M12,2C6.48,2,2,6.48,2,12s4.48,10,10,10s10-4.48,10-10S17.52,2,12,2z M13,17h-2v-2h2V17z M13,13h-2V7h2V13z");
            var drawing = new GeometryDrawing(
                new SolidColorBrush(Colors.Red),
                new Pen(new SolidColorBrush(Color.FromRgb(200, 0, 0)), 1),
                geometry);
            
            return new DrawingImage(drawing);
        }

        private void ApplyFadeInAnimation(Image imageControl)
        {
            imageControl.Opacity = 0;
            var animation = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(300));
            imageControl.BeginAnimation(UIElement.OpacityProperty, animation);
        }

        private void PreloadImageInternal(string imagePath, BitmapCompressionOptions options)
        {
            var bitmapImage = ResourceOptimizationManager.Instance.CompressBitmapImage(imagePath, options);
            
            if (bitmapImage != null)
            {
                var imageInfo = new LazyImageInfo
                {
                    BitmapImage = bitmapImage,
                    MemorySize = EstimateMemorySize(bitmapImage),
                    HitCount = 0,
                    LastAccessTime = DateTime.Now
                };

                _imageCache[imagePath] = imageInfo;
            }
        }

        private long EstimateMemorySize(BitmapImage bitmapImage)
        {
            // 估算位图内存占用
            if (bitmapImage.PixelWidth == 0 || bitmapImage.PixelHeight == 0)
                return 1024; // 默认1KB

            return bitmapImage.PixelWidth * bitmapImage.PixelHeight * 4; // 32位色深估算
        }

        #endregion
    }

    /// <summary>
    /// 懒加载图像选项
    /// </summary>
    public class LazyImageOptions
    {
        public bool ShowLoadingIndicator { get; set; } = true;
        public bool EnableFadeIn { get; set; } = true;
        public string ErrorImagePath { get; set; }
        public LazyImageLoader.LoadPriority Priority { get; set; } = LazyImageLoader.LoadPriority.Normal;
        public BitmapCompressionOptions CompressionOptions { get; set; } = new BitmapCompressionOptions();
    }

    /// <summary>
    /// 懒加载图像信息
    /// </summary>
    internal class LazyImageInfo
    {
        public BitmapImage BitmapImage { get; set; }
        public long MemorySize { get; set; }
        public int HitCount { get; set; }
        public DateTime LastAccessTime { get; set; }
    }

    /// <summary>
    /// 图像加载任务
    /// </summary>
    internal class ImageLoadTask
    {
        public Image ImageControl { get; set; }
        public string ImagePath { get; set; }
        public LazyImageOptions Options { get; set; }
        public LazyImageLoader.LoadPriority Priority { get; set; }
    }

    /// <summary>
    /// 图像缓存清理模式
    /// </summary>
    public enum ImageCacheClearMode
    {
        Normal,      // 清除长时间未使用的缓存
        Aggressive,  // 清除所有缓存并收集垃圾
        All          // 彻底清理所有资源
    }

    /// <summary>
    /// 图像缓存统计信息
    /// </summary>
    public class ImageCacheStatistics
    {
        public int TotalCachedImages { get; set; }
        public long TotalMemoryBytes { get; set; }
        public double TotalMemoryMB { get; set; }
        public string MostAccessedImage { get; set; }
        public int MostAccessedHitCount { get; set; }
        public int LeastRecentlyUsedCount { get; set; }
    }

    /// <summary>
    /// 图像加载器扩展方法
    /// </summary>
    public static class LazyImageExtensions
    {
        /// <summary>
        /// 为Image控件启用懒加载
        /// </summary>
        public static async Task LazyLoadAsync(this Image image, string imagePath, LazyImageOptions options = null)
        {
            await LazyImageLoader.Instance.LoadImageAsync(image, imagePath, options);
        }

        /// <summary>
        /// 预加载图像资源
        /// </summary>
        public static async Task PreloadAsync(this string imagePath)
        {
            await LazyImageLoader.Instance.PreloadImageAsync(imagePath);
        }

        /// <summary>
        /// 批量预加载图像
        /// </summary>
        public static async Task PreloadBatchAsync(this string[] imagePaths, Action<int, int> progressCallback = null)
        {
            await LazyImageLoader.Instance.PreloadImagesAsync(imagePaths, progressCallback);
        }
    }
}