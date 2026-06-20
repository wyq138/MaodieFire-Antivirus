using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
    /// 资源优化管理器 - 负责图⍰懒加载、资源压缩和缓存策略
    /// </summary>
    public class ResourceOptimizationManager
    {
        private static readonly ResourceOptimizationManager _instance = new ResourceOptimizationManager();
        
        public static ResourceOptimizationManager Instance => _instance;

        private readonly ConcurrentDictionary<string, BitmapImage> _imageCache;
        private readonly ConcurrentDictionary<string, object> _resourceCache;
        private readonly object _cacheLock = new object();
        private readonly Dispatcher _dispatcher;
        
        private readonly HashSet<string> _preloadedResources;
        private bool _isPreloadingCompleted;

        public ResourceOptimizationManager()
        {
            _imageCache = new ConcurrentDictionary<string, BitmapImage>();
            _resourceCache = new ConcurrentDictionary<string, object>();
            _preloadedResources = new HashSet<string>();
            _dispatcher = Dispatcher.CurrentDispatcher;
        }

        /// <summary>
        /// 懒加载图片到Image控件
        /// </summary>
        public async Task LazyLoadImageAsync(Image imageControl, string imagePath, ImageLoadOptions options = null)
        {
            if (imageControl == null) return;

            options ??= new ImageLoadOptions();

            // 检查缓存
            if (await TryLoadFromCacheAsync(imageControl, imagePath, options))
            {
                return;
            }

            // 显示加载指示器
            if (options.ShowLoadingIndicator)
            {
                await ShowLoadingIndicatorAsync(imageControl);
            }

            // 异步加载图片
            await LoadImageAsync(imageControl, imagePath, options);
        }

        /// <summary>
        /// 预加载关键资源
        /// </summary>
        public async Task PreloadCriticalResourcesAsync(IEnumerable<string> resourcePaths, Action<int, int> progressCallback = null)
        {
            var pathList = new List<string>(resourcePaths);
            var total = pathList.Count;
            var completed = 0;

            foreach (var path in pathList)
            {
                if (_preloadedResources.Contains(path))
                {
                    completed++;
                    progressCallback?.Invoke(completed, total);
                    continue;
                }

                try
                {
                    await Task.Run(() => PreloadResource(path));
                    _preloadedResources.Add(path);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"预加载资源失败 {path}: {ex.Message}");
                }

                completed++;
                progressCallback?.Invoke(completed, total);
                
                // 防止过度占用主线程
                await Task.Delay(10);
            }

            _isPreloadingCompleted = true;
        }

        /// <summary>
        /// 压缩位图资源
        /// </summary>
        public BitmapImage CompressBitmapImage(string imagePath, BitmapCompressionOptions options = null)
        {
            options ??= new BitmapCompressionOptions();

            try
            {
                var bitmapImage = new BitmapImage();
                
                bitmapImage.BeginInit();
                bitmapImage.UriSource = new Uri(imagePath, UriKind.RelativeOrAbsolute);
                
                if (options.DecodePixelWidth > 0)
                    bitmapImage.DecodePixelWidth = options.DecodePixelWidth;
                
                if (options.DecodePixelHeight > 0)
                    bitmapImage.DecodePixelHeight = options.DecodePixelHeight;
                
                bitmapImage.CacheOption = options.CacheOption;
                bitmapImage.CreateOptions = options.CreateOptions;
                
                bitmapImage.EndInit();
                bitmapImage.Freeze(); // 冻结以提高性能
                
                return bitmapImage;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// 获取缓存统计信息
        /// </summary>
        public ResourceCacheStatistics GetCacheStatistics()
        {
            return new ResourceCacheStatistics
            {
                ImageCacheCount = _imageCache.Count,
                ResourceCacheCount = _resourceCache.Count,
                TotalMemoryMB = EstimateCacheMemoryMB()
            };
        }

        private double EstimateCacheMemoryMB() => _imageCache.Count * 0.5;

        /// <summary>
        /// 清除缓存
        /// </summary>
        public void ClearCache(CacheClearOption option = CacheClearOption.All)
        {
            switch (option)
            {
                case CacheClearOption.ImagesOnly:
                    _imageCache.Clear();
                    break;
                case CacheClearOption.ResourcesOnly:
                    _resourceCache.Clear();
                    break;
                case CacheClearOption.All:
                    _imageCache.Clear();
                    _resourceCache.Clear();
                    _preloadedResources.Clear();
                    break;
            }
        }

        /// <summary>
        /// 获取缓存统计信息
        /// </summary>
        public ResourceCacheStatistics GetResourceCacheStatistics()
        {
            return new ResourceCacheStatistics
            {
                ImageCacheCount = _imageCache.Count,
                ResourceCacheCount = _resourceCache.Count,
                PreloadedResourcesCount = _preloadedResources.Count,
                TotalMemoryMB = GC.GetTotalMemory(false) / (1024.0 * 1024.0)
            };
        }

        /// <summary>
        /// 从缓存尝试加载
        /// </summary>
        private async Task<bool> TryLoadFromCacheAsync(Image imageControl, string imagePath, ImageLoadOptions options)
        {
            if (_imageCache.TryGetValue(imagePath, out var cachedImage))
            {
                await _dispatcher.BeginInvoke(new Action(() =>
                {
                    imageControl.Source = cachedImage;
                }));
                return true;
            }
            
            return false;
        }

        /// <summary>
        /// 异步加载图片
        /// </summary>
        private async Task LoadImageAsync(Image imageControl, string imagePath, ImageLoadOptions options)
        {
            await Task.Run(async () =>
            {
                try
                {
                    // 使用压缩选项加载图片
                    var bitmapImage = CompressBitmapImage(imagePath, options.CompressionOptions);
                    
                    if (bitmapImage != null)
                    {
                        // 缓存图片
                        _imageCache[imagePath] = bitmapImage;
                        
                        // 在UI线程设置图片源
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
                    System.Diagnostics.Debug.WriteLine($"加载图片失败 {imagePath}: {ex.Message}");
                    
                    // 显示错误图片
                    await _dispatcher.BeginInvoke(new Action(() =>
                    {
                        ShowErrorImage(imageControl, options);
                    }));
                }
            });
        }

        /// <summary>
        /// 显示加载指示器
        /// </summary>
        private async Task ShowLoadingIndicatorAsync(Image imageControl)
        {
            await _dispatcher.BeginInvoke(new Action(() =>
            {
                imageControl.Source = CreateLoadingIndicator();
            }));
        }

        /// <summary>
        /// 创建加载指示器
        /// </summary>
        private DrawingImage CreateLoadingIndicator()
        {
            var geometry = new EllipseGeometry(new Point(16, 16), 8, 8);
            var drawing = new GeometryDrawing(
                Brushes.LightGray,
                new Pen(Brushes.DarkGray, 1),
                geometry);
            
            return new DrawingImage(drawing);
        }

        /// <summary>
        /// 应用淡入动画
        /// </summary>
        private void ApplyFadeInAnimation(Image imageControl)
        {
            var animation = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(300));
            imageControl.BeginAnimation(UIElement.OpacityProperty, animation);
        }

        /// <summary>
        /// 显示错误图片
        /// </summary>
        private void ShowErrorImage(Image imageControl, ImageLoadOptions options)
        {
            if (!string.IsNullOrEmpty(options.ErrorImagePath))
            {
                var errorImage = CompressBitmapImage(options.ErrorImagePath);
                if (errorImage != null)
                {
                    imageControl.Source = errorImage;
                    return;
                }
            }
            
            // 显示默认错误图标
            imageControl.Source = CreateErrorIcon();
        }

        /// <summary>
        /// 创建错误图标
        /// </summary>
        private DrawingImage CreateErrorIcon()
        {
            var geometry = Geometry.Parse("M12,2C6.48,2,2,6.48,2,12s4.48,10,10,10s10-4.48,10-10S17.52,2,12,2z M13,17h-2v-2h2V17z M13,13h-2V7h2V13z");
            var drawing = new GeometryDrawing(
                Brushes.Red,
                new Pen(Brushes.DarkRed, 1),
                geometry);
            
            return new DrawingImage(drawing);
        }

        /// <summary>
        /// 预加载资源
        /// </summary>
        private void PreloadResource(string resourcePath)
        {
            var extension = Path.GetExtension(resourcePath)?.ToLowerInvariant();
            
            switch (extension)
            {
                case ".png":
                case ".jpg":
                case ".jpeg":
                case ".bmp":
                case ".gif":
                    PreloadImage(resourcePath);
                    break;
                    
                case ".xaml":
                case ".dll":
                case ".xml":
                    // 这些资源类型在需要时自动加载
                    break;
            }
        }

        /// <summary>
        /// 预加载图片
        /// </summary>
        private void PreloadImage(string imagePath)
        {
            var bitmapImage = CompressBitmapImage(imagePath, new BitmapCompressionOptions
            {
                DecodePixelWidth = 100, // 预加载时使用小尺寸
                CacheOption = BitmapCacheOption.OnLoad
            });
            
            _imageCache[imagePath] = bitmapImage;
        }
    }

    /// <summary>
    /// 图片加载选项
    /// </summary>
    public class ImageLoadOptions
    {
        public bool ShowLoadingIndicator { get; set; } = true;
        public bool EnableFadeIn { get; set; } = true;
        public string ErrorImagePath { get; set; }
        public BitmapCompressionOptions CompressionOptions { get; set; } = new BitmapCompressionOptions();
    }

    /// <summary>
    /// 位图压缩选项
    /// </summary>
    public class BitmapCompressionOptions
    {
        public int DecodePixelWidth { get; set; } = 0; // 0表示保持原尺寸
        public int DecodePixelHeight { get; set; } = 0;
        public BitmapCacheOption CacheOption { get; set; } = BitmapCacheOption.OnLoad;
        public BitmapCreateOptions CreateOptions { get; set; } = BitmapCreateOptions.None;
    }

    /// <summary>
    /// 缓存清理选项
    /// </summary>
    public enum CacheClearOption
    {
        ImagesOnly,
        ResourcesOnly,
        All
    }

    /// <summary>
    /// 缓存统计信息
    /// </summary>
    public class ResourceCacheStatistics
    {
        public int ImageCacheCount { get; set; }
        public int ResourceCacheCount { get; set; }
        public int PreloadedResourcesCount { get; set; }
        public double TotalMemoryMB { get; set; }
    }

    /// <summary>
    /// 资源优化器扩展方法
    /// </summary>
    public static class ResourceOptimizationExtensions
    {
        /// <summary>
        /// 为Image控件启用懒加载
        /// </summary>
        public static async Task LazyLoadAsync(this Image image, string imagePath, ImageLoadOptions options = null)
        {
            await ResourceOptimizationManager.Instance.LazyLoadImageAsync(image, imagePath, options);
        }

        /// <summary>
        /// 获取优化的图片源
        /// </summary>
        public static BitmapImage GetOptimizedImageSource(this string imagePath, BitmapCompressionOptions options = null)
        {
            return ResourceOptimizationManager.Instance.CompressBitmapImage(imagePath, options);
        }

        /// <summary>
        /// 预加载图片资源
        /// </summary>
        public static async Task PreloadImagesAsync(this IEnumerable<string> imagePaths, Action<int, int> progressCallback = null)
        {
            await ResourceOptimizationManager.Instance.PreloadCriticalResourcesAsync(imagePaths, progressCallback);
        }
    }
}