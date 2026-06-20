using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// 资源优化辅助工具类
    /// </summary>
    public static class ResourceOptimizationHelper
    {
        /// <summary>
        /// 获取应用程序的所有图像资源路径
        /// </summary>
        public static IEnumerable<string> GetAllImageResources()
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            var resourceNames = assembly.GetManifestResourceNames();
            
            var imageExtensions = new[] { ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".ico" };
            
            foreach (var resourceName in resourceNames)
            {
                if (imageExtensions.Any(ext => resourceName.ToLowerInvariant().EndsWith(ext)))
                {
                    yield return resourceName;
                }
            }
        }

        /// <summary>
        /// 获取应用程序关键启动资源
        /// </summary>
        public static IEnumerable<string> GetCriticalStartupResources()
        {
            var criticalResources = new List<string>
            {
                // 应用程序图标和Logo
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/app_icon.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/app_logo.png",
                
                // 主要页面关键图片
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/home_icon.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/scan_icon.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/quarantine_icon.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/settings_icon.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/performance_icon.png",
                
                // UI组件常用图标
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/success_icon.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/error_icon.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/warning_icon.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/info_icon.png",
                
                // 按钮和控件图标
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/start_scan.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/stop_scan.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/clear_cache.png",
                "pack://application:,,,/FireAntivirus.Host.WPF;component/Resources/refresh_icon.png"
            };

            // 筛选实际存在的资源
            foreach (var resource in criticalResources)
            {
                if (ResourceExists(resource))
                {
                    yield return resource;
                }
            }
        }

        /// <summary>
        /// 检查资源是否存在
        /// </summary>
        public static bool ResourceExists(string resourcePath)
        {
            try
            {
                var uri = new Uri(resourcePath, UriKind.RelativeOrAbsolute);
                var info = Application.GetResourceStream(uri);
                return info != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 优化图片文件大小
        /// </summary>
        public static byte[] OptimizeImageBytes(byte[] imageData, ImageOptimizationOptions options = null)
        {
            options ??= new ImageOptimizationOptions();

            try
            {
                using (var memoryStream = new MemoryStream(imageData))
                {
                    var bitmapImage = new BitmapImage();
                    bitmapImage.BeginInit();
                    bitmapImage.StreamSource = memoryStream;
                    
                    if (options.MaxWidth > 0)
                        bitmapImage.DecodePixelWidth = options.MaxWidth;
                    if (options.MaxHeight > 0)
                        bitmapImage.DecodePixelHeight = options.MaxHeight;
                    
                    bitmapImage.CacheOption = BitmapCacheOption.OnLoad;
                    bitmapImage.EndInit();
                    bitmapImage.Freeze();

                    // 重新编码为优化的格式
                    var encoder = GetImageEncoder(options.Format);
                    encoder.Frames.Add(BitmapFrame.Create(bitmapImage));
                    
                    using (var outputStream = new MemoryStream())
                    {
                        encoder.Save(outputStream);
                        return outputStream.ToArray();
                    }
                }
            }
            catch
            {
                return imageData; // 优化失败时返回原始数据
            }
        }

        /// <summary>
        /// 获取图像编码器
        /// </summary>
        private static BitmapEncoder GetImageEncoder(ImageFormat format)
        {
            return format switch
            {
                ImageFormat.Jpeg => new JpegBitmapEncoder { QualityLevel = 85 },
                ImageFormat.Png => new PngBitmapEncoder(),
                ImageFormat.Bmp => new BmpBitmapEncoder(),
                ImageFormat.Gif => new GifBitmapEncoder(),
                _ => new PngBitmapEncoder()
            };
        }

        /// <summary>
        /// 创建资源加载动画
        /// </summary>
        public static void ApplyResourceLoadAnimation(UIElement element, ResourceLoadAnimationType animationType)
        {
            if (element == null) return;

            switch (animationType)
            {
                case ResourceLoadAnimationType.FadeIn:
                    var fadeInAnimation = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(300));
                    element.BeginAnimation(UIElement.OpacityProperty, fadeInAnimation);
                    break;
                    
                case ResourceLoadAnimationType.ScaleIn:
                    var scaleAnimation = new DoubleAnimation(0.8, 1, TimeSpan.FromMilliseconds(250));
                    var scaleTransform = element.RenderTransform as ScaleTransform ?? new ScaleTransform();
                    element.RenderTransform = scaleTransform;
                    element.RenderTransformOrigin = new Point(0.5, 0.5);
                    scaleTransform.BeginAnimation(ScaleTransform.ScaleXProperty, scaleAnimation);
                    scaleTransform.BeginAnimation(ScaleTransform.ScaleYProperty, scaleAnimation);
                    break;
                    
                case ResourceLoadAnimationType.SlideIn:
                    var slideAnimation = new ThicknessAnimation(
                        new Thickness(-20, 0, 20, 0), 
                        new Thickness(0), 
                        TimeSpan.FromMilliseconds(300));
                    
                    if (element is FrameworkElement frameworkElement)
                    {
                        frameworkElement.BeginAnimation(FrameworkElement.MarginProperty, slideAnimation);
                    }
                    break;
            }
        }

        /// <summary>
        /// 获取资源优化的性能指标
        /// </summary>
        public static ResourceOptimizationMetrics GetOptimizationMetrics()
        {
            var metrics = new ResourceOptimizationMetrics();
            
            try
            {
                // 获取当前进程的GC内存信息
                metrics.GCTotalMemory = GC.GetTotalMemory(false);
                metrics.GCTotalAllocated = GC.GetTotalAllocatedBytes();
                
                // 获取Working Set内存
                using (var process = System.Diagnostics.Process.GetCurrentProcess())
                {
                    metrics.WorkingSetMemory = process.WorkingSet64;
                    metrics.PrivateMemory = process.PrivateMemorySize64;
                }
                
                // 获取缓存统计数据
                var cacheStats = ResourceOptimizationManager.Instance.GetCacheStatistics();
                metrics.CachedImages = cacheStats.ImageCacheCount;
                metrics.CachedResources = cacheStats.ResourceCacheCount;
                metrics.TotalCacheMemory = cacheStats.TotalMemoryMB;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"获取资源优化指标失败: {ex.Message}");
            }
            
            return metrics;
        }

        /// <summary>
        /// 清理未使用的图像资源
        /// </summary>
        public static void CleanUnusedImageResources()
        {
            try
            {
                // 清理图像缓存中长时间未使用的项目
                var cacheStats = ResourceOptimizationManager.Instance.GetCacheStatistics();
                
                if (cacheStats.TotalMemoryMB > 100) // 如果缓存超过100MB，触发清理
                {
                    ResourceOptimizationManager.Instance.ClearCache(CacheClearOption.ImagesOnly);
                    
                    // 强制GC收集，释放图像内存
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"清理未使用资源失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 检查是否需要优化大型资源
        /// </summary>
        public static bool NeedsResourceOptimization(string resourcePath, long maxSizeBytes = 1048576) // 默认1MB
        {
            try
            {
                if (!ResourceExists(resourcePath))
                    return false;

                var uri = new Uri(resourcePath, UriKind.RelativeOrAbsolute);
                var streamInfo = Application.GetResourceStream(uri);
                
                if (streamInfo?.Stream != null)
                {
                    return streamInfo.Stream.Length > maxSizeBytes;
                }
            }
            catch
            {
                // 忽略错误
            }
            
            return false;
        }
    }

    /// <summary>
    /// 图像优化选项
    /// </summary>
    public class ImageOptimizationOptions
    {
        public int MaxWidth { get; set; } = 0; // 0表示不限制
        public int MaxHeight { get; set; } = 0;
        public ImageFormat Format { get; set; } = ImageFormat.Png;
        public int Quality { get; set; } = 85; // 仅适用于JPG
    }

    /// <summary>
    /// 图像格式
    /// </summary>
    public enum ImageFormat
    {
        Jpeg,
        Png,
        Bmp,
        Gif
    }

    /// <summary>
    /// 资源加载动画类型
    /// </summary>
    public enum ResourceLoadAnimationType
    {
        FadeIn,
        ScaleIn,
        SlideIn
    }

    /// <summary>
    /// 资源优化指标
    /// </summary>
    public class ResourceOptimizationMetrics
    {
        public long GCTotalMemory { get; set; }
        public long GCTotalAllocated { get; set; }
        public long WorkingSetMemory { get; set; }
        public long PrivateMemory { get; set; }
        public int CachedImages { get; set; }
        public int CachedResources { get; set; }
        public double TotalCacheMemory { get; set; }
        
        public double GCTotalMemoryMB => GCTotalMemory / (1024.0 * 1024.0);
        public double WorkingSetMemoryMB => WorkingSetMemory / (1024.0 * 1024.0);
        public double PrivateMemoryMB => PrivateMemory / (1024.0 * 1024.0);
    }
}