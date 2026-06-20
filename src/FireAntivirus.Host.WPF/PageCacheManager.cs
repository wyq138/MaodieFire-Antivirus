using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// 页面缓存管理器，提供页面实例的缓存和复用
    /// </summary>
    public class PageCacheManager
    {
        private readonly Dictionary<string, Page> _pageCache;
        private readonly LinkedList<string> _accessOrder;
        private int _maxCacheSize;
        private readonly object _lockObject = new object();
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);
        
        // 缓存统计跟踪
        private int _cacheHits = 0;
        private int _cacheMisses = 0;

        public PageCacheManager(int maxCacheSize = 5)
        {
            _maxCacheSize = maxCacheSize;
            _pageCache = new Dictionary<string, Page>(maxCacheSize);
            _accessOrder = new LinkedList<string>();
        }

        /// <summary>
        /// 异步获取或创建页面实例，支持延迟加载
        /// 注意：此方法可能在非UI线程调用，Page对象的创建必须在使用时切换到UI线程
        /// </summary>
        public async Task<Page> GetOrCreatePageAsync(string pageKey, Func<Task<Page>> pageFactoryAsync)
        {
            await _semaphore.WaitAsync().ConfigureAwait(true);
            try
            {
                // 如果页面已缓存，直接返回
                if (_pageCache.ContainsKey(pageKey))
                {
                    // 更新访问顺序
                    _accessOrder.Remove(pageKey);
                    _accessOrder.AddFirst(pageKey);
                    _cacheHits++;

                    // 触发页面的激活事件
                    if (_pageCache[pageKey] is IPageWithLifecycle cachedPage)
                    {
                        _ = Task.Run(async () => {
                            await Task.Delay(10); // 轻微延迟确保UI完全渲染
                            cachedPage.OnPageActivated();
                        }).ConfigureAwait(false);
                    }

                    return _pageCache[pageKey];
                }

                // 检查缓存大小，如有需要移除最久未使用的页面
                if (_pageCache.Count >= _maxCacheSize)
                {
                    var lastAccessed = _accessOrder.Last?.Value;
                    if (lastAccessed != null)
                    {
                        RemovePage(lastAccessed);
                    }
                }

                // 异步创建新页面实例 - 必须在UI线程上创建Page
                var page = await pageFactoryAsync.Invoke().ConfigureAwait(true);
                _pageCache[pageKey] = page;
                _accessOrder.AddFirst(pageKey);
                _cacheMisses++;

                // 触发页面的缓存事件
                if (page is IPageWithLifecycle newPage)
                {
                    _ = Task.Run(async () => {
                        await Task.Delay(10); // 轻微延迟确保初始化完成
                        newPage.OnPageCached();
                    }).ConfigureAwait(false);
                }

                return page;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        /// <summary>
        /// 获取或创建页面实例
        /// </summary>
        public Page GetOrCreatePage(string pageKey, Func<Page> pageFactory)
        {
            lock (_lockObject)
            {
                // 如果页面已缓存，直接返回
                if (_pageCache.ContainsKey(pageKey))
                {
                    // 更新访问顺序
                    _accessOrder.Remove(pageKey);
                    _accessOrder.AddFirst(pageKey);
                    _cacheHits++;
                    
                    // 触发页面的激活事件
                    if (_pageCache[pageKey] is IPageWithLifecycle cachedLifecyclePage)
                    {
                        cachedLifecyclePage.OnPageActivated();
                    }
                    
                    return _pageCache[pageKey];
                }

                // 检查缓存大小，如有需要移除最久未使用的页面
                if (_pageCache.Count >= _maxCacheSize)
                {
                    var lastAccessed = _accessOrder.Last?.Value;
                    if (lastAccessed != null)
                    {
                        RemovePage(lastAccessed);
                    }
                }

                // 创建新页面实例
                var page = pageFactory.Invoke();
                _pageCache[pageKey] = page;
                _accessOrder.AddFirst(pageKey);
                _cacheMisses++;

                // 触发页面的缓存事件
                if (page is IPageWithLifecycle lifecyclePage)
                {
                    lifecyclePage.OnPageCached();
                }

                return page;
            }
        }

        /// <summary>
        /// 从缓存中获取页面，如果不存在则返回null
        /// </summary>
        public Page GetPage(string pageKey)
        {
            lock (_lockObject)
            {
                if (_pageCache.TryGetValue(pageKey, out var page))
                {
                    // 更新访问顺序
                    _accessOrder.Remove(pageKey);
                    _accessOrder.AddFirst(pageKey);
                    _cacheHits++;
                    
                    // 触发页面的激活事件
                    if (page is IPageWithLifecycle lifecyclePage)
                    {
                        lifecyclePage.OnPageActivated();
                    }
                    
                    return page;
                }
                _cacheMisses++;
                return null;
            }
        }

        /// <summary>
        /// 查看页面是否在缓存中
        /// </summary>
        public bool ContainsPage(string pageKey)
        {
            lock (_lockObject)
            {
                return _pageCache.ContainsKey(pageKey);
            }
        }

        /// <summary>
        /// 强制移除页面并清理资源
        /// </summary>
        public bool ForceRemovePage(string pageKey)
        {
            return RemovePage(pageKey);
        }

        /// <summary>
        /// 预加载页面
        /// </summary>
        public void PreloadPage(string pageKey, Func<Page> pageFactory)
        {
            GetOrCreatePage(pageKey, pageFactory);
        }

        /// <summary>
        /// 从缓存中移除页面
        /// </summary>
        public bool RemovePage(string pageKey)
        {
            lock (_lockObject)
            {
                if (_pageCache.TryGetValue(pageKey, out var page))
                {
                    // 触发页面卸载事件
                    if (page is IPageWithLifecycle lifecyclePage)
                    {
                        lifecyclePage.OnPageUnloaded();
                    }
                    
                    _pageCache.Remove(pageKey);
                    _accessOrder.Remove(pageKey);
                    
                    // 强制垃圾回收（如果页面包含大量资源）
                    if (page is IDisposable disposable)
                    {
                        disposable.Dispose();
                    }
                    
                    return true;
                }
                return false;
            }
        }

        /// <summary>
        /// 清理缓存中最久未使用的页面
        /// </summary>
        public bool RemoveLeastRecentlyUsed()
        {
            lock (_lockObject)
            {
                var lastAccessed = _accessOrder.Last?.Value;
                if (lastAccessed != null)
                {
                    return RemovePage(lastAccessed);
                }
                return false;
            }
        }

        /// <summary>
        /// 调整缓存大小限制
        /// </summary>
        public void ResizeCache(int newMaxSize)
        {
            lock (_lockObject)
            {
                _maxCacheSize = newMaxSize;
                // 如果当前缓存超过新限制，移除最久未使用的页面
                while (_pageCache.Count > _maxCacheSize)
                {
                    RemoveLeastRecentlyUsed();
                }
            }
        }

        /// <summary>
        /// 重置缓存统计计数器
        /// </summary>
        public void ResetStatistics()
        {
            lock (_lockObject)
            {
                _cacheHits = 0;
                _cacheMisses = 0;
            }
        }

        /// <summary>
        /// 获取缓存健康状态
        /// </summary>
        public CacheHealthStatus GetHealthStatus()
        {
            var stats = GetStatistics();
            return new CacheHealthStatus
            {
                IsHealthy = stats.CacheHitRate > 50.0f,
                CurrentUtilization = (float)_pageCache.Count / _maxCacheSize * 100.0f,
                HitRate = stats.CacheHitRate,
                CacheSizeMB = EstimateMemoryUsageMB()
            };
        }

        /// <summary>
        /// 估计当前缓存的内存使用量（MB）
        /// </summary>
        private float EstimateMemoryUsageMB()
        {
            // 简化的内存估算，实际项目可能需要更精确的计算
            float baseMemoryPerPage = 0.5f; // 每个页面基础内存占用
            return _pageCache.Count * baseMemoryPerPage;
        }

        /// <summary>
        /// 智能预加载常用页面（非阻塞式）
        /// </summary>
        public void PreloadPagesAsync(List<string> priorityPageKeys, Dictionary<string, Func<Page>> pageFactories)
        {
            _ = Task.Run(async () =>
            {
                var tasks = priorityPageKeys.Select(async pageKey =>
                {
                    try
                    {
                        if (pageFactories.ContainsKey(pageKey))
                        {
                            await GetOrCreatePageAsync(pageKey, async () => 
                            {
                                await Task.Delay(50); // 轻微延迟避免高峰加载
                                return await Task.Run(() => pageFactories[pageKey]());
                            }).ConfigureAwait(false);
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"预加载页面{pageKey}失败: {ex.Message}");
                    }
                });

                await Task.WhenAll(tasks);
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// 智能缓存调整 - 根据使用频率动态调整缓存策略
        /// </summary>
        public async Task PerformIntelligentCachingAsync()
        {
            await Task.Run(() =>
            {
                var stats = GetStatistics();
                
                // 动态调整缓存大小：根据命中率优化
                if (stats.CacheHitRate > 80.0f && _maxCacheSize < 10)
                {
                    ResizeCache(_maxCacheSize + 1);
                }
                else if (stats.CacheHitRate < 30.0f && _maxCacheSize > 3)
                {
                    ResizeCache(_maxCacheSize - 1);
                }

                // 清理长时间未使用的页面
                var oldestAccessTime = DateTime.Now.AddMinutes(-30); // 假设超过30分钟未使用
                var stalePages = _accessOrder.Where(key => 
                    _pageCache[key] is IPageWithLifecycle page && 
                    page.GetLastAccessTime() < oldestAccessTime).ToList();

                foreach (var stalePage in stalePages)
                {
                    RemovePage(stalePage);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// 获取性能分析报告
        /// </summary>
        public CachePerformanceReport GetPerformanceReport()
        {
            var stats = GetStatistics();
            var health = GetHealthStatus();
            
            return new CachePerformanceReport
            {
                Timestamp = DateTime.Now,
                Statistics = stats,
                HealthStatus = health,
                IsOptimized = health.HitRate > 60.0f && health.CurrentUtilization > 50.0f,
                Recommendations = GenerateOptimizationRecommendations(stats, health)
            };
        }

        /// <summary>
        /// 生成优化建议
        /// </summary>
        private List<string> GenerateOptimizationRecommendations(CacheStatistics stats, CacheHealthStatus health)
        {
            var recommendations = new List<string>();
            
            if (health.HitRate < 30.0f)
                recommendations.Add("缓存命中率较低，考虑增加缓存大小或优化缓存策略");
                
            if (health.CurrentUtilization > 90.0f)
                recommendations.Add("缓存利用率过高，建议增加最大缓存大小");
                
            if (health.CurrentUtilization < 20.0f)
                recommendations.Add("缓存利用率较低，可适当减小缓存大小以节省内存");
                
            if (stats.CacheMisses > stats.CacheHits)
                recommendations.Add("未命中次数超过命中次数，建议优化预加载策略");
            
            return recommendations;
        }

        /// <summary>
        /// 清空所有缓存页面
        /// </summary>
        public void ClearCache()
        {
            lock (_lockObject)
            {
                var pageKeys = _pageCache.Keys.ToList();
                foreach (var pageKey in pageKeys)
                {
                    RemovePage(pageKey);
                }
                _pageCache.Clear();
                _accessOrder.Clear();
            }
        }

        /// <summary>
        /// 获取缓存统计信息
        /// </summary>
        public CacheStatistics GetStatistics()
        {
            lock (_lockObject)
            {
                var totalRequests = _cacheHits + _cacheMisses;
                var hitRate = totalRequests > 0 ? (float)_cacheHits / totalRequests * 100.0f : 0.0f;
                
                return new CacheStatistics
                {
                    CacheSize = _pageCache.Count,
                    MaxCacheSize = _maxCacheSize,
                    CachedPages = _pageCache.Keys.ToList(),
                    CacheHitRate = hitRate,
                    CacheHits = _cacheHits,
                    CacheMisses = _cacheMisses,
                    TotalRequests = totalRequests,
                    CurrentCacheSize = _pageCache.Count,
                    RemainingCacheCapacity = _maxCacheSize - _pageCache.Count
                };
            }
        }

        /// <summary>
        /// 获取当前缓存的所有页面键
        /// </summary>
        public List<string> GetCachedPageKeys()
        {
            lock (_lockObject)
            {
                return _pageCache.Keys.ToList();
            }
        }
    }

    /// <summary>
    /// 页面生命周期接口
    /// </summary>
    public interface IPageWithLifecycle
    {
        /// <summary>
        /// 页面被缓存时调用
        /// </summary>
        void OnPageCached();
        
        /// <summary>
        /// 页面从缓存中激活时调用
        /// </summary>
        void OnPageActivated();
        
        /// <summary>
        /// 页面从缓存中卸载时调用
        /// </summary>
        void OnPageUnloaded();
        
        /// <summary>
        /// 获取页面最后访问时间（用于智能缓存清理）
        /// </summary>
        DateTime GetLastAccessTime();
        
        /// <summary>
        /// 获取页面内存使用量估算（MB）
        /// </summary>
        float GetMemoryUsage();
    }

    /// <summary>
    /// 缓存统计信息
    /// </summary>
    public class CacheStatistics
    {
        public int CacheSize { get; set; }
        public int MaxCacheSize { get; set; }
        public List<string> CachedPages { get; set; }
        public float CacheHitRate { get; set; }
        public int CacheHits { get; set; }
        public int CacheMisses { get; set; }
        public int TotalRequests { get; set; }
        public int CurrentCacheSize { get; set; }
        public int RemainingCacheCapacity { get; set; }
    }

    /// <summary>
    /// 缓存健康状态
    /// </summary>
    public class CacheHealthStatus
    {
        public bool IsHealthy { get; set; }
        public float CurrentUtilization { get; set; }
        public float HitRate { get; set; }
        public float CacheSizeMB { get; set; }
    }

    /// <summary>
    /// 缓存性能报告
    /// </summary>
    public class CachePerformanceReport
    {
        public DateTime Timestamp { get; set; }
        public CacheStatistics Statistics { get; set; }
        public CacheHealthStatus HealthStatus { get; set; }
        public bool IsOptimized { get; set; }
        public List<string> Recommendations { get; set; }
    }
}