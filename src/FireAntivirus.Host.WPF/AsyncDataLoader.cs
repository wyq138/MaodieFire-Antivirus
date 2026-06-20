using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// 异步数据加载服务，提供智能预加载和数据缓存功能
    /// </summary>
    public class AsyncDataLoader
    {
        private readonly Dictionary<string, object> _dataCache;
        private readonly Dictionary<string, object> _loadingTasks;
        private readonly Dictionary<string, DateTime> _lastAccessTimes;
        private readonly Dictionary<string, int> _accessCounts;
        private readonly object _lockObject = new object();
        private readonly Dispatcher _dispatcher;
        private readonly int _maxCacheSize;
        private readonly Timer _cleanupTimer;

        public AsyncDataLoader(Dispatcher dispatcher = null, int maxCacheSize = 100)
        {
            _dispatcher = dispatcher ?? Dispatcher.CurrentDispatcher;
            _maxCacheSize = maxCacheSize;
            _dataCache = new Dictionary<string, object>(maxCacheSize);
            _loadingTasks = new Dictionary<string, object>();
            _lastAccessTimes = new Dictionary<string, DateTime>();
            _accessCounts = new Dictionary<string, int>();

            // 定期清理过期缓存
            _cleanupTimer = new Timer(CleanupExpiredCache, null, 
                TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        }

        /// <summary>
        /// 异步加载数据，支持缓存和去重
        /// </summary>
        public async Task<T> LoadDataAsync<T>(string cacheKey, Func<Task<T>> dataLoader, 
            TimeSpan? cacheDuration = null, CachePriority priority = CachePriority.Normal)
        {
            if (string.IsNullOrEmpty(cacheKey))
                throw new ArgumentException("缓存键不能为空", nameof(cacheKey));

            object taskOrResult;
            lock (_lockObject)
            {
                // 检查缓存是否有效
                if (IsCacheValid(cacheKey, cacheDuration))
                {
                    UpdateAccessStats(cacheKey);
                    taskOrResult = _dataCache[cacheKey];
                }
                else if (_loadingTasks.TryGetValue(cacheKey, out var existingTask))
                {
                    taskOrResult = existingTask;
                }
                else
                {
                    // 创建新的加载任务
                    var loadingTask = CreateLoadingTask(cacheKey, dataLoader, priority);
                    _loadingTasks[cacheKey] = loadingTask;
                    taskOrResult = loadingTask;
                }
            }

            if (taskOrResult is Task<T> typedTask)
                return await typedTask.ConfigureAwait(false);
            return (T)taskOrResult;
        }

        /// <summary>
        /// 创建预加载任务
        /// </summary>
        private async Task<object> CreateLoadingTask<T>(string cacheKey, Func<Task<T>> dataLoader, CachePriority priority)
        {
            try
            {
                // 根据优先级设置适当的延迟
                await ApplyPriorityDelay(priority).ConfigureAwait(false);

                var data = await dataLoader().ConfigureAwait(false);

                lock (_lockObject)
                {
                    // 缓存数据
                    _dataCache[cacheKey] = data;
                    _lastAccessTimes[cacheKey] = DateTime.Now;
                    _accessCounts[cacheKey] = 1;
                    _loadingTasks.Remove(cacheKey);

                    // 确保缓存大小不超过限制
                    EnsureCacheSize();
                }

                return data;
            }
            catch (Exception ex)
            {
                lock (_lockObject)
                {
                    _loadingTasks.Remove(cacheKey);
                }
                
                System.Diagnostics.Debug.WriteLine($"数据加载失败 {cacheKey}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// 应用优先级延迟
        /// </summary>
        private async Task ApplyPriorityDelay(CachePriority priority)
        {
            var delay = priority switch
            {
                CachePriority.Low => TimeSpan.FromMilliseconds(200),
                CachePriority.High => TimeSpan.FromMilliseconds(10),
                _ => TimeSpan.FromMilliseconds(50)
            };

            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// 预加载常用数据
        /// </summary>
        public void PreloadData<T>(List<PreloadRequest<T>> preloadRequests)
        {
            _ = Task.Run(async () =>
            {
                var tasks = preloadRequests.Select(async request =>
                {
                    try
                    {
                        await LoadDataAsync(request.CacheKey, request.DataLoader, 
                            request.CacheDuration, request.Priority).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"预加载数据{request.CacheKey}失败: {ex.Message}");
                    }
                });

                await Task.WhenAll(tasks).ConfigureAwait(false);
            });
        }

        /// <summary>
        /// 检查缓存是否有效
        /// </summary>
        private bool IsCacheValid(string cacheKey, TimeSpan? cacheDuration)
        {
            if (!_dataCache.ContainsKey(cacheKey))
                return false;

            if (!cacheDuration.HasValue)
                return true; // 永久缓存

            var lastAccess = _lastAccessTimes[cacheKey];
            return DateTime.Now - lastAccess <= cacheDuration.Value;
        }

        /// <summary>
        /// 更新访问统计
        /// </summary>
        private void UpdateAccessStats(string cacheKey)
        {
            _lastAccessTimes[cacheKey] = DateTime.Now;
            if (!_accessCounts.TryGetValue(cacheKey, out var count))
                _accessCounts[cacheKey] = 1;
            else
                _accessCounts[cacheKey] = count + 1;
        }

        /// <summary>
        /// 确保缓存大小不超过限制
        /// </summary>
        private void EnsureCacheSize()
        {
            if (_dataCache.Count <= _maxCacheSize)
                return;

            // 移除最不常用的缓存项
            var itemsToRemove = _lastAccessTimes
                .OrderBy(x => x.Value)
                .ThenBy(x => _accessCounts.TryGetValue(x.Key, out var count) ? count : 0)
                .Take(_dataCache.Count - _maxCacheSize)
                .ToList();

            foreach (var item in itemsToRemove)
            {
                _dataCache.Remove(item.Key);
                _lastAccessTimes.Remove(item.Key);
                _accessCounts.Remove(item.Key);
            }
        }

        /// <summary>
        /// 清理过期缓存
        /// </summary>
        private void CleanupExpiredCache(object state)
        {
            lock (_lockObject)
            {
                var expiredKeys = _lastAccessTimes
                    .Where(x => DateTime.Now - x.Value > TimeSpan.FromHours(24))
                    .Select(x => x.Key)
                    .ToList();

                foreach (var key in expiredKeys)
                {
                    _dataCache.Remove(key);
                    _lastAccessTimes.Remove(key);
                    _accessCounts.Remove(key);
                }
            }
        }

        /// <summary>
        /// 获取缓存统计信息
        /// </summary>
        public DataLoaderCacheStatistics GetStatistics()
        {
            lock (_lockObject)
            {
                return new DataLoaderCacheStatistics
                {
                    CachedItems = _dataCache.Count,
                    LoadingTasks = _loadingTasks.Count,
                    MaxCacheSize = _maxCacheSize,
                    CacheUtilization = (float)_dataCache.Count / _maxCacheSize * 100.0f,
                    CachedKeys = _dataCache.Keys.ToList(),
                    ActiveLoaders = _loadingTasks.Keys.ToList()
                };
            }
        }

        /// <summary>
        /// 清空所有缓存
        /// </summary>
        public void ClearCache()
        {
            lock (_lockObject)
            {
                _dataCache.Clear();
                _lastAccessTimes.Clear();
                _accessCounts.Clear();
                _loadingTasks.Clear();
            }
        }

        /// <summary>
        /// 释放资源
        /// </summary>
        public void Dispose()
        {
            _cleanupTimer?.Dispose();
            ClearCache();
        }
    }

    /// <summary>
    /// 缓存优先级
    /// </summary>
    public enum CachePriority
    {
        Low,    // 低优先级，可以延迟加载
        Normal, // 正常优先级
        High    // 高优先级，立即加载
    }

    /// <summary>
    /// 预加载请求
    /// </summary>
    public class PreloadRequest<T>
    {
        public string CacheKey { get; set; }
        public Func<Task<T>> DataLoader { get; set; }
        public TimeSpan? CacheDuration { get; set; }
        public CachePriority Priority { get; set; }
    }

    /// <summary>
    /// 缓存统计信息
    /// </summary>
    public class DataLoaderCacheStatistics
    {
        public int CachedItems { get; set; }
        public int LoadingTasks { get; set; }
        public int MaxCacheSize { get; set; }
        public float CacheUtilization { get; set; }
        public List<string> CachedKeys { get; set; }
        public List<string> ActiveLoaders { get; set; }
    }
}