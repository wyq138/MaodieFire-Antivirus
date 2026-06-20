using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Linq;

namespace FireAntivirus.Host.WPF
{
    /// <summary>
    /// 虚拟化管理器 - 提供数据虚拟化和渐进式加载支持
    /// </summary>
    public class VirtualizationManager
    {
        private static readonly VirtualizationManager _instance = new VirtualizationManager();
        
        public static VirtualizationManager Instance => _instance;

        /// <summary>
        /// 启用控件的虚拟化功能
        /// </summary>
        public void EnableVirtualization(FrameworkElement control, VirtualizationOptions options = null)
        {
            if (control == null) return;

            options ??= new VirtualizationOptions();

            switch (control)
            {
                case ListView listView:
                    SetupListViewVirtualization(listView, options);
                    break;
                case ListBox listBox:
                    SetupListBoxVirtualization(listBox, options);
                    break;
                case DataGrid dataGrid:
                    SetupDataGridVirtualization(dataGrid, options);
                    break;
                case ItemsControl itemsControl:
                    SetupItemsControlVirtualization(itemsControl, options);
                    break;
            }
        }

        /// <summary>
        /// 为ListBox设置虚拟化
        /// </summary>
        private void SetupListBoxVirtualization(ListBox listBox, VirtualizationOptions options)
        {
            System.Windows.Controls.VirtualizingStackPanel.SetIsVirtualizing(listBox, true);
            System.Windows.Controls.VirtualizingStackPanel.SetVirtualizationMode(listBox, options.VirtualizationMode);
            System.Windows.Controls.VirtualizingStackPanel.SetCacheLength(listBox, options.CacheLength);
            System.Windows.Controls.VirtualizingStackPanel.SetCacheLengthUnit(listBox, options.CacheLengthUnit);
            ScrollViewer.SetIsDeferredScrollingEnabled(listBox, options.IsDeferredScrollingEnabled);
            
            if (options.EnableIncrementalLoading)
            {
                EnableIncrementalLoadingSupport(listBox, options);
            }
        }

        /// <summary>
        /// 为ListView设置虚拟化
        /// </summary>
        private void SetupListViewVirtualization(ListView listView, VirtualizationOptions options)
        {
            System.Windows.Controls.VirtualizingStackPanel.SetIsVirtualizing(listView, true);
            System.Windows.Controls.VirtualizingStackPanel.SetVirtualizationMode(listView, options.VirtualizationMode);
            System.Windows.Controls.VirtualizingStackPanel.SetCacheLength(listView, options.CacheLength);
            ScrollViewer.SetIsDeferredScrollingEnabled(listView, options.IsDeferredScrollingEnabled);
        }

        /// <summary>
        /// 为DataGrid设置虚拟化
        /// </summary>
        private void SetupDataGridVirtualization(DataGrid dataGrid, VirtualizationOptions options)
        {
            dataGrid.EnableRowVirtualization = options.EnableRowVirtualization;
            dataGrid.EnableColumnVirtualization = options.EnableColumnVirtualization;
            
            if (options.EnableRowVirtualization && options.VirtualizationMode == VirtualizationMode.Recycling)
            {
                VirtualizingPanel.SetVirtualizationMode(dataGrid, options.VirtualizationMode);
            }
        }

        /// <summary>
        /// 为ItemsControl设置虚拟化
        /// </summary>
        private void SetupItemsControlVirtualization(ItemsControl itemsControl, VirtualizationOptions options)
        {
            var panel = new VirtualizingStackPanel();
            VirtualizingPanel.SetVirtualizationMode(panel, options.VirtualizationMode);

            itemsControl.ItemsPanel = new ItemsPanelTemplate(new FrameworkElementFactory(typeof(VirtualizingStackPanel)));
        }

        /// <summary>
        /// 启用增量加载支持
        /// </summary>
        private void EnableIncrementalLoadingSupport(ItemsControl control, VirtualizationOptions options)
        {
            var scrollViewer = FindScrollViewer(control);
            if (scrollViewer != null)
            {
                scrollViewer.ScrollChanged += (s, e) =>
                {
                    if (e.VerticalChange > 0) // 向下滚动
                    {
                        var verticalOffset = e.VerticalOffset;
                        var viewportHeight = e.ViewportHeight;
                        var extentHeight = e.ExtentHeight;

                        // 当滚动到离底部还有一定距离时加载更多
                        if (extentHeight - verticalOffset - viewportHeight < options.LoadThreshold * viewportHeight)
                        {
                            TriggerIncrementalLoad(control, options);
                        }
                    }
                };
            }
        }

        /// <summary>
        /// 查找ScrollViewer
        /// </summary>
        private ScrollViewer FindScrollViewer(DependencyObject parent)
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is ScrollViewer scrollViewer)
                {
                    return scrollViewer;
                }
                
                var result = FindScrollViewer(child);
                if (result != null) return result;
            }

            return null;
        }

        /// <summary>
        /// 触发增量加载
        /// </summary>
        private async void TriggerIncrementalLoad(ItemsControl control, VirtualizationOptions options)
        {
            if (control.DataContext is IVirtualizableDataSource dataSource)
            {
                if (!dataSource.IsLoading && dataSource.HasMoreData)
                {
                    await dataSource.LoadMoreItemsAsync(options.PageSize);
                }
            }
        }

        /// <summary>
        /// 创建虚拟化集合视图
        /// </summary>
        public ICollectionView CreateVirtualizedCollectionView<T>(IEnumerable<T> source, int pageSize = 50)
        {
            var collectionView = new ListCollectionView(new List<T>(source));
            
            // 启用虚拟化支持
            if (collectionView is IEditableCollectionView editableView)
            {
                editableView.NewItemPlaceholderPosition = NewItemPlaceholderPosition.AtEnd;
            }

            return collectionView;
        }
    }

    /// <summary>
    /// 虚拟化选项配置
    /// </summary>
    public class VirtualizationOptions
    {
        public bool EnableRowVirtualization { get; set; } = true;
        public bool EnableColumnVirtualization { get; set; } = false;
        public VirtualizationMode VirtualizationMode { get; set; } = VirtualizationMode.Standard;
        public VirtualizationCacheLength CacheLength { get; set; } = new VirtualizationCacheLength(5);
        public VirtualizationCacheLengthUnit CacheLengthUnit { get; set; } = VirtualizationCacheLengthUnit.Item;
        public bool IsDeferredScrollingEnabled { get; set; } = true;
        public bool EnableIncrementalLoading { get; set; } = true;
        public int PageSize { get; set; } = 50;
        public double LoadThreshold { get; set; } = 0.2; // 距离底部20%时触发加载
    }

    /// <summary>
    /// 可虚拟化的数据源接口
    /// </summary>
    public interface IVirtualizableDataSource
    {
        /// <summary>
        /// 是否正在加载
        /// </summary>
        bool IsLoading { get; }

        /// <summary>
        /// 是否有更多数据
        /// </summary>
        bool HasMoreData { get; }

        /// <summary>
        /// 加载更多数据
        /// </summary>
        Task LoadMoreItemsAsync(int count);

        /// <summary>
        /// 重置数据源
        /// </summary>
        void Reset();
    }

    /// <summary>
    /// 分页虚拟化数据源
    /// </summary>
    public class PagedVirtualDataSource<T> : IVirtualizableDataSource, INotifyPropertyChanged
    {
        private readonly Func<int, int, Task<IEnumerable<T>>> _dataFetcher;
        private readonly List<T> _items;
        private int _currentPage;
        private bool _isLoading;
        private bool _hasMoreData;

        public PagedVirtualDataSource(Func<int, int, Task<IEnumerable<T>>> dataFetcher)
        {
            _dataFetcher = dataFetcher;
            _items = new List<T>();
            _currentPage = 0;
            _hasMoreData = true;
        }

        public IEnumerable<T> Items => _items;

        public bool IsLoading
        {
            get => _isLoading;
            private set
            {
                _isLoading = value;
                OnPropertyChanged(nameof(IsLoading));
            }
        }

        public bool HasMoreData
        {
            get => _hasMoreData;
            private set
            {
                _hasMoreData = value;
                OnPropertyChanged(nameof(HasMoreData));
            }
        }

        public async Task LoadMoreItemsAsync(int count)
        {
            if (IsLoading || !HasMoreData) return;

            IsLoading = true;

            try
            {
                var newItems = await _dataFetcher(_currentPage * count, count);
                var itemsList = newItems as IList<T> ?? newItems.ToList();

                if (itemsList.Count == 0)
                {
                    HasMoreData = false;
                }
                else
                {
                    foreach (var item in itemsList)
                    {
                        _items.Add(item);
                    }
                    _currentPage++;
                }
            }
            catch (Exception)
            {
                HasMoreData = false;
            }
            finally
            {
                IsLoading = false;
            }
        }

        public void Reset()
        {
            _items.Clear();
            _currentPage = 0;
            _hasMoreData = true;
            IsLoading = false;
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    /// <summary>
    /// 虚拟化辅助方法
    /// </summary>
    public static class VirtualizationHelper
    {
        /// <summary>
        /// 启用默认虚拟化配置
        /// </summary>
        public static void EnableDefaultVirtualization(this FrameworkElement control)
        {
            VirtualizationManager.Instance.EnableVirtualization(control);
        }

        /// <summary>
        /// 启用高性能虚拟化配置
        /// </summary>
        public static void EnableHighPerformanceVirtualization(this FrameworkElement control)
        {
            var options = new VirtualizationOptions
            {
                VirtualizationMode = VirtualizationMode.Recycling,
                CacheLength = new VirtualizationCacheLength(10, 10),
                IsDeferredScrollingEnabled = true,
                EnableIncrementalLoading = true
            };
            
            VirtualizationManager.Instance.EnableVirtualization(control, options);
        }

        /// <summary>
        /// 将集合转换为可虚拟化的集合视图
        /// </summary>
        public static ICollectionView ToVirtualizedView<T>(this IEnumerable<T> source)
        {
            return VirtualizationManager.Instance.CreateVirtualizedCollectionView(source);
        }
    }
}