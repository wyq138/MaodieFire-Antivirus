using System;
using System.Windows;
using System.Windows.Threading;

namespace FireAntivirus.Host.Helpers
{
    /// <summary>
    /// 异步操作帮助类 - 避免UI阻塞
    /// </summary>
    public static class AsyncHelper
    {
        /// <summary>
        /// 在UI线程上异步执行操作（非阻塞）
        /// </summary>
        public static void BeginInvokeOnUiThread(this Dispatcher dispatcher, Action action)
        {
            if (dispatcher.CheckAccess())
            {
                action();
            }
            else
            {
                dispatcher.BeginInvoke(action, DispatcherPriority.Normal);
            }
        }

        /// <summary>
        /// 在UI线程上异步执行操作（带节流）
        /// </summary>
        private static DateTime _lastThrottledUpdate = DateTime.MinValue;
        
        public static void ThrottledInvoke(this Dispatcher dispatcher, Action action, int minIntervalMs = 200)
        {
            var now = DateTime.Now;
            if ((now - _lastThrottledUpdate).TotalMilliseconds < minIntervalMs)
                return;
            
            _lastThrottledUpdate = now;
            dispatcher.BeginInvokeOnUiThread(action);
        }
    }
}
