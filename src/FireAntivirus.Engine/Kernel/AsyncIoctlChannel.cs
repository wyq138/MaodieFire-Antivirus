// 异步 IOCTL 微过滤通信（用户态）：
//   以 FILE_FLAG_OVERLAPPED 打开驱动控制设备，持续投递 FAV_IOCTL_GET_EVENTS(0x222014)；
//   驱动侧队列空时 IoMarkIrpPending 挂起 IRP，事件入队后在 FavPushEvent 中直接完成 →
//   用户态无轮询延迟、无 2 秒窗口。驱动不支持异步时自动降级为事件驱动同步拉取（400ms），并如实标记。
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FireAntivirus.Engine.Kernel
{
    public static class AsyncIoctlChannel
    {
        private const string DeviceName = "\\\\.\\FireAntivirusKernel";
        private const uint IoctlGetEvents = 0x222014;
        private const uint GenericRead = 0x80000000, GenericWrite = 0x40000000;
        private const uint ShareRead = 0x1, ShareWrite = 0x2;
        private const uint OpenExisting = 3;
        private const uint FileFlagOverlapped = 0x40000000;
        private const int ErrorIoPending = 997;
        private const int EventSize = 520;
        private const int MaxEvents = 64;

        [StructLayout(LayoutKind.Sequential)]
        private struct OVERLAPPED
        {
            public IntPtr Internal;
            public IntPtr InternalHigh;
            public int Offset;
            public int OffsetHigh;
            public IntPtr hEvent;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(IntPtr device, uint code, IntPtr inBuffer, uint inSize,
            IntPtr outBuffer, uint outSize, out uint returned, ref OVERLAPPED overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetOverlappedResult(IntPtr device, ref OVERLAPPED overlapped,
            out uint transferred, bool wait);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateEventW(IntPtr attributes, bool manualReset, bool initialState, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CancelIoEx(IntPtr device, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static event Action<List<KernelEvent>> EventsReceived;

        public static bool IsRunning { get; private set; }
        public static bool IsOverlappedMode { get; private set; }
        public static DateTime LastEventUtc { get; private set; }
        public static long TotalEvents { get; private set; }

        private static CancellationTokenSource _cts;
        private static Task _loop;
        private static readonly object _lock = new object();

        public static bool Start()
        {
            lock (_lock)
            {
                if (IsRunning) return true;
                _cts = new CancellationTokenSource();
                IsRunning = true;
                _loop = Task.Run(() => Loop(_cts.Token));
                return true;
            }
        }

        public static void Stop()
        {
            lock (_lock)
            {
                IsRunning = false;
                try { _cts?.Cancel(); } catch { }
                try { _cts?.Dispose(); } catch { }
                _cts = null;
            }
        }

        private static void Loop(CancellationToken token)
        {
            IntPtr device = IntPtr.Zero;
            IntPtr output = IntPtr.Zero;
            IntPtr ioEvent = IntPtr.Zero;
            var overlapped = new OVERLAPPED();

            try
            {
                device = CreateFileW(DeviceName, GenericRead | GenericWrite, ShareRead | ShareWrite,
                    IntPtr.Zero, OpenExisting, FileFlagOverlapped, IntPtr.Zero);

                bool overlappedUsable = device != IntPtr.Zero && device != new IntPtr(-1);
                IsOverlappedMode = overlappedUsable;

                if (overlappedUsable)
                {
                    output = Marshal.AllocHGlobal(4 + MaxEvents * EventSize);
                    ioEvent = CreateEventW(IntPtr.Zero, true, false, null);
                    overlapped.hEvent = ioEvent;

                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        "异步 IOCTL 事件通道已启动（overlapped，驱动 pending IRP）");
                }
                else
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        "驱动设备不可用，异步 IOCTL 通道降级为同步事件拉取（400ms）");
                }

                while (!token.IsCancellationRequested)
                {
                    if (!overlappedUsable)
                    {
                        var polled = KernelProtectionInterface.PollKernelEventsShared();
                        if (polled.Count > 0) Dispatch(polled);
                        token.WaitHandle.WaitOne(400);
                        continue;
                    }

                    overlapped.Internal = IntPtr.Zero;
                    overlapped.InternalHigh = IntPtr.Zero;
                    overlapped.Offset = 0;
                    overlapped.OffsetHigh = 0;

                    bool ok = DeviceIoControl(device, IoctlGetEvents, IntPtr.Zero, 0,
                        output, (uint)(4 + MaxEvents * EventSize), out uint transferred, ref overlapped);

                    if (!ok)
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error != ErrorIoPending)
                        {
                            // 驱动未支持异步语义（立即失败）：降级
                            overlappedUsable = false;
                            IsOverlappedMode = false;
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                $"异步 IOCTL 失败（Win32={error}），降级为同步拉取");
                            continue;
                        }

                        // 等事件（30 秒超时后取消本次 IOCTL 并重投）
                        uint wait = WaitForSingleObject(ioEvent, 30000);
                        if (wait != 0)
                        {
                            CancelIoEx(device, IntPtr.Zero);
                            continue;
                        }
                        if (!GetOverlappedResult(device, ref overlapped, out transferred, false))
                            continue;
                    }

                    if (transferred >= 4)
                        Dispatch(Parse(output, transferred));
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "异步 IOCTL 通道异常: " + ex.Message);
            }
            finally
            {
                IsRunning = false;
                IsOverlappedMode = false;
                if (device != IntPtr.Zero && device != new IntPtr(-1)) { try { CancelIoEx(device, IntPtr.Zero); } catch { } }
                if (output != IntPtr.Zero) Marshal.FreeHGlobal(output);
                if (ioEvent != IntPtr.Zero) CloseHandle(ioEvent);
                if (device != IntPtr.Zero && device != new IntPtr(-1)) CloseHandle(device);
            }
        }

        private static List<KernelEvent> Parse(IntPtr buffer, uint length)
        {
            var events = new List<KernelEvent>();
            int count = Marshal.ReadInt32(buffer);
            int limit = (int)Math.Min(count, (length - 4) / EventSize);
            for (int i = 0; i < limit; i++)
            {
                int offset = 4 + i * EventSize;
                var evt = new KernelEvent
                {
                    Type = (KernelEventType)Marshal.ReadInt32(buffer, offset),
                    Pid = (uint)Marshal.ReadInt32(buffer, offset + 4),
                    Source = ReadUnicode(buffer, offset + 8, 128).TrimEnd('\0'),
                    Detail = ReadUnicode(buffer, offset + 264, 128).TrimEnd('\0')
                };
                events.Add(evt);
            }
            return events;
        }

        private static string ReadUnicode(IntPtr buffer, int offset, int chars)
        {
            var bytes = new byte[chars * 2];
            Marshal.Copy(IntPtr.Add(buffer, offset), bytes, 0, bytes.Length);
            return Encoding.Unicode.GetString(bytes);
        }

        private static void Dispatch(List<KernelEvent> events)
        {
            if (events == null || events.Count == 0) return;
            LastEventUtc = DateTime.UtcNow;
            TotalEvents += events.Count;
            try { EventsReceived?.Invoke(events); }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "内核事件处理异常: " + ex.Message);
            }
        }
    }
}