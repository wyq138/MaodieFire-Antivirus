// 耄耋软件工作室 开发
// 原生系统托盘图标（WinUI 3 无内置 NotifyIcon，走 Shell_NotifyIconW 原生实现）：
//   独立 STA 线程 + 隐藏消息窗口 + 消息循环，保证应用常驻后台时托盘始终在右下角
//   左键 = 唤出主窗口；右键 = 菜单（打开主窗口 / 快速扫描 / 隔离区 / 设置 / 关于 / 退出）
//   托盘图标 = Assets\app_cat.ico（小猫图），加载失败回退系统盾牌。
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace FireAntivirus.Host.WinUI
{
    internal static class TrayIconHost
    {
        public static event Action OpenRequested;
        public static event Action QuickScanRequested;
        public static event Action QuarantineRequested;
        public static event Action SettingsRequested;
        public static event Action AboutRequested;
        public static event Action ExitRequested;

        // ---- Win32 声明 ----
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NOTIFYICONDATAW
        {
            public uint cbSize;
            public IntPtr hWnd;
            public uint uID;
            public uint uFlags;
            public uint uCallbackMessage;
            public IntPtr hIcon;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
            public uint dwState;
            public uint dwStateMask;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
            public uint uVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
            public uint dwInfoFlags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WNDCLASSW
        {
            public uint style;
            public IntPtr lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpszMenuName;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpszClassName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int ptX;
            public int ptY;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X; public int Y; }

        private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern ushort RegisterClassW(ref WNDCLASSW lpWndClass);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateWindowExW(uint exStyle, string className, string windowName, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);
        [DllImport("user32.dll")]
        private static extern bool DestroyWindow(IntPtr hWnd);
        [DllImport("user32.dll")]
        private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll")]
        private static extern bool GetMessageW(out MSG msg, IntPtr hWnd, uint min, uint max);
        [DllImport("user32.dll")]
        private static extern bool TranslateMessage(ref MSG msg);
        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessageW(ref MSG msg);
        [DllImport("user32.dll")]
        private static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr w, IntPtr l);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadIconW(IntPtr inst, string iconName);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadImageW(IntPtr hInst, string name, uint type, int cx, int cy, uint fuLoad);
        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int index);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr hIcon);
        [DllImport("user32.dll")]
        private static extern IntPtr CreatePopupMenu();
        [DllImport("user32.dll")]
        private static extern bool DestroyMenu(IntPtr menu);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern bool AppendMenuW(IntPtr menu, uint flags, IntPtr id, string text);
        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);
        [DllImport("user32.dll")]
        private static extern bool TrackPopupMenuEx(IntPtr menu, uint flags, int x, int y, IntPtr hWnd, IntPtr tpm);
        [DllImport("user32.dll")]
        private static extern bool GetCursorPos(out POINT p);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandleW(string name);

        private const uint NIM_ADD = 0x0, NIM_DELETE = 0x2;
        private const uint NIF_MESSAGE = 0x1, NIF_ICON = 0x2, NIF_TIP = 0x4;
        private const uint WM_APP_TRAY = 0x8000 + 0x0FA0; // WM_APP + 4000，避开常用段
        private const uint WM_COMMAND = 0x0111, WM_CLOSE = 0x0010;
        private const uint WM_LBUTTONUP = 0x0202, WM_RBUTTONUP = 0x0205;
        private const uint MI_OPEN = 1, MI_EXIT = 2, MI_QUICK = 3, MI_QUARANTINE = 4, MI_SETTINGS = 5, MI_ABOUT = 6;
        private const uint TPM_RIGHTBUTTON = 0x0002;
        private const uint MF_SEPARATOR = 0x0800;
        private const uint IMAGE_ICON = 1, LR_LOADFROMFILE = 0x10;
        private const int SM_CXSMICON = 49, SM_CYSMICON = 50;

        private static WndProcDelegate _wndProc; // 防委托被 GC
        private static IntPtr _msgWnd;
        private static IntPtr _hIcon;
        private static NOTIFYICONDATAW _nid;
        private static bool _added;

        private const string TipText = "耄耋安全 - 实时防护运行中（点击打开）";

        /// <summary>启动托盘（独立 STA 线程 + 消息循环，不阻塞 UI）。</summary>
        public static void Init()
        {
            var t = new Thread(TrayThread) { IsBackground = true, Name = "FAV-Tray" };
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
        }

        private static IntPtr LoadTrayIcon()
        {
            try
            {
                string path = Path.Combine(AppContext.BaseDirectory, "Assets", "app_cat.ico");
                if (File.Exists(path))
                {
                    int cx = Math.Max(16, GetSystemMetrics(SM_CXSMICON));
                    int cy = Math.Max(16, GetSystemMetrics(SM_CYSMICON));
                    IntPtr h = LoadImageW(IntPtr.Zero, path, IMAGE_ICON, cx, cy, LR_LOADFROMFILE);
                    if (h != IntPtr.Zero) return h;
                }
            }
            catch { }
            return LoadIconW(IntPtr.Zero, "#32516"); // 系统盾牌兜底
        }

        private static void TrayThread()
        {
            try
            {
                _wndProc = TrayWndProc;
                var cls = new WNDCLASSW
                {
                    lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
                    lpszClassName = "FAV_TrayMsgWnd",
                    hInstance = GetModuleHandleW(null)
                };
                RegisterClassW(ref cls);

                _msgWnd = CreateWindowExW(0, "FAV_TrayMsgWnd", "FAV_TrayMsgWnd", 0,
                    0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, cls.hInstance, IntPtr.Zero);
                if (_msgWnd == IntPtr.Zero) return;

                _hIcon = LoadTrayIcon();
                _nid = new NOTIFYICONDATAW
                {
                    cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                    hWnd = _msgWnd,
                    uID = 1,
                    uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
                    uCallbackMessage = WM_APP_TRAY,
                    hIcon = _hIcon,
                    szTip = TipText
                };
                _added = Shell_NotifyIconW(NIM_ADD, ref _nid);

                while (GetMessageW(out var msg, IntPtr.Zero, 0, 0))
                {
                    TranslateMessage(ref msg);
                    DispatchMessageW(ref msg);
                }
            }
            catch { }
        }

        private static IntPtr TrayWndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            if (msg == WM_APP_TRAY)
            {
                uint mouse = (uint)lParam & 0xFFFF;
                if (mouse == WM_LBUTTONUP) OpenRequested?.Invoke();
                else if (mouse == WM_RBUTTONUP) ShowMenu(hWnd);
            }
            else if (msg == WM_COMMAND)
            {
                uint id = (uint)wParam & 0xFFFF;
                switch (id)
                {
                    case MI_OPEN: OpenRequested?.Invoke(); break;
                    case MI_QUICK: QuickScanRequested?.Invoke(); break;
                    case MI_QUARANTINE: QuarantineRequested?.Invoke(); break;
                    case MI_SETTINGS: SettingsRequested?.Invoke(); break;
                    case MI_ABOUT: AboutRequested?.Invoke(); break;
                    case MI_EXIT: ExitRequested?.Invoke(); break;
                }
            }
            else if (msg == WM_CLOSE)
            {
                DestroyWindow(hWnd);
            }
            return DefWindowProcW(hWnd, msg, wParam, lParam);
        }

        private static void ShowMenu(IntPtr hWnd)
        {
            var menu = CreatePopupMenu();
            if (menu == IntPtr.Zero) return;

            AppendMenuW(menu, 0, (IntPtr)MI_OPEN, "打开主窗口");
            AppendMenuW(menu, 0, (IntPtr)MI_QUICK, "快速扫描");
            AppendMenuW(menu, MF_SEPARATOR, IntPtr.Zero, null);
            AppendMenuW(menu, 0, (IntPtr)MI_QUARANTINE, "隔离区");
            AppendMenuW(menu, 0, (IntPtr)MI_SETTINGS, "设置");
            AppendMenuW(menu, 0, (IntPtr)MI_ABOUT, "关于");
            AppendMenuW(menu, MF_SEPARATOR, IntPtr.Zero, null);
            AppendMenuW(menu, 0, (IntPtr)MI_EXIT, "退出");

            GetCursorPos(out var pt);
            SetForegroundWindow(hWnd); // 托盘菜单正常收起的必要条件
            TrackPopupMenuEx(menu, TPM_RIGHTBUTTON, pt.X, pt.Y, hWnd, IntPtr.Zero);
            DestroyMenu(menu);
        }

        /// <summary>应用真正退出前调用：移除托盘图标并结束消息线程。</summary>
        public static void Shutdown()
        {
            try { if (_added) Shell_NotifyIconW(NIM_DELETE, ref _nid); } catch { }
            try { if (_hIcon != IntPtr.Zero) DestroyIcon(_hIcon); } catch { }
            try { PostMessageW(_msgWnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero); } catch { }
        }
    }
}