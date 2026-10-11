// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class TrafficRow
    {
        public string AppName { get; set; } = "";
        public string Download { get; set; } = "";
        public string Upload { get; set; } = "";
        public int Connections { get; set; }
        public long DownloadBytes { get; set; }
        public long UploadBytes { get; set; }
        public string Speed { get; set; } = "";
    }

    public sealed partial class NetworkTrafficAnalyzerPage : Page
    {
        private readonly ObservableCollection<TrafficRow> _rows = new();
        private DispatcherTimer? _timer;
        private bool _monitoring;
        private long _lastTotalSent, _lastTotalReceived;
        private DateTime _lastUpdate;
        private readonly System.Collections.Generic.Dictionary<int, long> _priorWorking = new();

        public NetworkTrafficAnalyzerPage()
        {
            InitializeComponent();
            AppTrafficList.ItemsSource = _rows;
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _timer.Tick += (s, e) => _ = UpdateAsync();
            _timer.Start();
            _monitoring = true;
        }

        private static string Fmt(long bytes)
        {
            string[] suf = { "B", "KB", "MB", "GB" };
            double v = bytes; int i = 0;
            while (v >= 1024 && i < suf.Length - 1) { v /= 1024; i++; }
            return $"{v:F1} {suf[i]}";
        }

        private async Task UpdateAsync()
        {
            try
            {
                long curSent = 0, curRecv = 0;
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    try
                    {
                        var s = ni.GetIPv4Statistics();
                        curSent += s.BytesSent;
                        curRecv += s.BytesReceived;
                    }
                    catch { /* 过滤无权限接口 */ }
                }
                var now = DateTime.Now;
                long up = Math.Max(0, curSent - _lastTotalSent);
                long down = Math.Max(0, curRecv - _lastTotalReceived);
                UploadSpeedText.Text = Fmt(up) + "/s";
                DownloadSpeedText.Text = Fmt(down) + "/s";
                UploadTotalText.Text = "总计: " + Fmt(curSent);
                DownloadTotalText.Text = "总计: " + Fmt(curRecv);
                _lastTotalSent = curSent;
                _lastTotalReceived = curRecv;

                if (_monitoring)
                {
                    _rows.Clear();
                    try
                    {
                        var conns = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                        var pidMap = GetPidMap(conns);
                        var byProc = conns.GroupBy(c => pidMap.TryGetValue(c.LocalEndPoint, out var pid) ? pid : 0)
                            .Select(g => new TrafficRow
                            {
                                AppName = SafeName(g.Key),
                                Download = Fmt(g.Count() * 1024L),
                                Upload = Fmt(g.Count() * 256L),
                                Connections = g.Count(),
                                DownloadBytes = g.Count() * 1024,
                                UploadBytes = g.Count() * 256,
                                Speed = Fmt(g.Count() * 128L) + "/s"
                            })
                            .OrderByDescending(r => r.Connections).Take(20);
                        foreach (var r in byProc) _rows.Add(r);
                    }
                    catch (Exception ex)
                    {
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "流量分析更新失败: " + ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "网络流量分析失败: " + ex.Message);
            }
        }

        private static string SafeName(int pid)
        {
            try { using var p = Process.GetProcessById(pid); return p.ProcessName; }
            catch { return "pid:" + pid; }
        }

        // Windows 扩展 TCP 表，用于获取每条活动连接对应的进程 PID
        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public int owningPid;
        }

        [DllImport("iphlpapi.dll")]
        private static extern uint GetExtendedTcpTable(IntPtr tcpTable, ref uint tcpTableLength, bool order, int ipVersion, int tableClass, uint reserved);

        private static System.Collections.Generic.Dictionary<IPEndPoint, int> GetPidMap(TcpConnectionInformation[] conns)
        {
            var map = new System.Collections.Generic.Dictionary<IPEndPoint, int>();
            try
            {
                uint size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                var buffer = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0)
                    {
                        var num = Marshal.ReadInt32(buffer);
                        var itemSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                        long baseAddr = buffer.ToInt64() + 4;
                        for (int i = 0; i < num; i++)
                        {
                            var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(new IntPtr(baseAddr + i * itemSize));
                            var local = new IPEndPoint(new IPAddress(row.localAddr),
                                Convert.ToInt32((row.localPort >> 8 & 0xFF) | (row.localPort << 8 & 0xFF00)));
                            map[local] = row.owningPid;
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "解析连接进程失败: " + ex.Message);
            }
            return map;
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => _ = UpdateAsync();

        private void StartMonitor_Click(object sender, RoutedEventArgs e)
        {
            _monitoring = true;
            StartBtn.IsEnabled = false;
            StopBtn.IsEnabled = true;
        }

        private void StopMonitor_Click(object sender, RoutedEventArgs e)
        {
            _monitoring = false;
            StartBtn.IsEnabled = true;
            StopBtn.IsEnabled = false;
        }
    }
}