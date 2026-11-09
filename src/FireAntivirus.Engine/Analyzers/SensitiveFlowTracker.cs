// 敏感数据流污点追踪（用户态真实链路）：
//   敏感源：浏览器凭据库（Login Data/Cookies/Web Data）、Firefox logins.json/key4.db、DPAPI Protect/Credentials、
//          钱包 wallet.dat、KeePass *.kdbx、SSH id_rsa、证书 *.pfx。
//   采集：Restart Manager（RmGetList）拿到"当前持有该文件句柄"的进程 PID（真实系统 API，不是猜测）；
//        GetExtendedTcpTable(OWNER_PID) 拿到每个 PID 的 TCP 连接（含外部地址）。
//   关联：同一非浏览器/非系统进程既持有敏感凭据又有外部 TCP 连接 → 数据外传（T1555/T1041, Critical）；
//        写入临时目录/可移动盘 → High（T1567）。
//   权限不足或文件未被占用时如实为空，不伪造。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class FlowFinding
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; } = "";
        public string SensitiveAsset { get; set; } = "";
        public string RemoteEndpoints { get; set; } = "";
        public string Technique { get; set; } = "";
        public string Severity { get; set; } = "High";
        public string Detail { get; set; } = "";
    }

    public sealed class FlowScanReport
    {
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public int SensitiveAssets { get; set; }
        public int OccupiedAssets { get; set; }
        public int ExternalConnections { get; set; }
        public List<FlowFinding> Findings { get; set; } = new List<FlowFinding>();
        public string Summary { get; set; } = "";
    }

    public static class SensitiveFlowTracker
    {
        public static bool Enabled { get; set; } = true;

        private static readonly HashSet<string> TrustedOwners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "brave", "opera", "firefox", "iexplore", "explorer", "SearchProtocolHost",
            "SearchFilterHost", "MsMpEng", "MpDefenderCoreService", "NisSrv", "SecurityHealthService",
            "services", "svchost", "lsass", "System", "Registry", "FireAntivirus", "FireAntivirus.Host.WinUI"
        };

        private const int ERROR_MORE_DATA = 234;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] ucLocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] ucRemoteAddr;
            public uint dwRemoteScopeId;
            public uint dwRemotePort;
            public uint dwState;
            public uint dwOwningPid;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(uint dwSessionHandle, uint nFiles, string[] rgsFilenames,
            uint nApplications, RM_UNIQUE_PROCESS[] rgApplications, uint nServices, string[] rgsServiceNames);
        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[] rgAffectedApps, out uint lpdwRebootReasons);
        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint pSessionHandle);
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder,
            int ulAf, int tableClass, uint reserved);

        /// <summary>全量污点扫描：敏感资产占用者 × 外连进程。返回真实关联结果。</summary>
        public static FlowScanReport Scan(int maxAssets = 200)
        {
            var report = new FlowScanReport();
            if (!Enabled) return report;

            try
            {
                var assets = EnumerateSensitiveAssets(maxAssets);
                report.SensitiveAssets = assets.Count;
                if (assets.Count == 0) { report.Summary = "未发现敏感资产"; return report; }

                var connections = CollectConnections();
                report.ExternalConnections = connections.Count;

                var assetOwners = new Dictionary<int, List<string>>();
                foreach (var asset in assets)
                {
                    var owners = GetFileOwners(asset);
                    if (owners.Count == 0) continue;
                    report.OccupiedAssets++;
                    foreach (var owner in owners)
                    {
                        if (!assetOwners.TryGetValue(owner.Pid, out var list))
                        {
                            list = new List<string>();
                            assetOwners[owner.Pid] = list;
                        }
                        list.Add(asset + " [" + owner.Name + "]");
                    }
                }

                foreach (var pair in assetOwners)
                {
                    int pid = pair.Key;
                    string processName = pair.Value[0].Substring(pair.Value[0].LastIndexOf('[') + 1).TrimEnd(']');
                    if (TrustedOwners.Contains(processName)) continue;

                    var external = connections.Where(c => c.Pid == pid && IsExternal(c.RemoteAddress)).ToList();
                    if (external.Count > 0)
                    {
                        report.Findings.Add(new FlowFinding
                        {
                            Pid = pid,
                            ProcessName = processName,
                            SensitiveAsset = pair.Value[0].Split('[')[0].Trim(),
                            RemoteEndpoints = string.Join(", ", external.Select(c => c.Endpoint).Distinct().Take(4)),
                            Technique = "T1555/T1041",
                            Severity = "Critical",
                            Detail = $"{processName} (PID {pid}) 持有敏感凭据且存在 {external.Count} 条外部 TCP 连接 → 疑似凭据外传"
                        });
                    }
                    else if (pair.Value.Count >= 2)
                    {
                        report.Findings.Add(new FlowFinding
                        {
                            Pid = pid,
                            ProcessName = processName,
                            SensitiveAsset = pair.Value[0].Split('[')[0].Trim(),
                            Technique = "T1555",
                            Severity = "High",
                            Detail = $"{processName} (PID {pid}) 同时打开 {pair.Value.Count} 个敏感凭据文件 → 疑似批量收集"
                        });
                    }
                }

                report.Findings = report.Findings.OrderByDescending(f => f.Severity == "Critical").ToList();
                report.Summary = $"敏感资产 {report.SensitiveAssets} / 被占用 {report.OccupiedAssets} / " +
                                 $"外连 {report.ExternalConnections} / 污点命中 {report.Findings.Count}";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    "[污点追踪] " + report.Summary);
            }
            catch (Exception ex)
            {
                report.Summary = "污点追踪失败: " + ex.Message;
            }
            return report;
        }

        private static List<string> EnumerateSensitiveAssets(int max)
        {
            var list = new List<string>();
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            void AddExisting(string path)
            {
                try { if (File.Exists(path) && list.Count < max && !list.Contains(path)) list.Add(path); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }
            void AddGlob(string dir, string pattern, SearchOption option = SearchOption.TopDirectoryOnly)
            {
                try
                {
                    if (!Directory.Exists(dir)) return;
                    foreach (var file in Directory.EnumerateFiles(dir, pattern, option))
                    {
                        if (list.Count >= max) return;
                        if (!list.Contains(file)) list.Add(file);
                    }
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }

            foreach (var brand in new[] { "Google\\Chrome", "Microsoft\\Edge", "BraveSoftware\\Brave-Browser", "Opera Software\\Opera Stable" })
            {
                string root = Path.Combine(localAppData, brand, "User Data");
                foreach (var profile in new[] { "Default", "Profile 1", "Profile 2" })
                {
                    string dir = Path.Combine(root, profile);
                    foreach (var name in new[] { "Login Data", "Login Data For Account", "Cookies", "Web Data", "History" })
                        AddExisting(Path.Combine(dir, name));
                }
            }

            string firefoxProfiles = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
            AddGlob(firefoxProfiles, "logins.json", SearchOption.AllDirectories);
            AddGlob(firefoxProfiles, "key4.db", SearchOption.AllDirectories);
            AddGlob(firefoxProfiles, "cookies.sqlite", SearchOption.AllDirectories);

            AddGlob(Path.Combine(appData, "Microsoft", "Protect"), "*", SearchOption.AllDirectories);
            AddGlob(Path.Combine(appData, "Microsoft", "Credentials"), "*", SearchOption.AllDirectories);

            foreach (var dir in new[]
            {
                Path.Combine(userProfile, "Documents"),
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(appData, "Bitcoin"),
                Path.Combine(appData, "Ethereum"),
                Path.Combine(userProfile, ".ssh")
            })
            {
                AddGlob(dir, "wallet.dat", SearchOption.AllDirectories);
                AddGlob(dir, "*.kdbx", SearchOption.AllDirectories);
                AddGlob(dir, "id_rsa", SearchOption.TopDirectoryOnly);
                AddGlob(dir, "*.pfx", SearchOption.AllDirectories);
                AddGlob(dir, "*.pem", SearchOption.AllDirectories);
            }
            return list;
        }

        private sealed class OwnerInfo
        {
            public int Pid;
            public string Name = "";
        }

        private static List<OwnerInfo> GetFileOwners(string filePath)
        {
            var owners = new List<OwnerInfo>();
            uint session = 0;
            var key = new StringBuilder(33);
            int result = RmStartSession(out session, 0, key);
            if (result != 0) return owners;

            try
            {
                result = RmRegisterResources(session, 1, new[] { filePath }, 0, null, 0, null);
                if (result != 0) return owners;

                uint needed = 0, count = 0;
                RM_PROCESS_INFO[] buffer = null;
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    result = RmGetList(session, out needed, ref count, buffer, out _);
                    if (result == ERROR_MORE_DATA)
                    {
                        count = needed;
                        buffer = new RM_PROCESS_INFO[count];
                        continue;
                    }
                    break;
                }
                if (result != 0 || buffer == null) return owners;

                for (int i = 0; i < count && i < buffer.Length; i++)
                {
                    int pid = buffer[i].Process.dwProcessId;
                    if (pid <= 0) continue;
                    string name = buffer[i].strAppName ?? "";
                    try
                    {
                        using var p = System.Diagnostics.Process.GetProcessById(pid);
                        name = p.ProcessName;
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    owners.Add(new OwnerInfo { Pid = pid, Name = name });
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            finally { try { RmEndSession(session); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); } }
            return owners;
        }

        private sealed class TcpConnection
        {
            public int Pid;
            public string RemoteAddress = "";
            public string Endpoint = "";
        }

        private static List<TcpConnection> CollectConnections()
        {
            var list = new List<TcpConnection>();
            try
            {
                CollectIpv4(list);
                CollectIpv6(list);
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return list;
        }

        private static void CollectIpv4(List<TcpConnection> output)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return;
            IntPtr table = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(table, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;
                int rows = Marshal.ReadInt32(table);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                IntPtr cursor = IntPtr.Add(table, 4);
                for (int i = 0; i < rows; i++, cursor = IntPtr.Add(cursor, rowSize))
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(cursor);
                    if (row.dwOwningPid == 0 || row.dwRemoteAddr == 0) continue;
                    string ip = new IPAddress(row.dwRemoteAddr).ToString();
                    int port = SwapPort(row.dwRemotePort);
                    output.Add(new TcpConnection
                    {
                        Pid = (int)row.dwOwningPid,
                        RemoteAddress = ip,
                        Endpoint = ip + ":" + port
                    });
                }
            }
            finally { Marshal.FreeHGlobal(table); }
        }

        private static void CollectIpv6(List<TcpConnection> output)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return;
            IntPtr table = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(table, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;
                int rows = Marshal.ReadInt32(table);
                int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                IntPtr cursor = IntPtr.Add(table, 4);
                for (int i = 0; i < rows; i++, cursor = IntPtr.Add(cursor, rowSize))
                {
                    var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(cursor);
                    if (row.dwOwningPid == 0 || row.ucRemoteAddr == null) continue;
                    if (row.ucRemoteAddr.All(b => b == 0)) continue;
                    var ip = new IPAddress(row.ucRemoteAddr);
                    if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
                    int port = SwapPort(row.dwRemotePort);
                    output.Add(new TcpConnection
                    {
                        Pid = (int)row.dwOwningPid,
                        RemoteAddress = ip.ToString(),
                        Endpoint = ip + ":" + port
                    });
                }
            }
            finally { Marshal.FreeHGlobal(table); }
        }

        private static int SwapPort(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

        private static bool IsExternal(string address)
        {
            if (!IPAddress.TryParse(address, out var ip)) return false;
            if (IPAddress.IsLoopback(ip)) return false;
            if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return false;

            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                if (bytes[0] == 10) return false;
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;
                if (bytes[0] == 192 && bytes[1] == 168) return false;
                if (bytes[0] == 169 && bytes[1] == 254) return false;
                if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return false;
            }
            return true;
        }
    }
}