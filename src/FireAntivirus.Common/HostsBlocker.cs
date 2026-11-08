// 真实 hosts 拦截工具（公共）：用 FireAntivirus 受管标记段包裹，幂等、可逆，不破坏用户原有条目。
// 供网址封禁（WebProtection/AntiPhishing）与域名封禁（DNSProtection）统一使用。
// 真正使浏览器/系统解析失效（0.0.0.0 映射 + DNS 缓存刷新），而非仅记录在内存集合。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace FireAntivirus.Common
{
    public static class HostsBlocker
    {
        private static readonly object _lock = new object();
        private const string BeginTag = "# >>> FireAntivirus Block >>>";
        private const string EndTag = "# <<< FireAntivirus Block <<<";

        public static string HostsFilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

        /// <summary>URL/域名 → 主机名。</summary>
        public static string ExtractHost(string urlOrDomain)
        {
            var s = (urlOrDomain ?? "").Trim().ToLowerInvariant();
            if (s.Length == 0) return null;
            try
            {
                if (s.Contains("://") || s.Contains("/"))
                {
                    if (Uri.TryCreate(s.Contains("://") ? s : "http://" + s, UriKind.Absolute, out var u))
                        return u.Host;
                }
            }
            catch { }
            int slash = s.IndexOf('/');
            if (slash > 0) s = s.Substring(0, slash);
            int colon = s.IndexOf(':');
            if (colon > 0) s = s.Substring(0, colon);
            return s.Length > 0 ? s : null;
        }

        /// <summary>真实封禁/解封（hosts 写入 + DNS 缓存刷新）。失败返回 false 并给出原因（通常是缺管理员权限）。</summary>
        public static bool SetBlocked(string urlOrDomain, bool block, out string error)
        {
            error = null;
            try
            {
                string host = ExtractHost(urlOrDomain);
                if (string.IsNullOrEmpty(host)) { error = "无法解析主机名"; return false; }

                lock (_lock)
                {
                    string path = HostsFilePath;
                    var lines = File.Exists(path)
                        ? File.ReadAllLines(path).ToList()
                        : new List<string>();

                    int begin = lines.IndexOf(BeginTag);
                    int end = lines.IndexOf(EndTag);
                    var managed = (begin >= 0 && end > begin)
                        ? lines.GetRange(begin + 1, end - begin - 1)
                        : new List<string>();

                    string entry = "0.0.0.0 " + host;
                    if (block)
                    {
                        if (!managed.Any(l => l.Trim().Equals(entry, StringComparison.OrdinalIgnoreCase)))
                            managed.Add(entry);
                    }
                    else
                    {
                        managed.RemoveAll(l => l.Trim().Equals(entry, StringComparison.OrdinalIgnoreCase));
                    }

                    if (begin >= 0 && end > begin) lines.RemoveRange(begin, end - begin + 1);
                    if (managed.Count > 0)
                    {
                        lines.Add(BeginTag);
                        lines.AddRange(managed);
                        lines.Add(EndTag);
                    }
                    else if (begin < 0)
                    {
                        return true; // 无受管段且无内容：无需改动
                    }

                    File.WriteAllLines(path, lines);
                }

                FlushDnsCache();
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                LogHelper.Log(LogHelper.LogLevel.Warning,
                    "hosts 拦截写入失败（需管理员权限）: " + ex.Message);
                return false;
            }
        }

        /// <summary>查询某主机是否已被本软件 hosts 封禁。</summary>
        public static bool IsBlocked(string urlOrDomain)
        {
            try
            {
                string host = ExtractHost(urlOrDomain);
                if (string.IsNullOrEmpty(host)) return false;
                lock (_lock)
                {
                    string path = HostsFilePath;
                    if (!File.Exists(path)) return false;
                    var lines = File.ReadAllLines(path).ToList();
                    string entry = "0.0.0.0 " + host;
                    return lines.Any(l => l.Trim().Equals(entry, StringComparison.OrdinalIgnoreCase));
                }
            }
            catch { return false; }
        }

        /// <summary>读取当前受管段内全部封禁条目（主机名列表）。</summary>
        public static List<string> GetBlockedHosts()
        {
            var result = new List<string>();
            try
            {
                lock (_lock)
                {
                    string path = HostsFilePath;
                    if (!File.Exists(path)) return result;
                    var lines = File.ReadAllLines(path).ToList();
                    int begin = lines.IndexOf(BeginTag);
                    int end = lines.IndexOf(EndTag);
                    if (begin < 0 || end <= begin) return result;
                    foreach (var line in lines.GetRange(begin + 1, end - begin - 1))
                    {
                        var t = line.Trim();
                        if (t.Length == 0 || t.StartsWith("#")) continue;
                        var parts = t.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2) result.Add(parts[1]);
                    }
                }
            }
            catch { }
            return result;
        }

        private static void FlushDnsCache()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(5000);
            }
            catch { }
        }
    }
}