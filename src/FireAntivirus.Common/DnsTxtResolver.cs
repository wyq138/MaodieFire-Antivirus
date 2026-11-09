// 真实 DNS TXT 记录解析（公共）：UDP 53 直接向系统 DNS 服务器查询，支持 SPF / DMARC 等 TXT 记录验证。
// 替代此前 CheckSPFRecord/CheckDMARCPolicy 直接 return true 的假验证。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace FireAntivirus.Common
{
    public static class DnsTxtResolver
    {
        /// <summary>查询域名的全部 TXT 记录（真实网络 DNS 查询，失败返回空列表）。</summary>
        public static List<string> QueryTxt(string domain)
        {
            var results = new List<string>();
            if (string.IsNullOrWhiteSpace(domain)) return results;

            try
            {
                var servers = GetDnsServers();
                foreach (var server in servers)
                {
                    try
                    {
                        var records = QuerySingle(domain, server);
                        if (records.Count > 0)
                        {
                            results.AddRange(records);
                            break;
                        }
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return results;
        }

        private static List<IPAddress> GetDnsServers()
        {
            var list = new List<IPAddress>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    try
                    {
                        foreach (var dns in nic.GetIPProperties().DnsAddresses)
                            if (!list.Contains(dns)) list.Add(dns);
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            if (list.Count == 0)
            {
                try { list.Add(IPAddress.Parse("223.5.5.5")); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            }
            return list;
        }

        private static List<string> QuerySingle(string domain, IPAddress server)
        {
            var results = new List<string>();
            // DNS 事务 ID 用 CSPRNG（System.Random 可预测, 存在缓存投毒面）
            int id = (System.Security.Cryptography.RandomNumberGenerator.GetBytes(2)[0] | (System.Security.Cryptography.RandomNumberGenerator.GetBytes(2)[1] << 8)) % 65535 + 1;
            byte[] query = BuildQuery(domain, id);

            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = 3000;
            udp.Send(query, query.Length, new IPEndPoint(server, 53));

            var remote = new IPEndPoint(IPAddress.Any, 0);
            byte[] resp = udp.Receive(ref remote);
            if (resp == null || resp.Length < 12) return results;

            int qdCount = (resp[4] << 8) | resp[5];
            int anCount = (resp[6] << 8) | resp[7];
            int idx = 12;

            for (int i = 0; i < qdCount && idx < resp.Length; i++)
                idx = SkipName(resp, idx) + 4;

            for (int i = 0; i < anCount && idx < resp.Length; i++)
            {
                idx = SkipName(resp, idx);
                if (idx + 10 > resp.Length) break;

                int type = (resp[idx] << 8) | resp[idx + 1];
                int rdlen = (resp[idx + 8] << 8) | resp[idx + 9];
                idx += 10;

                if (type == 16 && rdlen > 1 && idx + rdlen <= resp.Length)
                {
                    // TXT 记录可能被分成多条 <=255 字节的字符串段：同一条记录内拼接
                    var sb = new StringBuilder();
                    int p = idx;
                    int end = idx + rdlen;
                    while (p < end)
                    {
                        int len = resp[p++];
                        if (len == 0) break;
                        if (p + len > end) break;
                        sb.Append(Encoding.ASCII.GetString(resp, p, len));
                        p += len;
                    }
                    if (sb.Length > 0) results.Add(sb.ToString());
                }

                idx += rdlen;
            }
            return results;
        }

        private static int SkipName(byte[] data, int idx)
        {
            while (idx < data.Length)
            {
                int len = data[idx];
                if (len == 0) return idx + 1;
                if ((len & 0xC0) == 0xC0) return idx + 2; // 压缩指针
                idx += len + 1;
            }
            return idx;
        }

        private static byte[] BuildQuery(string domain, int id)
        {
            using var ms = new MemoryStream();
            ms.WriteByte((byte)(id >> 8));
            ms.WriteByte((byte)id);
            ms.Write(new byte[] { 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

            foreach (var part in domain.TrimEnd('.').Split('.'))
            {
                var b = Encoding.ASCII.GetBytes(part);
                if (b.Length == 0 || b.Length > 63) continue;
                ms.WriteByte((byte)b.Length);
                ms.Write(b);
            }
            ms.WriteByte(0);
            ms.Write(new byte[] { 0x00, 0x10, 0x00, 0x01 }); // QTYPE=TXT, QCLASS=IN
            return ms.ToArray();
        }
    }
}