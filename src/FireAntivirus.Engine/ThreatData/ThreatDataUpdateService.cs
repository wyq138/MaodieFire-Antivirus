// 耄耋软件工作室 开发
// 特征库（ThreatData 8 个 JSON）在线更新服务：
//   运行时库目录 = %ProgramData%\FireAntivirus\ThreatData（在线更新落点，加载优先级最高）
//   出厂库目录   = 程序目录\ThreatData（兜底，保证离线可用）
//   更新源       = %ProgramData%\FireAntivirus\ThreatData\update_source.txt 中的基础 URL
//                  （自托管/GitHub Raw 目录地址均可，一次一行）；未配置时出厂库兜底并如实提示。
//   版本清单     = {源}/version.json：{ "updated": "...", "files": { "<文件名>": {"version":"...","sha256":"..."} } }
//                  下载后先做 sha256 校验（清单提供时强制一致）才落盘，杜绝半截/被篡改文件入库。
//   完成后通知 ExternalThreatData / EmbeddedThreatDatabase 运行时重载，新库即时生效（无需重启）。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace FireAntivirus.Engine
{
    public static class ThreatDataUpdateService
    {
        public static string RuntimeDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "ThreatData");

        private static string SourceFile => Path.Combine(RuntimeDir, "update_source.txt");
        private static string VersionFile => Path.Combine(RuntimeDir, "version.json");

        private static readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };

        static ThreatDataUpdateService()
        {
            try { _http.DefaultRequestHeaders.Add("User-Agent", "FireAntivirus/3.0 (+threatdata-update)"); } catch { }
        }

        public sealed class UpdateResult
        {
            public bool Succeeded;
            public string Message;
            public int FilesUpdated;
            public DateTime? NewVersion;
        }

        public sealed class RuntimeVersionInfo
        {
            public bool HasRuntimeDb;
            public DateTime? Updated;
            public int FileCount;
            public string Source;
        }

        /// <summary>运行时库状态（首页显示用）。</summary>
        public static RuntimeVersionInfo GetStatus()
        {
            var info = new RuntimeVersionInfo();
            try
            {
                if (!Directory.Exists(RuntimeDir)) return info;
                var jsons = Directory.GetFiles(RuntimeDir, "*.json")
                    .Where(f => !Path.GetFileName(f).Equals("version.json", StringComparison.OrdinalIgnoreCase)).ToList();
                info.FileCount = jsons.Count;
                info.HasRuntimeDb = info.FileCount > 0;
                info.Source = ReadSource();
                if (File.Exists(VersionFile))
                {
                    var doc = JsonSerializer.Deserialize<VersionDoc>(File.ReadAllText(VersionFile));
                    info.Updated = doc?.Updated;
                }
                else if (info.HasRuntimeDb)
                {
                    info.Updated = jsons.Max(File.GetLastWriteTime);
                }
            }
            catch { }
            return info;
        }

        /// <summary>读取更新源 URL（空 = 未配置）。</summary>
        public static string ReadSource()
        {
            try { return File.Exists(SourceFile) ? File.ReadAllText(SourceFile).Trim() : ""; }
            catch { return ""; }
        }

        /// <summary>设置更新源 URL（空 = 清除）。</summary>
        public static void SetSource(string url)
        {
            Directory.CreateDirectory(RuntimeDir);
            if (string.IsNullOrWhiteSpace(url))
            {
                if (File.Exists(SourceFile)) File.Delete(SourceFile);
            }
            else
            {
                File.WriteAllText(SourceFile, url.Trim());
            }
        }

        private sealed class VersionDoc
        {
            public DateTime Updated { get; set; }
            public Dictionary<string, FileEntry> Files { get; set; } = new Dictionary<string, FileEntry>();
        }

        private sealed class FileEntry
        {
            public string Version { get; set; }
            public string Sha256 { get; set; }
        }

        /// <summary>
        /// 在线更新特征库。percent 0-100 实时上报（清单 5% + 逐文件按字节聚合 90% + 校验落盘 5%）。
        /// </summary>
        public static async Task<UpdateResult> UpdateAsync(IProgress<(int Percent, string Stage)> progress = null)
        {
            var result = new UpdateResult();
            string source = ReadSource();
            if (string.IsNullOrEmpty(source))
            {
                result.Message = "未配置特征库更新源，出厂特征库继续生效";
                return result;
            }
            source = source.TrimEnd('/');

            try
            {
                void Report(int p, string s) { try { progress?.Report((Math.Min(99, Math.Max(0, p)), s)); } catch { } }

                Report(2, "下载版本清单...");
                string manifestJson = await _http.GetStringAsync(source + "/version.json");
                var manifest = JsonSerializer.Deserialize<VersionDoc>(manifestJson);
                if (manifest?.Files == null || manifest.Files.Count == 0)
                {
                    result.Message = "远端版本清单为空";
                    return result;
                }

                Directory.CreateDirectory(RuntimeDir);
                int total = manifest.Files.Count;
                int done = 0, updated = 0, skipped = 0;
                var okFiles = new Dictionary<string, FileEntry>();

                foreach (var kv in manifest.Files)
                {
                    string name = kv.Key;
                    done++;
                    if (!IsValidFileName(name)) { skipped++; continue; }

                    Report(5 + (int)((double)done / total * 90), $"下载 {name}（{done}/{total}）...");
                    byte[] bytes = await _http.GetByteArrayAsync(source + "/" + name);

                    // sha256 校验：清单提供哈希则强制一致，不一致跳过该文件
                    string hash = kv.Value?.Sha256;
                    if (!string.IsNullOrWhiteSpace(hash))
                    {
                        string actual = Convert.ToHexString(SHA256.HashData(bytes)).Replace("-", "").ToLowerInvariant();
                        if (!actual.Equals(hash.Trim().ToLowerInvariant(), StringComparison.OrdinalIgnoreCase))
                        {
                            skipped++;
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                $"特征库在线更新: {name} 哈希校验失败，已跳过");
                            continue;
                        }
                    }

                    await File.WriteAllBytesAsync(Path.Combine(RuntimeDir, name), bytes);
                    okFiles[name] = kv.Value ?? new FileEntry { Version = DateTime.UtcNow.ToString("O") };
                    updated++;
                }

                if (updated > 0)
                {
                    var doc2 = new VersionDoc
                    {
                        Updated = manifest.Updated == default ? DateTime.UtcNow : manifest.Updated,
                        Files = okFiles
                    };
                    await File.WriteAllTextAsync(VersionFile,
                        JsonSerializer.Serialize(doc2, new JsonSerializerOptions
                        {
                            WriteIndented = true,
                            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                        }));
                }

                // 运行时重载：新库即时生效
                ExternalThreatData.Reload();
                Data.EmbeddedThreatDatabase.Reset();

                Report(100, "更新完成");
                result.Succeeded = updated > 0;
                result.FilesUpdated = updated;
                result.NewVersion = manifest.Updated == default ? DateTime.Now : manifest.Updated.ToLocalTime();
                result.Message = updated > 0
                    ? $"特征库已更新 {updated} 个文件" + (skipped > 0 ? $"（{skipped} 个校验失败跳过）" : "")
                    : "远端无可用新文件";
                return result;
            }
            catch (Exception ex)
            {
                result.Message = "更新失败: " + ex.Message;
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "特征库在线更新失败", ex.Message);
                return result;
            }
        }

        private static bool IsValidFileName(string name) =>
            !string.IsNullOrWhiteSpace(name)
            && name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
            && name.IndexOf('\\') < 0 && name.IndexOf('/') < 0
            && name.IndexOf("..", StringComparison.Ordinal) < 0;
    }
}