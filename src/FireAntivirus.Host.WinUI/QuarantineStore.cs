// 真实隔离区（统一存储，修复"提示已隔离但隔离区看不到"）：
// 根目录统一为 Common.PathHelper.GetQuarantinePath()（%AppData%\FireAntivirus\Data\Quarantine），
// 实时防护(RTPPlus→DataManager.QuarantineFile)、恶意清除(MalwareRemoval)、扫描处置共用同一目录；
// 历史隔离目录（ProgramData\FireAntivirus\Quarantine）启动时自动迁移。
// ListAll 采用"目录扫描 + 索引合并"：即使文件由其他模块写入（无本索引条目），隔离区页面也能看到。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace FireAntivirus.Host.WinUI
{
    public sealed class QuarantineEntry
    {
        public string OriginalPath { get; set; }
        public string QuarantinedPath { get; set; }
        public string ThreatName { get; set; }
        public string Severity { get; set; }
        public DateTime QuarantinedAt { get; set; }
    }

    public static class QuarantineStore
    {
        private static readonly object _lock = new object();

        /// <summary>隔离根目录：唯一真源 = Common.PathHelper（与 DataManager/RTPPlus/MalwareRemoval 共用）。</summary>
        public static string Root { get; } = FireAntivirus.Common.PathHelper.GetQuarantinePath();

        private static string IndexPath => Path.Combine(Root, "index.json");

        static QuarantineStore()
        {
            // 历史目录迁移：此前隔离区页面使用 ProgramData\FireAntivirus\Quarantine，
            // 而实时防护隔离写的是 Data 目录 → 用户"隔离区看不到"。统一到同一目录并迁移旧数据。
            try
            {
                var legacy = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Quarantine");

                if (!string.Equals(Path.GetFullPath(legacy).TrimEnd('\\'),
                                   Path.GetFullPath(Root).TrimEnd('\\'),
                                   StringComparison.OrdinalIgnoreCase)
                    && Directory.Exists(legacy))
                {
                    Directory.CreateDirectory(Root);
                    foreach (var f in Directory.GetFiles(legacy))
                    {
                        var dest = Path.Combine(Root, Path.GetFileName(f));
                        if (!File.Exists(dest))
                            File.Copy(f, dest, false);
                        File.Delete(f);
                    }
                    try { Directory.Delete(legacy, true); } catch { }
                }
            }
            catch { }
        }

        private static List<QuarantineEntry> Load()
        {
            try
            {
                if (File.Exists(IndexPath))
                    return Newtonsoft.Json.JsonConvert.DeserializeObject<List<QuarantineEntry>>(File.ReadAllText(IndexPath))
                           ?? new List<QuarantineEntry>();
            }
            catch { }
            return new List<QuarantineEntry>();
        }

        private static void Save(List<QuarantineEntry> entries)
        {
            Directory.CreateDirectory(Root);
            File.WriteAllText(IndexPath, Newtonsoft.Json.JsonConvert.SerializeObject(entries, Newtonsoft.Json.Formatting.Indented));
        }

        private static bool Matches(QuarantineEntry e, string filePath) =>
            string.Equals(e.OriginalPath, filePath, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(e.QuarantinedPath, filePath, StringComparison.OrdinalIgnoreCase);

        /// <summary>隔离：把文件移入隔离目录，返回是否成功。</summary>
        public static bool Quarantine(string filePath, string threatName, string severity, out string error)
        {
            error = null;
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                error = "文件不存在";
                return false;
            }
            lock (_lock)
            {
                try
                {
                    var entries = Load();
                    if (entries.Any(e => string.Equals(e.OriginalPath, filePath, StringComparison.OrdinalIgnoreCase)))
                    {
                        error = "该文件已在隔离区";
                        return false;
                    }
                    Directory.CreateDirectory(Root);
                    var dest = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".qtn");
                    File.Move(filePath, dest);
                    entries.Add(new QuarantineEntry
                    {
                        OriginalPath = filePath,
                        QuarantinedPath = dest,
                        ThreatName = threatName ?? "未知威胁",
                        Severity = severity ?? "Medium",
                        QuarantinedAt = DateTime.Now
                    });
                    Save(entries);
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        $"已隔离: {filePath} -> {dest} ({threatName})");
                    return true;
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "隔离失败: " + ex.Message);
                    return false;
                }
            }
        }

        /// <summary>彻底删除隔离区中的条目（支持按原路径或隔离文件路径匹配）。</summary>
        public static bool Delete(string filePath, out string error)
        {
            error = null;
            lock (_lock)
            {
                try
                {
                    var entries = Load();
                    var entry = entries.FirstOrDefault(e => Matches(e, filePath));
                    if (entry != null)
                    {
                        if (File.Exists(entry.QuarantinedPath)) File.Delete(entry.QuarantinedPath);
                        entries.Remove(entry);
                        Save(entries);
                    }
                    else if (File.Exists(filePath))
                    {
                        File.Delete(filePath);
                    }
                    else
                    {
                        error = "文件不存在";
                        return false;
                    }
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, $"已删除隔离文件: {filePath}");
                    return true;
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "删除失败: " + ex.Message);
                    return false;
                }
            }
        }

        /// <summary>从隔离区恢复到原位置（信任处理）。</summary>
        public static bool Restore(string filePath, out string error)
        {
            error = null;
            lock (_lock)
            {
                try
                {
                    var entries = Load();
                    var entry = entries.FirstOrDefault(e => Matches(e, filePath));
                    if (entry == null) { error = "隔离区中无此条目"; return false; }
                    if (entry.OriginalPath != null && entry.OriginalPath.StartsWith("(其他防护模块隔离)", StringComparison.Ordinal))
                    {
                        error = "该条目来源路径未知（由其他防护模块隔离），无法自动恢复，可彻底删除";
                        return false;
                    }
                    if (File.Exists(entry.QuarantinedPath))
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(entry.OriginalPath));
                        File.Move(entry.QuarantinedPath, entry.OriginalPath);
                    }
                    entries.Remove(entry);
                    Save(entries);
                    return true;
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                    return false;
                }
            }
        }

        /// <summary>
        /// 列出隔离区全部条目：索引条目 + 目录扫描补充（其他防护模块写入、无本索引的文件也可见）。
        /// </summary>
        public static List<QuarantineEntry> ListAll()
        {
            lock (_lock)
            {
                var indexed = Load();
                var result = new List<QuarantineEntry>(indexed);
                try
                {
                    Directory.CreateDirectory(Root);
                    var indexedPaths = new HashSet<string>(
                        indexed.Select(e => Path.GetFullPath(e.QuarantinedPath)),
                        StringComparer.OrdinalIgnoreCase);

                    foreach (var file in Directory.GetFiles(Root))
                    {
                        var name = Path.GetFileName(file);
                        if (name.Equals("index.json", StringComparison.OrdinalIgnoreCase)) continue;
                        if (indexedPaths.Contains(Path.GetFullPath(file))) continue;

                        result.Add(new QuarantineEntry
                        {
                            OriginalPath = "(其他防护模块隔离) " + name,
                            QuarantinedPath = file,
                            ThreatName = "已隔离文件（实时防护/恶意清除）",
                            Severity = "Medium",
                            QuarantinedAt = File.GetLastWriteTime(file)
                        });
                    }
                }
                catch { }
                return result;
            }
        }
    }
}