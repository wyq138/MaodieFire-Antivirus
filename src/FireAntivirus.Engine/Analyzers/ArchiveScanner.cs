// 压缩包扫描（照搬 XIGUASecurity 10x archive_scanner.rs 的能力，C# 实现）：
//   zip（System.IO.Compression 原生）/ tar / gz 全支持；rar/7z 通过 7-Zip（程序目录或系统安装）解包；
//   防炸弹：条目数 ≤5000、单文件 ≤64MB、累计解压 ≤512MB、密码保护如实标记。
//   解出的内部文件写临时目录后交给引擎扫描（真实查杀，而非只列文件名）。
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class ArchiveFileResult
    {
        public string InnerPath { get; set; }
        public long Size { get; set; }
        public bool IsEncrypted { get; set; }
        public bool IsMalicious { get; set; }
        public string ThreatName { get; set; }
        public string Error { get; set; }
    }

    public sealed class ArchiveScanResult
    {
        public string ArchivePath { get; set; }
        public string ArchiveType { get; set; }
        public bool HasPassword { get; set; }
        public List<ArchiveFileResult> Files { get; set; } = new List<ArchiveFileResult>();
        public bool MaliciousFound => Files.Any(f => f.IsMalicious);
        public string Error { get; set; }
    }

    public static class ArchiveScanner
    {
        /// <summary>设置开关（全局：扫描页与实时防护共用，由宿主启动时按设置同步）。</summary>
        public static bool Enabled { get; set; } = true;

        private const int MaxEntries = 5000;
        private const long MaxEntryBytes = 64L * 1024 * 1024;
        private const long MaxTotalBytes = 512L * 1024 * 1024;

        public static bool IsArchiveExt(string path)
        {
            string ext = Path.GetExtension(path ?? "").ToLowerInvariant();
            return ext is ".zip" or ".rar" or ".7z" or ".tar" or ".gz" or ".tgz" or ".bz2" or ".xz";
        }

        /// <summary>展开压缩包并对内部文件真实扫描。scanFile：内部文件 → 引擎结果。</summary>
        public static ArchiveScanResult Scan(string archivePath, Func<string, ScanResult> scanFile)
        {
            var result = new ArchiveScanResult { ArchivePath = archivePath };
            string ext = Path.GetExtension(archivePath ?? "").ToLowerInvariant();
            result.ArchiveType = ext.TrimStart('.');

            string tmpRoot = Path.Combine(Path.GetTempPath(), "FireAntivirus_Archive_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(tmpRoot);

                switch (ext)
                {
                    case ".zip":
                        ScanZip(archivePath, tmpRoot, scanFile, result);
                        break;
                    case ".tar":
                        ScanTar(archivePath, tmpRoot, scanFile, result);
                        break;
                    case ".gz":
                    case ".tgz":
                        ScanGzip(archivePath, tmpRoot, scanFile, result);
                        break;
                    case ".rar":
                    case ".7z":
                    case ".bz2":
                    case ".xz":
                        ScanWith7Zip(archivePath, tmpRoot, scanFile, result);
                        break;
                    default:
                        result.Error = "不支持的压缩格式";
                        break;
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            finally
            {
                try { Directory.Delete(tmpRoot, true); } catch { }
            }
            return result;
        }

        private static void ScanZip(string archivePath, string tmpRoot, Func<string, ScanResult> scanFile, ArchiveScanResult result)
        {
            using var zip = ZipFile.OpenRead(archivePath);
            long total = 0;
            int count = 0;

            foreach (var entry in zip.Entries)
            {
                if (++count > MaxEntries) { result.Error = "条目数超限（防压缩炸弹）"; break; }
                if (string.IsNullOrEmpty(entry.Name)) continue;

                var fileResult = new ArchiveFileResult { InnerPath = entry.FullName, Size = entry.Length };
                if (entry.Length > MaxEntryBytes) { fileResult.Error = "内部文件超限，跳过"; result.Files.Add(fileResult); continue; }
                if (total + entry.Length > MaxTotalBytes) { result.Error = "累计解压超限（防压缩炸弹）"; break; }

                try
                {
                    string dest = Path.Combine(tmpRoot, Guid.NewGuid().ToString("N") + "_" + Sanitize(entry.Name));
                    using (var src = entry.Open())
                    using (var dst = File.Create(dest))
                        src.CopyTo(dst);

                    total += entry.Length;
                    var r = scanFile(dest);
                    if (r != null && r.IsInfected)
                    {
                        fileResult.IsMalicious = true;
                        fileResult.ThreatName = r.ThreatName;
                    }
                    try { File.Delete(dest); } catch { }
                }
                catch (InvalidDataException)
                {
                    // 加密条目读取会抛 InvalidDataException
                    fileResult.IsEncrypted = true;
                    result.HasPassword = true;
                }
                catch (Exception ex)
                {
                    fileResult.Error = ex.Message;
                }
                result.Files.Add(fileResult);
            }
        }

        private static void ScanTar(string archivePath, string tmpRoot, Func<string, ScanResult> scanFile, ArchiveScanResult result)
        {
            using var stream = File.OpenRead(archivePath);
            using var reader = new System.Formats.Tar.TarReader(stream);
            long total = 0;
            int count = 0;

            while (reader.GetNextEntry() is { } entry)
            {
                if (++count > MaxEntries) { result.Error = "条目数超限（防压缩炸弹）"; break; }
                if (entry.EntryType != System.Formats.Tar.TarEntryType.RegularFile) continue;
                if (entry.Length > MaxEntryBytes || total + entry.Length > MaxTotalBytes) continue;

                var fileResult = new ArchiveFileResult { InnerPath = entry.Name, Size = entry.Length };
                try
                {
                    string dest = Path.Combine(tmpRoot, Guid.NewGuid().ToString("N") + "_" + Sanitize(entry.Name));
                    entry.ExtractToFile(dest, overwrite: true);
                    total += entry.Length;
                    var r = scanFile(dest);
                    if (r != null && r.IsInfected) { fileResult.IsMalicious = true; fileResult.ThreatName = r.ThreatName; }
                    try { File.Delete(dest); } catch { }
                }
                catch (Exception ex) { fileResult.Error = ex.Message; }
                result.Files.Add(fileResult);
            }
        }

        private static void ScanGzip(string archivePath, string tmpRoot, Func<string, ScanResult> scanFile, ArchiveScanResult result)
        {
            try
            {
                string dest = Path.Combine(tmpRoot, Guid.NewGuid().ToString("N") + "_" + Sanitize(Path.GetFileName(archivePath)));
                bool overflow = false;
                using (var src = File.OpenRead(archivePath))
                using (var gz = new GZipStream(src, CompressionMode.Decompress))
                using (var dst = File.Create(dest))
                {
                    var buffer = new byte[81920];
                    long total = 0;
                    int read;
                    while ((read = gz.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        total += read;
                        if (total > MaxTotalBytes) { result.Error = "解压超限（防压缩炸弹）"; overflow = true; break; }
                        dst.Write(buffer, 0, read);
                    }
                }

                if (overflow)
                {
                    try { File.Delete(dest); } catch { }
                    return;
                }

                var fileResult = new ArchiveFileResult { InnerPath = Path.GetFileName(archivePath), Size = new FileInfo(dest).Length };
                var r = scanFile(dest);
                if (r != null && r.IsInfected) { fileResult.IsMalicious = true; fileResult.ThreatName = r.ThreatName; }
                result.Files.Add(fileResult);
                try { File.Delete(dest); } catch { }
            }
            catch (Exception ex) { result.Error = ex.Message; }
        }

        private static void ScanWith7Zip(string archivePath, string tmpRoot, Func<string, ScanResult> scanFile, ArchiveScanResult result)
        {
            string sevenZip = Find7Zip();
            if (sevenZip == null)
            {
                result.Error = "需要 7-Zip 解包组件（程序目录 7z.exe 或系统 7-Zip）";
                return;
            }

            try
            {
                string extractDir = Path.Combine(tmpRoot, "x");
                Directory.CreateDirectory(extractDir);

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = sevenZip,
                    Arguments = $"x -y -o\"{extractDir}\" \"{archivePath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = System.Diagnostics.Process.Start(psi);
                if (p == null) { result.Error = "7-Zip 启动失败"; return; }
                string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit(120000);

                if (output.Contains("Wrong password") || output.Contains("Enter password"))
                {
                    result.HasPassword = true;
                    result.Error = "压缩包已加密";
                    return;
                }

                long total = 0;
                foreach (var file in Directory.GetFiles(extractDir, "*", SearchOption.AllDirectories))
                {
                    var fi = new FileInfo(file);
                    if (fi.Length > MaxEntryBytes || total + fi.Length > MaxTotalBytes) continue;
                    total += fi.Length;

                    var fileResult = new ArchiveFileResult
                    {
                        InnerPath = Path.GetRelativePath(extractDir, file),
                        Size = fi.Length
                    };
                    try
                    {
                        var r = scanFile(file);
                        if (r != null && r.IsInfected) { fileResult.IsMalicious = true; fileResult.ThreatName = r.ThreatName; }
                    }
                    catch (Exception ex) { fileResult.Error = ex.Message; }
                    result.Files.Add(fileResult);
                }
            }
            catch (Exception ex) { result.Error = ex.Message; }
        }

        private static string Find7Zip()
        {
            var candidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "7z.exe"),
                Path.Combine(AppContext.BaseDirectory, "tools", "7z.exe"),
                @"C:\Program Files\7-Zip\7z.exe",
                @"C:\Program Files (x86)\7-Zip\7z.exe",
            };
            return candidates.FirstOrDefault(File.Exists);
        }

        private static string Sanitize(string name)
        {
            var invalid = Path.GetInvalidFileNameChars();
            var chars = name.Select(c => invalid.Contains(c) ? '_' : c).ToArray();
            var s = new string(chars);
            return s.Length <= 80 ? s : s.Substring(s.Length - 80);
        }
    }
}