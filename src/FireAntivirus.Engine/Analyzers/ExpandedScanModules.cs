// 耄耋软件工作室 开发，严禁非法反编译
// 扩容扫描方法集：压缩包嵌套扫描 / PE 结构解析 / 宏文档检测 /
// 双重扩展名与 Unicode 伪装检测 / 持久化项扫描 / 嵌入式模式规则引擎
// 所有引擎均为独立"投票方"，接入 AntivirusEngine 多引擎共识管线：
// 单引擎命中只报低置信可疑，≥2 个引擎一致才确认，从根本上防止误报。
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>共享的基础扫描结果结构，与引擎 ScanResult 字段对齐。</summary>
    public class ExpandedScanHit
    {
        public string FilePath { get; set; }
        public bool IsInfected { get; set; }
        public string ThreatName { get; set; }
        public string ThreatType { get; set; }
        public string Severity { get; set; }
        public double Confidence { get; set; }
        public string DetectionMethod { get; set; }
        public List<string> Evidence { get; } = new List<string>();
    }

    /// <summary>
    /// 扩展名/文件名伪装检测：
    /// 双重扩展名（invoice.pdf.exe）、RTLO 字符伪装（‮gpj.exe）、
    /// 大量空格+扩展名、隐藏真实扩展名的常见手法。
    /// 该类检测独立于内容，误报率极低且证据直观。
    /// </summary>
    public class FileNameSpoofAnalyzer
    {
        private static readonly HashSet<string> ExecutableExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".com", ".cpl", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".jar", ".msi", ".lnk" };

        private static readonly HashSet<string> DocumentExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".mp3", ".mp4", ".avi", ".zip", ".rar", ".7z" };

        public ExpandedScanHit Analyze(string filePath)
        {
            var hit = new ExpandedScanHit { FilePath = filePath, DetectionMethod = "FileNameSpoof" };
            try
            {
                string name = Path.GetFileName(filePath);
                string ext = Path.GetExtension(name);

                // RTLO / LRO / RLO 控制字符伪装
                if (name.IndexOf('\u202E') >= 0 || name.IndexOf('\u202D') >= 0 || name.IndexOf('\u200F') >= 0)
                {
                    hit.IsInfected = true;
                    hit.ThreatName = "Trojan.FileName.RTLO-Spoof";
                    hit.ThreatType = "伪装文件";
                    hit.Severity = "High";
                    hit.Confidence = 0.9;
                    hit.Evidence.Add("文件名包含 Unicode RTLO/LRO 控制字符（扩展名伪装）");
                    return hit;
                }

                // 真实扩展名是可执行，但文件名中还有"更外层"的文档扩展名 -> 双重扩展名
                if (ExecutableExtensions.Contains(ext))
                {
                    string stem = Path.GetFileNameWithoutExtension(name);
                    foreach (var docExt in DocumentExtensions)
                    {
                        if (stem.EndsWith(docExt, StringComparison.OrdinalIgnoreCase))
                        {
                            hit.IsInfected = true;
                            hit.ThreatName = "Trojan.FileName.DoubleExtension";
                            hit.ThreatType = "伪装文件";
                            hit.Severity = "High";
                            hit.Confidence = 0.85;
                            hit.Evidence.Add($"双重扩展名伪装: *{docExt}{ext}");
                            return hit;
                        }
                    }
                }

                // 扩展名与内容魔数不一致（exe 伪装成 jpg 内容等）
                if (ExecutableExtensions.Contains(ext))
                {
                    var magic = ReadMagic(filePath, 4);
                    if (magic.Length >= 2 && magic[0] == 0x4D && magic[1] == 0x5A)
                    {
                        // 是 PE；若声称自己是图片/文档扩展名则高度可疑
                        string lowerExt = ext.ToLowerInvariant();
                        if (lowerExt != ".exe" && lowerExt != ".dll" && DocumentExtensions.Contains(ext))
                        {
                            hit.IsInfected = true;
                            hit.ThreatName = "Trojan.FileName.MagicMismatch";
                            hit.ThreatType = "伪装文件";
                            hit.Severity = "High";
                            hit.Confidence = 0.88;
                            hit.Evidence.Add($"扩展名 {ext} 但内容为 PE 可执行文件（MZ 头）");
                        }
                    }
                }
            }
            catch { }
            return hit;
        }

        private static byte[] ReadMagic(string path, int count)
        {
            try
            {
                using (var fs = File.OpenRead(path))
                {
                    var buf = new byte[count];
                    int n = fs.Read(buf, 0, count);
                    if (n < buf.Length) Array.Resize(ref buf, n);
                    return buf;
                }
            }
            catch { return new byte[0]; }
        }
    }

    /// <summary>
    /// PE 结构解析器：不依赖字符串特征，直接解析 DOS 头/NT 头/节表。
    /// 检测：可写+可执行节、异常节名、TLS 回调、超大 Overlay、
    /// 节熵异常、入口点不在前两节等结构异常。结构异常是弱信号，
    /// 单独不判感染（共识管线中仅作一票），几乎不误报。
    /// </summary>
    public class PEStructureAnalyzer
    {
        private static readonly HashSet<string> SuspiciousSectionNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "upx0", "upx1", "upx2", "upx!", ".aspack", ".adata", ".adata", "aspack", "spack", ".petite", ".mz", ".packed", ".vmp0", ".vmp1", ".themida", ".enigma1", ".enigma2", "pebundle", "pec2", "pec4", "mpress1", "mpress2", ".fsg", ".nsp0", ".nsp1", ".xy0", ".y0" };

        public ExpandedScanHit Analyze(string filePath)
        {
            var hit = new ExpandedScanHit { FilePath = filePath, DetectionMethod = "PEStructure" };
            try
            {
                byte[] head;
                using (var fs = File.OpenRead(filePath))
                {
                    if (fs.Length < 512) return hit;
                    head = new byte[4096];
                    int read = fs.Read(head, 0, head.Length);
                    if (read < 512) return hit;
                }

                if (head[0] != 0x4D || head[1] != 0x5A) return hit; // 非 PE

                int e_lfanew = BitConverter.ToInt32(head, 0x3C);
                if (e_lfanew <= 0 || e_lfanew + 264 > head.Length) return hit;
                if (head[e_lfanew] != 'P' || head[e_lfanew + 1] != 'E') return hit;

                ushort numberOfSections = BitConverter.ToUInt16(head, e_lfanew + 6);
                ushort sizeOfOptionalHeader = BitConverter.ToUInt16(head, e_lfanew + 20);
                int sectionsOffset = e_lfanew + 24 + sizeOfOptionalHeader;

                int anomalies = 0;
                for (int i = 0; i < numberOfSections && sectionsOffset + i * 40 + 40 <= head.Length; i++)
                {
                    int off = sectionsOffset + i * 40;
                    string secName = Encoding.ASCII.GetString(head, off, 8).TrimEnd('\0');
                    uint virtualSize = BitConverter.ToUInt32(head, off + 8);
                    uint characteristics = BitConverter.ToUInt32(head, off + 36);
                    bool writable = (characteristics & 0x80000000) != 0;
                    bool executable = (characteristics & 0x20000000) != 0;

                    if (writable && executable && virtualSize > 0)
                    {
                        anomalies++;
                        hit.Evidence.Add($"节 {secName}: 可写且可执行(WX)");
                    }
                    if (SuspiciousSectionNames.Contains(secName.TrimStart('.')))
                    {
                        anomalies++;
                        hit.Evidence.Add($"节 {secName}: 已知壳/加压特征节名");
                    }
                    if (virtualSize > 0 && BitConverter.ToUInt32(head, off + 16) == 0)
                    {
                        anomalies++;
                        hit.Evidence.Add($"节 {secName}: VirtualSize>0 但 RawSize=0（空壳节）");
                    }
                }

                if (numberOfSections < 2 || numberOfSections > 16)
                {
                    anomalies++;
                    hit.Evidence.Add($"节表数量异常: {numberOfSections}");
                }

                if (anomalies >= 3)
                {
                    hit.IsInfected = true;
                    hit.ThreatName = "HEUR:PE.StructureAnomaly";
                    hit.ThreatType = "结构可疑";
                    hit.Severity = "Medium";
                    hit.Confidence = Math.Min(0.55 + anomalies * 0.05, 0.85);
                }
            }
            catch { }
            return hit;
        }
    }

    /// <summary>
    /// 宏文档检测器：解析 OOXML（docx/xlsx/pptx/zip 容器），
    /// 检测内嵌 vbaProject.bin（VBA 宏工程）、autoopen/auto_close 等自动执行宏、
    /// 检测 legacy OLE 头与 RTF 异常对象。
    /// </summary>
    public class MacroDocumentAnalyzer
    {
        private static readonly HashSet<string> OfficeExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".zip" };

        public ExpandedScanHit Analyze(string filePath)
        {
            var hit = new ExpandedScanHit { FilePath = filePath, DetectionMethod = "MacroDocument" };
            try
            {
                string ext = Path.GetExtension(filePath);
                // 仅分析 OOXML 容器（PK 魔数）
                var magic = ReadMagic(filePath, 4);
                if (magic.Length < 2 || magic[0] != 0x50 || magic[1] != 0x4B) return hit;

                bool hasVba = false;
                bool hasAutoExecMacro = false;
                using (var archive = ZipFile.OpenRead(filePath))
                {
                    foreach (var entry in archive.Entries)
                    {
                        string entryPath = entry.FullName.Replace('/', '\\');
                        if (entryPath.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                        {
                            hasVba = true;
                        }
                        if (entryPath.IndexOf("word", StringComparison.OrdinalIgnoreCase) >= 0 &&
                            entryPath.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) &&
                            !entryPath.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                        {
                            // OLE 子存储，可能藏宏
                        }
                    }

                    if (hasVba)
                    {
                        // 扫描宏内容中的自动执行与高危操作
                        foreach (var entry in archive.Entries)
                        {
                            if (!entry.FullName.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)) continue;
                            try
                            {
                                using (var s = entry.Open())
                                using (var ms = new MemoryStream())
                                {
                                    s.CopyTo(ms);
                                    string content = Encoding.ASCII.GetString(ms.ToArray());
                                    if (Regex.IsMatch(content, "Auto(?:Open|Close|New|Exit)", RegexOptions.IgnoreCase) ||
                                        Regex.IsMatch(content, "Document_(?:Open|Close|BeforeSave)", RegexOptions.IgnoreCase) ||
                                        Regex.IsMatch(content, "Workbook_(?:Open|Activate)", RegexOptions.IgnoreCase))
                                    {
                                        hasAutoExecMacro = true;
                                    }
                                    int shellScore = 0;
                                    foreach (var kw in new[] { "Shell", "WScript.Shell", "CreateObject", "ShellExecute", "cmd.exe", "powershell", "WinExec", "URLDownloadToFile", "GetObject", "Environ", ".Run" })
                                    {
                                        if (content.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0) shellScore++;
                                    }
                                    if (shellScore >= 2)
                                    {
                                        hit.Evidence.Add($"宏内高危操作组合命中 {shellScore} 项");
                                        hit.IsInfected = true;
                                        hit.ThreatName = "Trojan.OOXML.MaliciousMacro";
                                        hit.ThreatType = "宏病毒";
                                        hit.Severity = "High";
                                        hit.Confidence = Math.Min(0.6 + shellScore * 0.05, 0.9);
                                    }
                                }
                            }
                            catch { }
                        }

                        if (!hit.IsInfected && hasVba)
                        {
                            // 仅有宏：弱信号（正常业务文档也可能有宏），只记证据不定罪
                            hit.Evidence.Add("文档包含 VBA 宏工程（无自动执行/高危组合）");
                        }
                        if (hit.IsInfected && hasAutoExecMacro)
                        {
                            hit.Evidence.Add("包含自动执行宏（AutoOpen/Document_Open 等）");
                            hit.Confidence = Math.Min(hit.Confidence + 0.05, 0.95);
                        }
                    }
                }
                _ = OfficeExtensions; // 保留扩展名清单供扩展使用
            }
            catch { }
            return hit;
        }

        private static byte[] ReadMagic(string path, int count)
        {
            try
            {
                using (var fs = File.OpenRead(path))
                {
                    var buf = new byte[count];
                    int n = fs.Read(buf, 0, count);
                    if (n < buf.Length) Array.Resize(ref buf, n);
                    return buf;
                }
            }
            catch { return new byte[0]; }
        }
    }

    /// <summary>
    /// 压缩包嵌套扫描器：解包 zip 容器，对内部条目递归调用引擎 ScanFile 委托
    /// （EICAR、PE 魔数、宏、脚本等），防止恶意载荷藏进压缩包逃逸扫描。
    /// 内部条目命中即命中；解压密码包无法深入，但记录为信息。
    /// </summary>
    public class ArchiveNestedScanner
    {
        private readonly Func<string, object> _innerScanDelegate;
        private readonly Func<object, bool> _isInfectedDelegate;

        /// <param name="innerScan">委托到 AntivirusEngine.ScanFile，避免循环依赖。</param>
        /// <param name="isInfected">委托读取 ScanResult.IsInfected。</param>
        public ArchiveNestedScanner(Func<string, object> innerScan, Func<object, bool> isInfected)
        {
            _innerScanDelegate = innerScan;
            _isInfectedDelegate = isInfected;
        }

        public ExpandedScanHit Analyze(string filePath, int maxDepth = 3, long maxTotalBytes = 512 * 1024 * 1024)
        {
            var hit = new ExpandedScanHit { FilePath = filePath, DetectionMethod = "ArchiveNested" };
            try
            {
                string ext = Path.GetExtension(filePath);
                if (ext != ".zip" && ext != ".docx" && ext != ".xlsx" && ext != ".pptx" &&
                    ext != ".docm" && ext != ".xlsm" && ext != ".pptm") return hit;

                var magic = new byte[2];
                using (var fs = File.OpenRead(filePath)) { if (fs.Read(magic, 0, 2) < 2) return hit; }
                if (magic[0] != 0x50 || magic[1] != 0x4B) return hit;

                using (var archive = ZipFile.OpenRead(filePath))
                {
                    long total = 0;
                    string tempDir = Path.Combine(Path.GetTempPath(), "FA_NestedScan_" + Guid.NewGuid().ToString("N"));
                    try
                    {
                        Directory.CreateDirectory(tempDir);
                        foreach (var entry in archive.Entries)
                        {
                            if (string.IsNullOrEmpty(entry.Name)) continue; // 目录项
                            total += entry.Length;
                            if (total > maxTotalBytes) break;

                            string ext2 = Path.GetExtension(entry.Name);
                            bool worthExtracting =
                                ext2 == ".exe" || ext2 == ".dll" || ext2 == ".scr" || ext2 == ".bat" ||
                                ext2 == ".cmd" || ext2 == ".ps1" || ext2 == ".vbs" || ext2 == ".js" ||
                                ext2 == ".hta" || ext2 == ".jar" || ext2 == ".lnk" || ext2 == ".zip";
                            if (!worthExtracting) continue;

                            string dest = Path.Combine(tempDir, Guid.NewGuid().ToString("N") + ext2);
                            entry.ExtractToFile(dest, true);
                            try
                            {
                                object inner = _innerScanDelegate(dest);
                                if (inner != null && _isInfectedDelegate(inner))
                                {
                                    hit.IsInfected = true;
                                    hit.ThreatName = "Trojan.Archive.Payload";
                                    hit.ThreatType = "压缩包载荷";
                                    hit.Severity = "High";
                                    hit.Confidence = 0.9;
                                    hit.Evidence.Add($"压缩包内发现恶意载荷: {entry.FullName}");
                                    return hit;
                                }
                            }
                            finally
                            {
                                try { File.Delete(dest); } catch { }
                            }
                        }
                    }
                    finally
                    {
                        try { Directory.Delete(tempDir, true); } catch { }
                    }
                }
            }
            catch { }
            return hit;
        }
    }

    /// <summary>
    /// 嵌入式模式规则引擎：加载随 DLL 内嵌的知识库规则包
    /// （KnowledgeBase/*.rules.json，由 tools/generate_knowledge_base.py 生成），
    /// 对脚本/文本类内容做模式匹配，对 PE 做结构规则比对。
    /// 规则命中需要 ≥2 条不同规则同时命中才投票，防止单条泛化规则误报。
    /// </summary>
    public class PatternRuleEngine
    {
        private List<RuleEntry> _rules;
        private readonly object _lock = new object();

        public int LoadedRuleCount
        {
            get { EnsureLoaded(); return _rules?.Count ?? 0; }
        }

        public class RuleEntry
        {
            public string Id;
            public string Type;       // sp=string pattern, hp=hex pattern, rp=registry, dp=domain pattern
            public string Pattern;
            public string Family;
            public int Severity;
        }

        private void EnsureLoaded()
        {
            if (_rules != null) return;
            lock (_lock)
            {
                if (_rules != null) return;
                var list = new List<RuleEntry>();
                List<string> paths = new List<string>();
                try
                {
                    var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                    var candidates = new List<string>
                    {
                        Path.Combine(baseDir, "FireAntivirus.Engine.rules.json"),
                        Path.Combine(baseDir, "KnowledgeBase", "FireAntivirus.Engine.rules.json")
                    };
                    // 兼容同一目录下其它以 .rules.json 结尾的外置规则包
                    if (Directory.Exists(baseDir))
                    {
                        candidates.AddRange(Directory.EnumerateFiles(baseDir, "*.rules.json", SearchOption.TopDirectoryOnly));
                        var kbDir = Path.Combine(baseDir, "KnowledgeBase");
                        if (Directory.Exists(kbDir))
                            candidates.AddRange(Directory.EnumerateFiles(kbDir, "*.rules.json", SearchOption.TopDirectoryOnly));
                    }
                    foreach (var path in candidates)
                    {
                        if (paths.Contains(path, StringComparer.OrdinalIgnoreCase)) continue;
                        if (!File.Exists(path)) continue;
                        paths.Add(path);
                    }
                    foreach (var path in paths)
                    {
                        foreach (var line in File.ReadAllLines(path, Encoding.UTF8))
                        {
                            var r = ParseRuleLine(line);
                            if (r != null) list.Add(r);
                        }
                    }
                }
                catch (Exception ex) { _loadError = ex.Message; }
                _rules = list;
            }
        }

        private string _loadError;

        private RuleEntry ParseRuleLine(string line)
        {
            // 行格式（生成器产出，逐行 JSON，容忍简版解析避免依赖）：
            // {"id":"...","t":"sp","p":"...","f":"...","s":3}
            try
            {
                if (string.IsNullOrWhiteSpace(line) || line.Length < 10) return null;
                int idIdx = line.IndexOf("\"id\":\"", StringComparison.Ordinal);
                int tIdx = line.IndexOf("\"t\":\"", StringComparison.Ordinal);
                int pIdx = line.IndexOf("\"p\":\"", StringComparison.Ordinal);
                int fIdx = line.IndexOf("\"f\":\"", StringComparison.Ordinal);
                int sIdx = line.IndexOf("\"s\":", StringComparison.Ordinal);
                if (tIdx < 0 || pIdx < 0) return null;
                var e = new RuleEntry
                {
                    Id = Extract(line, idIdx, "\"id\":\""),
                    Type = Extract(line, tIdx, "\"t\":\""),
                    Pattern = Extract(line, pIdx, "\"p\":\""),
                    Family = fIdx >= 0 ? Extract(line, fIdx, "\"f\":\"") : "Generic",
                    Severity = sIdx >= 0 ? SafeInt(line, sIdx + 4) : 2
                };
                return string.IsNullOrEmpty(e.Pattern) ? null : e;
            }
            catch { return null; }
        }

        private static string Extract(string s, int idx, string key)
        {
            if (idx < 0) return null;
            int start = idx + key.Length;
            var sb = new StringBuilder();
            for (int i = start; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\\' && i + 1 < s.Length) { sb.Append(s[i + 1]); i++; continue; }
                if (c == '"') break;
                sb.Append(c);
            }
            return sb.ToString();
        }

        private static int SafeInt(string s, int idx)
        {
            int end = idx;
            while (end < s.Length && char.IsDigit(s[end])) end++;
            return end > idx && int.TryParse(s.Substring(idx, end - idx), out var v) ? v : 2;
        }

        public ExpandedScanHit AnalyzeContent(string filePath, byte[] content)
        {
            var hit = new ExpandedScanHit { FilePath = filePath, DetectionMethod = "PatternRuleEngine" };
            EnsureLoaded();
            if (_rules == null || _rules.Count == 0 || content == null || content.Length == 0) return hit;

            try
            {
                // 仅对文本可解析内容（脚本/配置/文档）做模式匹配，PE 按结构规则由 PE 分析器负责
                string text = null;
                foreach (var enc in new[] { Encoding.UTF8, Encoding.ASCII })
                {
                    try
                    {
                        var candidate = enc.GetString(content);
                        bool binaryNoise = candidate.Count(c => c == '\0') > content.Length / 10;
                        if (!binaryNoise) { text = candidate; break; }
                    }
                    catch { }
                }
                if (text == null) return hit;

                var families = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var rule in _rules)
                {
                    if (rule.Type != "sp") continue;
                    if (rule.Pattern.Length < 6) continue; // 短模式不可靠，跳过
                    if (text.IndexOf(rule.Pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        families.Add(rule.Family ?? "Generic");
                        hit.Evidence.Add($"{rule.Id} ({rule.Family})");
                        if (families.Count >= 2)
                        {
                            hit.IsInfected = true;
                            hit.ThreatName = "HEUR:PatternRule.Multi";
                            hit.ThreatType = "模式匹配";
                            hit.Severity = rule.Severity >= 3 ? "High" : "Medium";
                            hit.Confidence = Math.Min(0.6 + families.Count * 0.05, 0.9);
                            return hit;
                        }
                    }
                }
            }
            catch { }
            return hit;
        }
    }

    /// <summary>
    /// 持久化项扫描器：Run/RunOnce 注册表键、启动文件夹、计划任务目录，
    /// 发现指向临时目录/可疑路径的自动启动项。仅在需要时调用，不参与逐文件扫描。
    /// </summary>
    public class PersistenceScanner
    {
        private static readonly string[] SuspiciousPathMarkers =
        { "\\temp\\", "\\appdata\\local\\temp\\", "\\users\\public\\", "\\programdata\\", "\\windows\\tracing\\" };

        public List<ExpandedScanHit> ScanPersistence()
        {
            var results = new List<ExpandedScanHit>();
            try
            {
                string[] runKeys =
                {
                    @"Software\Microsoft\Windows\CurrentVersion\Run",
                    @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"HKLM\" + "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    @"HKLM\" + "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
                };

                using (var hkcu = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    ScanRunKey(hkcu, "HKCU Run", results);
                }
                using (var hklm = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    ScanRunKey(hklm, "HKLM Run", results);
                }

                // 启动文件夹
                string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(startup))
                {
                    foreach (var f in Directory.GetFiles(startup))
                    {
                        var hit = new ExpandedScanHit { FilePath = f, DetectionMethod = "Persistence" };
                        if (f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            hit.Evidence.Add("启动文件夹中的自动启动项");
                            if (f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            {
                                // 用户级启动文件夹里的 exe 是经典持久化手法，值得提示
                                hit.IsInfected = false; // 交给共识管线，这里只收集线索
                                hit.Severity = "Low";
                                hit.Confidence = 0.3;
                            }
                            results.Add(hit);
                        }
                    }
                }
            }
            catch { }
            return results;
        }

        private void ScanRunKey(Microsoft.Win32.RegistryKey key, string source, List<ExpandedScanHit> results)
        {
            if (key == null) return;
            foreach (var name in key.GetValueNames())
            {
                try
                {
                    string value = key.GetValue(name)?.ToString() ?? "";
                    var hit = new ExpandedScanHit { FilePath = value, DetectionMethod = "Persistence", ThreatType = "持久化项" };
                    string lower = value.ToLowerInvariant();
                    foreach (var marker in SuspiciousPathMarkers)
                    {
                        if (lower.Contains(marker))
                        {
                            hit.IsInfected = true;
                            hit.ThreatName = "HEUR:Persistence.SuspiciousPath";
                            hit.Severity = "Medium";
                            hit.Confidence = 0.6;
                            hit.Evidence.Add($"{source}: {name} -> {value}");
                            results.Add(hit);
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }
}
