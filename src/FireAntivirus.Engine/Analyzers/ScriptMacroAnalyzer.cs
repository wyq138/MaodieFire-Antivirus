// 脚本/宏文档深度检测层（独立投票方，参与 ScanFile 多源共识）：
//   1) 脚本混淆与下载器特征（PowerShell/BAT/CMD/JS/VBS/WSF/HTA）
//   2) Office 宏植入（OOXML vbaProject.bin / 旧版 OLE VBA 流 / RTF 漏洞利用关键字）
// 全部为真实字节级/文本级特征匹配，无占位逻辑。命中作为一票弱证据，由共识裁决定罪。
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class ScriptMacroAnalyzer
    {
        private const int MaxScanBytes = 512 * 1024;       // 文本类读取上限
        private const int MaxBinaryScanBytes = 4 * 1024 * 1024; // OOXML/OLE 头部搜索范围

        // ---- 脚本高危特征（分组计类：命中 ≥2 组才报警，避免单串误报）----
        private static readonly string[][] ScriptFeatureGroups =
        {
            // 组1：PowerShell 编码/混淆执行
            new[] { "-enc ", "-encodedcommand", "frombase64string", "iex (", "invoke-expression", "-nop -w hidden", "-windowstyle hidden", "executionpolicy bypass" },
            // 组2：脚本下载器
            new[] { "downloadstring", "downloadfile", "net.webclient", "invoke-webrequest", "invoke-restmethod", "xmlhttp", "msxml2.serverxmlhttp" },
            // 组3：VBS/JS 混淆与自启动
            new[] { "wscript.shell", "eval(", "chr(", "adodb.stream", "shell.application", "regwrite", "hkey_current_user\\software\\microsoft\\windows\\currentversion\\run" },
            // 组4：BAT/CMD 武器化命令
            new[] { "certutil -urlcache", "bitsadmin /transfer", "vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set {default} recoveryenabled no", "net user /add", "schtasks /create /sc" },
            // 组5：HTA/WSF 植入
            new[] { "mshta", "<script", "regsvr32 /i:http", "rundll32 javascript" }
        };

        // ---- RTF 漏洞利用特征 ----
        private static readonly string[] RtfIndicators = { "\\objupdate", "equation.native", "\\objectdata", "\\objclass", "msxml2" };

        public ScanResult Analyze(string filePath)
        {
            var result = new ScanResult
            {
                FilePath = filePath,
                IsInfected = false,
                DetectionTime = DateTime.Now
            };
            if (!File.Exists(filePath)) return result;

            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            try
            {
                switch (ext)
                {
                    case ".ps1":
                    case ".bat":
                    case ".cmd":
                    case ".js":
                    case ".jse":
                    case ".vbs":
                    case ".vbe":
                    case ".wsf":
                    case ".hta":
                        return AnalyzeScript(filePath, result, ext);
                    case ".docm":
                    case ".dotm":
                    case ".xlsm":
                    case ".xlam":
                    case ".pptm":
                        return AnalyzeOoxmlMacro(filePath, result);
                    case ".doc":
                    case ".xls":
                    case ".ppt":
                        return AnalyzeOleMacro(filePath, result);
                    case ".rtf":
                        return AnalyzeRtf(filePath, result);
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"脚本宏检测失败 {filePath}: {ex.Message}");
            }
            return result;
        }

        private ScanResult AnalyzeScript(string filePath, ScanResult result, string ext)
        {
            string text = ReadTextHead(filePath, MaxScanBytes);
            if (string.IsNullOrEmpty(text)) return result;
            string lower = text.ToLowerInvariant();

            int groupsHit = 0;
            var hits = new List<string>();
            for (int g = 0; g < ScriptFeatureGroups.Length; g++)
            {
                foreach (var feature in ScriptFeatureGroups[g])
                {
                    if (lower.Contains(feature))
                    {
                        groupsHit++;
                        hits.Add($"组{g + 1}:{feature}");
                        break;
                    }
                }
            }

            if (groupsHit >= 2)
            {
                result.IsInfected = true;
                result.ThreatName = groupsHit >= 3 ? "Script.Obfuscated-Downloader" : "Script.Suspicious-Combined";
                result.ThreatType = "Trojan";
                result.Severity = groupsHit >= 3 ? "High" : "Medium";
                result.Confidence = Math.Min(0.9, 0.72 + groupsHit * 0.04);
                result.DetectionMethod = "ScriptMacro-Script";
                result.AdditionalInfo = $"脚本高危特征 {groupsHit} 组同时命中: {string.Join("; ", hits)}";
            }

            // AMSI：调用系统 amsi.dll 对脚本内容做真实扫描，作为独立强证据源。
            // 未安装 AMSI provider 时系统返回 CLEAN/NOT_DETECTED，不会凭空定罪。
            try
            {
                var verdict = AmsiScanner.ScanContent(text, Path.GetFileName(filePath));
                if (verdict == AmsiVerdict.Detected || verdict == AmsiVerdict.BlockedByAdmin)
                {
                    result.IsInfected = true;
                    result.ThreatName = "Script.Amsi.Detected";
                    result.ThreatType = "Trojan";
                    result.Severity = "High";
                    result.Confidence = Math.Max(result.Confidence, 0.95);
                    result.DetectionMethod = string.IsNullOrEmpty(result.DetectionMethod)
                        ? "AMSI"
                        : result.DetectionMethod + "+AMSI";
                    string amsiInfo = $"AMSI 引擎判定恶意（{verdict}）";
                    result.AdditionalInfo = string.IsNullOrEmpty(result.AdditionalInfo)
                        ? amsiInfo
                        : result.AdditionalInfo + "; " + amsiInfo;
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    "AMSI 扫描异常（跳过该证据）: " + ex.Message);
            }
            return result;
        }

        private ScanResult AnalyzeOoxmlMacro(string filePath, ScanResult result)
        {
            // OOXML = ZIP 容器；宏文件必含 vbaProject.bin 条目（头部 4MB 内搜索目录名，免全解压）
            byte[] head = ReadBinaryHead(filePath, MaxBinaryScanBytes);
            if (head.Length < 4 || head[0] != 'P' || head[1] != 'K') return result; // 非 ZIP

            if (ContainsAscii(head, "vbaProject.bin") || ContainsAscii(head, "vbaProject"))
            {
                result.IsInfected = true;
                result.ThreatName = "Macro.Office.Loader";
                result.ThreatType = "Trojan";
                result.Severity = "High";
                result.Confidence = 0.8;
                result.DetectionMethod = "ScriptMacro-OOXML";
                result.AdditionalInfo = "Office 启用宏文档（含 vbaProject 宏工程），宏为恶意文档主要投递载体";
            }
            return result;
        }

        private ScanResult AnalyzeOleMacro(string filePath, ScanResult result)
        {
            // 旧版 Office = OLE 复合文档（CFB），VBA 宏以 vbaProject/VBA 存储出现
            byte[] head = ReadBinaryHead(filePath, MaxBinaryScanBytes);
            if (head.Length < 8) return result;
            if (!(head[0] == 0xD0 && head[1] == 0xCF && head[2] == 0x11 && head[3] == 0xE0)) return result;

            if (ContainsAscii(head, "vbaProject") || ContainsAscii(head, "_VBA_PROJECT"))
            {
                result.IsInfected = true;
                result.ThreatName = "Macro.Office.Loader";
                result.ThreatType = "Trojan";
                result.Severity = "High";
                result.Confidence = 0.78;
                result.DetectionMethod = "ScriptMacro-OLE";
                result.AdditionalInfo = "旧版 Office 文档含 VBA 宏工程";
            }
            return result;
        }

        private ScanResult AnalyzeRtf(string filePath, ScanResult result)
        {
            string text = ReadTextHead(filePath, MaxScanBytes);
            if (string.IsNullOrEmpty(text)) return result;
            string lower = text.ToLowerInvariant();

            int hits = 0;
            foreach (var ind in RtfIndicators)
                if (lower.Contains(ind)) hits++;

            if (hits >= 2)
            {
                result.IsInfected = true;
                result.ThreatName = "Rtf.Exploit.Loader";
                result.ThreatType = "Exploit";
                result.Severity = "High";
                result.Confidence = 0.82;
                result.DetectionMethod = "ScriptMacro-RTF";
                result.AdditionalInfo = $"RTF 漏洞利用特征 {hits} 项同时命中（objupdate/OLE 对象链）";
            }
            return result;
        }

        // ---- 工具 ----

        private static string ReadTextHead(string path, int maxBytes)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            int len = (int)Math.Min(fs.Length, maxBytes);
            var buf = new byte[len];
            int read = 0;
            while (read < len)
            {
                int n = fs.Read(buf, read, len - read);
                if (n <= 0) break;
                read += n;
            }
            return Encoding.UTF8.GetString(buf, 0, read);
        }

        private static byte[] ReadBinaryHead(string path, int maxBytes)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            int len = (int)Math.Min(fs.Length, maxBytes);
            var buf = new byte[len];
            int read = 0;
            while (read < len)
            {
                int n = fs.Read(buf, read, len - read);
                if (n <= 0) break;
                read += n;
            }
            if (read < buf.Length) Array.Resize(ref buf, read);
            return buf;
        }

        private static bool ContainsAscii(byte[] data, string needle)
        {
            var pat = Encoding.ASCII.GetBytes(needle);
            if (pat.Length == 0 || data.Length < pat.Length) return false;
            for (int i = 0; i <= data.Length - pat.Length; i++)
            {
                int j = 0;
                for (; j < pat.Length; j++)
                    if ((data[i + j] & 0xDF) != (pat[j] & 0xDF)) break; // 大小写不敏感
                if (j == pat.Length) return true;
            }
            return false;
        }

        /// <summary>脚本/宏/文档类扩展名（本检测层负责的范围）。</summary>
        public static bool IsScriptOrDocExt(string filePath)
        {
            string ext = Path.GetExtension(filePath)?.ToLowerInvariant() ?? "";
            switch (ext)
            {
                case ".ps1": case ".bat": case ".cmd": case ".js": case ".jse":
                case ".vbs": case ".vbe": case ".wsf": case ".hta":
                case ".docm": case ".dotm": case ".xlsm": case ".xlam": case ".pptm":
                case ".doc": case ".xls": case ".ppt": case ".rtf":
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>ML 特征评分候选（PE + 脚本/宏文档，全部参与）。</summary>
        public static bool IsMlCandidateExt(string filePath)
        {
            if (IsScriptOrDocExt(filePath)) return true;
            string ext = Path.GetExtension(filePath)?.ToLowerInvariant() ?? "";
            switch (ext)
            {
                case ".exe": case ".dll": case ".scr": case ".com": case ".pif":
                case ".cpl": case ".ocx": case ".sys": case ".msi": case ".jar":
                    return true;
                default:
                    return false;
            }
        }
    }
}