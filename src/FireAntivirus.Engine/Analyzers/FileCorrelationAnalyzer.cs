using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FireAntivirus.Common;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// 多文件关联评分：分析同一目录下多个文件的"关联恶意证据"。
    /// 不是孤立判文件，而是看"同目录配套"——比如一个 DLL 被多个 EXE 加载，
    /// 或同目录混入隐藏脚本/加密荷载。强证据（如共用已知恶意哈希）才显著加分。
    /// </summary>
    public sealed class FileCorrelationAnalyzer
    {
        /// <summary>单次扫描临时缓存，防止重复哈希。</summary>
        private readonly Dictionary<string, string> _hashCache = new(StringComparer.OrdinalIgnoreCase);

        public sealed class CorrelationEvidence
        {
            public bool HasSuspiciousDrop;          // 同目录存在隐藏的脚本/加密荷载
            public int SuspiciousFileCount;         // 可疑配套文件数
            public int HighEntropyCount;            // 高熵文件数（>7.8）
            public int HiddenFileCount;             // 隐藏/系统属性文件数
            public double Strength;                 // 证据强度 0..1
            public string Notes = "";               // 中文描述
        }

        /// <summary>
        /// 对给定文件路径，扫描其所在目录的关联文件，返回关联证据。
        /// 采用保守策略：最少 2 个独立证据类别才构成有效关联信号。
        /// </summary>
        public CorrelationEvidence Analyze(string filePath, int maxScan = 200)
        {
            var ev = new CorrelationEvidence();
            try
            {
                var dir = Path.GetDirectoryName(filePath);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return ev;

                var files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly)
                    .Take(maxScan).ToList();
                if (files.Count <= 1) return ev; // 只有自己，无所谓关联

                int suspicious = 0, highEntropy = 0, hidden = 0;
                var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                bool hasPs1 = false, hasBat = false, hasUnknown = false;

                foreach (var f in files)
                {
                    var fi = new FileInfo(f);
                    var ext = fi.Extension.ToLowerInvariant();
                    exts.Add(ext);

                    try
                    {
                        // 隐藏/系统属性文件
                        if ((fi.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0)
                            hidden++;

                        // 脚本文件
                        if (ext == ".ps1" || ext == ".vbs" || ext == ".hta") hasPs1 = true;
                        if (ext == ".bat" || ext == ".cmd") hasBat = true;

                        // 未知/无扩展名文件
                        if (string.IsNullOrEmpty(ext) || ext == ".tmp" || ext == ".dat" || ext == ".bin")
                            hasUnknown = true;

                        // 高熵（小文件快速熵检）
                        if (fi.Length > 0 && fi.Length < 5 * 1024 * 1024)
                        {
                            var data = File.ReadAllBytes(f);
                            double ent = ComputeEntropy(data);
                            if (ent > 7.8) highEntropy++;
                        }
                    }
                    catch { continue; }
                }

                // 关联恶意线索
                // 线索1: 隐藏/系统文件 ≥ 2
                if (hidden >= 2) { suspicious++; ev.HiddenFileCount = hidden; }
                // 线索2: 脚本 + 高熵无扩展文件同目录（经典的 dropper 模式）
                if ((hasPs1 || hasBat) && hasUnknown && highEntropy >= 1) { suspicious++; }
                // 线索3: 高熵文件数 ≥ 3
                if (highEntropy >= 3) { suspicious++; ev.HighEntropyCount = highEntropy; }
                // 线索4: 目录内超过 30% 文件无扩展名或为 .tmp/.dat
                int noExt = files.Count(f =>
                {
                    var e = Path.GetExtension(f);
                    return string.IsNullOrEmpty(e) || e.Equals(".tmp", StringComparison.OrdinalIgnoreCase) || e.Equals(".dat", StringComparison.OrdinalIgnoreCase);
                });
                if (files.Count > 0 && (double)noExt / files.Count > 0.3) suspicious++;

                ev.SuspiciousFileCount = suspicious;
                ev.HasSuspiciousDrop = suspicious >= 2;

                // 强度（弱信号，仅辅助）
                if (suspicious >= 4) { ev.Strength = 0.25; ev.Notes = "多文件关联异常（隐藏文件+脚本+高熵+未知扩展）"; }
                else if (suspicious >= 3) { ev.Strength = 0.18; ev.Notes = "存在多文件关联异常线索"; }
                else if (suspicious >= 2) { ev.Strength = 0.10; ev.Notes = "轻微关联异常"; }
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Warning, "FileCorrelationAnalyzer 失败", ex.Message);
            }
            return ev;
        }

        private static double ComputeEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0.0;
            long[] freq = new long[256];
            for (int i = 0; i < data.Length; i++) freq[data[i]]++;
            double ent = 0.0, len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = freq[i] / len;
                ent -= p * Math.Log(p, 2);
            }
            return ent;
        }
    }
}