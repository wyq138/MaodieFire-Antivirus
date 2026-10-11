using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using FireAntivirus.Common;

namespace FireAntivirus.Engine.Analyzers
{
    /// <summary>
    /// 勒索行为链推理：不是查单个"勒索特征词"，而是通过组合证据链判定。
    /// 证据链：加密API调用 + 卷影删除 + 文件遍历 + 勒索留言特征 同时出现才显著计分。
    /// 正常软件不会同时触发这些行为。
    /// </summary>
    public sealed class RansomwareBehaviorChainAnalyzer
    {
        // 勒索必备的证据链元素
        private static readonly string[] CryptoApis =
        {
            "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenKey",
            "CryptExportKey", "BCryptEncrypt", "BCryptGenerateSymmetricKey",
            "RSAEncrypt", "RSADecrypt", "AESEncrypt", "AESDecrypt"
        };

        private static readonly string[] ShadowCopySignals =
        {
            "vssadmin delete shadows", "wmic shadowcopy delete", "vssadmin resize shadowstorage",
            "diskshadow", "VssCreateVss", "VssDelete"
        };

        private static readonly string[] FileTraversalSignals =
        {
            "FindFirstFile", "FindNextFile", "FindFirstFileEx", "GetLogicalDrives",
            "GetDriveType", "Directory.GetFiles", "Directory.EnumerateFiles"
        };

        private static readonly string[] RansomNotePatterns =
        {
            "readme", "README", "help_decrypt", "HOW_TO_DECRYPT", "recover",
            "@ransom", "decrypt", "payment", "bitcoin", "monero", "wallet",
            "your files", "YourFiles", "have been encrypted", "encrypted by",
            "private key", "ransom"
        };

        private static readonly string[] ExtensionSpoofPatterns =
        {
            ".encrypted", ".locked", ".crypt", ".cryptolocker", ".cry", ".locky",
            ".cerber", ".dharma", ".phobos", ".stop", ".wallet", ".wanna"
        };

        public sealed class RansomwareChainEvidence
        {
            public bool HasCryptoApi;               // 加密API调用
            public bool HasShadowDelete;             // 卷影删除
            public bool HasFileTraversal;            // 文件遍历
            public bool HasRansomNote;               // 勒索留言特征
            public bool HasExtensionSpoof;           // 后缀篡改
            public int ChainCount;                   // 独立证据链环节数 0..5
            public double Strength;                  // 证据强度 0..1
            public string Notes = "";
        }

        /// <summary>
        /// 分析给定文本（导入表/命令行/字符串/文件内容）中的勒索证据链。
        /// 文本内容来自导入表、进程命令行、文件字符串等。
        /// </summary>
        public RansomwareChainEvidence Analyze(string content)
        {
            var ev = new RansomwareChainEvidence();
            if (string.IsNullOrWhiteSpace(content)) return ev;

            try
            {
                ev.HasCryptoApi = CryptoApis.Any(a => content.Contains(a, StringComparison.OrdinalIgnoreCase));
                ev.HasShadowDelete = ShadowCopySignals.Any(s => content.Contains(s, StringComparison.OrdinalIgnoreCase));
                ev.HasFileTraversal = FileTraversalSignals.Any(f => content.Contains(f, StringComparison.OrdinalIgnoreCase));
                ev.HasRansomNote = RansomNotePatterns.Any(r => content.Contains(r, StringComparison.OrdinalIgnoreCase));
                ev.HasExtensionSpoof = ExtensionSpoofPatterns.Any(e => content.Contains(e, StringComparison.OrdinalIgnoreCase));

                ev.ChainCount = (ev.HasCryptoApi ? 1 : 0) + (ev.HasShadowDelete ? 1 : 0) +
                                (ev.HasFileTraversal ? 1 : 0) + (ev.HasRansomNote ? 1 : 0) +
                                (ev.HasExtensionSpoof ? 1 : 0);

                // 强度：链越长越可疑
                if (ev.ChainCount >= 4) { ev.Strength = 0.85; ev.Notes = "勒索行为链完整（加密+卷影+遍历+留言+后缀）"; }
                else if (ev.ChainCount >= 3) { ev.Strength = 0.55; ev.Notes = "勒索行为链部分证据"; }
                else if (ev.ChainCount >= 2) { ev.Strength = 0.25; ev.Notes = "勒索行为初始线索"; }
            }
            catch (Exception ex)
            {
                LogHelper.Log(LogHelper.LogLevel.Warning, "RansomwareBehaviorChainAnalyzer 失败", ex.Message);
            }
            return ev;
        }
    }
}