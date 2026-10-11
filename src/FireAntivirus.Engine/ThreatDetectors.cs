// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using FireAntivirus.Common;
using FireAntivirus.Engine.Strings;

namespace FireAntivirus.Engine
{
    /// <summary>
    /// 漏洞利用检测器 - 检测已知的漏洞利用行为和模式
    /// </summary>
    public class ExploitDetector
    {
        private readonly List<string> _exploitPatterns = new List<string>
        {
            // Shellcode模式
            @"\x90\x90\x90\x90", // NOP sled
            @"\xCC\xCC\xCC\xCC", // INT3断点
            @"\xEB\x..",         // JMP指令
            @"\xE9\x..",         // JMP NEAR
            @"\xFF\xE4",         // JMP ESP
            @"\xFF\xE0",         // JMP EAX
            @"\xFF\xD0",         // CALL EAX
            @"\xFF\xD2",         // CALL EDX
            
            // ROP链模式
            @"ROP",
            @"gadget",
            @"\x58\x59\x5A\x5B", // POP EAX, ECX, EDX, EBX
            @"\xC3",             // RET
            
            // 堆喷射模式
            @"heap spray",
            @"\x0D\x0D\x0D\x0D",
            @"\x0C\x0C\x0C\x0C",
            
            // 常见漏洞利用函数
            @"VirtualProtect",
            @"VirtualAlloc",
            @"HeapCreate",
            @"RtlMoveMemory",
            @"NtCreateThread",
            @"NtQueueApcThread"
        };

        // 已知漏洞CVE标识
        private readonly Dictionary<string, string> _knownExploits = new Dictionary<string, string>
        {
            { "CVE-2017-0199", "Office RTF漏洞利用" },
            { "CVE-2017-11882", "Office公式编辑器漏洞" },
            { "CVE-2018-0802", "Office公式编辑器漏洞" },
            { "CVE-2018-8174", "IE VBScript引擎漏洞" },
            { "CVE-2018-8440", "Windows ALPC漏洞" },
            { "CVE-2019-0708", "BlueKeep RDP漏洞" },
            { "CVE-2019-1388", "Windows证书对话框漏洞" },
            { "CVE-2020-0601", "Windows CryptoAPI漏洞" },
            { "CVE-2020-1054", "Windows内核漏洞" },
            { "CVE-2020-0787", "Windows SMB漏洞" },
            { "CVE-2020-16875", "Exchange Server漏洞" },
            { "CVE-2021-34527", "PrintNightmare打印机漏洞" },
            { "CVE-2021-44228", "Log4j远程代码执行漏洞" },
            { "CVE-2022-21907", "HTTP协议栈漏洞" },
            { "CVE-2022-26809", "RPC远程代码执行漏洞" }
        };

        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Exploit",
                Confidence = 0.0
            };

            try
            {
                // 1. 检测Shellcode模式
                int shellcodeScore = DetectShellcodePatterns(fileContent);

                // 2. 检测ROP链
                int ropScore = DetectROPChains(fileContent);

                // 3. 检测已知漏洞标识
                var exploitInfo = DetectKnownExploits(fileContent);

                // 4. 检测反调试技术
                int antiDebugScore = DetectAntiDebugTechniques(fileContent);

                // 5. 检测可疑的内存操作模式
                int memoryOpsScore = DetectSuspiciousMemoryOps(fileContent);

                // 综合评估
                double totalScore = (shellcodeScore * 0.25) + (ropScore * 0.2) + 
                                   (exploitInfo.found ? 0.4 : 0) + 
                                   (antiDebugScore * 0.1) + (memoryOpsScore * 0.05);

                if (totalScore > 0.7)
                {
                    result.IsDetected = true;
                    result.ThreatName = exploitInfo.found ? exploitInfo.name : "疑似漏洞利用代码";
                    result.Confidence = Math.Min(1.0, totalScore + 0.1);
                    result.Details = $"Shellcode分数: {shellcodeScore}, ROP分数: {ropScore}, 反调试分数: {antiDebugScore}";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ThreatDetectors.cs 捕获异常", ex.Message); }

            return result;
        }

        private int DetectShellcodePatterns(byte[] content)
        {
            int score = 0;
            int nopCount = 0;
            int int3Count = 0;
            bool hasJmpEsp = false;
            bool hasJmpEax = false;
            bool hasCallEax = false;

            // 检测NOP滑行和INT3断点
            for (int i = 0; i < content.Length - 4; i++)
            {
                if (content[i] == 0x90 && content[i + 1] == 0x90 && 
                    content[i + 2] == 0x90 && content[i + 3] == 0x90)
                {
                    nopCount++;
                }

                if (content[i] == 0xCC && content[i + 1] == 0xCC &&
                    content[i + 2] == 0xCC && content[i + 3] == 0xCC)
                {
                    int3Count++;
                }
            }

            // 大幅提高NOP sled阈值: >100 才加分
            if (nopCount > 100) score += 10;

            // INT3 断点单独出现不加分，仅作标记
            if (int3Count > 5) score += 5;

            // 检测JMP ESP/CALL EAX等
            for (int i = 0; i < content.Length - 2; i++)
            {
                // JMP ESP (FF E4)
                if (content[i] == 0xFF && content[i + 1] == 0xE4) hasJmpEsp = true;
                // JMP EAX (FF E0)
                if (content[i] == 0xFF && content[i + 1] == 0xE0) hasJmpEax = true;
                // CALL EAX (FF D0)
                if (content[i] == 0xFF && content[i + 1] == 0xD0) hasCallEax = true;
            }

            // 关键：只有 NOP + INT3 + JMP ESP 多种shellcode模式同时出现时才大幅加分
            if (nopCount > 0 && int3Count > 0 && hasJmpEsp)
            {
                score += 40;
            }
            else if (nopCount > 0 && hasJmpEsp)
            {
                score += 15;
            }
            else if (hasJmpEsp || hasJmpEax || hasCallEax)
            {
                score += 5;
            }

            return Math.Min(100, score);
        }

        private int DetectROPChains(byte[] content)
        {
            int score = 0;
            string contentStr = Encoding.ASCII.GetString(content, 0, Math.Min(content.Length, 10000));

            // 检测ROP相关字符串
            if (contentStr.Contains("ROP") || contentStr.Contains("gadget")) score += 40;

            // 检测连续的POP指令模式
            int popSequence = 0;
            for (int i = 0; i < content.Length - 4; i++)
            {
                // POP EAX, ECX, EDX, EBX序列 (58 59 5A 5B)
                if (content[i] == 0x58 && content[i + 1] == 0x59 &&
                    content[i + 2] == 0x5A && content[i + 3] == 0x5B)
                {
                    popSequence++;
                }
            }

            if (popSequence > 5) score += 30;
            else if (popSequence > 0) score += 15;

            return Math.Min(100, score);
        }

        private (bool found, string name) DetectKnownExploits(byte[] content)
        {
            string contentStr = Encoding.ASCII.GetString(content, 0, Math.Min(content.Length, 50000));

            foreach (var exploit in _knownExploits)
            {
                if (contentStr.Contains(exploit.Key))
                {
                    return (true, exploit.Value);
                }
            }

            return (false, string.Empty);
        }

        private int DetectAntiDebugTechniques(byte[] content)
        {
            int score = 0;
            int antiDebugCount = 0;
            string contentStr = Encoding.ASCII.GetString(content, 0, Math.Min(content.Length, 10000));

            // 反调试API - 需要至少2种反调试特征同时出现才加分
            if (contentStr.Contains("IsDebuggerPresent")) antiDebugCount++;
            if (contentStr.Contains("CheckRemoteDebuggerPresent")) antiDebugCount++;
            if (contentStr.Contains("NtQueryInformationProcess")) antiDebugCount++;
            if (contentStr.Contains("NtSetInformationThread")) antiDebugCount++;
            if (contentStr.Contains("OutputDebugString")) antiDebugCount++;
            if (contentStr.Contains("rdtsc") || contentStr.Contains("QueryPerformanceCounter")) antiDebugCount++;

            // 至少2种反调试特征同时出现才加分
            if (antiDebugCount >= 3) score += 30;
            else if (antiDebugCount >= 2) score += 15;
            else if (antiDebugCount >= 1) score += 5;

            return Math.Min(100, score);
        }

        private int DetectSuspiciousMemoryOps(byte[] content)
        {
            int score = 0;
            string contentStr = Encoding.ASCII.GetString(content, 0, Math.Min(content.Length, 10000));

            bool hasNormalApi = contentStr.Contains("VirtualProtect") || 
                                contentStr.Contains("VirtualAlloc") || 
                                contentStr.Contains("HeapCreate");
            int suspiciousCount = 0;
            
            if (contentStr.Contains("WriteProcessMemory")) suspiciousCount++;
            if (contentStr.Contains("CreateRemoteThread")) suspiciousCount++;
            if (contentStr.Contains("RtlMoveMemory")) suspiciousCount++;
            if (contentStr.Contains("NtCreateThread")) suspiciousCount++;
            if (contentStr.Contains("NtQueueApcThread")) suspiciousCount++;

            // VirtualProtect/VirtualAlloc/HeapCreate 等正常API需要配合至少2种其他可疑模式才加分
            if (hasNormalApi && suspiciousCount >= 2)
            {
                score += 25;
            }
            else if (suspiciousCount >= 3)
            {
                score += 20;
            }
            else if (suspiciousCount >= 2)
            {
                score += 10;
            }

            return Math.Min(100, score);
        }
    }

    /// <summary>
    /// 勒索软件检测器 - 检测勒索软件行为特征
    /// </summary>
    public class RansomwareDetector
    {
        private readonly HashSet<string> _ransomwareExtensions;
        private readonly HashSet<string> _ransomwareNames;
        private readonly List<string> _ransomNotes;

        // 勒索软件特征从外部 JSON 加载（ThreatData/ransomware_signatures.json），不内嵌于 DLL
        public RansomwareDetector()
        {
            ExternalThreatData.EnsureLoaded();
            _ransomwareExtensions = ExternalThreatData.RansomwareExtensions;
            _ransomwareNames = ExternalThreatData.RansomwareNames;
            _ransomNotes = ExternalThreatData.RansomNotes;
        }

        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Ransomware",
                Confidence = 0.0
            };

            try
            {
                string fileName = Path.GetFileName(filePath);
                string extension = Path.GetExtension(filePath);
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 10000));

                // 1. 检查勒索软件扩展名
                bool hasRansomExt = _ransomwareExtensions.Contains(extension);

                // 2. 检查勒索信文件名
                bool isRansomNote = _ransomNotes.Any(note => fileName.Equals(note, StringComparison.OrdinalIgnoreCase));

                // 3. 检查已知的勒索软件名称
                bool hasRansomName = _ransomwareNames.Any(name => contentStr.Contains(name) || fileName.Contains(name));

                // 4. 检测加密特征
                int encryptionScore = DetectEncryptionPatterns(fileContent);

                // 5. 检测勒索信内容模式
                int ransomNoteScore = DetectRansomNoteContent(contentStr);

                // 6. 检测批量加密行为特征
                int batchEncryptScore = DetectBatchEncryptionFeatures(fileContent);

                // 综合评估
                double score = 0;
                if (hasRansomExt) score += 0.35;
                if (isRansomNote) score += 0.4;
                if (hasRansomName) score += 0.3;
                score += encryptionScore * 0.003;
                score += ransomNoteScore * 0.003;
                score += batchEncryptScore * 0.002;

                if (score > 0.7)
                {
                    result.IsDetected = true;
                    result.ThreatName = hasRansomName ? "Known Ransomware" : "Suspected Ransomware";
                    result.Confidence = Math.Min(1.0, score);
                    result.Details = $"扩展名匹配: {hasRansomExt}, 勒索信: {isRansomNote}, 加密特征分数: {encryptionScore}";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ThreatDetectors.cs 捕获异常", ex.Message); }

            return result;
        }

        private int DetectEncryptionPatterns(byte[] content)
        {
            int score = 0;
            string contentStr = Encoding.ASCII.GetString(content, 0, Math.Min(content.Length, 50000));

            // 检测加密API调用
            if (contentStr.Contains("CryptEncrypt")) score += 25;
            if (contentStr.Contains("CryptDeriveKey")) score += 20;
            if (contentStr.Contains("CryptGenKey")) score += 20;
            if (contentStr.Contains("CryptAcquireContext")) score += 15;
            if (contentStr.Contains("BCryptEncrypt")) score += 25;

            // 检测RSA/加密相关
            if (contentStr.Contains("RSA") && contentStr.Contains("AES")) score += 20;
            if (contentStr.Contains("AES-256") || contentStr.Contains("AES256")) score += 15;

            // 检测密钥生成
            if (contentStr.Contains("GenerateKey") || contentStr.Contains("CreateKey")) score += 15;

            return Math.Min(100, score);
        }

        private int DetectRansomNoteContent(string content)
        {
            int score = 0;

            // 检测勒索信关键词
            string[] ransomKeywords = {
                "bitcoin", "btc", "ransom", "decrypt", "encrypted",
                "payment", "private key", "public key", "tor ",
                "deadline", "pay", "money", "wallet address",
                "satoshi", "blockchain", "monero", "xmr"
            };

            foreach (var keyword in ransomKeywords)
            {
                if (content.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score += 8;
                }
            }

            // 检测比特币地址格式
            var btcRegex = new Regex(@"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b");
            if (btcRegex.IsMatch(content)) score += 30;

            // 检测TOR地址
            if (content.Contains(".onion")) score += 25;

            return Math.Min(100, score);
        }

        private int DetectBatchEncryptionFeatures(byte[] content)
        {
            int score = 0;
            string contentStr = Encoding.ASCII.GetString(content, 0, Math.Min(content.Length, 50000));

            // 检测文件遍历相关
            if (contentStr.Contains("FindFirstFile") && contentStr.Contains("FindNextFile")) score += 20;
            if (contentStr.Contains("Directory.GetFiles")) score += 15;
            if (contentStr.Contains("GetDirectories")) score += 10;

            // 检测文件操作
            if (contentStr.Contains("File.Move") || contentStr.Contains("MoveFile")) score += 15;
            if (contentStr.Contains("File.Delete") || contentStr.Contains("DeleteFile")) score += 10;

            // 检测影子拷贝删除命令（命令串从外部 JSON 加载，不内嵌于 DLL）
            foreach (var cmd in ExternalThreatData.CommandIndicators)
            {
                if (contentStr.IndexOf(cmd, StringComparison.OrdinalIgnoreCase) >= 0) score += 40;
            }

            return Math.Min(100, score);
        }
    }

    /// <summary>
    /// 木马检测器 - 检测各种类型的木马程序
    /// </summary>
    public class TrojanDetector
    {
        private readonly List<string> _trojanIndicators = new List<string>
        {
            // 远程控制功能
            "RemoteAdmin", "BackDoor", "Backdoor", "RAT", "RemoteAccess",
            "RemoteControl", "PCAnywhere", "VNC",
            
            // 网络功能
            "ReverseShell", "BindShell", "PortKnock", "PortForward",
            
            // 信息窃取
            "KeyLog", "KeyLogger", "Stealer", "PasswordStealer",
            "CookieStealer", "CredentialStealer", "BrowserStealer",
            
            // 下载功能
            "Downloader", "Dropper", "Loader", "Payload",
            
            // 隐藏技术
            "Rootkit", "Bootkit", "ProcessHollow", "DLLInject",
            
            // 代理功能
            "Proxy", "SOCKS", "Bot", "Botnet"
        };

        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Trojan",
                Confidence = 0.0
            };

            try
            {
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));
                string fileName = Path.GetFileName(filePath);

                // 1. 检测木马行为特征
                int behaviorScore = DetectTrojanBehaviors(fileContent);

                // 2. 检测网络连接模式
                int networkScore = DetectNetworkPatterns(contentStr);

                // 3. 检测进程注入特征
                int injectionScore = DetectInjectionPatterns(contentStr);

                // 4. 检测持久化机制
                int persistenceScore = DetectPersistenceMechanisms(contentStr);

                // 5. 检测反分析技术
                int antiAnalysisScore = DetectAntiAnalysis(contentStr);

                // 6. 检测可疑的字符串模式
                int suspiciousStringsScore = DetectSuspiciousStrings(contentStr);

                // 综合评估
                double score = (behaviorScore * 0.002) + (networkScore * 0.003) +
                              (injectionScore * 0.003) + (persistenceScore * 0.002) +
                              (antiAnalysisScore * 0.001) + (suspiciousStringsScore * 0.002);

                if (score > 0.65)
                {
                    result.IsDetected = true;
                    result.ThreatName = DetermineTrojanType(behaviorScore, networkScore, injectionScore);
                    result.Confidence = Math.Min(1.0, score + 0.1);
                    result.Details = $"行为: {behaviorScore}, 网络: {networkScore}, 注入: {injectionScore}, 持久化: {persistenceScore}";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ThreatDetectors.cs 捕获异常", ex.Message); }

            return result;
        }

        private int DetectTrojanBehaviors(byte[] content)
        {
            int score = 0;
            string contentStr = Encoding.ASCII.GetString(content, 0, Math.Min(content.Length, 50000));

            // 远程控制API - CreateRemoteThread需要配合其他API才加分
            int remoteThreadIndicators = 0;
            if (contentStr.Contains("CreateRemoteThread")) remoteThreadIndicators++;
            if (contentStr.Contains("OpenProcess")) remoteThreadIndicators++;
            if (contentStr.Contains("VirtualAllocEx")) remoteThreadIndicators++;
            if (contentStr.Contains("WriteProcessMemory")) remoteThreadIndicators++;
            if (contentStr.Contains("QueueUserAPC")) remoteThreadIndicators++;

            if (remoteThreadIndicators >= 3) score += 30;
            else if (remoteThreadIndicators >= 2) score += 15;

            if (contentStr.Contains("SetWindowsHookEx")) score += 20;
            if (contentStr.Contains("GetAsyncKeyState")) score += 25; // 键盘记录

            // 屏幕截图 - 降低分数，正常GUI程序都用
            if (contentStr.Contains("BitBlt") && contentStr.Contains("CreateCompatibleDC")) score += 5;

            // 剪贴板窃取
            if (contentStr.Contains("OpenClipboard") && contentStr.Contains("GetClipboardData")) score += 20;

            return Math.Min(100, score);
        }

        private int DetectNetworkPatterns(string content)
        {
            int score = 0;

            // 反向连接模式
            if (content.Contains("connect") && content.Contains("socket")) score += 20;
            if (content.Contains("WSAConnect")) score += 15;
            if (content.Contains("InternetConnect")) score += 15;

            // 数据外泄
            if (content.Contains("send") && content.Contains("socket")) score += 15;
            if (content.Contains("HttpSendRequest")) score += 10;
            if (content.Contains("WinHttpSendRequest")) score += 10;

            // 可疑端口
            if (Regex.IsMatch(content, @":\d{4,5}")) score += 5;

            // 硬编码IP地址
            var ipRegex = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
            var ips = ipRegex.Matches(content);
            if (ips.Count > 3) score += 15;

            return Math.Min(100, score);
        }

        private int DetectInjectionPatterns(string content)
        {
            int score = 0;

            // DLL注入
            if (content.Contains("LoadLibrary") && content.Contains("CreateRemoteThread")) score += 35;
            if (content.Contains("SetThreadContext")) score += 25;
            if (content.Contains("NtMapViewOfSection")) score += 20;

            // 进程镂空
            if (content.Contains("CreateProcess") && content.Contains("NtUnmapViewOfSection")) score += 40;
            if (content.Contains("ResumeThread")) score += 15;

            // 反射式注入（漏洞利用名从外部 JSON 加载）
            if (ExternalThreatData.ExploitNames.Contains("ReflectiveLoader") &&
                content.Contains("ReflectiveLoader")) score += 40;

            return Math.Min(100, score);
        }

        private int DetectPersistenceMechanisms(string content)
        {
            int score = 0;

            // 注册表自启动
            if (content.Contains("Run") && content.Contains("SetValue")) score += 20;
            if (content.Contains("CurrentVersion\\Run")) score += 25;
            if (content.Contains("CurrentVersion\\RunOnce")) score += 25;

            // 计划任务
            if (content.Contains("schtasks") || content.Contains("TaskScheduler")) score += 20;

            // 服务安装
            if (content.Contains("CreateService") || content.Contains("OpenSCManager")) score += 20;

            // WMI持久化
            if (content.Contains("Win32_Process") && content.Contains("Create")) score += 25;

            // 启动文件夹
            if (content.Contains("Startup") || content.Contains("Start Menu\\Programs\\Startup")) score += 15;

            return Math.Min(100, score);
        }

        private int DetectAntiAnalysis(string content)
        {
            int score = 0;

            // 虚拟机检测
            if (content.Contains("VMware") || content.Contains("VirtualBox")) score += 15;
            if (content.Contains("VBOX") || content.Contains("QEMU")) score += 15;
            if (content.Contains("Sandboxie")) score += 15;

            // 调试器检测
            if (content.Contains("IsDebuggerPresent")) score += 20;
            if (content.Contains("CheckRemoteDebugger")) score += 20;

            // 延迟执行
            if (content.Contains("Sleep") && content.Contains("10000")) score += 10;

            return Math.Min(100, score);
        }

        private int DetectSuspiciousStrings(string content)
        {
            int score = 0;

            foreach (var indicator in _trojanIndicators)
            {
                if (content.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score += 8;
                }
            }

            return Math.Min(100, score);
        }

        private string DetermineTrojanType(int behaviorScore, int networkScore, int injectionScore)
        {
            if (behaviorScore > 70) return LocalizedStrings.Trojan + " - Remote Control";
            if (injectionScore > 50) return LocalizedStrings.Trojan + " - Process Injection";
            if (networkScore > 50) return LocalizedStrings.Trojan + " - Network Backdoor";
            return LocalizedStrings.Trojan;
        }
    }

    /// <summary>
    /// 间谍软件检测器 - 检测信息窃取和监控软件
    /// </summary>
    public class SpywareDetector
    {
        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Spyware",
                Confidence = 0.0
            };

            try
            {
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));

                // 1. 检测键盘记录器
                int keyloggerScore = DetectKeylogger(contentStr);

                // 2. 检测屏幕监控
                int screenMonitorScore = DetectScreenMonitoring(contentStr);

                // 3. 检测数据窃取
                int dataTheftScore = DetectDataTheft(contentStr);

                // 4. 检测隐私侵犯
                int privacyViolationScore = DetectPrivacyViolation(contentStr);

                // 综合评估
                double score = (keyloggerScore * 0.004) + (screenMonitorScore * 0.003) +
                              (dataTheftScore * 0.003) + (privacyViolationScore * 0.002);

                if (score > 0.65)
                {
                    result.IsDetected = true;
                    result.ThreatName = DetermineSpywareType(keyloggerScore, screenMonitorScore, dataTheftScore);
                    result.Confidence = Math.Min(1.0, score);
                    result.Details = $"键盘记录: {keyloggerScore}, 屏幕监控: {screenMonitorScore}, 数据窃取: {dataTheftScore}";
                }
            }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "Spyware detection failed", ex.Message); }

            return result;
        }

        private int DetectKeylogger(string content)
        {
            int score = 0;

            // 键盘钩子
            if (content.Contains("SetWindowsHookEx")) score += 30;
            if (content.Contains("WH_KEYBOARD")) score += 35;
            if (content.Contains("WH_KEYBOARD_LL")) score += 35;
            if (content.Contains("GetAsyncKeyState")) score += 25;
            if (content.Contains("GetKeyState")) score += 20;
            if (content.Contains("CallNextHookEx")) score += 15;

            // 原始输入
            if (content.Contains("RegisterRawInputDevices")) score += 25;

            return Math.Min(100, score);
        }

        private int DetectScreenMonitoring(string content)
        {
            int score = 0;

            // 检查是否存在keylogger/间谍相关特征
            bool hasKeyloggerFeature = content.Contains("SetWindowsHookEx") || 
                                       content.Contains("GetAsyncKeyState") ||
                                       content.Contains("WH_KEYBOARD");

            // BitBlt/GetDC/CreateCompatibleDC/GetDesktopWindow 是几乎所有GUI程序都用的GDI API
            // 必须要求它们与 SetWindowsHookEx 或 keylogger 相关特征同时出现才报警
            if (!hasKeyloggerFeature)
            {
                // 无keylogger特征时，GDI API不加分
                if (content.Contains("PrintWindow")) score += 10;
                return Math.Min(100, score);
            }

            // 有keylogger特征时，屏幕监控API才加分
            if (content.Contains("BitBlt")) score += 15;
            if (content.Contains("GetDC") && content.Contains("CreateCompatibleDC")) score += 20;
            if (content.Contains("CreateCompatibleBitmap")) score += 10;
            if (content.Contains("GetDesktopWindow")) score += 15;
            if (content.Contains("PrintWindow")) score += 25;

            // 定时截图
            if (content.Contains("SetTimer") && content.Contains("BitBlt")) score += 25;

            return Math.Min(100, score);
        }

        private int DetectDataTheft(string content)
        {
            int score = 0;

            // 浏览器数据
            if (content.Contains("Cookies") && content.Contains("Login Data")) score += 30;
            if (content.Contains("Web Data") || content.Contains("History")) score += 20;
            if (content.Contains("formhistory.sqlite")) score += 25;
            if (content.Contains("places.sqlite")) score += 20;
            if (content.Contains("key4.db")) score += 25;

            // 密码窃取
            if (content.Contains("CryptUnprotectData")) score += 30;
            if (content.Contains("PStoreCreateInstance")) score += 35;
            if (content.Contains("DPAPI")) score += 20;

            // 剪贴板
            if (content.Contains("OpenClipboard") && content.Contains("GetClipboardData")) score += 25;

            return Math.Min(100, score);
        }

        private int DetectPrivacyViolation(string content)
        {
            int score = 0;

            // 摄像头/麦克风
            if (content.Contains("capCreateCaptureWindow")) score += 35;
            if (content.Contains("waveInOpen") || content.Contains("DirectSoundCapture")) score += 30;

            // 文件搜索
            if (content.Contains("FindFirstFile") && content.Contains(".doc")) score += 15;
            if (content.Contains(".pdf") && content.Contains("upload")) score += 20;

            // GetUserName/GetComputerName/GetSystemInfo 等系统信息获取API极其常见
            // 不能单独作为检测依据，已移除

            return Math.Min(100, score);
        }

        private string DetermineSpywareType(int keyloggerScore, int screenMonitorScore, int dataTheftScore)
        {
            if (keyloggerScore > 50) return LocalizedStrings.Spyware + " - Keylogger";
            if (screenMonitorScore > 40) return LocalizedStrings.Spyware + " - Screen Monitor";
            if (dataTheftScore > 40) return LocalizedStrings.Spyware + " - Data Stealer";
            return LocalizedStrings.Spyware;
        }
    }

    /// <summary>
    /// 广告软件检测器 - 检测广告软件和弹窗程序
    /// </summary>
    public class AdwareDetector
    {
        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Adware",
                Confidence = 0.0
            };

            try
            {
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));
                string fileName = Path.GetFileName(filePath).ToLower();

                // 1. 检测弹窗广告
                int popupScore = DetectPopupAds(contentStr);

                // 2. 检测浏览器劫持
                int hijackScore = DetectBrowserHijacking(contentStr);

                // 3. 检测广告注入
                int injectScore = DetectAdInjection(contentStr);

                // 4. 检测可疑文件名模式
                int nameScore = DetectSuspiciousNames(fileName);

                // 综合评估
                double score = (popupScore * 0.003) + (hijackScore * 0.003) +
                              (injectScore * 0.003) + (nameScore * 0.002);

                if (score > 0.6)
                {
                    result.IsDetected = true;
                    result.ThreatName = LocalizedStrings.Adware;
                    result.Confidence = Math.Min(1.0, score);
                    result.Details = $"弹窗: {popupScore}, 劫持: {hijackScore}, 注入: {injectScore}";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ThreatDetectors.cs 捕获异常", ex.Message); }

            return result;
        }

        private int DetectPopupAds(string content)
        {
            int score = 0;

            // 弹窗相关
            if (content.Contains("CreateWindow") && content.Contains("popup")) score += 20;
            if (content.Contains("ShellExecute") && content.Contains("http")) score += 15;
            if (content.Contains("InternetExplorer") || content.Contains("iexplore")) score += 10;
            if (content.Contains("Navigate") && content.Contains("url")) score += 15;

            // 广告域名模式
            if (Regex.IsMatch(content, @"ads?\.", RegexOptions.IgnoreCase)) score += 15;
            if (Regex.IsMatch(content, @".*\.ad\..*", RegexOptions.IgnoreCase)) score += 15;

            return Math.Min(100, score);
        }

        private int DetectBrowserHijacking(string content)
        {
            int score = 0;

            // 主页修改
            if (content.Contains("Start Page") || content.Contains("StartPage")) score += 25;
            if (content.Contains("HomePage") && content.Contains("http")) score += 25;
            if (content.Contains("SearchProvider")) score += 20;

            // 浏览器扩展
            if (content.Contains("Browser Helper Object")) score += 30;
            if (content.Contains("BrowserExtension")) score += 20;
            if (content.Contains("chrome\\extensions")) score += 25;

            // DNS劫持
            if (content.Contains("hosts")) score += 20;
            if (content.Contains("NameServer")) score += 15;

            return Math.Min(100, score);
        }

        private int DetectAdInjection(string content)
        {
            int score = 0;

            // HTML/JS注入
            if (content.Contains("<iframe") && content.Contains("http")) score += 25;
            if (content.Contains("document.write")) score += 20;
            if (content.Contains("eval(")) score += 15;
            if (content.Contains("appendChild") && content.Contains("script")) score += 20;

            // 内容替换
            if (content.Contains("innerHTML") && content.Contains("replace")) score += 15;

            return Math.Min(100, score);
        }

        private int DetectSuspiciousNames(string fileName)
        {
            int score = 0;

            string[] adwarePatterns = { "helper", "update", "installer", "setup",
                                       "coupon", "deal", "offer", "savings",
                                       "bargain", "discount", "promo" };

            foreach (var pattern in adwarePatterns)
            {
                if (fileName.Contains(pattern)) score += 10;
            }

            return Math.Min(100, score);
        }
    }

    /// <summary>
    /// 键盘记录器检测器 - 专门检测键盘记录软件
    /// </summary>
    public class KeyloggerDetector
    {
        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Keylogger",
                Confidence = 0.0
            };

            try
            {
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));

                // 检测键盘记录技术
                int hookScore = 0;
                int pollingScore = 0;
                int rawInputScore = 0;

                // Hook技术
                if (contentStr.Contains("SetWindowsHookEx")) hookScore += 35;
                if (contentStr.Contains("WH_KEYBOARD")) hookScore += 40;
                if (contentStr.Contains("WH_KEYBOARD_LL")) hookScore += 40;
                if (contentStr.Contains("CallNextHookEx")) hookScore += 20;

                // 轮询技术
                if (contentStr.Contains("GetAsyncKeyState")) pollingScore += 40;
                if (contentStr.Contains("GetKeyState")) pollingScore += 30;
                if (contentStr.Contains("GetKeyboardState")) pollingScore += 25;

                // 原始输入
                if (contentStr.Contains("RegisterRawInputDevices")) rawInputScore += 35;
                if (contentStr.Contains("WM_INPUT")) rawInputScore += 30;
                if (contentStr.Contains("GetRawInputData")) rawInputScore += 30;

                // 数据记录
                int loggingScore = 0;
                if (contentStr.Contains("File.Write") || contentStr.Contains("WriteFile")) loggingScore += 15;
                if (contentStr.Contains("StreamWriter")) loggingScore += 15;
                if (contentStr.Contains("File.Append")) loggingScore += 20;
                if (contentStr.Contains("send") && contentStr.Contains("socket")) loggingScore += 25;

                // 综合评估
                int maxScore = Math.Max(hookScore, Math.Max(pollingScore, rawInputScore));
                double score = (maxScore * 0.006) + (loggingScore * 0.003);

                if (score > 0.65)
                {
                    result.IsDetected = true;
                    string method = hookScore >= pollingScore && hookScore >= rawInputScore ? "Hook" :
                                   pollingScore >= rawInputScore ? "轮询" : "原始输入";
                    result.ThreatName = $"键盘记录器 ({method})";
                    result.Confidence = Math.Min(1.0, score);
                    result.Details = $"Hook: {hookScore}, 轮询: {pollingScore}, 原始输入: {rawInputScore}, 记录: {loggingScore}";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ThreatDetectors.cs 捕获异常", ex.Message); }

            return result;
        }
    }

    /// <summary>
    /// 后门检测器 - 检测后门程序和远程访问工具
    /// </summary>
    public class BackdoorDetector
    {
        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Backdoor",
                Confidence = 0.0
            };

            try
            {
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));

                // 1. 检测反向连接
                int reverseConnectScore = DetectReverseConnect(contentStr);

                // 2. 检测监听端口
                int listeningScore = DetectListeningPort(contentStr);

                // 3. 检测远程命令执行
                int cmdExecScore = DetectRemoteCommandExecution(contentStr);

                // 4. 检测隐蔽通道
                int covertChannelScore = DetectCovertChannel(contentStr);

                // 综合评估
                double score = (reverseConnectScore * 0.004) + (listeningScore * 0.003) +
                              (cmdExecScore * 0.004) + (covertChannelScore * 0.002);

                if (score > 0.65)
                {
                    result.IsDetected = true;
                    result.ThreatName = DetermineBackdoorType(reverseConnectScore, listeningScore, cmdExecScore);
                    result.Confidence = Math.Min(1.0, score);
                    result.Details = $"反向连接: {reverseConnectScore}, 监听: {listeningScore}, 命令执行: {cmdExecScore}";
                }
            }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "Backdoor detection failed", ex.Message); }

            return result;
        }

        private int DetectReverseConnect(string content)
        {
            int score = 0;

            if (content.Contains("connect") && content.Contains("socket")) score += 30;
            if (content.Contains("WSAConnect")) score += 30;
            if (content.Contains("InternetConnect")) score += 25;
            if (content.Contains("ConnectEx")) score += 25;

            // 反向Shell - 降低cmd.exe/powershell相关分数
            if (content.Contains("cmd.exe") && content.Contains("socket")) score += 20;
            if (content.Contains("powershell") && content.Contains("connect")) score += 15;

            return Math.Min(100, score);
        }

        private int DetectListeningPort(string content)
        {
            int score = 0;

            if (content.Contains("bind") && content.Contains("socket")) score += 25;
            if (content.Contains("listen")) score += 20;
            if (content.Contains("accept")) score += 15;
            if (content.Contains("WSAListen")) score += 25;

            // 特定端口绑定
            var portRegex = new Regex(@"bind.*?(\d{4,5})");
            if (portRegex.IsMatch(content)) score += 20;

            return Math.Min(100, score);
        }

        private int DetectRemoteCommandExecution(string content)
        {
            int score = 0;

            // 命令执行API
            if (content.Contains("CreateProcess")) score += 20;
            if (content.Contains("ShellExecute")) score += 20;
            if (content.Contains("WinExec")) score += 20;
            if (content.Contains("system(")) score += 25;

            // cmd.exe 和 powershell 检测降低单次匹配分数（太宽泛）
            if (content.Contains("cmd.exe")) score += 5;
            if (content.Contains("powershell")) score += 5;

            // 管道
            if (content.Contains("CreatePipe") && content.Contains("CreateProcess")) score += 25;

            return Math.Min(100, score);
        }

        private int DetectCovertChannel(string content)
        {
            int score = 0;

            // DNS隧道
            if (content.Contains("DnsQuery") || content.Contains("Query_DNS")) score += 25;

            // ICMP隧道
            if (content.Contains("IcmpSendEcho")) score += 25;

            // HTTP隧道
            if (content.Contains("HttpSendRequest") && content.Contains("POST")) score += 15;

            return Math.Min(100, score);
        }

        private string DetermineBackdoorType(int reverseScore, int listeningScore, int cmdScore)
        {
            if (reverseScore > 50) return LocalizedStrings.Backdoor + " - Reverse Connection";
            if (listeningScore > 40) return LocalizedStrings.Backdoor + " - Port Listener";
            if (cmdScore > 50) return LocalizedStrings.Backdoor + " - Remote Command";
            return LocalizedStrings.Backdoor;
        }
    }

    /// <summary>
    /// 蠕虫检测器 - 检测网络蠕虫
    /// </summary>
    public class WormDetector
    {
        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Worm",
                Confidence = 0.0
            };

            try
            {
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));

                // 1. 检测自我复制
                int replicationScore = DetectSelfReplication(contentStr);

                // 2. 检测网络传播
                int propagationScore = DetectNetworkPropagation(contentStr);

                // 3. 检测漏洞利用
                int exploitScore = DetectExploitUsage(contentStr);

                // 4. 检测邮件传播
                int emailScore = DetectEmailSpreading(contentStr);

                // 综合评估
                double score = (replicationScore * 0.003) + (propagationScore * 0.004) +
                              (exploitScore * 0.003) + (emailScore * 0.002);

                if (score > 0.65)
                {
                    result.IsDetected = true;
                    result.ThreatName = LocalizedStrings.Worm;
                    result.Confidence = Math.Min(1.0, score);
                    result.Details = $"复制: {replicationScore}, 传播: {propagationScore}, 漏洞: {exploitScore}";
                }
            }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "Worm detection failed", ex.Message); }

            return result;
        }

        private int DetectSelfReplication(string content)
        {
            int score = 0;

            // CopyFile 和 File.Copy 极其常见（安装程序核心操作），已移除单独检测
            // System32/AppData 路径引用极其常见，已移除单独检测
            
            // 启动项 - 需要配合其他蠕虫特征
            if (content.Contains("Run") && content.Contains("SetValue")) score += 10;

            return Math.Min(100, score);
        }

        private int DetectNetworkPropagation(string content)
        {
            int score = 0;

            // SMB传播
            if (content.Contains("WMIC") || content.Contains("smb")) score += 25;
            if (content.Contains("net use") || content.Contains("Admin$")) score += 30;

            // 网络扫描
            if (content.Contains("NetScheduleJobAdd")) score += 25;
            // 远程执行/传播工具（特征外置）
            if (FireAntivirus.Engine.Data.EmbeddedThreatDatabase.NetworkPropagationSignals
                .Any(s => content.Contains(s, StringComparison.OrdinalIgnoreCase)))
                score += 30;

            // 批量连接
            var ipPattern = new Regex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");
            var ips = ipPattern.Matches(content);
            if (ips.Count > 5) score += 20;

            return Math.Min(100, score);
        }

        private int DetectExploitUsage(string content)
        {
            int score = 0;

            // 已知漏洞利用（利用名从外部 JSON 加载，不内嵌于 DLL，含 EternalBlue/MS17-010 等）
            int matchedExploitCount = 0;
            foreach (var e in ExternalThreatData.ExploitNames)
            {
                if (content.IndexOf(e, StringComparison.OrdinalIgnoreCase) >= 0) matchedExploitCount++;
            }
            if (matchedExploitCount > 0) score += 50;
            if (content.Contains("CVE-2019-0708")) score += 50;
            if (content.Contains("PrintNightmare")) score += 45;

            return Math.Min(100, score);
        }

        private int DetectEmailSpreading(string content)
        {
            int score = 0;

            // 邮件API
            if (content.Contains("MAPI") || content.Contains("SimpleMAPI")) score += 25;
            if (content.Contains("Outlook.Application")) score += 30;

            // SMTP
            if (content.Contains("SmtpClient") || content.Contains("SMTP")) score += 20;

            return Math.Min(100, score);
        }
    }

    /// <summary>
    /// 病毒检测器 - 检测传统病毒
    /// </summary>
    public class VirusDetector
    {
        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Virus",
                Confidence = 0.0
            };

            try
            {
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));

                // 1. 检测文件感染特征
                int infectionScore = DetectFileInfection(contentStr);

                // 2. 检测多态特征
                int polymorphicScore = DetectPolymorphic(contentStr);

                // 3. 检测加壳
                int packingScore = DetectPacking(contentStr);

                // 4. 检测自修改代码
                int selfModifyingScore = DetectSelfModifying(contentStr);

                // 综合评估
                double score = (infectionScore * 0.004) + (polymorphicScore * 0.003) +
                              (packingScore * 0.002) + (selfModifyingScore * 0.003);

                if (score > 0.6)
                {
                    result.IsDetected = true;
                    result.ThreatName = LocalizedStrings.Virus;
                    result.Confidence = Math.Min(1.0, score);
                    result.Details = $"感染: {infectionScore}, 多态: {polymorphicScore}, 加壳: {packingScore}";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ThreatDetectors.cs 捕获异常", ex.Message); }

            return result;
        }

        private int DetectFileInfection(string content)
        {
            int score = 0;

            // PE文件修改
            if (content.Contains("SetFilePointer") && content.Contains("WriteFile")) score += 20;
            if (content.Contains("CreateFileMapping")) score += 15;
            if (content.Contains("MapViewOfFile")) score += 15;

            // "infected" 或 "virus" 字符串在安全软件自身的文件中必然出现，已移除

            return Math.Min(100, score);
        }

        private int DetectPolymorphic(string content)
        {
            int score = 0;

            // 代码变异
            if (content.Contains("XOR") && content.Contains("decrypt")) score += 25;
            if (content.Contains("ROR") || content.Contains("ROL")) score += 20;
            if (content.Contains("mutate") || content.Contains("polymorphic")) score += 35;

            return Math.Min(100, score);
        }

        private int DetectPacking(string content)
        {
            int score = 0;

            // UPX/ASPack/PECompact 等加壳器是合法的商业软件压缩器
            // 降低权重为原来的1/4 (每个从30降到8)
            string[] packers = { "UPX", "ASPack", "PECompact", "Themida", 
                                "VMProtect", "Armadillo", "Petite", "NSPack" };

            foreach (var packer in packers)
            {
                if (content.Contains(packer)) score += 8;
            }

            return Math.Min(100, score);
        }

        private int DetectSelfModifying(string content)
        {
            int score = 0;

            if (content.Contains("VirtualProtect") && content.Contains("WriteProcessMemory")) score += 30;
            if (content.Contains("FlushInstructionCache")) score += 25;
            if (content.Contains("PAGE_EXECUTE_READWRITE")) score += 25;

            return Math.Min(100, score);
        }
    }

    /// <summary>
    /// 挖矿软件检测器 - 检测加密货币挖矿软件
    /// </summary>
    public class MinerDetector
    {
        private readonly HashSet<string> _minerPools;
        private readonly HashSet<string> _minerBinaries;

        // 矿池地址/矿机二进制名从外部 JSON 加载（ThreatData/malicious_indicators.json），不内嵌于 DLL
        public MinerDetector()
        {
            ExternalThreatData.EnsureLoaded();
            _minerPools = ExternalThreatData.MiningPools;
            _minerBinaries = ExternalThreatData.MiningBinaries;
        }

        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "Miner",
                Confidence = 0.0
            };

            try
            {
                string fileName = Path.GetFileName(filePath).ToLower();
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));

                // 1. 检测矿池地址
                int poolScore = DetectMiningPools(contentStr);

                // 2. 检测矿机程序名
                int binaryScore = DetectMinerBinaries(fileName);

                // 3. 检测挖矿算法
                int algorithmScore = DetectMiningAlgorithms(contentStr);

                // 4. 检测钱包地址
                int walletScore = DetectWalletAddresses(contentStr);

                // 5. 检测资源消耗模式
                int resourceScore = DetectResourceIntensivePatterns(contentStr);

                // 综合评估
                double score = (poolScore * 0.004) + (binaryScore * 0.003) +
                              (algorithmScore * 0.002) + (walletScore * 0.003) +
                              (resourceScore * 0.001);

                if (score > 0.6)
                {
                    result.IsDetected = true;
                    result.ThreatName = LocalizedStrings.Miner;
                    result.Confidence = Math.Min(1.0, score);
                    result.Details = $"矿池: {poolScore}, 程序: {binaryScore}, 钱包: {walletScore}";
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ThreatDetectors.cs 捕获异常", ex.Message); }

            return result;
        }

        private int DetectMiningPools(string content)
        {
            int score = 0;

            foreach (var pool in _minerPools)
            {
                if (content.IndexOf(pool, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score += 40;
                    break;
                }
            }

            // 检测stratum协议（协议关键字从外部 JSON 加载）
            foreach (var proto in ExternalThreatData.MiningProtocols)
            {
                if (content.Contains(proto)) { score += 35; break; }
            }

            return Math.Min(100, score);
        }

        private int DetectMinerBinaries(string fileName)
        {
            if (_minerBinaries.Contains(fileName))
            {
                return 80;
            }

            // 检测相似命名
            foreach (var miner in _minerBinaries)
            {
                if (fileName.Contains(Path.GetFileNameWithoutExtension(miner).ToLower()))
                {
                    return 50;
                }
            }

            return 0;
        }

        private int DetectMiningAlgorithms(string content)
        {
            int score = 0;

            // 加密货币算法（特征外置）
            foreach (var algo in FireAntivirus.Engine.Data.EmbeddedThreatDatabase.MinerAlgorithms)
            {
                if (content.IndexOf(algo, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score += 20;
                }
            }

            return Math.Min(100, score);
        }

        private int DetectWalletAddresses(string content)
        {
            int score = 0;

            // Monero钱包地址 (4开头，95字符)
            var xmrPattern = new Regex(@"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b");
            if (xmrPattern.IsMatch(content)) score += 40;

            // 以太坊钱包地址 (0x开头，42字符)
            var ethPattern = new Regex(@"\b0x[a-fA-F0-9]{40}\b");
            if (ethPattern.IsMatch(content)) score += 25;

            // 比特币钱包地址
            var btcPattern = new Regex(@"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b");
            var btcMatches = btcPattern.Matches(content);
            if (btcMatches.Count > 2) score += 20;

            return Math.Min(100, score);
        }

        private int DetectResourceIntensivePatterns(string content)
        {
            int score = 0;

            // GPU挖矿相关
            if (content.Contains("CUDA") || content.Contains("OpenCL")) score += 20;
            if (content.Contains("GPU") && content.Contains("thread")) score += 15;

            // CPU多线程
            if (content.Contains("SetThreadPriority")) score += 10;
            if (content.Contains("CreateThread") && content.Contains("CPU")) score += 15;

            return Math.Min(100, score);
        }
    }

    /// <summary>
    /// 潜在不受欢迎程序(PUP)检测器
    /// </summary>
    public class PUPDetector
    {
        // 已移除中文关键词和通用优化词汇，避免对项目本身的误报
        private readonly HashSet<string> _pupCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "driver update", "pc repair", "registry clean"
        };

        public DetectionResult Detect(string filePath, byte[] fileContent)
        {
            var result = new DetectionResult
            {
                IsDetected = false,
                ThreatName = string.Empty,
                ThreatType = "PUP",
                Confidence = 0.0
            };

            try
            {
                string fileName = Path.GetFileName(filePath).ToLower();
                string contentStr = Encoding.ASCII.GetString(fileContent, 0, Math.Min(fileContent.Length, 50000));

                // 1. 检测捆绑软件
                int bundleScore = DetectBundledSoftware(contentStr);

                // 2. 检测假优化工具
                int fakeOptimizerScore = DetectFakeOptimizer(fileName, contentStr);

                // 3. 检测过度权限
                int permissionScore = DetectExcessivePermissions(contentStr);

                // 4. 检测误导性宣传
                int misleadingScore = DetectMisleadingMarketing(contentStr);

                // 综合评估
                double score = (bundleScore * 0.003) + (fakeOptimizerScore * 0.003) +
                              (permissionScore * 0.002) + (misleadingScore * 0.003);

                if (score > 0.6)
                {
                    result.IsDetected = true;
                    result.ThreatName = DeterminePUPType(fakeOptimizerScore, misleadingScore);
                    result.Confidence = Math.Min(1.0, score);
                    result.Details = $"捆绑: {bundleScore}, 假优化: {fakeOptimizerScore}, 误导: {misleadingScore}";
                }
            }
            catch (Exception ex) { LogHelper.Log(LogHelper.LogLevel.Error, "PUP检测失败", ex.Message); }

            return result;
        }

        private int DetectBundledSoftware(string content)
        {
            int score = 0;

            // 安装相关
            if (content.Contains("bundled") || content.Contains("bundle")) score += 20;
            if (content.Contains("additional offers")) score += 25;
            if (content.Contains("recommended download")) score += 20;
            if (content.Contains("optional installation")) score += 20;

            return Math.Min(100, score);
        }

        private int DetectFakeOptimizer(string fileName, string content)
        {
            int score = 0;

            foreach (var category in _pupCategories)
            {
                if (fileName.Contains(category) || content.Contains(category))
                {
                    score += 15;
                }
            }

            // 扫描功能但无实质
            if (content.Contains("scan") && content.Contains("fix") && content.Contains("purchase"))
            {
                score += 25;
            }

            return Math.Min(100, score);
        }

        private int DetectExcessivePermissions(string content)
        {
            int score = 0;

            // 收集过多信息
            if (content.Contains("GetSystemInfo") && content.Contains("send")) score += 20;
            if (content.Contains("collect") && content.Contains("usage")) score += 15;

            return Math.Min(100, score);
        }

        private int DetectMisleadingMarketing(string content)
        {
            int score = 0;

            // 恐吓战术
            string[] scarePhrases = { "your pc is infected", "critical error", 
                                     "system at risk", "immediate action required",
                                     "系统存在风险", "发现严重问题" };

            foreach (var phrase in scarePhrases)
            {
                if (content.IndexOf(phrase, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    score += 20;
                }
            }

            // 付费提示
            if (content.Contains("purchase") && content.Contains("license")) score += 15;
            if (content.Contains("subscribe") && content.Contains("premium")) score += 15;

            return Math.Min(100, score);
        }

        private string DeterminePUPType(int optimizerScore, int misleadingScore)
        {
            if (optimizerScore > 40) return LocalizedStrings.Riskware + " - Fake Optimizer";
            if (misleadingScore > 40) return LocalizedStrings.Riskware + " - Misleading Software";
            return LocalizedStrings.Riskware;
    }
}
}