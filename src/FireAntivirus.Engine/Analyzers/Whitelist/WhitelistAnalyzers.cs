// 白名单分析器集合 - 各种类型的白名单检查

using System;
using System.Collections.Generic;
using System.IO;

namespace FireAntivirus.Engine.Analyzers.Whitelist
{
    #region 文件白名单分析器
    public class FileWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedFiles = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _whitelistedPaths = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string filePath)
        {
            if (_whitelistedFiles.Contains(filePath)) return true;
            foreach (var path in _whitelistedPaths)
                if (filePath.StartsWith(path, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public void Add(string path) { _whitelistedPaths.Add(path); }
        public void AddFile(string file) { _whitelistedFiles.Add(file); }
    }
    #endregion

    #region 进程白名单分析器
    public class ProcessWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedProcesses = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string processName)
        {
            var name = Path.GetFileNameWithoutExtension(processName);
            return _whitelistedProcesses.Contains(name);
        }

        public void Add(string processName)
        {
            _whitelistedProcesses.Add(Path.GetFileNameWithoutExtension(processName));
        }
    }
    #endregion

    #region 网络白名单分析器
    public class NetworkWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedIPs = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _whitelistedDomains = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string address)
        {
            return _whitelistedIPs.Contains(address) || _whitelistedDomains.Contains(address);
        }

        public void AddIP(string ip) { _whitelistedIPs.Add(ip); }
        public void AddDomain(string domain) { _whitelistedDomains.Add(domain); }
    }
    #endregion

    #region 注册表白名单分析器
    public class RegistryWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedKeys = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string keyPath)
        {
            foreach (var key in _whitelistedKeys)
                if (keyPath.StartsWith(key, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public void Add(string keyPath) { _whitelistedKeys.Add(keyPath); }
    }
    #endregion

    #region 行为白名单分析器
    public class BehaviorWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedBehaviors = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string behavior)
        {
            return _whitelistedBehaviors.Contains(behavior);
        }

        public void Add(string behavior) { _whitelistedBehaviors.Add(behavior); }
    }
    #endregion

    #region 启发式白名单分析器
    public class HeuristicWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedPatterns = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string pattern)
        {
            return _whitelistedPatterns.Contains(pattern);
        }

        public void Add(string pattern) { _whitelistedPatterns.Add(pattern); }
    }
    #endregion

    #region 证书白名单分析器
    public class CertificateWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedPublishers = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _whitelistedThumbprints = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelistedPublisher(string publisher)
        {
            foreach (var p in _whitelistedPublishers)
                if (publisher.Contains(p, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public bool IsWhitelistedThumbprint(string thumbprint)
        {
            return _whitelistedThumbprints.Contains(thumbprint);
        }

        public void AddPublisher(string publisher) { _whitelistedPublishers.Add(publisher); }
        public void AddThumbprint(string thumbprint) { _whitelistedThumbprints.Add(thumbprint); }
    }
    #endregion

    #region 数字签名白名单分析器
    public class DigitalSignatureWhitelistAnalyzer
    {
        private readonly CertificateWhitelistAnalyzer _certAnalyzer = new();

        public bool IsWhitelisted(string publisher) => _certAnalyzer.IsWhitelistedPublisher(publisher);
        public void Add(string publisher) => _certAnalyzer.AddPublisher(publisher);
    }
    #endregion

    #region 防火墙规则白名单分析器
    public class FirewallRuleWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedRules = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _whitelistedPrograms = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelistedRule(string ruleName) => _whitelistedRules.Contains(ruleName);
        public bool IsWhitelistedProgram(string programPath) => _whitelistedPrograms.Contains(programPath);

        public void AddRule(string ruleName) { _whitelistedRules.Add(ruleName); }
        public void AddProgram(string programPath) { _whitelistedPrograms.Add(programPath); }
    }
    #endregion

    #region 网络流量白名单分析器
    public class NetworkTrafficWhitelistAnalyzer
    {
        private readonly NetworkWhitelistAnalyzer _networkAnalyzer = new();

        public bool IsWhitelisted(string address) => _networkAnalyzer.IsWhitelisted(address);
        public void Add(string address) => _networkAnalyzer.AddIP(address);
    }
    #endregion

    #region 安全评分白名单分析器
    public class SecurityScoreWhitelistAnalyzer
    {
        private readonly HashSet<string> _ignoredFactors = new(StringComparer.OrdinalIgnoreCase);

        public bool IsIgnored(string factorName) => _ignoredFactors.Contains(factorName);
        public void Ignore(string factorName) { _ignoredFactors.Add(factorName); }
    }
    #endregion

    #region 威胁猎手白名单分析器
    public class ThreatHunterWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedIndicators = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string indicator) => _whitelistedIndicators.Contains(indicator);
        public void Add(string indicator) { _whitelistedIndicators.Add(indicator); }
    }
    #endregion

    #region 威胁情报白名单分析器
    public class ThreatIntelligenceWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedIOCs = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string ioc) => _whitelistedIOCs.Contains(ioc);
        public void Add(string ioc) { _whitelistedIOCs.Add(ioc); }
    }
    #endregion

    #region 机器学习白名单分析器
    public class MachineLearningWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedFeatures = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string feature) => _whitelistedFeatures.Contains(feature);
        public void Add(string feature) { _whitelistedFeatures.Add(feature); }
    }
    #endregion

    #region 云扫描白名单分析器
    public class CloudWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedHashes = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string hash) => _whitelistedHashes.Contains(hash);
        public void Add(string hash) { _whitelistedHashes.Add(hash); }
    }
    #endregion

    #region 沙箱白名单分析器
    public class SandboxWhitelistAnalyzer
    {
        private readonly HashSet<string> _whitelistedPrograms = new(StringComparer.OrdinalIgnoreCase);

        public bool IsWhitelisted(string programPath) => _whitelistedPrograms.Contains(programPath);
        public void Add(string programPath) { _whitelistedPrograms.Add(programPath); }
    }
    #endregion

    #region 恶意软件移除白名单分析器
    public class MalwareRemovalWhitelistAnalyzer
    {
        private readonly HashSet<string> _protectedFiles = new(StringComparer.OrdinalIgnoreCase);

        public bool IsProtected(string filePath) => _protectedFiles.Contains(filePath);
        public void Protect(string filePath) { _protectedFiles.Add(filePath); }
    }
    #endregion

    #region 事件响应白名单分析器
    public class IncidentResponseWhitelistAnalyzer
    {
        private readonly HashSet<string> _ignoredEvents = new(StringComparer.OrdinalIgnoreCase);

        public bool IsIgnored(string eventType) => _ignoredEvents.Contains(eventType);
        public void Ignore(string eventType) { _ignoredEvents.Add(eventType); }
    }
    #endregion

    #region 完整性白名单分析器
    public class IntegrityWhitelistAnalyzer
    {
        private readonly Dictionary<string, string> _knownGoodHashes = new(StringComparer.OrdinalIgnoreCase);

        public bool IsKnownGood(string filePath, string hash)
        {
            return _knownGoodHashes.TryGetValue(filePath, out var knownHash) && knownHash == hash;
        }

        public void AddKnownGood(string filePath, string hash) { _knownGoodHashes[filePath] = hash; }
    }
    #endregion

    #region 恢复白名单分析器
    public class RecoveryWhitelistAnalyzer
    {
        private readonly HashSet<string> _recoveryPoints = new(StringComparer.OrdinalIgnoreCase);

        public bool IsRecoveryPoint(string path) => _recoveryPoints.Contains(path);
        public void AddRecoveryPoint(string path) { _recoveryPoints.Add(path); }
    }
    #endregion

    #region 备份白名单分析器
    public class BackupWhitelistAnalyzer
    {
        private readonly HashSet<string> _backupPaths = new(StringComparer.OrdinalIgnoreCase);

        public bool IsBackup(string path) => _backupPaths.Contains(path);
        public void AddBackupPath(string path) { _backupPaths.Add(path); }
    }
    #endregion

    #region 应用控制白名单分析器
    public class ApplicationControlWhitelistAnalyzer
    {
        private readonly HashSet<string> _allowedApps = new(StringComparer.OrdinalIgnoreCase);

        public bool IsAllowed(string appPath) => _allowedApps.Contains(appPath);
        public void Allow(string appPath) { _allowedApps.Add(appPath); }
    }
    #endregion

    #region 应用白名单分析器
    public class ApplicationWhitelistAnalyzer
    {
        private readonly HashSet<string> _allowedApps = new(StringComparer.OrdinalIgnoreCase);

        public bool IsAllowed(string appName) => _allowedApps.Contains(appName);
        public void Allow(string appName) { _allowedApps.Add(appName); }
    }
    #endregion

    #region 性能白名单分析器
    public class PerformanceWhitelistAnalyzer
    {
        private readonly HashSet<string> _ignoredProcesses = new(StringComparer.OrdinalIgnoreCase);

        public bool IsIgnored(string processName) => _ignoredProcesses.Contains(processName);
        public void Ignore(string processName) { _ignoredProcesses.Add(processName); }
    }
    #endregion

    #region 隐私白名单分析器
    public class PrivacyWhitelistAnalyzer
    {
        private readonly HashSet<string> _trustedApps = new(StringComparer.OrdinalIgnoreCase);

        public bool IsTrusted(string appPath) => _trustedApps.Contains(appPath);
        public void Trust(string appPath) { _trustedApps.Add(appPath); }
    }
    #endregion

    #region 漏洞白名单分析器
    public class VulnerabilityWhitelistAnalyzer
    {
        private readonly HashSet<string> _acceptedRisks = new(StringComparer.OrdinalIgnoreCase);

        public bool IsAccepted(string vulnId) => _acceptedRisks.Contains(vulnId);
        public void Accept(string vulnId) { _acceptedRisks.Add(vulnId); }
    }
    #endregion

    #region 优化白名单分析器
    public class OptimizationWhitelistAnalyzer
    {
        private readonly HashSet<string> _excludedPaths = new(StringComparer.OrdinalIgnoreCase);

        public bool IsExcluded(string path) => _excludedPaths.Contains(path);
        public void Exclude(string path) { _excludedPaths.Add(path); }
    }
    #endregion

    #region 系统优化白名单分析器
    public class SystemOptimizationWhitelistAnalyzer
    {
        private readonly HashSet<string> _protectedItems = new(StringComparer.OrdinalIgnoreCase);

        public bool IsProtected(string item) => _protectedItems.Contains(item);
        public void Protect(string item) { _protectedItems.Add(item); }
    }
    #endregion

    #region 系统恢复白名单分析器
    public class SystemRestoreWhitelistAnalyzer
    {
        private readonly HashSet<string> _restorePoints = new(StringComparer.OrdinalIgnoreCase);

        public bool IsRestorePoint(string id) => _restorePoints.Contains(id);
        public void AddRestorePoint(string id) { _restorePoints.Add(id); }
    }
    #endregion

    #region USB防护白名单分析器
    public class USBProtectionWhitelistAnalyzer
    {
        private readonly HashSet<string> _trustedDevices = new(StringComparer.OrdinalIgnoreCase);

        public bool IsTrusted(string deviceId) => _trustedDevices.Contains(deviceId);
        public void Trust(string deviceId) { _trustedDevices.Add(deviceId); }
    }
    #endregion

    #region 网页防护白名单分析器
    public class WebProtectionWhitelistAnalyzer
    {
        private readonly HashSet<string> _trustedDomains = new(StringComparer.OrdinalIgnoreCase);

        public bool IsTrusted(string domain) => _trustedDomains.Contains(domain);
        public void Trust(string domain) { _trustedDomains.Add(domain); }
    }
    #endregion

    #region 邮件防护白名单分析器
    public class EmailProtectionWhitelistAnalyzer
    {
        private readonly HashSet<string> _trustedSenders = new(StringComparer.OrdinalIgnoreCase);

        public bool IsTrusted(string sender) => _trustedSenders.Contains(sender);
        public void Trust(string sender) { _trustedSenders.Add(sender); }
    }
    #endregion

    #region 蓝牙防护白名单分析器
    public class BluetoothProtectionWhitelistAnalyzer
    {
        private readonly HashSet<string> _trustedDevices = new(StringComparer.OrdinalIgnoreCase);

        public bool IsTrusted(string deviceAddress) => _trustedDevices.Contains(deviceAddress);
        public void Trust(string deviceAddress) { _trustedDevices.Add(deviceAddress); }
    }
    #endregion

    #region WiFi防护白名单分析器
    public class WifiProtectionWhitelistAnalyzer
    {
        private readonly HashSet<string> _trustedNetworks = new(StringComparer.OrdinalIgnoreCase);

        public bool IsTrusted(string ssid) => _trustedNetworks.Contains(ssid);
        public void Trust(string ssid) { _trustedNetworks.Add(ssid); }
    }
    #endregion

    #region 脚本白名单分析器
    public class ScriptWhitelistAnalyzer
    {
        private readonly HashSet<string> _trustedScripts = new(StringComparer.OrdinalIgnoreCase);

        public bool IsTrusted(string scriptPath) => _trustedScripts.Contains(scriptPath);
        public void Trust(string scriptPath) { _trustedScripts.Add(scriptPath); }
    }
    #endregion

    #region 签名白名单分析器
    public class SignatureWhitelistAnalyzer
    {
        private readonly HashSet<string> _trustedSignatures = new(StringComparer.OrdinalIgnoreCase);

        public bool IsTrusted(string signature) => _trustedSignatures.Contains(signature);
        public void Trust(string signature) { _trustedSignatures.Add(signature); }
    }
    #endregion
}
