using System;
using System.IO;
using Newtonsoft.Json;

namespace FireAntivirus.Engine.Strings
{
    /// <summary>
    /// Externalized string loader - loads runtime display strings from JSON file
    /// to prevent antivirus false positives by not embedding Chinese strings in DLL
    /// </summary>
    public static class LocalizedStrings
    {
        private static StringsData _data;
        private static bool _loaded = false;
        private static readonly object _lock = new object();

        private class StringsData
        {
            [JsonProperty("ThreatTypes")] public ThreatTypesData ThreatTypes { get; set; }
            [JsonProperty("ScanResults")] public ScanResultsData ScanResults { get; set; }
            [JsonProperty("ErrorMessages")] public ErrorMessagesData ErrorMessages { get; set; }
            [JsonProperty("RiskLevels")] public RiskLevelsData RiskLevels { get; set; }
            [JsonProperty("DetectionReasons")] public DetectionReasonsData DetectionReasons { get; set; }
            [JsonProperty("AdvancedProtection")] public AdvancedProtectionData AdvancedProtection { get; set; }
            [JsonProperty("StatusMessages")] public StatusMessagesData StatusMessages { get; set; }
            [JsonProperty("Recommendations")] public RecommendationsData Recommendations { get; set; }
            [JsonProperty("ResponseActions")] public ResponseActionsData ResponseActions { get; set; }
            [JsonProperty("AnalyzerNotes")] public AnalyzerNotesData AnalyzerNotes { get; set; }
        }

        private class ThreatTypesData
        {
            [JsonProperty("Trojan")] public string Trojan { get; set; }
            [JsonProperty("Backdoor")] public string Backdoor { get; set; }
            [JsonProperty("Worm")] public string Worm { get; set; }
            [JsonProperty("Virus")] public string Virus { get; set; }
            [JsonProperty("Miner")] public string Miner { get; set; }
            [JsonProperty("Spyware")] public string Spyware { get; set; }
            [JsonProperty("Adware")] public string Adware { get; set; }
            [JsonProperty("Ransomware")] public string Ransomware { get; set; }
            [JsonProperty("Suspicious")] public string Suspicious { get; set; }
            [JsonProperty("Riskware")] public string Riskware { get; set; }
            [JsonProperty("RemoteControlTrojan")] public string RemoteControlTrojan { get; set; }
            [JsonProperty("TrojanVirus")] public string TrojanVirus { get; set; }
            [JsonProperty("ComputerVirus")] public string ComputerVirus { get; set; }
        }

        private class ScanResultsData
        {
            [JsonProperty("ThreatDetected")] public string ThreatDetected { get; set; }
            [JsonProperty("NoThreat")] public string NoThreat { get; set; }
            [JsonProperty("ScanComplete")] public string ScanComplete { get; set; }
            [JsonProperty("ScanFailed")] public string ScanFailed { get; set; }
            [JsonProperty("FileNotFound")] public string FileNotFound { get; set; }
            [JsonProperty("AccessDenied")] public string AccessDenied { get; set; }
            [JsonProperty("SuspiciousFile")] public string SuspiciousFile { get; set; }
            [JsonProperty("MaliciousProcess")] public string MaliciousProcess { get; set; }
            [JsonProperty("SuspiciousProcess")] public string SuspiciousProcess { get; set; }
        }

        private class ErrorMessagesData
        {
            [JsonProperty("ScanFailed")] public string ScanFailed { get; set; }
            [JsonProperty("NetworkScanFailed")] public string NetworkScanFailed { get; set; }
            [JsonProperty("MemoryScanFailed")] public string MemoryScanFailed { get; set; }
            [JsonProperty("StartupScanFailed")] public string StartupScanFailed { get; set; }
            [JsonProperty("RegistryScanFailed")] public string RegistryScanFailed { get; set; }
            [JsonProperty("UpdateFailed")] public string UpdateFailed { get; set; }
            [JsonProperty("UpdateSuccess")] public string UpdateSuccess { get; set; }
            [JsonProperty("SignatureInitFailed")] public string SignatureInitFailed { get; set; }
            [JsonProperty("AnalyzeProcessFailed")] public string AnalyzeProcessFailed { get; set; }
        }

        private class RiskLevelsData
        {
            [JsonProperty("Critical")] public string Critical { get; set; }
            [JsonProperty("High")] public string High { get; set; }
            [JsonProperty("Medium")] public string Medium { get; set; }
            [JsonProperty("Low")] public string Low { get; set; }
            [JsonProperty("Info")] public string Info { get; set; }
        }

        private class DetectionReasonsData
        {
            [JsonProperty("HiddenProcess")] public string HiddenProcess { get; set; }
            [JsonProperty("UnsignedDriver")] public string UnsignedDriver { get; set; }
            [JsonProperty("SuspiciousStartup")] public string SuspiciousStartup { get; set; }
            [JsonProperty("SuspiciousService")] public string SuspiciousService { get; set; }
            [JsonProperty("SuspiciousFile")] public string SuspiciousFile { get; set; }
            [JsonProperty("ProcessInjection")] public string ProcessInjection { get; set; }
            [JsonProperty("RegistryHook")] public string RegistryHook { get; set; }
            [JsonProperty("FileHidden")] public string FileHidden { get; set; }
        }

        private class AdvancedProtectionData
        {
            [JsonProperty("HeuristicDetected")] public string HeuristicDetected { get; set; }
            [JsonProperty("HeuristicDetectedSuspicious")] public string HeuristicDetectedSuspicious { get; set; }
            [JsonProperty("BehaviorDetected")] public string BehaviorDetected { get; set; }
            [JsonProperty("BehaviorDetectedSuspicious")] public string BehaviorDetectedSuspicious { get; set; }
            [JsonProperty("UnknownThreat")] public string UnknownThreat { get; set; }
            [JsonProperty("UnknownType")] public string UnknownType { get; set; }
            [JsonProperty("HeuristicThreat")] public string HeuristicThreat { get; set; }
            [JsonProperty("Malware")] public string Malware { get; set; }
            [JsonProperty("BehaviorThreat")] public string BehaviorThreat { get; set; }
            [JsonProperty("UnknownNetworkThreat")] public string UnknownNetworkThreat { get; set; }
            [JsonProperty("SuspiciousNetworkConnection")] public string SuspiciousNetworkConnection { get; set; }
            [JsonProperty("NetworkThreat")] public string NetworkThreat { get; set; }
            [JsonProperty("SuspiciousNetworkTraffic")] public string SuspiciousNetworkTraffic { get; set; }
            [JsonProperty("SuspiciousDomain")] public string SuspiciousDomain { get; set; }
        }

        private class StatusMessagesData
        {
            [JsonProperty("Safe")] public string Safe { get; set; }
            [JsonProperty("Secure")] public string Secure { get; set; }
            [JsonProperty("Good")] public string Good { get; set; }
            [JsonProperty("Fair")] public string Fair { get; set; }
            [JsonProperty("Risk")] public string Risk { get; set; }
            [JsonProperty("Danger")] public string Danger { get; set; }
            [JsonProperty("None")] public string None { get; set; }
            [JsonProperty("Low")] public string Low { get; set; }
        }

        private class RecommendationsData
        {
            [JsonProperty("UpdateSignatureDb")] public string UpdateSignatureDb { get; set; }
            [JsonProperty("CheckStartupItems")] public string CheckStartupItems { get; set; }
            [JsonProperty("CheckSharePermissions")] public string CheckSharePermissions { get; set; }
            [JsonProperty("CheckAdminAccounts")] public string CheckAdminAccounts { get; set; }
        }

        private class ResponseActionsData
        {
            [JsonProperty("MalwareDetected")] public string MalwareDetected { get; set; }
            [JsonProperty("QuarantineFile")] public string QuarantineFile { get; set; }
            [JsonProperty("MalwareQuarantined")] public string MalwareQuarantined { get; set; }
            [JsonProperty("SuspiciousConnection")] public string SuspiciousConnection { get; set; }
            [JsonProperty("BlockConnection")] public string BlockConnection { get; set; }
            [JsonProperty("ConnectionBlocked")] public string ConnectionBlocked { get; set; }
            [JsonProperty("SystemAnomaly")] public string SystemAnomaly { get; set; }
            [JsonProperty("SystemScan")] public string SystemScan { get; set; }
            [JsonProperty("AnomalyProcessed")] public string AnomalyProcessed { get; set; }
            [JsonProperty("LogEvent")] public string LogEvent { get; set; }
            [JsonProperty("EventLogged")] public string EventLogged { get; set; }
            [JsonProperty("EventProcessingFailed")] public string EventProcessingFailed { get; set; }
            [JsonProperty("MalwareRemovalFailed")] public string MalwareRemovalFailed { get; set; }
            [JsonProperty("DeleteFile")] public string DeleteFile { get; set; }
            [JsonProperty("MalwareDeleted")] public string MalwareDeleted { get; set; }
        }

        private class AnalyzerNotesData
        {
            [JsonProperty("MultiAntiDebug")] public string MultiAntiDebug { get; set; }
            [JsonProperty("PartialAntiDebug")] public string PartialAntiDebug { get; set; }
        }

        /// <summary>Ensure strings are loaded (idempotent).</summary>
        public static void EnsureLoaded()
        {
            if (_loaded) return;
            lock (_lock)
            {
                if (_loaded) return;
                try
                {
                    var dirs = new[]
                    {
                        AppDomain.CurrentDomain.BaseDirectory,
                        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Strings"),
                        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Engine", "Strings")
                    };

                    string path = null;
                    foreach (var d in dirs)
                    {
                        var cand = Path.Combine(d, "LocalizedStrings.json");
                        if (File.Exists(cand)) { path = cand; break; }
                    }

                    if (path != null)
                    {
                        _data = JsonConvert.DeserializeObject<StringsData>(File.ReadAllText(path));
                    }
                }
                catch
                {
                    // Use defaults on load failure
                }
                _loaded = true;
            }
        }

        // Threat Types
        public static string Trojan => _data?.ThreatTypes?.Trojan ?? "Trojan";
        public static string Backdoor => _data?.ThreatTypes?.Backdoor ?? "Backdoor";
        public static string Worm => _data?.ThreatTypes?.Worm ?? "Worm";
        public static string Virus => _data?.ThreatTypes?.Virus ?? "Virus";
        public static string Miner => _data?.ThreatTypes?.Miner ?? "Miner";
        public static string Spyware => _data?.ThreatTypes?.Spyware ?? "Spyware";
        public static string Adware => _data?.ThreatTypes?.Adware ?? "Adware";
        public static string Ransomware => _data?.ThreatTypes?.Ransomware ?? "Ransomware";
        public static string Suspicious => _data?.ThreatTypes?.Suspicious ?? "Suspicious";
        public static string Riskware => _data?.ThreatTypes?.Riskware ?? "Riskware";
        public static string RemoteControlTrojan => _data?.ThreatTypes?.RemoteControlTrojan ?? "Remote Control Trojan";
        public static string TrojanVirus => _data?.ThreatTypes?.TrojanVirus ?? "Trojan Virus";
        public static string ComputerVirus => _data?.ThreatTypes?.ComputerVirus ?? "Computer Virus";

        // Scan Results
        public static string ThreatDetected => _data?.ScanResults?.ThreatDetected ?? "Threat detected";
        public static string NoThreat => _data?.ScanResults?.NoThreat ?? "No threat found";
        public static string ScanComplete => _data?.ScanResults?.ScanComplete ?? "Scan complete";
        public static string ScanFailed => _data?.ScanResults?.ScanFailed ?? "Scan failed";
        public static string FileNotFound => _data?.ScanResults?.FileNotFound ?? "File not found";
        public static string AccessDenied => _data?.ScanResults?.AccessDenied ?? "Access denied";
        public static string SuspiciousFile => _data?.ScanResults?.SuspiciousFile ?? "Suspicious file";
        public static string MaliciousProcess => _data?.ScanResults?.MaliciousProcess ?? "Malicious process detected";
        public static string SuspiciousProcess => _data?.ScanResults?.SuspiciousProcess ?? "Suspicious process detected";

        // Error Messages
        public static string Error_ScanFailed => _data?.ErrorMessages?.ScanFailed ?? "Scan failed";
        public static string Error_NetworkScanFailed => _data?.ErrorMessages?.NetworkScanFailed ?? "Network scan failed";
        public static string Error_MemoryScanFailed => _data?.ErrorMessages?.MemoryScanFailed ?? "Memory scan failed";
        public static string Error_StartupScanFailed => _data?.ErrorMessages?.StartupScanFailed ?? "Startup scan failed";
        public static string Error_RegistryScanFailed => _data?.ErrorMessages?.RegistryScanFailed ?? "Registry scan failed";
        public static string Error_UpdateFailed => _data?.ErrorMessages?.UpdateFailed ?? "Update failed";
        public static string Error_UpdateSuccess => _data?.ErrorMessages?.UpdateSuccess ?? "Update successful";
        public static string Error_SignatureInitFailed => _data?.ErrorMessages?.SignatureInitFailed ?? "Signature database initialization failed";
        public static string Error_AnalyzeProcessFailed => _data?.ErrorMessages?.AnalyzeProcessFailed ?? "Failed to analyze process";

        // Risk Levels
        public static string Risk_Critical => _data?.RiskLevels?.Critical ?? "Critical";
        public static string Risk_High => _data?.RiskLevels?.High ?? "High";
        public static string Risk_Medium => _data?.RiskLevels?.Medium ?? "Medium";
        public static string Risk_Low => _data?.RiskLevels?.Low ?? "Low";
        public static string Risk_Info => _data?.RiskLevels?.Info ?? "Info";

        // Detection Reasons
        public static string Reason_HiddenProcess => _data?.DetectionReasons?.HiddenProcess ?? "Process is hidden";
        public static string Reason_UnsignedDriver => _data?.DetectionReasons?.UnsignedDriver ?? "Unsigned driver";
        public static string Reason_SuspiciousStartup => _data?.DetectionReasons?.SuspiciousStartup ?? "Suspicious startup item";
        public static string Reason_SuspiciousService => _data?.DetectionReasons?.SuspiciousService ?? "Suspicious service";
        public static string Reason_SuspiciousFile => _data?.DetectionReasons?.SuspiciousFile ?? "Suspicious file name";
        public static string Reason_ProcessInjection => _data?.DetectionReasons?.ProcessInjection ?? "Process injection detected";
        public static string Reason_RegistryHook => _data?.DetectionReasons?.RegistryHook ?? "Registry hook detected";
        public static string Reason_FileHidden => _data?.DetectionReasons?.FileHidden ?? "File may be hidden";

        // Advanced Protection
        public static string Adv_HeuristicDetected => _data?.AdvancedProtection?.HeuristicDetected ?? "Heuristic analysis detected malicious file";
        public static string Adv_HeuristicDetectedSuspicious => _data?.AdvancedProtection?.HeuristicDetectedSuspicious ?? "Heuristic analysis detected suspicious file";
        public static string Adv_BehaviorDetected => _data?.AdvancedProtection?.BehaviorDetected ?? "Behavior analysis detected malicious file";
        public static string Adv_BehaviorDetectedSuspicious => _data?.AdvancedProtection?.BehaviorDetectedSuspicious ?? "Behavior analysis detected suspicious file";
        public static string Adv_UnknownThreat => _data?.AdvancedProtection?.UnknownThreat ?? "Unknown threat";
        public static string Adv_UnknownType => _data?.AdvancedProtection?.UnknownType ?? "Unknown type";
        public static string Adv_HeuristicThreat => _data?.AdvancedProtection?.HeuristicThreat ?? "Heuristic detection threat";
        public static string Adv_Malware => _data?.AdvancedProtection?.Malware ?? "Malware";
        public static string Adv_BehaviorThreat => _data?.AdvancedProtection?.BehaviorThreat ?? "Behavior analysis detected threat";
        public static string Adv_UnknownNetworkThreat => _data?.AdvancedProtection?.UnknownNetworkThreat ?? "Unknown network threat";
        public static string Adv_SuspiciousNetworkConnection => _data?.AdvancedProtection?.SuspiciousNetworkConnection ?? "Suspicious network connection";
        public static string Adv_NetworkThreat => _data?.AdvancedProtection?.NetworkThreat ?? "Network threat";
        public static string Adv_SuspiciousNetworkTraffic => _data?.AdvancedProtection?.SuspiciousNetworkTraffic ?? "Suspicious network traffic";
        public static string Adv_SuspiciousDomain => _data?.AdvancedProtection?.SuspiciousDomain ?? "Suspicious domain";

        // Status Messages
        public static string Status_Safe => _data?.StatusMessages?.Safe ?? "Safe";
        public static string Status_Secure => _data?.StatusMessages?.Secure ?? "Secure";
        public static string Status_Good => _data?.StatusMessages?.Good ?? "Good";
        public static string Status_Fair => _data?.StatusMessages?.Fair ?? "Fair";
        public static string Status_Risk => _data?.StatusMessages?.Risk ?? "Risk";
        public static string Status_Danger => _data?.StatusMessages?.Danger ?? "Danger";
        public static string Status_None => _data?.StatusMessages?.None ?? "None";

        // Recommendations
        public static string Rec_UpdateSignatureDb => _data?.Recommendations?.UpdateSignatureDb ?? "Update virus definition database";
        public static string Rec_CheckStartupItems => _data?.Recommendations?.CheckStartupItems ?? "Check and remove suspicious startup items";
        public static string Rec_CheckSharePermissions => _data?.Recommendations?.CheckSharePermissions ?? "Check network share permissions";
        public static string Rec_CheckAdminAccounts => _data?.Recommendations?.CheckAdminAccounts ?? "Check if all admin accounts are necessary";

        // Response Actions
        public static string Resp_MalwareDetected => _data?.ResponseActions?.MalwareDetected ?? "Malware detected";
        public static string Resp_QuarantineFile => _data?.ResponseActions?.QuarantineFile ?? "Quarantine malicious file";
        public static string Resp_MalwareQuarantined => _data?.ResponseActions?.MalwareQuarantined ?? "Malicious file has been quarantined";
        public static string Resp_SuspiciousConnection => _data?.ResponseActions?.SuspiciousConnection ?? "Suspicious network connection";
        public static string Resp_BlockConnection => _data?.ResponseActions?.BlockConnection ?? "Block network connection";
        public static string Resp_ConnectionBlocked => _data?.ResponseActions?.ConnectionBlocked ?? "Suspicious network connection has been blocked";
        public static string Resp_SystemAnomaly => _data?.ResponseActions?.SystemAnomaly ?? "System anomaly";
        public static string Resp_SystemScan => _data?.ResponseActions?.SystemScan ?? "System scan";
        public static string Resp_AnomalyProcessed => _data?.ResponseActions?.AnomalyProcessed ?? "System anomaly processed";
        public static string Resp_LogEvent => _data?.ResponseActions?.LogEvent ?? "Log event";
        public static string Resp_EventLogged => _data?.ResponseActions?.EventLogged ?? "Security event has been logged";
        public static string Resp_EventProcessingFailed => _data?.ResponseActions?.EventProcessingFailed ?? "Failed to process security event";
        public static string Resp_MalwareRemovalFailed => _data?.ResponseActions?.MalwareRemovalFailed ?? "Failed to remove malware";
        public static string Resp_DeleteFile => _data?.ResponseActions?.DeleteFile ?? "Delete file";
        public static string Resp_MalwareDeleted => _data?.ResponseActions?.MalwareDeleted ?? "Malware has been deleted";

        // Analyzer Notes
        public static string Note_MultiAntiDebug => _data?.AnalyzerNotes?.MultiAntiDebug ?? "Multi-layer anti-analysis protection";
        public static string Note_PartialAntiDebug => _data?.AnalyzerNotes?.PartialAntiDebug ?? "Partial anti-analysis features";
    }
}
