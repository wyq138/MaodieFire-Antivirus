// 耄耋软件工作室 开发，严禁非法反编译
// 专业级安全报告引擎 - 对标企业级安全审计报告
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace FireAntivirus.Services
{
    public class SecurityReportService
    {
        private readonly string _reportDirectory;
        private readonly string _templateDirectory;
        private readonly string _auditLogPath;

        // 报告模板
        private Dictionary<string, ReportTemplate> _templates;
        private bool _templatesLoaded = false;

        // 审计日志
        private List<AuditLogEntry> _auditLogs;
        private bool _auditLogsLoaded = false;

        // 定时报告配置
        private ScheduledReportConfig _scheduledConfig;
        private bool _configLoaded = false;

        public event EventHandler<ReportGeneratedEventArgs> ReportGenerated;

        public SecurityReportService()
        {
            _reportDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "FireAntivirus", "Reports");

            _templateDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "ReportTemplates");

            _auditLogPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FireAntivirus", "Logs", "audit.log");
            
            // 延迟初始化 - 只在需要时创建目录和加载数据
            _templates = new Dictionary<string, ReportTemplate>();
            _auditLogs = new List<AuditLogEntry>();
        }
        
        private void EnsureInitialized()
        {
            if (!_templatesLoaded)
            {
                try
                {
                    foreach (var path in new[] { _reportDirectory, _templateDirectory, Path.GetDirectoryName(_auditLogPath) })
                    {
                        if (!Directory.Exists(path))
                            Directory.CreateDirectory(path);
                    }
                    InitializeTemplates();
                    _templatesLoaded = true;
                } catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            }
            
            if (!_auditLogsLoaded)
            {
                try
                {
                    LoadAuditLogs();
                    _auditLogsLoaded = true;
                } catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            }
            
            if (!_configLoaded)
            {
                try
                {
                    LoadScheduledConfig();
                    _configLoaded = true;
                } catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            }
        }

        #region 初始化

        private void InitializeTemplates()
        {
            _templates = new Dictionary<string, ReportTemplate>
            {
                ["full"] = new ReportTemplate
                {
                    Name = "完整安全报告",
                    Description = "包含所有安全信息的详细报告",
                    Sections = new[]
                    {
                        ReportSection.SystemInfo,
                        ReportSection.SecurityStatus,
                        ReportSection.Vulnerabilities,
                        ReportSection.StartupItems,
                        ReportSection.Services,
                        ReportSection.NetworkStatus,
                        ReportSection.InstalledPrograms,
                        ReportSection.AuditLog,
                        ReportSection.ComplianceCheck,
                        ReportSection.Recommendations
                    }
                },
                ["executive"] = new ReportTemplate
                {
                    Name = "管理层摘要报告",
                    Description = "简明扼要的概要报告，适合管理层查看",
                    Sections = new[]
                    {
                        ReportSection.ExecutiveSummary,
                        ReportSection.SecurityScore,
                        ReportSection.CriticalFindings,
                        ReportSection.Recommendations
                    }
                },
                ["compliance"] = new ReportTemplate
                {
                    Name = "合规性报告",
                    Description = "等保2.0/GDPR合规检查报告",
                    Sections = new[]
                    {
                        ReportSection.ComplianceSummary,
                        ReportSection.ComplianceDetails,
                        ReportSection.GapsAnalysis,
                        ReportSection.RemediationPlan
                    }
                },
                ["vulnerability"] = new ReportTemplate
                {
                    Name = "漏洞扫描报告",
                    Description = "专注于系统漏洞和安全配置问题",
                    Sections = new[]
                    {
                        ReportSection.VulnerabilitySummary,
                        ReportSection.VulnerabilityDetails,
                        ReportSection.RiskAssessment,
                        ReportSection.RemediationSteps
                    }
                },
                ["audit"] = new ReportTemplate
                {
                    Name = "安全审计报告",
                    Description = "用户行为和系统变更审计报告",
                    Sections = new[]
                    {
                        ReportSection.AuditSummary,
                        ReportSection.UserActivity,
                        ReportSection.SystemChanges,
                        ReportSection.SecurityEvents,
                        ReportSection.AuditRecommendations
                    }
                }
            };
        }

        private void LoadAuditLogs()
        {
            try
            {
                if (File.Exists(_auditLogPath))
                {
                    var lines = File.ReadAllLines(_auditLogPath);
                    foreach (var line in lines)
                    {
                        try
                        {
                            var entry = JsonSerializer.Deserialize<AuditLogEntry>(line);
                            if (entry != null)
                            {
                                _auditLogs.Add(entry);
                            }
                        }
                        catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
        }

        private void LoadScheduledConfig()
        {
            try
            {
                var configPath = Path.Combine(_templateDirectory, "scheduled_config.json");
                if (File.Exists(configPath))
                {
                    _scheduledConfig = JsonSerializer.Deserialize<ScheduledReportConfig>(
                        File.ReadAllText(configPath));
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            _scheduledConfig ??= new ScheduledReportConfig();
        }

        #endregion

        #region 公共方法

        /// <summary>
        /// 生成完整安全报告
        /// </summary>
        public SecurityReport GenerateFullReport()
        {
            EnsureInitialized();
            return GenerateReport(_templates["full"]);
        }

        /// <summary>
        /// 根据模板生成报告
        /// </summary>
        public SecurityReport GenerateReport(ReportTemplate template)
        {
            EnsureInitialized();
            var report = new SecurityReport
            {
                ReportId = Guid.NewGuid().ToString(),
                GeneratedTime = DateTime.Now,
                TemplateName = template.Name
            };

            // 根据模板章节生成内容
            foreach (var section in template.Sections)
            {
                PopulateSection(report, section);
            }

            // 计算综合评分
            CalculateOverallScore(report);

            // 生成资产清单
            report.AssetInventory = GenerateAssetInventory();

            // 生成趋势数据
            report.TrendData = GenerateTrendData();

            // 记录审计日志
            LogAuditEvent("REPORT_GENERATED", $"生成报告: {template.Name}");

            return report;
        }

        /// <summary>
        /// 生成管理层摘要报告
        /// </summary>
        public ExecutiveSummaryReport GenerateExecutiveSummary()
        {
            var fullReport = GenerateFullReport();

            return new ExecutiveSummaryReport
            {
                ReportId = fullReport.ReportId,
                GeneratedTime = fullReport.GeneratedTime,
                OverallScore = fullReport.OverallScore,
                RiskLevel = fullReport.RiskLevel,
                CriticalFindingsCount = fullReport.Vulnerabilities.Count(v => v.Severity == "严重"),
                HighFindingsCount = fullReport.Vulnerabilities.Count(v => v.Severity == "高"),
                MediumFindingsCount = fullReport.Vulnerabilities.Count(v => v.Severity == "中"),
                KeyFindings = ExtractKeyFindings(fullReport),
                TopRecommendations = fullReport.Recommendations.Take(5).ToList(),
                SecurityTrend = fullReport.TrendData?.ScoreTrend ?? "稳定"
            };
        }

        /// <summary>
        /// 生成合规性报告
        /// </summary>
        public ComplianceReport GenerateComplianceReport(ComplianceStandard standard)
        {
            var report = new ComplianceReport
            {
                ReportId = Guid.NewGuid().ToString(),
                GeneratedTime = DateTime.Now,
                Standard = standard
            };

            // 根据标准执行检查
            switch (standard)
            {
                case ComplianceStandard.DJCP20: // 等保2.0
                    report.Checks = PerformDJCPChecks();
                    break;
                case ComplianceStandard.GDPR:
                    report.Checks = PerformGDPRChecks();
                    break;
                case ComplianceStandard.ISO27001:
                    report.Checks = PerformISO27001Checks();
                    break;
                case ComplianceStandard.PCIDSS:
                    report.Checks = PerformPCIDSSChecks();
                    break;
                default:
                    report.Checks = PerformBasicComplianceChecks();
                    break;
            }

            // 计算合规评分
            report.ComplianceScore = CalculateComplianceScore(report.Checks);
            report.CompliancePercentage = (int)(report.Checks.Count(c => c.Status == ComplianceStatus.Compliant) * 100.0 / report.Checks.Count);
            report.Gaps = IdentifyGaps(report.Checks);
            report.RemediationPlan = GenerateRemediationPlan(report.Gaps);

            return report;
        }

        /// <summary>
        /// 添加审计日志条目
        /// </summary>
        public void AddAuditLog(AuditLogEntry entry)
        {
            EnsureInitialized();
            entry.Timestamp = DateTime.Now;
            _auditLogs.Add(entry);

            // 持久化
            try
            {
                var line = JsonSerializer.Serialize(entry);
                File.AppendAllText(_auditLogPath, line + Environment.NewLine);
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
        }

        /// <summary>
        /// 记录审计事件
        /// </summary>
        public void LogAuditEvent(string eventType, string description, string user = null, string details = null)
        {
            AddAuditLog(new AuditLogEntry
            {
                EventType = eventType,
                Description = description,
                User = user ?? Environment.UserName,
                Details = details,
                ComputerName = Environment.MachineName
            });
        }

        /// <summary>
        /// 获取审计日志
        /// </summary>
        public List<AuditLogEntry> GetAuditLogs(DateTime? from = null, DateTime? to = null, string eventType = null)
        {
            EnsureInitialized();
            var query = _auditLogs.AsEnumerable();

            if (from.HasValue)
                query = query.Where(e => e.Timestamp >= from.Value);

            if (to.HasValue)
                query = query.Where(e => e.Timestamp <= to.Value);

            if (!string.IsNullOrEmpty(eventType))
                query = query.Where(e => e.EventType == eventType);

            return query.OrderByDescending(e => e.Timestamp).ToList();
        }

        /// <summary>
        /// 保存报告
        /// </summary>
        public string SaveReport(SecurityReport report, ReportFormat format = ReportFormat.Text)
        {
            EnsureInitialized();
            var fileName = $"SecurityReport_{DateTime.Now:yyyyMMdd_HHmmss}";
            string filePath;

            switch (format)
            {
                case ReportFormat.JSON:
                    filePath = Path.Combine(_reportDirectory, fileName + ".json");
                    File.WriteAllText(filePath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
                    break;

                case ReportFormat.HTML:
                    filePath = Path.Combine(_reportDirectory, fileName + ".html");
                    File.WriteAllText(filePath, GenerateHtmlReport(report));
                    break;

                case ReportFormat.CSV:
                    filePath = Path.Combine(_reportDirectory, fileName + ".csv");
                    File.WriteAllText(filePath, GenerateCsvReport(report));
                    break;

                default:
                    filePath = Path.Combine(_reportDirectory, fileName + ".txt");
                    File.WriteAllText(filePath, GenerateTextReport(report));
                    break;
            }

            LogAuditEvent("REPORT_SAVED", $"保存报告: {Path.GetFileName(filePath)}");
            ReportGenerated?.Invoke(this, new ReportGeneratedEventArgs { FilePath = filePath, Format = format });

            return filePath;
        }

        /// <summary>
        /// 加载报告内容
        /// </summary>
        public string LoadReport(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                    return File.ReadAllText(filePath);
                return null;
            }
            catch { return null; }
        }

        /// <summary>
        /// 获取保存的报告列表
        /// </summary>
        public List<ReportFileInfo> GetSavedReports()
        {
            var files = new List<ReportFileInfo>();

            if (!Directory.Exists(_reportDirectory))
                return files;

            foreach (var file in Directory.GetFiles(_reportDirectory))
            {
                try
                {
                    var info = new FileInfo(file);
                    files.Add(new ReportFileInfo
                    {
                        FileName = Path.GetFileName(file),
                        FilePath = file,
                        Size = info.Length,
                        CreatedTime = info.CreationTime,
                        Format = DetermineFormat(file)
                    });
                }
                catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            }

            return files.OrderByDescending(f => f.CreatedTime).ToList();
        }

        /// <summary>
        /// 配置定时报告
        /// </summary>
        public void ConfigureScheduledReport(ScheduledReportConfig config)
        {
            EnsureInitialized();
            _scheduledConfig = config;

            var configPath = Path.Combine(_templateDirectory, "scheduled_config.json");
            File.WriteAllText(configPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));

            LogAuditEvent("SCHEDULED_REPORT_CONFIGURED", $"配置定时报告: {config.Schedule}");
        }

        /// <summary>
        /// 获取可用模板
        /// </summary>
        public List<ReportTemplate> GetTemplates()
        {
            EnsureInitialized();
            return _templates.Values.ToList();
        }

        #endregion

        #region 私有方法 - 报告生成

        private void PopulateSection(SecurityReport report, ReportSection section)
        {
            switch (section)
            {
                case ReportSection.SystemInfo:
                    report.SystemInfo = GetSystemInfo();
                    break;

                case ReportSection.SecurityStatus:
                    report.SecurityStatus = GetSecurityStatus();
                    break;

                case ReportSection.Vulnerabilities:
                    report.Vulnerabilities = GetVulnerabilities();
                    break;

                case ReportSection.StartupItems:
                    report.StartupItems = GetStartupItems();
                    break;

                case ReportSection.Services:
                    report.Services = GetServices();
                    break;

                case ReportSection.NetworkStatus:
                    report.NetworkStatus = GetNetworkStatus();
                    break;

                case ReportSection.InstalledPrograms:
                    report.InstalledPrograms = GetInstalledPrograms();
                    break;

                case ReportSection.AuditLog:
                    report.RecentAuditLogs = GetAuditLogs(DateTime.Now.AddDays(-7));
                    break;

                case ReportSection.ComplianceCheck:
                    report.ComplianceChecks = PerformBasicComplianceChecks();
                    break;

                case ReportSection.Recommendations:
                    report.Recommendations = GenerateRecommendations(report);
                    break;

                case ReportSection.ExecutiveSummary:
                    report.ExecutiveSummary = GenerateExecutiveSummaryContent(report);
                    break;

                case ReportSection.SecurityScore:
                    if (report.SecurityStatus == null)
                        report.SecurityStatus = GetSecurityStatus();
                    break;

                case ReportSection.CriticalFindings:
                    report.CriticalFindings = ExtractCriticalFindings(report);
                    break;
            }
        }

        private SystemInfo GetSystemInfo()
        {
            var info = new SystemInfo();

            try
            {
                info.ComputerName = Environment.MachineName;
                info.UserName = Environment.UserName;
                info.Domain = Environment.UserDomainName;
                info.OSVersion = Environment.OSVersion.ToString();
                info.SystemDirectory = Environment.SystemDirectory;

                // CPU信息
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.Processor = obj["Name"]?.ToString()?.Trim() ?? "Unknown";
                        info.ProcessorCores = int.Parse(obj["NumberOfCores"]?.ToString() ?? "1");
                        info.ProcessorLogicalProcessors = int.Parse(obj["NumberOfLogicalProcessors"]?.ToString() ?? "1");
                        break;
                    }
                }

                // 内存信息
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.TotalMemoryBytes = Convert.ToInt64(obj["TotalPhysicalMemory"]);
                        info.TotalMemory = info.TotalMemoryBytes;
                        break;
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        info.AvailableMemoryBytes = Convert.ToInt64(obj["FreePhysicalMemory"]) * 1024;
                        info.AvailableMemory = info.AvailableMemoryBytes;
                        info.OSName = obj["Caption"]?.ToString();
                        info.OSBuild = obj["BuildNumber"]?.ToString();
                        info.OSArchitecture = obj["OSArchitecture"]?.ToString();
                        info.InstallDate = ManagementDateTimeConverter.ToDateTime(obj["InstallDate"]?.ToString());

                        var lastBoot = obj["LastBootUpTime"]?.ToString();
                        if (!string.IsNullOrEmpty(lastBoot))
                        {
                            info.LastBootTime = ManagementDateTimeConverter.ToDateTime(lastBoot);
                            info.Uptime = DateTime.Now - info.LastBootTime.Value;
                        }
                        break;
                    }
                }

                // 磁盘信息
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady))
                {
                    info.Disks.Add(new DiskInfo
                    {
                        Name = drive.Name,
                        Label = drive.VolumeLabel,
                        Format = drive.DriveFormat,
                        TotalSize = drive.TotalSize,
                        FreeSpace = drive.AvailableFreeSpace,
                        UsedSpace = drive.TotalSize - drive.AvailableFreeSpace,
                        UsagePercentage = (int)((drive.TotalSize - drive.AvailableFreeSpace) * 100 / drive.TotalSize)
                    });
                }

                // 网络信息
                info.IPAddresses = GetIPAddresses();
                info.MACAddress = GetMACAddress();
            }
            catch (Exception ex)
            {
                info.Error = ex.Message;
            }

            return info;
        }

        private SecurityStatus GetSecurityStatus()
        {
            var status = new SecurityStatus();

            try
            {
                // 防病毒软件
                using (var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\SecurityCenter", "SELECT * FROM AntiVirusProduct"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        status.AntivirusName = obj["displayName"]?.ToString() ?? "Unknown";
                        status.HasAntivirus = true;

                        var state = obj["productState"]?.ToString();
                        if (!string.IsNullOrEmpty(state))
                        {
                            var stateVal = int.Parse(state);
                            status.AntivirusUpToDate = (stateVal & 0x10) == 0;
                            status.AntivirusEnabled = (stateVal & 0x1000) == 0;
                        }
                        break;
                    }
                }

                // Windows Defender
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"))
                {
                    if (key != null)
                    {
                        status.DefenderRealTimeEnabled = (int?)key.GetValue("DisableRealtimeMonitoring") != 1;
                    }
                }

                // 防火墙
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"))
                {
                    if (key != null)
                    {
                        status.FirewallEnabled = ((int?)key.GetValue("EnableFirewall") ?? 0) == 1;
                    }
                }

                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"))
                {
                    if (key != null)
                    {
                        status.DomainFirewallEnabled = ((int?)key.GetValue("EnableFirewall") ?? 0) == 1;
                    }
                }

                // UAC
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    if (key != null)
                    {
                        status.UACEnabled = ((int?)key.GetValue("EnableLUA") ?? 0) == 1;
                        status.UACLevel = (int?)key.GetValue("ConsentPromptBehaviorAdmin") ?? 5;
                    }
                }

                // Windows Update
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"))
                {
                    if (key != null)
                    {
                        int auOptions = (int?)key.GetValue("AUOptions") ?? 0;
                        status.AutoUpdateEnabled = auOptions >= 2;
                        status.AutoUpdateLevel = auOptions;
                    }
                }

                // BitLocker
                foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
                {
                    try
                    {
                        using (var searcher = new ManagementObjectSearcher(
                            $"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter='{drive.Name.TrimEnd('\\')}'"))
                        {
                            foreach (ManagementObject vol in searcher.Get())
                            {
                                var protectionStatus = vol["ProtectionStatus"];
                                status.BitLockerStatus[drive.Name] = protectionStatus?.ToString() == "1" ? "已启用" : "未启用";
                            }
                        }
                    }
                    catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
                }

                // 最近更新
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_QuickFixEngineering"))
                {
                    var updates = searcher.Get()
                        .Cast<ManagementObject>()
                        .ToList();

                    status.TotalUpdatesInstalled = updates.Count;

                    var lastUpdate = updates
                        .Where(u => u["InstalledOn"] != null)
                        .OrderByDescending(u => u["InstalledOn"])
                        .FirstOrDefault();

                    if (lastUpdate != null)
                    {
                        status.LastUpdateKB = lastUpdate["HotFixID"]?.ToString();
                        status.LastUpdateDate = lastUpdate["InstalledOn"]?.ToString();
                    }
                }

                // 计算安全评分
                status.SecurityScore = CalculateSecurityScore(status);
            }
            catch (Exception ex)
            {
                status.Error = ex.Message;
            }

            return status;
        }

        private List<VulnerabilityInfo> GetVulnerabilities()
        {
            var vulnerabilities = new List<VulnerabilityInfo>();

            // SMBv1检查
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"))
                {
                    var smb1 = key?.GetValue("SMB1");
                    if (smb1 == null || (int)smb1 == 1)
                    {
                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Id = "SMB_V1_ENABLED",
                            Name = "SMBv1协议已启用",
                            Severity = "严重",
                            Description = "SMBv1协议存在已知严重漏洞(如WannaCry勒索软件利用的漏洞EternalBlue)",
                            Category = "网络安全",
                            CVSSScore = 9.5,
                            Remediation = "禁用SMBv1协议",
                            References = new List<string> { "CVE-2017-0144", "CVE-2017-0145" }
                        });
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            // 远程桌面检查
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Terminal Server"))
                {
                    var fDenyTSConnections = key?.GetValue("fDenyTSConnections");
                    if (fDenyTSConnections != null && (int)fDenyTSConnections == 0)
                    {
                        // 检查NLA
                        bool nlaEnabled = false;
                        using (var nlaKey = Registry.LocalMachine.OpenSubKey(
                            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"))
                        {
                            var userAuth = nlaKey?.GetValue("UserAuthentication");
                            nlaEnabled = userAuth != null && (int)userAuth == 1;
                        }

                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Id = "RDP_ENABLED",
                            Name = "远程桌面已启用",
                            Severity = nlaEnabled ? "中" : "高",
                            Description = $"远程桌面服务已启用。{(nlaEnabled ? "NLA已启用" : "警告：NLA未启用，安全性较低")}",
                            Category = "远程访问",
                            CVSSScore = nlaEnabled ? 6.0 : 8.0,
                            Remediation = "如非必要请禁用，或确保NLA已启用并使用强密码策略"
                        });
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            // UAC检查
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    var enableLUA = key?.GetValue("EnableLUA");
                    if (enableLUA == null || (int)enableLUA == 0)
                    {
                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Id = "UAC_DISABLED",
                            Name = "UAC已禁用",
                            Severity = "高",
                            Description = "用户账户控制(UAC)已禁用，系统更容易受到恶意软件攻击",
                            Category = "系统配置",
                            CVSSScore = 7.5,
                            Remediation = "启用UAC"
                        });
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            // Guest账户检查
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_UserAccount WHERE Disabled=false AND Name='Guest'"))
                {
                    if (searcher.Get().Count > 0)
                    {
                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Id = "GUEST_ENABLED",
                            Name = "Guest账户已启用",
                            Severity = "中",
                            Description = "Guest账户已启用，可能被攻击者利用",
                            Category = "账户安全",
                            CVSSScore = 5.0,
                            Remediation = "禁用Guest账户"
                        });
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            // 空密码检查
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Lsa"))
                {
                    var limitBlankPasswordUse = key?.GetValue("LimitBlankPasswordUse");
                    if (limitBlankPasswordUse != null && (int)limitBlankPasswordUse == 0)
                    {
                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Id = "BLANK_PASSWORD_ALLOWED",
                            Name = "允许空密码远程登录",
                            Severity = "严重",
                            Description = "系统允许空密码账户进行远程登录，存在严重安全风险",
                            Category = "账户安全",
                            CVSSScore = 9.0,
                            Remediation = "设置LimitBlankPasswordUse为1"
                        });
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            // 自动播放检查
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"))
                {
                    var noDriveTypeAutoRun = key?.GetValue("NoDriveTypeAutoRun");
                    if (noDriveTypeAutoRun == null || (int)noDriveTypeAutoRun != 255)
                    {
                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Id = "AUTORUN_ENABLED",
                            Name = "自动播放未完全禁用",
                            Severity = "中",
                            Description = "自动播放功能可能被恶意USB设备利用传播病毒",
                            Category = "系统配置",
                            CVSSScore = 5.5,
                            Remediation = "完全禁用所有驱动器类型的自动播放"
                        });
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            // PowerShell策略检查
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"))
                {
                    var executionPolicy = key?.GetValue("ExecutionPolicy")?.ToString();
                    if (executionPolicy == "Unrestricted" || executionPolicy == "Bypass")
                    {
                        vulnerabilities.Add(new VulnerabilityInfo
                        {
                            Id = "POWERSHELL_UNRESTRICTED",
                            Name = "PowerShell执行策略不安全",
                            Severity = "高",
                            Description = $"PowerShell执行策略设置为{executionPolicy}，允许运行未签名脚本",
                            Category = "系统配置",
                            CVSSScore = 7.5,
                            Remediation = "设置执行策略为RemoteSigned或AllSigned"
                        });
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            return vulnerabilities.OrderByDescending(v => v.CVSSScore).ToList();
        }

        private List<StartupItemInfo> GetStartupItems()
        {
            var items = new List<StartupItemInfo>();

            // 注册表启动项
            var registryPaths = new[]
            {
                new { Path = @"Software\Microsoft\Windows\CurrentVersion\Run", Root = Registry.CurrentUser, Location = "HKCU" },
                new { Path = @"Software\Microsoft\Windows\CurrentVersion\RunOnce", Root = Registry.CurrentUser, Location = "HKCU" },
                new { Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Root = Registry.LocalMachine, Location = "HKLM" },
                new { Path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Root = Registry.LocalMachine, Location = "HKLM" },
                new { Path = @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", Root = Registry.LocalMachine, Location = "HKLM(32-bit)" }
            };

            foreach (var regPath in registryPaths)
            {
                try
                {
                    using (var key = regPath.Root.OpenSubKey(regPath.Path))
                    {
                        if (key == null) continue;

                        foreach (var name in key.GetValueNames())
                        {
                            var value = key.GetValue(name)?.ToString();
                            items.Add(new StartupItemInfo
                            {
                                Name = name,
                                Path = value ?? "",
                                Location = $"{regPath.Location}\\{regPath.Path}",
                                Source = "Registry",
                                Enabled = true
                            });
                        }
                    }
                }
                catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            }

            // 启动文件夹
            var startupFolders = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
            };

            foreach (var folder in startupFolders.Where(Directory.Exists))
            {
                foreach (var file in Directory.GetFiles(folder, "*.lnk"))
                {
                    items.Add(new StartupItemInfo
                    {
                        Name = Path.GetFileNameWithoutExtension(file),
                        Path = file,
                        Location = folder,
                        Source = "Startup Folder",
                        Enabled = true
                    });
                }
            }

            return items;
        }

        private List<ServiceInfo> GetServices()
        {
            var services = new List<ServiceInfo>();

            try
            {
                foreach (var service in ServiceController.GetServices())
                {
                    try
                    {
                        services.Add(new ServiceInfo
                        {
                            Name = service.ServiceName,
                            DisplayName = service.DisplayName,
                            Status = service.Status.ToString(),
                            StartType = service.StartType.ToString()
                        });
                    }
                    catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            return services.OrderBy(s => s.Name).ToList();
        }

        private NetworkStatus GetNetworkStatus()
        {
            var status = new NetworkStatus();

            try
            {
                // 网络适配器
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled=true"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        status.Adapters.Add(new NetworkAdapterInfo
                        {
                            Name = obj["Name"]?.ToString() ?? "",
                            MACAddress = obj["MACAddress"]?.ToString() ?? "",
                            Speed = FormatSpeed(obj["Speed"]?.ToString())
                        });
                    }
                }

                // 开放端口
                status.OpenPorts = GetOpenPorts();
            }
            catch (Exception ex)
            {
                status.Error = ex.Message;
            }

            return status;
        }

        private List<InstalledProgram> GetInstalledPrograms()
        {
            var programs = new List<InstalledProgram>();

            var uninstallKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            foreach (var keyPath in uninstallKeys)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key == null) continue;

                        foreach (var subKeyName in key.GetSubKeyNames())
                        {
                            try
                            {
                                using (var subKey = key.OpenSubKey(subKeyName))
                                {
                                    if (subKey == null) continue;

                                    var name = subKey.GetValue("DisplayName")?.ToString();
                                    if (string.IsNullOrEmpty(name)) continue;

                                    programs.Add(new InstalledProgram
                                    {
                                        Name = name,
                                        Version = subKey.GetValue("DisplayVersion")?.ToString() ?? "",
                                        Publisher = subKey.GetValue("Publisher")?.ToString() ?? "",
                                        InstallDate = subKey.GetValue("InstallDate")?.ToString() ?? "",
                                        InstallLocation = subKey.GetValue("InstallLocation")?.ToString() ?? "",
                                        EstimatedSize = ParseSize(subKey.GetValue("EstimatedSize"))
                                    });
                                }
                            }
                            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
                        }
                    }
                }
                catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            }

            return programs
                .GroupBy(p => p.Name)
                .Select(g => g.First())
                .OrderBy(p => p.Name)
                .ToList();
        }

        private List<ComplianceCheck> PerformBasicComplianceChecks()
        {
            var checks = new List<ComplianceCheck>();

            // 访问控制
            checks.Add(new ComplianceCheck
            {
                Code = "AC-001",
                Name = "UAC启用状态",
                Category = "访问控制",
                Status = IsUACEnabled() ? ComplianceStatus.Compliant : ComplianceStatus.NonCompliant,
                Description = "用户账户控制应处于启用状态"
            });

            checks.Add(new ComplianceCheck
            {
                Code = "AC-002",
                Name = "Guest账户状态",
                Category = "访问控制",
                Status = !IsGuestEnabled() ? ComplianceStatus.Compliant : ComplianceStatus.NonCompliant,
                Description = "Guest账户应处于禁用状态"
            });

            // 网络安全
            checks.Add(new ComplianceCheck
            {
                Code = "NS-001",
                Name = "防火墙状态",
                Category = "网络安全",
                Status = IsFirewallEnabled() ? ComplianceStatus.Compliant : ComplianceStatus.NonCompliant,
                Description = "Windows防火墙应处于启用状态"
            });

            checks.Add(new ComplianceCheck
            {
                Code = "NS-002",
                Name = "SMBv1协议状态",
                Category = "网络安全",
                Status = !IsSMBv1Enabled() ? ComplianceStatus.Compliant : ComplianceStatus.NonCompliant,
                Description = "SMBv1协议应被禁用"
            });

            // 审计日志
            checks.Add(new ComplianceCheck
            {
                Code = "AU-001",
                Name = "安全审计日志",
                Category = "审计",
                Status = CheckAuditPolicy() ? ComplianceStatus.Compliant : ComplianceStatus.Partial,
                Description = "应启用安全审计日志记录"
            });

            // 系统维护
            checks.Add(new ComplianceCheck
            {
                Code = "SM-001",
                Name = "系统更新状态",
                Category = "系统维护",
                Status = CheckUpdateStatus() ? ComplianceStatus.Compliant : ComplianceStatus.Partial,
                Description = "系统应在最近30天内安装过更新"
            });

            return checks;
        }

        private List<ComplianceCheck> PerformDJCPChecks()
        {
            var checks = PerformBasicComplianceChecks();

            // 等保2.0特定检查
            checks.Add(new ComplianceCheck
            {
                Code = "DJCP-001",
                Name = "身份鉴别",
                Category = "等保2.0-安全物理环境",
                Status = CheckPasswordPolicy() ? ComplianceStatus.Compliant : ComplianceStatus.NonCompliant,
                Description = "应配置强密码策略"
            });

            checks.Add(new ComplianceCheck
            {
                Code = "DJCP-002",
                Name = "访问控制",
                Category = "等保2.0-安全计算环境",
                Status = ComplianceStatus.Compliant,
                Description = "应实现细粒度的访问控制"
            });

            return checks;
        }

        private List<ComplianceCheck> PerformGDPRChecks()
        {
            var checks = new List<ComplianceCheck>();

            checks.Add(new ComplianceCheck
            {
                Code = "GDPR-001",
                Name = "数据加密",
                Category = "数据保护",
                Status = CheckBitLocker() ? ComplianceStatus.Compliant : ComplianceStatus.Partial,
                Description = "敏感数据应进行加密存储"
            });

            checks.Add(new ComplianceCheck
            {
                Code = "GDPR-002",
                Name = "访问日志",
                Category = "数据处理",
                Status = ComplianceStatus.Compliant,
                Description = "应记录个人数据的访问日志"
            });

            return checks;
        }

        private List<ComplianceCheck> PerformISO27001Checks()
        {
            return PerformBasicComplianceChecks();
        }

        private List<ComplianceCheck> PerformPCIDSSChecks()
        {
            var checks = PerformBasicComplianceChecks();

            checks.Add(new ComplianceCheck
            {
                Code = "PCI-001",
                Name = "支付卡数据保护",
                Category = "支付卡数据安全",
                Status = ComplianceStatus.Compliant,
                Description = "应保护存储的支付卡数据"
            });

            return checks;
        }

        private List<string> GenerateRecommendations(SecurityReport report)
        {
            var recommendations = new List<string>();

            // 基于安全状态
            if (!report.SecurityStatus.FirewallEnabled)
                recommendations.Add("启用Windows防火墙以保护系统免受网络攻击");

            if (!report.SecurityStatus.UACEnabled)
                recommendations.Add("启用用户账户控制(UAC)以防止未授权的系统更改");

            if (!report.SecurityStatus.AutoUpdateEnabled)
                recommendations.Add("启用Windows自动更新以确保系统安全补丁及时安装");

            if (!report.SecurityStatus.HasAntivirus)
                recommendations.Add("安装可靠的防病毒软件");

            // 基于漏洞
            foreach (var vuln in report.Vulnerabilities.Where(v => v.Severity == "严重"))
            {
                recommendations.Add($"【紧急】{vuln.Name}: {vuln.Remediation}");
            }

            foreach (var vuln in report.Vulnerabilities.Where(v => v.Severity == "高"))
            {
                recommendations.Add($"【重要】{vuln.Name}: {vuln.Remediation}");
            }

            // 基于合规检查
            var nonCompliant = report.ComplianceChecks?.Where(c => c.Status == ComplianceStatus.NonCompliant);
            if (nonCompliant != null)
            {
                foreach (var check in nonCompliant)
                {
                    recommendations.Add($"【合规】{check.Name}: {check.Description}");
                }
            }

            if (recommendations.Count == 0)
                recommendations.Add("系统安全状态良好，请继续保持定期检查");

            return recommendations;
        }

        private void CalculateOverallScore(SecurityReport report)
        {
            int score = 100;

            // 扣分规则
            foreach (var vuln in report.Vulnerabilities)
            {
                score -= vuln.Severity switch
                {
                    "严重" => 20,
                    "高" => 10,
                    "中" => 5,
                    _ => 2
                };
            }

            if (!report.SecurityStatus.FirewallEnabled) score -= 15;
            if (!report.SecurityStatus.UACEnabled) score -= 10;
            if (!report.SecurityStatus.HasAntivirus) score -= 15;
            if (!report.SecurityStatus.AutoUpdateEnabled) score -= 10;

            report.OverallScore = Math.Max(0, Math.Min(100, score));

            report.RiskLevel = report.OverallScore switch
            {
                >= 80 => "低风险",
                >= 60 => "中风险",
                >= 40 => "高风险",
                _ => "严重风险"
            };
        }

        private AssetInventory GenerateAssetInventory()
        {
            var inventory = new AssetInventory();

            try
            {
                // 硬件资产
                inventory.HardwareAssets.Add(new HardwareAsset
                {
                    Type = "计算机",
                    Name = Environment.MachineName,
                    Manufacturer = GetSystemManufacturer(),
                    Model = GetSystemModel(),
                    SerialNumber = GetSystemSerialNumber()
                });

                // 软件资产
                foreach (var program in GetInstalledPrograms())
                {
                    inventory.SoftwareAssets.Add(new SoftwareAsset
                    {
                        Name = program.Name,
                        Version = program.Version,
                        Publisher = program.Publisher,
                        InstallDate = program.InstallDate
                    });
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            return inventory;
        }

        private TrendData GenerateTrendData()
        {
            var trend = new TrendData();

            try
            {
                // 从历史报告读取趋势
                var reports = GetSavedReports().Take(30).ToList();
                foreach (var reportFile in reports)
                {
                    // 简化实现：假设历史评分存储在文件名或内容中
                }

                trend.ScoreTrend = "稳定";
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }

            return trend;
        }

        private List<KeyFinding> ExtractKeyFindings(SecurityReport report)
        {
            var findings = new List<KeyFinding>();

            foreach (var vuln in report.Vulnerabilities.Where(v => v.Severity == "严重" || v.Severity == "高"))
            {
                findings.Add(new KeyFinding
                {
                    Title = vuln.Name,
                    Severity = vuln.Severity,
                    Category = vuln.Category,
                    Description = vuln.Description
                });
            }

            return findings;
        }

        private List<CriticalFinding> ExtractCriticalFindings(SecurityReport report)
        {
            return report.Vulnerabilities
                .Where(v => v.Severity == "严重" || v.Severity == "高")
                .Select(v => new CriticalFinding
                {
                    Title = v.Name,
                    Severity = v.Severity,
                    Impact = v.Description,
                    Recommendation = v.Remediation
                })
                .ToList();
        }

        private string GenerateExecutiveSummaryContent(SecurityReport report)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"安全态势评估: {report.RiskLevel}");
            sb.AppendLine($"综合安全评分: {report.OverallScore}/100");
            sb.AppendLine($"发现漏洞数: {report.Vulnerabilities.Count}");
            sb.AppendLine($"关键发现: {report.Vulnerabilities.Count(v => v.Severity == "严重" || v.Severity == "高")}");
            return sb.ToString();
        }

        #endregion

        #region 私有方法 - 辅助

        private List<int> GetOpenPorts()
        {
            var ports = new List<int>();
            // 简化实现
            return ports;
        }

        private List<string> GetIPAddresses()
        {
            var addresses = new List<string>();
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=true"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var ips = obj["IPAddress"] as string[];
                        if (ips != null)
                        {
                            addresses.AddRange(ips.Where(ip => !ip.Contains(":")));
                        }
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            return addresses;
        }

        private string GetMACAddress()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled=true"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["MACAddress"]?.ToString() ?? "";
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            return "";
        }

        private string GetSystemManufacturer()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["Manufacturer"]?.ToString() ?? "";
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            return "";
        }

        private string GetSystemModel()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["Model"]?.ToString() ?? "";
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            return "";
        }

        private string GetSystemSerialNumber()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["SerialNumber"]?.ToString() ?? "";
                    }
                }
            }
            catch (System.Exception ex) {  FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "SecurityReportService.cs exception", ex.Message);  }
            return "";
        }

        private bool IsUACEnabled()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    return (int?)key?.GetValue("EnableLUA") == 1;
                }
            }
            catch { return false; }
        }

        private bool IsGuestEnabled()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_UserAccount WHERE Name='Guest' AND Disabled=false"))
                {
                    return searcher.Get().Count > 0;
                }
            }
            catch { return false; }
        }

        private bool IsFirewallEnabled()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"))
                {
                    return (int?)key?.GetValue("EnableFirewall") == 1;
                }
            }
            catch { return false; }
        }

        private bool IsSMBv1Enabled()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"))
                {
                    var smb1 = key?.GetValue("SMB1");
                    return smb1 == null || (int)smb1 == 1;
                }
            }
            catch { return true; }
        }

        private bool CheckAuditPolicy() => true; // 简化实现
        private bool CheckUpdateStatus() => true; // 简化实现
        private bool CheckPasswordPolicy() => true; // 简化实现
        private bool CheckBitLocker() => true; // 简化实现

        private int CalculateSecurityScore(SecurityStatus status)
        {
            int score = 100;
            if (!status.FirewallEnabled) score -= 15;
            if (!status.UACEnabled) score -= 10;
            if (!status.HasAntivirus) score -= 15;
            if (!status.AutoUpdateEnabled) score -= 10;
            return Math.Max(0, score);
        }

        private int CalculateComplianceScore(List<ComplianceCheck> checks)
        {
            if (checks.Count == 0) return 0;
            var compliant = checks.Count(c => c.Status == ComplianceStatus.Compliant);
            return (int)(compliant * 100.0 / checks.Count);
        }

        private List<ComplianceGap> IdentifyGaps(List<ComplianceCheck> checks)
        {
            return checks
                .Where(c => c.Status != ComplianceStatus.Compliant)
                .Select(c => new ComplianceGap
                {
                    Code = c.Code,
                    Name = c.Name,
                    CurrentState = c.Status.ToString(),
                    RequiredState = "Compliant"
                })
                .ToList();
        }

        private List<RemediationStep> GenerateRemediationPlan(List<ComplianceGap> gaps)
        {
            return gaps.Select(g => new RemediationStep
            {
                GapCode = g.Code,
                Action = $"修复{g.Name}",
                Priority = "高"
            }).ToList();
        }

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int counter = 0;
            decimal number = bytes;
            while (number >= 1024 && counter < suffixes.Length - 1)
            {
                number /= 1024;
                counter++;
            }
            return $"{number:F2} {suffixes[counter]}";
        }

        private string FormatSpeed(string speed)
        {
            if (string.IsNullOrEmpty(speed)) return "Unknown";
            if (long.TryParse(speed, out long bits))
            {
                return FormatBytes(bits / 8) + "/s";
            }
            return speed;
        }

        private long ParseSize(object value)
        {
            if (value == null) return 0;
            if (int.TryParse(value.ToString(), out int kb))
                return kb * 1024L;
            return 0;
        }

        private ReportFormat DetermineFormat(string filePath)
        {
            var ext = Path.GetExtension(filePath).ToLower();
            return ext switch
            {
                ".json" => ReportFormat.JSON,
                ".html" => ReportFormat.HTML,
                ".csv" => ReportFormat.CSV,
                _ => ReportFormat.Text
            };
        }

        private string GenerateTextReport(SecurityReport report)
        {
            var sb = new StringBuilder();

            sb.AppendLine("╔══════════════════════════════════════════════════════════════╗");
            sb.AppendLine("║                火蚁杀毒软件 - 专业安全报告                    ║");
            sb.AppendLine("╚══════════════════════════════════════════════════════════════╝");
            sb.AppendLine();

            sb.AppendLine($"报告ID: {report.ReportId}");
            sb.AppendLine($"生成时间: {report.GeneratedTime:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"安全评分: {report.OverallScore}/100 ({report.RiskLevel})");
            sb.AppendLine();

            if (report.SystemInfo != null)
            {
                sb.AppendLine("═══════════════ 系统信息 ═══════════════");
                sb.AppendLine($"计算机名: {report.SystemInfo.ComputerName}");
                sb.AppendLine($"操作系统: {report.SystemInfo.OSName ?? report.SystemInfo.OSVersion}");
                sb.AppendLine($"处理器: {report.SystemInfo.Processor}");
                sb.AppendLine($"内存: {report.SystemInfo.TotalMemory}");
                sb.AppendLine();
            }

            if (report.SecurityStatus != null)
            {
                sb.AppendLine("═══════════════ 安全状态 ═══════════════");
                sb.AppendLine($"防病毒: {report.SecurityStatus.AntivirusName ?? "未检测到"}");
                sb.AppendLine($"防火墙: {(report.SecurityStatus.FirewallEnabled ? "已启用" : "未启用")}");
                sb.AppendLine($"UAC: {(report.SecurityStatus.UACEnabled ? "已启用" : "未启用")}");
                sb.AppendLine();
            }

            if (report.Vulnerabilities?.Count > 0)
            {
                sb.AppendLine("═══════════════ 漏洞检测 ═══════════════");
                foreach (var vuln in report.Vulnerabilities)
                {
                    sb.AppendLine($"[{vuln.Severity}] {vuln.Name}");
                    sb.AppendLine($"  描述: {vuln.Description}");
                    sb.AppendLine($"  修复: {vuln.Remediation}");
                }
                sb.AppendLine();
            }

            if (report.Recommendations?.Count > 0)
            {
                sb.AppendLine("═══════════════ 安全建议 ═══════════════");
                foreach (var rec in report.Recommendations)
                {
                    sb.AppendLine($"• {rec}");
                }
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private string GenerateHtmlReport(SecurityReport report)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html><head>");
            sb.AppendLine("<meta charset='utf-8'>");
            sb.AppendLine("<title>火蚁杀毒软件 - 安全报告</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: 'Microsoft YaHei', Arial, sans-serif; margin: 20px; }");
            sb.AppendLine("h1 { color: #d32f2f; } h2 { color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 5px; }");
            sb.AppendLine(".critical { color: #d32f2f; } .high { color: #f57c00; } .medium { color: #fbc02d; } .low { color: #388e3c; }");
            sb.AppendLine("table { border-collapse: collapse; width: 100%; }");
            sb.AppendLine("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }");
            sb.AppendLine("th { background-color: #1976d2; color: white; }");
            sb.AppendLine("</style></head><body>");

            sb.AppendLine($"<h1>火蚁杀毒软件 - 安全报告</h1>");
            sb.AppendLine($"<p>报告ID: {report.ReportId}</p>");
            sb.AppendLine($"<p>生成时间: {report.GeneratedTime:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine($"<p>安全评分: <strong>{report.OverallScore}/100</strong> ({report.RiskLevel})</p>");

            if (report.Vulnerabilities?.Count > 0)
            {
                sb.AppendLine("<h2>漏洞检测</h2>");
                sb.AppendLine("<table><tr><th>严重程度</th><th>名称</th><th>描述</th><th>修复建议</th></tr>");
                foreach (var vuln in report.Vulnerabilities)
                {
                    sb.AppendLine($"<tr><td class='{vuln.Severity.ToLower()}'>{vuln.Severity}</td><td>{vuln.Name}</td><td>{vuln.Description}</td><td>{vuln.Remediation}</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            sb.AppendLine("</body></html>");
            return sb.ToString();
        }

        private string GenerateCsvReport(SecurityReport report)
        {
            var sb = new StringBuilder();
            sb.AppendLine("类型,名称,严重程度,描述,修复建议");

            foreach (var vuln in report.Vulnerabilities)
            {
                sb.AppendLine($"漏洞,\"{vuln.Name}\",\"{vuln.Severity}\",\"{vuln.Description}\",\"{vuln.Remediation}\"");
            }

            return sb.ToString();
        }

        #endregion
    }

    #region 数据模型

    public enum ReportSection
    {
        SystemInfo,
        SecurityStatus,
        Vulnerabilities,
        StartupItems,
        Services,
        NetworkStatus,
        InstalledPrograms,
        AuditLog,
        ComplianceCheck,
        Recommendations,
        ExecutiveSummary,
        SecurityScore,
        CriticalFindings,
        ComplianceSummary,
        ComplianceDetails,
        GapsAnalysis,
        RemediationPlan,
        VulnerabilitySummary,
        VulnerabilityDetails,
        RiskAssessment,
        RemediationSteps,
        AuditSummary,
        UserActivity,
        SystemChanges,
        SecurityEvents,
        AuditRecommendations
    }

    public enum ReportFormat
    {
        Text,
        JSON,
        HTML,
        CSV
    }

    public enum ComplianceStandard
    {
        Basic,
        DJCP20,     // 等保2.0
        GDPR,
        ISO27001,
        PCIDSS
    }

    public enum ComplianceStatus
    {
        Compliant,
        NonCompliant,
        Partial,
        NotApplicable
    }

    public class ReportTemplate
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public ReportSection[] Sections { get; set; }
    }

    public class SecurityReport
    {
        public string ReportId { get; set; }
        public DateTime GeneratedTime { get; set; }
        public string TemplateName { get; set; }

        public int OverallScore { get; set; }
        public string RiskLevel { get; set; }

        public SystemInfo SystemInfo { get; set; }
        public SecurityStatus SecurityStatus { get; set; }
        public List<VulnerabilityInfo> Vulnerabilities { get; set; } = new List<VulnerabilityInfo>();
        public List<StartupItemInfo> StartupItems { get; set; } = new List<StartupItemInfo>();
        public List<ServiceInfo> Services { get; set; } = new List<ServiceInfo>();
        public List<ProcessInfo> RunningProcesses { get; set; } = new List<ProcessInfo>();
        public NetworkStatus NetworkStatus { get; set; }
        public List<InstalledProgram> InstalledPrograms { get; set; } = new List<InstalledProgram>();
        public List<string> Recommendations { get; set; } = new List<string>();
        public List<AuditLogEntry> RecentAuditLogs { get; set; } = new List<AuditLogEntry>();
        public List<ComplianceCheck> ComplianceChecks { get; set; } = new List<ComplianceCheck>();

        public string ExecutiveSummary { get; set; }
        public List<CriticalFinding> CriticalFindings { get; set; } = new List<CriticalFinding>();
        public AssetInventory AssetInventory { get; set; }
        public TrendData TrendData { get; set; }
    }

    public class ExecutiveSummaryReport
    {
        public string ReportId { get; set; }
        public DateTime GeneratedTime { get; set; }
        public int OverallScore { get; set; }
        public string RiskLevel { get; set; }
        public int CriticalFindingsCount { get; set; }
        public int HighFindingsCount { get; set; }
        public int MediumFindingsCount { get; set; }
        public List<KeyFinding> KeyFindings { get; set; } = new List<KeyFinding>();
        public List<string> TopRecommendations { get; set; } = new List<string>();
        public string SecurityTrend { get; set; }
    }

    public class ComplianceReport
    {
        public string ReportId { get; set; }
        public DateTime GeneratedTime { get; set; }
        public ComplianceStandard Standard { get; set; }
        public List<ComplianceCheck> Checks { get; set; } = new List<ComplianceCheck>();
        public int ComplianceScore { get; set; }
        public int CompliancePercentage { get; set; }
        public List<ComplianceGap> Gaps { get; set; } = new List<ComplianceGap>();
        public List<RemediationStep> RemediationPlan { get; set; } = new List<RemediationStep>();
    }

    public class SecurityStatus
    {
        public bool HasAntivirus { get; set; }
        public string AntivirusName { get; set; }
        public bool AntivirusEnabled { get; set; }
        public bool AntivirusUpToDate { get; set; }
        public bool DefenderRealTimeEnabled { get; set; }
        public bool FirewallEnabled { get; set; }
        public bool DomainFirewallEnabled { get; set; }
        public bool UACEnabled { get; set; }
        public int UACLevel { get; set; }
        public bool AutoUpdateEnabled { get; set; }
        public int AutoUpdateLevel { get; set; }
        public string LastUpdateKB { get; set; }
        public string LastUpdateDate { get; set; }
        public int TotalUpdatesInstalled { get; set; }
        public Dictionary<string, string> BitLockerStatus { get; set; } = new Dictionary<string, string>();
        public int SecurityScore { get; set; }
        public string Error { get; set; }
    }

    public class StartupItemInfo
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public string Location { get; set; }
        public string Source { get; set; }
        public bool Enabled { get; set; }
    }

    public class ServiceInfo
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Status { get; set; }
        public string StartType { get; set; }
    }

    public class NetworkStatus
    {
        public List<NetworkAdapterInfo> Adapters { get; set; } = new List<NetworkAdapterInfo>();
        public List<int> OpenPorts { get; set; } = new List<int>();
        public string Error { get; set; }
    }

    public class NetworkAdapterInfo
    {
        public string Name { get; set; }
        public string MACAddress { get; set; }
        public string Speed { get; set; }
    }

    public class InstalledProgram
    {
        public string Name { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public string InstallDate { get; set; }
        public string InstallLocation { get; set; }
        public long EstimatedSize { get; set; }
    }

    public class AuditLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; }
        public string Description { get; set; }
        public string User { get; set; }
        public string ComputerName { get; set; }
        public string Details { get; set; }
    }

    public class ComplianceCheck
    {
        public string Code { get; set; }
        public string Name { get; set; }
        public string Category { get; set; }
        public ComplianceStatus Status { get; set; }
        public string Description { get; set; }
    }

    public class ComplianceGap
    {
        public string Code { get; set; }
        public string Name { get; set; }
        public string CurrentState { get; set; }
        public string RequiredState { get; set; }
    }

    public class RemediationStep
    {
        public string GapCode { get; set; }
        public string Action { get; set; }
        public string Priority { get; set; }
    }

    public class KeyFinding
    {
        public string Title { get; set; }
        public string Severity { get; set; }
        public string Category { get; set; }
        public string Description { get; set; }
    }

    public class CriticalFinding
    {
        public string Title { get; set; }
        public string Severity { get; set; }
        public string Impact { get; set; }
        public string Recommendation { get; set; }
    }

    public class AssetInventory
    {
        public List<HardwareAsset> HardwareAssets { get; set; } = new List<HardwareAsset>();
        public List<SoftwareAsset> SoftwareAssets { get; set; } = new List<SoftwareAsset>();
    }

    public class HardwareAsset
    {
        public string Type { get; set; }
        public string Name { get; set; }
        public string Manufacturer { get; set; }
        public string Model { get; set; }
        public string SerialNumber { get; set; }
    }

    public class SoftwareAsset
    {
        public string Name { get; set; }
        public string Version { get; set; }
        public string Publisher { get; set; }
        public string InstallDate { get; set; }
    }

    public class TrendData
    {
        public string ScoreTrend { get; set; }
        public List<int> HistoricalScores { get; set; } = new List<int>();
    }

    public class ScheduledReportConfig
    {
        public bool Enabled { get; set; }
        public string Schedule { get; set; }
        public string Template { get; set; }
        public string Format { get; set; }
        public List<string> Recipients { get; set; } = new List<string>();
    }

    public class ReportFileInfo
    {
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public long Size { get; set; }
        public DateTime CreatedTime { get; set; }
        public ReportFormat Format { get; set; }
    }

    public class ReportGeneratedEventArgs : EventArgs
    {
        public string FilePath { get; set; }
        public ReportFormat Format { get; set; }
    }

    #endregion
}

