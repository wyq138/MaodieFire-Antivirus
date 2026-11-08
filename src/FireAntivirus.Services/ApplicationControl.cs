using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Threading;

namespace FireAntivirus.Services
{
    public class ApplicationControl
    {
        private string _rulesFilePath;
        private List<ApplicationRule> _rules;
        private bool _enabled;
        private object _rulesLock = new object();

        public event EventHandler<ApplicationControlEventArgs> ApplicationControlEvent;

        public ApplicationControl(string rulesFilePath = null)
        {
            _rulesFilePath = rulesFilePath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Rules", "application_rules.json");
            _rules = new List<ApplicationRule>();
            _enabled = true;

            InitializeRules();
        }

        private void InitializeRules()
        {
            try
            {
                var directory = Path.GetDirectoryName(_rulesFilePath);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                if (File.Exists(_rulesFilePath))
                {
                    var content = File.ReadAllText(_rulesFilePath);
                    _rules = Newtonsoft.Json.JsonConvert.DeserializeObject<List<ApplicationRule>>(content) ?? new List<ApplicationRule>();
                }
                else
                {
                    // 创建默认规则
                    _rules = new List<ApplicationRule>
                    {
                        new ApplicationRule
                        {
                            Id = Guid.NewGuid().ToString(),
                            ApplicationPath = "C:\\Windows\\System32\\*.exe",
                            Action = ApplicationAction.Allow,
                            Description = "Allow Windows system files",
                            Priority = 100,
                            CreatedDate = DateTime.Now
                        },
                        new ApplicationRule
                        {
                            Id = Guid.NewGuid().ToString(),
                            ApplicationPath = "C:\\Program Files\\*",
                            Action = ApplicationAction.Allow,
                            Description = "Allow Program Files applications",
                            Priority = 90,
                            CreatedDate = DateTime.Now
                        },
                        new ApplicationRule
                        {
                            Id = Guid.NewGuid().ToString(),
                            ApplicationPath = "C:\\Program Files (x86)\\*",
                            Action = ApplicationAction.Allow,
                            Description = "Allow Program Files (x86) applications",
                            Priority = 80,
                            CreatedDate = DateTime.Now
                        }
                    };
                    SaveRules();
                }
            }
            catch (Exception ex)
            {
                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Failed to initialize application rules: " + ex.Message));
                _rules = new List<ApplicationRule>();
            }
        }

        public void StartMonitoring()
        {
            try
            {
                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, "Starting application control monitoring..."));

                // 启动进程监控
                Task.Run(() => MonitorProcesses());

                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, "Application control monitoring started successfully."));
            }
            catch (Exception ex)
            {
                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Failed to start application control monitoring: " + ex.Message));
            }
        }

        private async Task MonitorProcesses()
        {
            while (_enabled)
            {
                try
                {
                    // 获取当前运行的进程
                    var processes = Process.GetProcesses();
                    foreach (var process in processes)
                    {
                        try
                        {
                            if (!string.IsNullOrEmpty(process.MainModule?.FileName))
                            {
                                var filePath = process.MainModule.FileName;
                                var rule = GetMatchingRule(filePath);
                                if (rule != null && rule.Action == ApplicationAction.Block)
                                {
                                    // 阻止进程
                                    BlockProcess(process, rule);
                                }
                            }
                        }
                        catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ApplicationControl.cs 捕获异常", ex.Message); }
                    }
                }
                catch (Exception ex)
                {
                    RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Process monitoring failed: " + ex.Message));
                }

                await Task.Delay(1000);
            }
        }

        private ApplicationRule GetMatchingRule(string filePath)
        {
            lock (_rulesLock)
            {
                // 按优先级排序，高优先级优先
                return _rules.OrderByDescending(r => r.Priority)
                    .FirstOrDefault(r => FilePathMatchesPattern(filePath, r.ApplicationPath));
            }
        }

        private bool FilePathMatchesPattern(string filePath, string pattern)
        {
            try
            {
                // 简单的路径匹配
                if (pattern.Contains("*"))
                {
                    // 替换通配符为正则表达式
                    var regexPattern = pattern.Replace("\\", "\\\\").Replace("*", ".*");
                    return System.Text.RegularExpressions.Regex.IsMatch(filePath, regexPattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                }
                else
                {
                    return string.Equals(filePath, pattern, StringComparison.OrdinalIgnoreCase);
                }
            }
            catch
            {
                return false;
            }
        }

        private void BlockProcess(Process process, ApplicationRule rule)
        {
            try
            {
                // 记录阻止事件
                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Block, $"Blocked process: {process.ProcessName} ({process.MainModule.FileName}) based on rule: {rule.Description}"));

                // 终止进程（受保护进程跳过）
                if (!FireAntivirus.Common.TrustedProcessGuard.CanTerminate(process))
                {
                    RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, $"Process is protected, skipped termination: {process.ProcessName}"));
                    return;
                }
                process.Kill();
                process.WaitForExit();

                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, $"Successfully blocked process: {process.ProcessName}"));
            }
            catch (Exception ex)
            {
                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Failed to block process: " + ex.Message));
            }
        }

        public void AddRule(ApplicationRule rule)
        {
            lock (_rulesLock)
            {
                try
                {
                    rule.Id = Guid.NewGuid().ToString();
                    rule.CreatedDate = DateTime.Now;
                    _rules.Add(rule);
                    SaveRules();

                    // 真实阻止：Block 规则写入 IFEO（Image File Execution Options），
                    // 系统启动该应用时因 Debugger 指向不存在程序而无法运行。
                    // 此前规则只存储、BlockProcess 零调用 = 应用控制零消费（假功能）。
                    if (rule.Action == ApplicationAction.Block)
                        ApplyIfeoBlock(rule.ApplicationPath, true);

                    RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, "Application rule added: " + rule.Description));
                }
                catch (Exception ex)
                {
                    RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Failed to add application rule: " + ex.Message));
                }
            }
        }

        /// <summary>真实应用启动阻止/恢复：HKLM IFEO Debugger 键（Windows 标准机制）。</summary>
        private void ApplyIfeoBlock(string applicationPath, bool block)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(applicationPath)) return;
                string exeName = System.IO.Path.GetFileName(applicationPath.Trim());
                if (string.IsNullOrWhiteSpace(exeName)) return;

                string ifeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" + exeName;
                if (block)
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(ifeoPath);
                    if (key == null) return;
                    // Debugger 指向不存在的路径：应用一启动即失败，达到阻止效果
                    key.SetValue("Debugger", @"C:\Windows\System32\FireAntivirusBlocked\blocked.exe",
                        Microsoft.Win32.RegistryValueKind.String);
                }
                else
                {
                    Microsoft.Win32.Registry.LocalMachine.DeleteSubKeyTree(ifeoPath, false);
                }

                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"应用控制 IFEO 已{(block ? "写入（真实阻止启动）" : "移除（恢复启动）")}: {exeName}");
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                    $"应用控制 IFEO 写入失败（需管理员权限）: {ex.Message}");
            }
        }

        public void UpdateRule(ApplicationRule rule)
        {
            lock (_rulesLock)
            {
                try
                {
                    var existingRule = _rules.FirstOrDefault(r => r.Id == rule.Id);
                    if (existingRule != null)
                    {
                        existingRule.ApplicationPath = rule.ApplicationPath;
                        existingRule.Action = rule.Action;
                        existingRule.Description = rule.Description;
                        existingRule.Priority = rule.Priority;
                        existingRule.LastModifiedDate = DateTime.Now;
                        SaveRules();

                        // IFEO 同步：动作变更时解除旧阻止、应用新阻止（防残留锁定）
                        ApplyIfeoBlock(existingRule.ApplicationPath, rule.Action == ApplicationAction.Block);
                        RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, "Application rule updated: " + rule.Description));
                    }
                    else
                    {
                        RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Application rule not found: " + rule.Id));
                    }
                }
                catch (Exception ex)
                {
                    RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Failed to update application rule: " + ex.Message));
                }
            }
        }

        public void DeleteRule(string ruleId)
        {
            lock (_rulesLock)
            {
                try
                {
                    var rule = _rules.FirstOrDefault(r => r.Id == ruleId);
                    if (rule != null)
                    {
                        _rules.Remove(rule);
                        SaveRules();

                        // 解除真实阻止（删除规则后 IFEO 必须同步移除，否则应用永久无法启动）
                        if (rule.Action == ApplicationAction.Block)
                            ApplyIfeoBlock(rule.ApplicationPath, false);

                        RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, "Application rule deleted: " + rule.Description));
                    }
                    else
                    {
                        RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Application rule not found: " + ruleId));
                    }
                }
                catch (Exception ex)
                {
                    RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Failed to delete application rule: " + ex.Message));
                }
            }
        }

        public List<ApplicationRule> GetRules()
        {
            lock (_rulesLock)
            {
                return new List<ApplicationRule>(_rules);
            }
        }

        public ApplicationRule GetRule(string ruleId)
        {
            lock (_rulesLock)
            {
                return _rules.FirstOrDefault(r => r.Id == ruleId);
            }
        }

        public ApplicationAction GetApplicationAction(string filePath)
        {
            var rule = GetMatchingRule(filePath);
            return rule?.Action ?? ApplicationAction.Default;
        }

        public bool IsApplicationAllowed(string filePath)
        {
            var action = GetApplicationAction(filePath);
            return action == ApplicationAction.Allow || action == ApplicationAction.Default;
        }

        public bool IsApplicationBlocked(string filePath)
        {
            var action = GetApplicationAction(filePath);
            return action == ApplicationAction.Block;
        }

        private void SaveRules()
        {
            try
            {
                var content = Newtonsoft.Json.JsonConvert.SerializeObject(_rules, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(_rulesFilePath, content);
            }
            catch (Exception ex)
            {
                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Failed to save application rules: " + ex.Message));
            }
        }

        public void ImportRules(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var content = File.ReadAllText(filePath);
                    var importedRules = Newtonsoft.Json.JsonConvert.DeserializeObject<List<ApplicationRule>>(content) ?? new List<ApplicationRule>();
                    
                    lock (_rulesLock)
                    {
                        _rules.AddRange(importedRules);
                        SaveRules();
                    }
                    
                    RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, $"Imported {importedRules.Count} application rules"));
                }
                else
                {
                    RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Import file not found: " + filePath));
                }
            }
            catch (Exception ex)
            {
                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Failed to import application rules: " + ex.Message));
            }
        }

        public void ExportRules(string filePath)
        {
            try
            {
                var content = Newtonsoft.Json.JsonConvert.SerializeObject(_rules, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(filePath, content);
                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, "Exported application rules to: " + filePath));
            }
            catch (Exception ex)
            {
                RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Error, "Failed to export application rules: " + ex.Message));
            }
        }

        public void Enable()
        {
            _enabled = true;
            StartMonitoring();
            RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, "Application control enabled"));
        }

        public void Disable()
        {
            _enabled = false;
            RaiseApplicationControlEvent(new ApplicationControlEventArgs(ApplicationControlEventType.Info, "Application control disabled"));
        }

        public bool IsEnabled()
        {
            return _enabled;
        }

        private void RaiseApplicationControlEvent(ApplicationControlEventArgs e)
        {
            ApplicationControlEvent?.Invoke(this, e);
        }
    }

    public class ApplicationRule
    {
        public string Id { get; set; }
        public string ApplicationPath { get; set; }
        public ApplicationAction Action { get; set; }
        public string Description { get; set; }
        public int Priority { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime? LastModifiedDate { get; set; }
        public List<string> Tags { get; set; } = new List<string>();
    }

    public enum ApplicationAction
    {
        Default,
        Allow,
        Block
    }

    public class ApplicationControlEventArgs : EventArgs
    {
        public ApplicationControlEventType EventType { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }

        public ApplicationControlEventArgs(ApplicationControlEventType eventType, string message)
        {
            EventType = eventType;
            Message = message;
            Timestamp = DateTime.Now;
        }
    }

    public enum ApplicationControlEventType
    {
        Info,
        Warning,
        Error,
        Block,
        Allow,
        RuleAdded,
        RuleUpdated,
        RuleDeleted
    }
}