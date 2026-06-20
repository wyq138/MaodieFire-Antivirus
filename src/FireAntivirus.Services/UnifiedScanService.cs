using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.ClamAV;

namespace FireAntivirus.Services
{
    public class UnifiedScanService : IDisposable
    {
        private DefenderScanService _defenderService;
        private ClamAVManager _clamAVManager;
        private DataManager _dataManager;
        private bool _defenderAvailable;
        private bool _clamAVAvailable;
        private CancellationTokenSource _cts;
        private bool _initialized;
        
        public bool IsScanning { get; private set; }
        public bool DefenderAvailable => _defenderAvailable;
        public bool ClamAVAvailable => _clamAVAvailable;
        public string CurrentEngine { get; private set; }
        
        public event EventHandler<UnifiedScanProgress> OnProgressChanged;
        
        public UnifiedScanService(DataManager dataManager)
        {
            _dataManager = dataManager;
            CurrentEngine = "????...";
            
            // ?????,???
            _ = Task.Run(() => InitializeAsync());
        }
        
        private void InitializeAsync()
        {
            try
            {
                // ?? Defender ???
                _defenderAvailable = CheckDefenderAvailable();
                if (_defenderAvailable)
                {
                    try
                    {
                        _defenderService = new DefenderScanService(_dataManager);
                        _defenderService.OnProgressChanged += (progress) => 
                        {
                            try { OnProgressChanged?.Invoke(this, ConvertProgress(progress, "Windows Defender")); }
                            catch { }
                        };
                    }
                    catch { _defenderAvailable = false; }
                }
                
                // ?? ClamAV ???
                _clamAVAvailable = CheckClamAVAvailable();
                if (_clamAVAvailable)
                {
                    try
                    {
                        _clamAVManager = new ClamAVManager(_dataManager);
                        // UseLocalDirectory removed
                    }
                    catch { _clamAVAvailable = false; }
                }
                
                CurrentEngine = _defenderAvailable ? "Windows Defender" : (_clamAVAvailable ? "ClamAV" : "?????");
                _initialized = true;
            }
            catch (Exception ex)
            {
                CurrentEngine = "?????";
                _dataManager?.LogError("UnifiedScanService ?????: " + ex.Message);
            }
        }
        
        private bool CheckDefenderAvailable()
        {
            try
            {
                string path86 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Defender", "MpCmdRun.exe");
                if (File.Exists(path86)) return true;
                string path64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
                return File.Exists(path64);
            }
            catch { return false; }
        }
        
        private bool CheckClamAVAvailable()
        {
            try
            {
                string baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                string clamscanPath = Path.Combine(baseDir, "clamav", "clamscan.exe");
                return File.Exists(clamscanPath);
            }
            catch { return false; }
        }
        
        public async Task<UnifiedScanResult> QuickScanAsync()
        {
            // ???????
            int waitCount = 0;
            while (!_initialized && waitCount < 50)
            {
                await Task.Delay(100).ConfigureAwait(false);
                waitCount++;
            }
            
            if (!_initialized)
            {
                return new UnifiedScanResult { Success = false, ErrorMessage = "???????" };
            }
            
            return await ScanAsync(ScanType.Quick, null).ConfigureAwait(false);
        }
        
        public async Task<UnifiedScanResult> FullScanAsync()
        {
            int waitCount = 0;
            while (!_initialized && waitCount < 50)
            {
                await Task.Delay(100).ConfigureAwait(false);
                waitCount++;
            }
            
            if (!_initialized)
            {
                return new UnifiedScanResult { Success = false, ErrorMessage = "???????" };
            }
            
            return await ScanAsync(ScanType.Full, null).ConfigureAwait(false);
        }
        
        public async Task<UnifiedScanResult> CustomScanAsync(string path)
        {
            int waitCount = 0;
            while (!_initialized && waitCount < 50)
            {
                await Task.Delay(100).ConfigureAwait(false);
                waitCount++;
            }
            
            if (!_initialized)
            {
                return new UnifiedScanResult { Success = false, ErrorMessage = "???????" };
            }
            
            return await ScanAsync(ScanType.Custom, path).ConfigureAwait(false);
        }
        
        private async Task<UnifiedScanResult> ScanAsync(ScanType scanType, string customPath)
        {
            if (IsScanning)
            {
                return new UnifiedScanResult { Success = false, ErrorMessage = "??????????" };
            }
            
            IsScanning = true;
            var result = new UnifiedScanResult { ScanType = scanType, StartTime = DateTime.Now };
            
            try
            {
                // ??1: Windows Defender
                if (_defenderAvailable)
                {
                    CurrentEngine = "Windows Defender";
                    try
                    {
                        var defenderResult = await ScanWithDefender(scanType, customPath).ConfigureAwait(false);
                        if (defenderResult.Success)
                        {
                            result = defenderResult;
                            result.Engine = "Windows Defender";
                            IsScanning = false;
                            return result;
                        }
                    }
                    catch { }
                }
                
                // ??2: ClamAV
                if (_clamAVAvailable)
                {
                    CurrentEngine = "ClamAV";
                    var clamResult = await ScanWithClamAV(scanType, customPath).ConfigureAwait(false);
                    result = clamResult;
                    result.Engine = "ClamAV";
                }
                else
                {
                    result.Success = false;
                    result.ErrorMessage = "?????????";
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                IsScanning = false;
                result.EndTime = DateTime.Now;
                result.Duration = result.EndTime - result.StartTime;
            }
            
            return result;
        }
        
        private async Task<UnifiedScanResult> ScanWithDefender(ScanType scanType, string customPath)
        {
            try
            {
                DefenderScanResult defenderResult = scanType switch
                {
                    ScanType.Quick => await _defenderService.QuickScanAsync().ConfigureAwait(false),
                    ScanType.Full => await _defenderService.FullScanAsync().ConfigureAwait(false),
                    ScanType.Custom => await _defenderService.CustomScanAsync(customPath).ConfigureAwait(false),
                    _ => await _defenderService.QuickScanAsync().ConfigureAwait(false)
                };
                
                return new UnifiedScanResult
                {
                    Success = defenderResult.Success,
                    ErrorMessage = defenderResult.ErrorMessage,
                    ScanType = scanType,
                    StartTime = defenderResult.StartTime,
                    EndTime = defenderResult.EndTime,
                    Duration = defenderResult.Duration,
                    FilesScanned = 0,
                    ThreatsFound = defenderResult.ThreatsFound,
                    Threats = defenderResult.Threats?.Select(t => new UnifiedThreatInfo { 
                        FilePath = t.Path ?? "", 
                        ThreatName = t.Name ?? "??", 
                        Severity = ConvertSeverity(t.Severity) 
                    }).ToList() ?? new List<UnifiedThreatInfo>(),
                    Engine = "Windows Defender"
                };
            }
            catch (Exception ex)
            {
                return new UnifiedScanResult { Success = false, ErrorMessage = ex.Message, ScanType = scanType };
            }
        }
        
        private async Task<UnifiedScanResult> ScanWithClamAV(ScanType scanType, string customPath)
        {
            var result = new UnifiedScanResult { ScanType = scanType, StartTime = DateTime.Now };
            
            try
            {
                string baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                string clamavDir = Path.Combine(baseDir, "clamav");
                string clamscanPath = Path.Combine(clamavDir, "clamscan.exe");
                string databasePath = Path.Combine(clamavDir, "database");
                
                if (!File.Exists(clamscanPath))
                {
                    result.Success = false;
                    result.ErrorMessage = "ClamAV ???????";
                    return result;
                }
                
                string scanPath = scanType switch
                {
                    ScanType.Quick => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ScanType.Full => Path.GetPathRoot(Environment.SystemDirectory),
                    ScanType.Custom => customPath,
                    _ => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
                };
                
                var processInfo = new ProcessStartInfo
                {
                    FileName = clamscanPath,
                    Arguments = "--database=\"" + databasePath + "\" --recursive --infected --no-summary \"" + scanPath + "\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = clamavDir
                };
                
                var threats = new List<UnifiedThreatInfo>();
                int filesScanned = 0;
                
                using (var process = new Process { StartInfo = processInfo })
                {
                    process.OutputDataReceived += (s, e) =>
                    {
                        if (!string.IsNullOrEmpty(e.Data))
                        {
                            try
                            {
                                if (e.Data.Contains("FOUND"))
                                {
                                    var parts = e.Data.Split(new[] { " FOUND" }, StringSplitOptions.None);
                                    if (parts.Length > 0)
                                    {
                                        threats.Add(new UnifiedThreatInfo
                                        {
                                            FilePath = parts[0].Trim(),
                                            ThreatName = "ClamAV.Detected",
                                            Severity = UnifiedThreatSeverity.Medium
                                        });
                                    }
                                }
                                else if (e.Data.Contains("Scanning"))
                                {
                                    filesScanned++;
                                    try
                                    {
                                        OnProgressChanged?.Invoke(this, new UnifiedScanProgress
                                        {
                                            Status = ScanStatus.Running,
                                            FilesScanned = filesScanned,
                                            Engine = "ClamAV"
                                        });
                                    }
                                    catch { }
                                }
                            }
                            catch { }
                        }
                    };
                    
                    process.ErrorDataReceived += (s, e) => { };
                    
                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    
                    try
                    {
                        OnProgressChanged?.Invoke(this, new UnifiedScanProgress
                        {
                            Status = ScanStatus.Running,
                            FilesScanned = 0,
                            Engine = "ClamAV"
                        });
                    }
                    catch { }
                    
                    await Task.Run(() => process.WaitForExit()).ConfigureAwait(false);
                    
                    result.FilesScanned = filesScanned;
                    result.ThreatsFound = threats.Count;
                    result.Threats = threats;
                    result.Success = true;
                    
                    try
                    {
                        OnProgressChanged?.Invoke(this, new UnifiedScanProgress
                        {
                            Status = ScanStatus.Completed,
                            FilesScanned = filesScanned,
                            ThreatsFound = threats.Count,
                            Engine = "ClamAV"
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                
                try
                {
                    OnProgressChanged?.Invoke(this, new UnifiedScanProgress
                    {
                        Status = ScanStatus.Error,
                        ErrorMessage = ex.Message,
                        Engine = "ClamAV"
                    });
                }
                catch { }
            }
            
            return result;
        }
        
        public async Task<UpdateResult> UpdateVirusDatabaseAsync()
        {
            var result = new UpdateResult { StartTime = DateTime.Now };
            
            if (_clamAVAvailable)
            {
                var freshclamResult = await RunFreshclamAsync().ConfigureAwait(false);
                if (freshclamResult.Success)
                {
                    result.Success = true;
                    result.Message = "???????";
                    result.Method = "freshclam.exe";
                    return result;
                }
            }
            
            var downloadResult = await DownloadFromOfficialAsync().ConfigureAwait(false);
            if (downloadResult.Success)
            {
                result.Success = true;
                result.Message = "???????";
                result.Method = "????";
                return result;
            }
            
            result.Success = false;
            result.Message = "???????";
            return result;
        }
        
        private async Task<UpdateResult> RunFreshclamAsync()
        {
            var result = new UpdateResult();
            
            try
            {
                string baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                string freshclamPath = Path.Combine(baseDir, "clamav", "freshclam.exe");
                
                if (!File.Exists(freshclamPath))
                {
                    result.Success = false;
                    result.ErrorMessage = "freshclam.exe ???";
                    return result;
                }
                
                using (var process = Process.Start(new ProcessStartInfo
                {
                    FileName = freshclamPath,
                    Arguments = "--quiet",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = Path.Combine(baseDir, "clamav")
                }))
                {
                    if (process == null)
                    {
                        result.Success = false;
                        result.ErrorMessage = "???? freshclam";
                        return result;
                    }
                    
                    bool exited = await Task.Run(() => process.WaitForExit(120000)).ConfigureAwait(false);
                    
                    if (!exited)
                    {
                        process.Kill();
                        result.Success = false;
                        result.ErrorMessage = "freshclam ??";
                        return result;
                    }
                    
                    result.Success = process.ExitCode == 0;
                    if (!result.Success) result.ErrorMessage = "freshclam ???: " + process.ExitCode;
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            
            return result;
        }
        
        private async Task<UpdateResult> DownloadFromOfficialAsync()
        {
            var result = new UpdateResult();
            
            try
            {
                string baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                string databasePath = Path.Combine(baseDir, "clamav", "database");
                
                Directory.CreateDirectory(databasePath);
                
                string[] cvdFiles = { "daily.cvd", "main.cvd", "bytecode.cvd" };
                
                using (var client = new WebClient())
                {
                    foreach (var file in cvdFiles)
                    {
                        try
                        {
                            await client.DownloadFileTaskAsync("https://database.clamav.net/" + file, Path.Combine(databasePath, file));
                        }
                        catch { }
                    }
                }
                
                int downloadedCount = cvdFiles.Count(f => File.Exists(Path.Combine(databasePath, f)));
                result.Success = downloadedCount > 0;
                if (!result.Success) result.ErrorMessage = "???????????";
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            
            return result;
        }
        
        private UnifiedScanProgress ConvertProgress(DefenderScanProgress progress, string engine)
        {
            return new UnifiedScanProgress
            {
                Status = progress.Status == DefenderScanStatus.Running ? ScanStatus.Running :
                         progress.Status == DefenderScanStatus.Completed ? ScanStatus.Completed :
                         progress.Status == DefenderScanStatus.Cancelled ? ScanStatus.Cancelled :
                         progress.Status == DefenderScanStatus.Error ? ScanStatus.Error : ScanStatus.Idle,
                FilesScanned = (int)progress.FilesScanned,
                ThreatsFound = progress.ThreatsFound,
                ElapsedTime = progress.ElapsedTime,
                Engine = engine
            };
        }
        
        private UnifiedThreatSeverity ConvertSeverity(DefenderThreatSeverity severity)
        {
            return severity switch
            {
                DefenderThreatSeverity.Critical => UnifiedThreatSeverity.Critical,
                DefenderThreatSeverity.High => UnifiedThreatSeverity.High,
                DefenderThreatSeverity.Medium => UnifiedThreatSeverity.Medium,
                DefenderThreatSeverity.Low => UnifiedThreatSeverity.Low,
                _ => UnifiedThreatSeverity.Unknown
            };
        }
        
        public void StopScan()
        {
            try
            {
                if (_defenderService?.IsScanning == true)
                {
                    _defenderService.StopScan();
                }
            }
            catch { }
            
            _cts?.Cancel();
            IsScanning = false;
        }
        
        public void Dispose()
        {
            try { _defenderService?.Dispose(); } catch { }
            try { _cts?.Dispose(); } catch { }
        }
    }
    
    public enum ScanType { Quick, Full, Custom }
    public enum ScanStatus { Idle, Running, Completed, Cancelled, Error }
    public enum UnifiedThreatSeverity { Unknown, Low, Medium, High, Critical }
    
    public class UnifiedScanResult
    {
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public ScanType ScanType { get; set; }
        public string Engine { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public int FilesScanned { get; set; }
        public int ThreatsFound { get; set; }
        public List<UnifiedThreatInfo> Threats { get; set; } = new List<UnifiedThreatInfo>();
    }
    
    public class UnifiedScanProgress
    {
        public ScanStatus Status { get; set; }
        public int FilesScanned { get; set; }
        public int ThreatsFound { get; set; }
        public TimeSpan ElapsedTime { get; set; }
        public string Engine { get; set; }
        public string CurrentPath { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    public class UnifiedThreatInfo
    {
        public string FilePath { get; set; }
        public string ThreatName { get; set; }
        public UnifiedThreatSeverity Severity { get; set; }
    }
    
    public class UpdateResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
        public string Method { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
    }
}
