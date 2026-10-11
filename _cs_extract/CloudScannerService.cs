// 耄耋软件工作室 开发，严禁非法反编译
// 云扫描服务 - 真实可用的多引擎云查杀服务
// 集成 MalwareBazaar + VirusTotal(70+引擎) + HybridAnalysis + OTX
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.CloudScanner;
using FireAntivirus.Common.Notification;
// 使用 CloudScanner 项目的 CloudScanResult(支持多引擎聚合字段)
using CloudScanResult = FireAntivirus.CloudScanner.CloudScanResult;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 云扫描服务 - 真实多引擎云查杀 (替代旧版模拟实现)
    /// </summary>
    public class CloudScannerService : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private AntivirusEngine _antivirusEngine;
        private CloudScanAggregator _aggregator;
        private CloudScanConfig _config;

        /// <summary>扫描进度更新事件 (当前文件, 已扫描数, 总数)</summary>
        public event Action<string, int, int> ScanProgressChanged;

        /// <summary>检测到威胁事件</summary>
        public event Action<CloudScanResult, string> ThreatDetected;

        public CloudScannerService(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            _dataManager = dataManager;
            _antivirusEngine = antivirusEngine;
            _config = CloudScanConfig.Load();
            _aggregator = new CloudScanAggregator(_config);
        }

        public void Start()
        {
            _isRunning = true;
            _monitorThread = new Thread(MonitorCloudScanning);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "CloudScannerStart",
                Message = "云查杀服务已启动",
                Details = $"已启用引擎: {string.Join(", ", GetEnabledEngines())}"
            });
        }

        public void Stop()
        {
            _isRunning = false;
            _monitorThread?.Join(2000);
            _aggregator?.Dispose();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "CloudScannerStop",
                Message = "云查杀服务已停止",
                Details = string.Empty
            });
        }

        private void MonitorCloudScanning()
        {
            while (_isRunning)
            {
                try
                {
                    // 定期清理过期缓存
                    CloudScanAggregator.CleanExpiredCache();
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "CloudScannerError",
                        Message = "云查杀服务错误",
                        Details = ex.Message
                    });
                }

                Thread.Sleep(300000); // 每5分钟清理一次缓存
            }
        }

        /// <summary>
        /// 扫描单个文件 - 真实调用多引擎云查杀
        /// </summary>
        public async Task<CloudScanResult> ScanFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("文件不存在", filePath);
            }

            CloudScanResult result = null;

            try
            {
                // 调用聚合器(并行查询所有云引擎)
                result = await _aggregator.ScanFileAsync(filePath);

                if (result == null)
                {
                    result = new CloudScanResult
                    {
                        FilePath = filePath,
                        FileName = Path.GetFileName(filePath),
                        ScanTime = DateTime.Now,
                        Success = false,
                        Message = "云查杀返回空结果"
                    };
                }
                else
                {
                    result.FilePath = filePath;
                    result.FileName = Path.GetFileName(filePath);

                    if (result.IsInfected)
                    {
                        ThreatDetected?.Invoke(result, filePath);

                        NotificationService.Instance.ShowNotification(
                            "云查杀发现威胁",
                            $"{Path.GetFileName(filePath)}: {result.ThreatName} ({result.PositiveEngines}/{result.TotalEngines} 引擎)",
                            NotificationType.Error
                        );

                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "CloudScanInfected",
                            Message = $"云查杀发现威胁: {result.ThreatName}",
                            Details = $"文件: {filePath}, 引擎: {result.PositiveEngines}/{result.TotalEngines}, 哈希: {result.FileHash}"
                        });
                    }
                    else
                    {
                        _dataManager.AddLog(new LogEntry
                        {
                            Id = Guid.NewGuid().ToString(),
                            Time = DateTime.Now,
                            Type = "CloudScanClean",
                            Message = "云查杀未发现威胁",
                            Details = $"文件: {filePath}, 引擎: {result.TotalEngines}, 哈希: {result.FileHash}"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "CloudScanError",
                    Message = "云查杀失败",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });

                result = new CloudScanResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    ScanTime = DateTime.Now,
                    Success = false,
                    Message = $"云查杀失败: {ex.Message}"
                };
            }

            return result;
        }

        /// <summary>
        /// 扫描目录 - 递归扫描所有文件
        /// </summary>
        public async Task<CloudScanResult> ScanDirectory(string directoryPath, CancellationToken cancellationToken = default)
        {
            if (!Directory.Exists(directoryPath))
            {
                throw new DirectoryNotFoundException($"目录不存在: {directoryPath}");
            }

            CloudScanResult result = new CloudScanResult
            {
                FilePath = directoryPath,
                FileName = Path.GetFileName(directoryPath),
                ScanTime = DateTime.Now
            };

            int infectedCount = 0;
            int totalScanned = 0;
            var infectedFiles = new List<string>();

            try
            {
                string[] files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories);
                int totalFiles = files.Length;

                foreach (string file in files)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    totalScanned++;
                    ScanProgressChanged?.Invoke(file, totalScanned, totalFiles);

                    try
                    {
                        var fileResult = await ScanFile(file);
                        if (fileResult != null && fileResult.IsInfected)
                        {
                            infectedCount++;
                            infectedFiles.Add(file);
                        }
                    }
                    catch
                    {
                        // 单个文件失败不影响整体扫描
                    }
                }

                result.IsInfected = infectedCount > 0;
                result.TotalEngines = totalScanned;
                result.PositiveEngines = infectedCount;
                if (infectedCount > 0)
                {
                    result.ThreatName = $"{infectedCount} 个威胁文件";
                    result.Message = string.Join("\n", infectedFiles.Take(20));
                }

                if (result.IsInfected)
                {
                    NotificationService.Instance.ShowNotification(
                        "云查杀结果",
                        $"目录 {result.FileName} 中发现 {infectedCount} 个威胁文件",
                        NotificationType.Error
                    );

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "CloudScanDirectoryInfected",
                        Message = "云查杀发现病毒",
                        Details = $"目录: {result.FileName}, 感染文件数: {infectedCount}, 总文件数: {totalScanned}"
                    });
                }
                else
                {
                    NotificationService.Instance.ShowNotification(
                        "云查杀结果",
                        $"目录 {result.FileName} 扫描完成, 未发现威胁 (共{totalScanned}个文件)",
                        NotificationType.Info
                    );
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "CloudScanDirectoryError",
                    Message = "目录扫描失败",
                    Details = $"目录: {directoryPath}, 错误: {ex.Message}"
                });
            }

            return result;
        }

        /// <summary>
        /// 扫描 URL - 真实调用 OTX + VirusTotal URL 查询
        /// </summary>
        public async Task<CloudScanResult> ScanUrl(string url)
        {
            CloudScanResult result;

            try
            {
                // 构造 CloudScannerManager 来调用 URL 扫描
                var manager = new CloudScannerManager(_dataManager, _antivirusEngine);
                result = await manager.ScanUrl(url);
                result.FilePath = url;

                if (result.IsInfected)
                {
                    NotificationService.Instance.ShowNotification(
                        "URL扫描结果",
                        $"URL {url} 检测到威胁: {result.ThreatName}",
                        NotificationType.Error
                    );
                }
                else
                {
                    NotificationService.Instance.ShowNotification(
                        "URL扫描结果",
                        $"URL {url} 未检测到威胁",
                        NotificationType.Info
                    );
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "CloudScanUrlError",
                    Message = "URL扫描失败",
                    Details = $"URL: {url}, 错误: {ex.Message}"
                });

                result = new CloudScanResult
                {
                    Url = url,
                    FilePath = url,
                    ScanTime = DateTime.Now,
                    Success = false,
                    Message = $"URL扫描失败: {ex.Message}"
                };
            }

            return result;
        }

        /// <summary>获取已启用的云引擎列表</summary>
        public List<string> GetEnabledEngines()
        {
            var engines = new List<string>();
            if (_config.EnableMalwareBazaar) engines.Add("MalwareBazaar");
            if (_config.EnableOTX) engines.Add("AlienVault-OTX");
            if (_config.EnableVirusTotal)
                engines.Add(string.IsNullOrEmpty(_config.VirusTotalApiKey) ? "VirusTotal(未配置Key)" : "VirusTotal(70+引擎)");
            if (_config.EnableHybridAnalysis)
                engines.Add(string.IsNullOrEmpty(_config.HybridAnalysisApiKey) ? "HybridAnalysis(未配置Key)" : "HybridAnalysis(沙箱)");
            return engines;
        }

        /// <summary>更新云查杀配置</summary>
        public void UpdateConfig(CloudScanConfig newConfig)
        {
            _config = newConfig;
            _config.Save();
            _aggregator?.Dispose();
            _aggregator = new CloudScanAggregator(_config);
        }

        /// <summary>当前配置</summary>
        public CloudScanConfig GetConfig() => _config;
    }
}

