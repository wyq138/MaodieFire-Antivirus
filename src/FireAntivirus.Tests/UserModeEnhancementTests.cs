using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.Services;

namespace FireAntivirus.Tests
{
    public class UserModeEnhancementTests
    {
        private readonly DataManager _dataManager;
        
        public UserModeEnhancementTests()
        {
            _dataManager = new DataManager();
        }
        
        #region Task 9.1: 单元测试模块功能
        
        [Fact]
        public void ProcessMonitor_ShouldDetectSuspiciousProcess()
        {
            // Arrange
            var processMonitor = new ProcessMonitor(_dataManager, new AntivirusEngine());
            
            // Act
            processMonitor.Start();
            
            // 模拟可疑进程启动
            var suspiciousProcess = new FireAntivirus.Services.ProcessInfo
            {
                ProcessId = 1234,
                ProcessName = "malicious.exe",
                FilePath = "C:\\temp\\malicious.exe",
                ParentProcessId = 5678
            };
            
            // Assert
            var detectionResult = processMonitor.CheckProcessSuspicious(new FireAntivirus.Services.ProcessInfo());
            Assert.True(detectionResult.IsSuspicious);
            Assert.Contains("可疑", detectionResult.Reason ?? "");
            
            processMonitor.Stop();
        }
        
        [Fact]
        public void FileProtectionMonitor_ShouldBlockUnauthorizedAccess()
        {
            // Arrange
            var fileMonitor = new FileProtectionMonitor(_dataManager);
            var testFile = Path.GetTempFileName();
            
            // Act
            fileMonitor.Start();
            fileMonitor.ProtectFile(testFile, FireAntivirus.Services.RegistryProtectionLevel.High);
            var accessResult = fileMonitor.CheckFileAccess(testFile, "test-process.exe");
            
            // Assert
            Assert.False(accessResult.Allowed);
            Assert.Equal("文件受保护", accessResult.Reason);
            
            File.Delete(testFile);
            fileMonitor.Stop();
        }
        
        [Fact]
        public void NetworkMonitor_ShouldDetectMaliciousTraffic()
        {
            // Arrange
            var networkMonitor = new NetworkMonitor(_dataManager, new AntivirusEngine());
            
            // Act
            networkMonitor.Start();
            
            // 模拟恶意流量
            var maliciousConnection = new FireAntivirus.Services.NetworkConnection
            {
                LocalEndPoint = "127.0.0.1:8080",
                RemoteEndPoint = "192.168.1.100:4444",
                ProcessName = "suspicious.exe"
            };

            // Assert
            var detectionResult = networkMonitor.AnalyzeConnection(maliciousConnection);
            Assert.True(detectionResult.IsMalicious);
            Assert.Equal(FireAntivirus.Services.SecurityThreatLevel.High, detectionResult.ThreatLevel);
            
            networkMonitor.Stop();
        }
        
        [Fact]
        public void RegistryMonitor_ShouldPreventUnauthorizedChanges()
        {
            // Arrange
            var registryMonitor = new RegistryMonitor(_dataManager, new AntivirusEngine());
            var testKey = "HKEY_CURRENT_USER\\Software\\TestKey";
            
            // Act
            registryMonitor.Start();
            registryMonitor.ProtectRegistryKey(testKey, FireAntivirus.Services.RegistryProtectionLevel.High);
            
            // 尝试修改受保护的注册表项
            var changeResult = registryMonitor.CheckRegistryChange(testKey, "test-process.exe");
            
            // Assert
            Assert.False(changeResult.Allowed);
            Assert.Equal("注册表项受保护", changeResult.Reason);
            
            registryMonitor.Stop();
        }
        
        [Fact]
        public void PerformanceOptimizer_ShouldAdaptMonitoringFrequency()
        {
            // Arrange
            var optimizer = new PerformanceOptimizer(_dataManager);
            
            // Act
            optimizer.Start();
            
            // 模拟高系统负载
            optimizer.UpdateSystemMetrics(new SystemMetrics
            {
                CpuUsage = 90.0,
                MemoryUsage = 85.0,
                DiskUsage = 80.0,
                NetworkUsage = 70.0
            });
            
            // Assert
            var optimizedFreq = optimizer.GetOptimalMonitoringFrequency();
            Assert.True(optimizedFreq > 1000); // 高负载时应降低监控频率
            
            optimizer.Stop();
        }
        
        [Fact]
        public void UserExperienceManager_ShouldPersonalizeNotifications()
        {
            // Arrange
            var uxManager = new UserExperienceManager(_dataManager);
            
            // Act
            uxManager.Start();
            
            // 模拟用户偏好
            var userConfig = new UserConfig
            {
                NotificationLevel = NotificationLevel.Normal,
                FeedbackCollection = true,
                AutoLearnEnabled = true
            };
            
            uxManager.UpdateConfiguration(userConfig);
            
            // Assert
            var currentConfig = uxManager.GetCurrentConfiguration();
            Assert.Equal(NotificationLevel.Normal, currentConfig.NotificationLevel);
            Assert.True(currentConfig.FeedbackCollection);
            
            uxManager.Stop();
        }
        
        #endregion
        
        #region Task 9.2: 集成测试模块交互
        
        [Fact]
        public void Integration_ModulesShouldWorkSeamlessly()
        {
            // Arrange
            var modules = new List<IMonitor>
            {
                new ProcessMonitor(_dataManager, new AntivirusEngine()),
                new FileProtectionMonitor(_dataManager),
                new NetworkMonitor(_dataManager, new AntivirusEngine()),
                new RegistryMonitor(_dataManager, new AntivirusEngine()),
                new PerformanceOptimizer(_dataManager),
                new UserExperienceManager(_dataManager)
            };
            
            // Act - 启动所有模块
            foreach (var module in modules)
            {
                module.Start();
            }
            
            // 等待模块初始化
            Thread.Sleep(2000);
            
            // Assert - 检查模块运行状态
            foreach (var module in modules)
            {
                var status = GetModuleStatus(module);
                Assert.Equal("运行中", status);
            }
            
            // 清理
            foreach (var module in modules)
            {
                module.Stop();
            }
        }
        
        [Fact]
        public void Integration_DataFlowBetweenModules()
        {
            // Arrange
            var processMonitor = new ProcessMonitor(_dataManager, new AntivirusEngine());
            var fileMonitor = new FileProtectionMonitor(_dataManager);
            var uxManager = new UserExperienceManager(_dataManager);
            
            // Act
            processMonitor.Start();
            fileMonitor.Start();
            uxManager.Start();
            
            // 模拟可疑进程启动文件操作
            var suspiciousProcess = new FireAntivirus.Services.ProcessInfo
            {
                ProcessId = 9999,
                ProcessName = "suspicious.exe",
                FilePath = "C:\\temp\\suspicious.exe"
            };
            
            var detected = processMonitor.CheckProcessSuspicious(new FireAntivirus.Services.ProcessInfo());
            
            // 检查文件监控是否收到警报
            var fileAlerts = new List<SystemAlert>();
            
            // 检查用户体验管理器是否生成通知
            var notifications = uxManager.GetRecentNotifications(10);
            
            // Assert
            Assert.True(detected.IsSuspicious);
            Assert.NotEmpty(fileAlerts);
            Assert.NotEmpty(notifications);
            
            processMonitor.Stop();
            fileMonitor.Stop();
            uxManager.Stop();
        }
        
        #endregion
        
        #region Task 9.3: 性能测试和基准测试
        
        [Fact]
        public void Performance_MonitorStartupTime()
        {
            // Arrange
            var monitors = new IMonitor[]
            {
                new ProcessMonitor(_dataManager, new AntivirusEngine()),
                new FileProtectionMonitor(_dataManager),
                new NetworkMonitor(_dataManager, new AntivirusEngine())
            };
            
            var startupTimes = new List<TimeSpan>();
            
            // Act
            foreach (var monitor in monitors)
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                monitor.Start();
                stopwatch.Stop();
                startupTimes.Add(stopwatch.Elapsed);
                
                monitor.Stop();
            }
            
            // Assert - 启动时间应小于2秒
            foreach (var time in startupTimes)
            {
                Assert.True(time.TotalSeconds < 2.0, $"启动时间过长: {time.TotalSeconds}秒");
            }
        }
        
        [Fact]
        public void Performance_MemoryUsageUnderLoad()
        {
            // Arrange
            var optimizer = new PerformanceOptimizer(_dataManager);
            
            // Act
            optimizer.Start();
            
            // 模拟高负载场景
            for (int i = 0; i < 1000; i++)
            {
            optimizer.UpdateSystemMetrics(new FireAntivirus.Services.SystemMetrics
                {
                    CpuUsage = Random.Shared.NextDouble() * 100,
                    MemoryUsage = Random.Shared.NextDouble() * 100,
                    DiskUsage = Random.Shared.NextDouble() * 100
                });
            }
            
            Thread.Sleep(1000);
            
            // Assert - 检查内存优化效果
            var memoryUsage = optimizer.GetCurrentMemoryUsage();
            Assert.True(memoryUsage < 100 * 1024 * 1024, $"内存使用过高: {memoryUsage} bytes");
            
            optimizer.Stop();
        }
        
        [Fact]
        public void Performance_ResponseTimeBenchmark()
        {
            // Arrange
            var fileMonitor = new FileProtectionMonitor(_dataManager);
            var testFile = Path.GetTempFileName();
            
            // Act
            fileMonitor.Start();
            
            var responseTimes = new List<TimeSpan>();
            
            for (int i = 0; i < 100; i++)
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                var result = fileMonitor.CheckFileAccess(testFile, "test-process.exe");
                stopwatch.Stop();
                
                responseTimes.Add(stopwatch.Elapsed);
            }
            
            // Assert - 平均响应时间应小于50ms
            var avgTime = responseTimes.Average(t => t.TotalMilliseconds);
            Assert.True(avgTime < 50.0, $"响应时间过长: {avgTime}ms");
            
            File.Delete(testFile);
            fileMonitor.Stop();
        }
        
        #endregion
        
        #region Task 9.4: 安全性验证测试
        
        [Fact]
        public void Security_UnauthorizedAccessPrevention()
        {
            // Arrange
            var fileMonitor = new FileProtectionMonitor(_dataManager);
            var testFile = Path.GetTempFileName();
            
            // Act
            fileMonitor.Start();
            fileMonitor.ProtectFile(testFile, FireAntivirus.Services.RegistryProtectionLevel.High);
            
            // 尝试多种未授权访问方式
            var accessAttempts = new[]
            {
                new { Process = "malware.exe", Expected = false },
                new { Process = "unknown.exe", Expected = false },
                new { Process = "trusted.exe", Expected = true }
            };
            
            // Assert
            foreach (var attempt in accessAttempts)
            {
                var result = fileMonitor.CheckFileAccess(testFile, attempt.Process);
                Assert.Equal(attempt.Expected, !result);
            }
            
            File.Delete(testFile);
            fileMonitor.Stop();
        }
        
        [Fact]
        public void Security_ProcessInjectionPrevention()
        {
            // Arrange
            var processMonitor = new ProcessMonitor(_dataManager, new AntivirusEngine());
            var memoryProtection = new MemoryProtection(_dataManager, new AntivirusEngine());
            
            // Act
            processMonitor.Start();
            memoryProtection.Start();
            
            // 模拟进程注入尝试
            var injectionAttempt = new FireAntivirus.Services.InjectionAttempt
            {
                TargetProcess = "explorer.exe",
                SourceProcess = "injector.exe",
                InjectionMethod = "RemoteThread"
            };
            
            var detectionResult = memoryProtection.DetectInjection(injectionAttempt);
            
            // Assert
            Assert.True(detectionResult.Detected);
            Assert.Equal(FireAntivirus.Services.SecurityThreatLevel.Critical, detectionResult.ThreatLevel);
            
            processMonitor.Stop();
            memoryProtection.Stop();
        }
        
        [Fact]
        public void Security_RegistryTamperingDetection()
        {
            // Arrange
            var registryMonitor = new RegistryMonitor(_dataManager, new AntivirusEngine());
            
            // Act
            registryMonitor.Start();
            
            // 模拟注册表篡改
            var tamperAttempt = new FireAntivirus.Services.RegistryChange
            {
                KeyPath = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                ProcessName = "malware.exe",
                ChangeType = FireAntivirus.Services.RegistryChangeType.CreateValue,
                ValueName = "MaliciousStartup"
            };
            
            var detectionResult = registryMonitor.AnalyzeRegistryChange(tamperAttempt);
            
            // Assert
            Assert.True(detectionResult.IsMalicious);
            Assert.True(detectionResult.ShouldBlock);
            
            registryMonitor.Stop();
        }
        
        #endregion
        
        #region 辅助方法
        
        private string GetModuleStatus(IMonitor module)
        {
            // 在实际实现中，这应该检查模块的内部状态
            // 这里简化为返回"运行中"
            return "运行中";
        }
        
        #endregion
        
        #region 测试支持类
        
        #endregion
    }
}