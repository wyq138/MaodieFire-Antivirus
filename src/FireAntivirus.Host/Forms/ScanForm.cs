using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using FireAntivirus.Engine;

namespace FireAntivirus.Host
{
    public class ScanForm : Form
    {
        private FireAntivirus.Engine.ScanType scanType;
        private ProgressBar scanProgressBar;
        private Label statusLabel;
        private Button stopButton;

        public ScanForm(FireAntivirus.Engine.ScanType type)
        {
            scanType = type;
            InitializeComponents();
            StartScan();
        }

        private void InitializeComponents()
        {
            this.Text = $"{GetScanTypeName(scanType)} - 哈基咪杀毒";
            this.Size = new Size(600, 300);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Icon = SystemIcons.Shield;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 4,
                ColumnCount = 1
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var titleLabel = new Label
            {
                Text = GetScanTypeName(scanType),
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.Black,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            scanProgressBar = new ProgressBar
            {
                Dock = DockStyle.Fill,
                Minimum = 0,
                Maximum = 100,
                Value = 0,
                Margin = new Padding(20)
            };

            statusLabel = new Label
            {
                Text = "正在准备扫描...",
                Font = new Font("微软雅黑", 12),
                ForeColor = Color.Gray,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            stopButton = new Button
            {
                Text = "停止扫描",
                Width = 120,
                Height = 40,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Red,
                ForeColor = Color.White
            };

            stopButton.FlatAppearance.BorderSize = 0;
            stopButton.Click += (s, e) => this.Close();

            var buttonPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            stopButton.Location = new Point(240, 5);
            buttonPanel.Controls.Add(stopButton);

            mainLayout.Controls.Add(titleLabel, 0, 0);
            mainLayout.Controls.Add(scanProgressBar, 0, 1);
            mainLayout.Controls.Add(statusLabel, 0, 2);
            mainLayout.Controls.Add(buttonPanel, 0, 3);

            this.Controls.Add(mainLayout);
        }

        private string GetScanTypeName(FireAntivirus.Engine.ScanType type)
        {
            switch (type)
            {
                case FireAntivirus.Engine.ScanType.Quick:
                    return "快速扫描";
                case FireAntivirus.Engine.ScanType.Full:
                    return "全盘扫描";
                case FireAntivirus.Engine.ScanType.Custom:
                    return "自定义扫描";
                default:
                    return "扫描";
            }
        }

        private void StartScan()
        {
            // 调用实际的扫描功能
            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var engine = new FireAntivirus.Engine.AntivirusEngine();
                    
                    // 注册进度事件
                    engine.ScanProgress += (sender, e) =>
                    {
                        this.Invoke((Action)(() =>
                        {
                            scanProgressBar.Value = Math.Min(100, Math.Max(0, (int)e.Progress));
                            statusLabel.Text = $"正在扫描: {e.CurrentFile} ({(int)e.Progress}%)";
                        }));
                    };

                    // 注册威胁检测事件
                    engine.ThreatDetected += (sender, e) =>
                    {
                        this.Invoke((Action)(() =>
                        {
                            if (e.Threat != null)
                                statusLabel.Text = $"发现威胁: {e.Threat.ThreatName} - {e.Threat.FilePath}";
                        }));
                    };

                    // 根据扫描类型确定扫描路径
                    var options = new FireAntivirus.Engine.ScanOptions
                    {
                        ScanType = scanType,
                        ScanMemory = true,
                        ScanRegistry = true,
                        ScanStartupItems = true,
                        ScanNetworkConnections = true,
                        ScanProcesses = true
                    };

                    // 收集所有扫描结果
                    var allResults = new System.Collections.Generic.List<FireAntivirus.Engine.ScanResult>();

                    // 确定扫描目录
                    var scanPaths = GetScanPaths();
                    foreach (var dirPath in scanPaths)
                    {
                        if (System.IO.Directory.Exists(dirPath))
                        {
                            var dirResults = engine.ScanDirectory(dirPath, options);
                            if (dirResults != null)
                                allResults.AddRange(dirResults);
                        }
                    }

                    // 显示扫描结果
                    this.Invoke((Action)(() =>
                    {
                        int infectedCount = allResults.Where(r => r.IsInfected).Count();
                        statusLabel.Text = $"扫描完成，发现 {infectedCount} 个威胁";
                        stopButton.Text = "关闭";
                    }));
                }
                catch (Exception ex)
                {
                    this.Invoke((Action)(() =>
                    {
                        statusLabel.Text = $"扫描错误: {ex.Message}";
                        stopButton.Text = "关闭";
                    }));
                }
            });
        }

        private System.Collections.Generic.List<string> GetScanPaths()
        {
            var paths = new System.Collections.Generic.List<string>();
            switch (scanType)
            {
                case FireAntivirus.Engine.ScanType.Quick:
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.System));
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                    break;
                case FireAntivirus.Engine.ScanType.Full:
                case FireAntivirus.Engine.ScanType.Custom:
                    foreach (var drive in System.IO.DriveInfo.GetDrives())
                    {
                        if (drive.IsReady && drive.DriveType == System.IO.DriveType.Fixed)
                            paths.Add(drive.RootDirectory.FullName);
                    }
                    break;
            }
            return paths;
        }
    }
}