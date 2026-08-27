// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Linq;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;

namespace FireAntivirus.Host
{
    public partial class NetworkTrafficAnalyzerPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;
        private NetworkTrafficAnalyzerService _networkService;
        private Label _downloadSpeedLabel;
        private Label _uploadSpeedLabel;
        private Label _connectionsLabel;
        private ListView _connectionsListView;
        private ProgressBar _downloadProgress;
        private ProgressBar _uploadProgress;
        private Label _statusLabel;
        private bool _isMonitoring = false;

        public NetworkTrafficAnalyzerPage()
        {
            InitializeComponent();
            InitializeService();
            UpdateUI();
        }

        private void InitializeService()
        {
            _networkService = new NetworkTrafficAnalyzerService();
            _networkService.TrafficUpdated += OnTrafficUpdated;
            _networkService.SuspiciousConnectionDetected += OnSuspiciousConnectionDetected;
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // NetworkTrafficAnalyzerPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "NetworkTrafficAnalyzerPage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
                if (_connectionsListView != null)
                {
                    _connectionsListView.BackColor = Color.FromArgb(45, 45, 45);
                    _connectionsListView.ForeColor = Color.White;
                }
            }
            else
            {
                this.BackColor = Color.White;
                if (_connectionsListView != null)
                {
                    _connectionsListView.BackColor = Color.White;
                    _connectionsListView.ForeColor = Color.Black;
                }
            }
        }

        private void UpdateUI()
        {
            this.Controls.Clear();

            // 标题
            var titleLabel = new Label
            {
                Text = "网络流量监控",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 15),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 描述
            var descriptionLabel = new Label
            {
                Text = "实时监控网络流量和活动连接",
                Font = new Font("微软雅黑", 10),
                ForeColor = Color.Gray,
                Location = new Point(20, 45),
                AutoSize = true
            };
            this.Controls.Add(descriptionLabel);

            // 状态标签
            _statusLabel = new Label
            {
                Text = "状态: 未监控",
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.Orange,
                Location = new Point(20, 70),
                AutoSize = true
            };
            this.Controls.Add(_statusLabel);

            // 速度面板
            var speedPanel = new Panel
            {
                Location = new Point(20, 95),
                Size = new Size(320, 130),
                BackColor = Color.FromArgb(240, 240, 240)
            };
            this.Controls.Add(speedPanel);

            // 下载速度
            var downloadIcon = new Label
            {
                Text = "↓",
                Font = new Font("Arial", 16),
                ForeColor = Color.Green,
                Location = new Point(10, 10),
                AutoSize = true
            };
            speedPanel.Controls.Add(downloadIcon);

            var downloadLabel = new Label
            {
                Text = "下载速度",
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.Gray,
                Location = new Point(35, 15),
                AutoSize = true
            };
            speedPanel.Controls.Add(downloadLabel);

            _downloadSpeedLabel = new Label
            {
                Text = "0 KB/s",
                Font = new Font("微软雅黑", 12, FontStyle.Bold),
                ForeColor = Color.Green,
                Location = new Point(35, 35),
                AutoSize = true
            };
            speedPanel.Controls.Add(_downloadSpeedLabel);

            _downloadProgress = new ProgressBar
            {
                Location = new Point(10, 60),
                Size = new Size(300, 15),
                Maximum = 1000,
                Value = 0
            };
            speedPanel.Controls.Add(_downloadProgress);

            // 上传速度
            var uploadIcon = new Label
            {
                Text = "↑",
                Font = new Font("Arial", 16),
                ForeColor = Color.Blue,
                Location = new Point(10, 75),
                AutoSize = true
            };
            speedPanel.Controls.Add(uploadIcon);

            var uploadLabel = new Label
            {
                Text = "上传速度",
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.Gray,
                Location = new Point(35, 80),
                AutoSize = true
            };
            speedPanel.Controls.Add(uploadLabel);

            _uploadSpeedLabel = new Label
            {
                Text = "0 KB/s",
                Font = new Font("微软雅黑", 12, FontStyle.Bold),
                ForeColor = Color.Blue,
                Location = new Point(35, 100),
                AutoSize = true
            };
            speedPanel.Controls.Add(_uploadSpeedLabel);

            // 操作面板
            var actionPanel = new Panel
            {
                Location = new Point(360, 95),
                Size = new Size(320, 130),
                BackColor = Color.FromArgb(240, 240, 240)
            };
            this.Controls.Add(actionPanel);

            var startButton = new Button
            {
                Text = _isMonitoring ? "停止监控" : "开始监控",
                Location = new Point(10, 10),
                Size = new Size(100, 35),
                BackColor = _isMonitoring ? Color.FromArgb(244, 67, 54) : Color.FromArgb(76, 175, 80),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            startButton.FlatAppearance.BorderSize = 0;
            startButton.Click += (s, e) =>
            {
                if (_isMonitoring)
                {
                    _networkService.StopMonitoring();
                    _isMonitoring = false;
                    startButton.Text = "开始监控";
                    startButton.BackColor = Color.FromArgb(76, 175, 80);
                    _statusLabel.Text = "状态: 已停止";
                    _statusLabel.ForeColor = Color.Orange;
                }
                else
                {
                    _networkService.StartMonitoring();
                    _isMonitoring = true;
                    startButton.Text = "停止监控";
                    startButton.BackColor = Color.FromArgb(244, 67, 54);
                    _statusLabel.Text = "状态: 监控中";
                    _statusLabel.ForeColor = Color.Green;
                }
            };
            actionPanel.Controls.Add(startButton);

            var speedTestButton = new Button
            {
                Text = "网速测试",
                Location = new Point(120, 10),
                Size = new Size(90, 35),
                BackColor = Color.FromArgb(255, 152, 0),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            speedTestButton.FlatAppearance.BorderSize = 0;
            speedTestButton.Click += SpeedTestButton_Click;
            actionPanel.Controls.Add(speedTestButton);

            var refreshButton = new Button
            {
                Text = "刷新连接",
                Location = new Point(220, 10),
                Size = new Size(90, 35),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            refreshButton.FlatAppearance.BorderSize = 0;
            refreshButton.Click += (s, e) => RefreshConnections();
            actionPanel.Controls.Add(refreshButton);

            var suspiciousButton = new Button
            {
                Text = "检测可疑连接",
                Location = new Point(10, 55),
                Size = new Size(120, 35),
                BackColor = Color.FromArgb(156, 39, 176),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            suspiciousButton.FlatAppearance.BorderSize = 0;
            suspiciousButton.Click += CheckSuspiciousConnections;
            actionPanel.Controls.Add(suspiciousButton);

            var historyButton = new Button
            {
                Text = "流量历史",
                Location = new Point(140, 55),
                Size = new Size(90, 35),
                BackColor = Color.FromArgb(0, 150, 136),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 9)
            };
            historyButton.FlatAppearance.BorderSize = 0;
            historyButton.Click += ViewHistoryButton_Click;
            actionPanel.Controls.Add(historyButton);

            // 连接数统计
            _connectionsLabel = new Label
            {
                Text = "活动连接: 0",
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.Gray,
                Location = new Point(10, 100),
                AutoSize = true
            };
            actionPanel.Controls.Add(_connectionsLabel);

            // 连接列表
            var connectionsLabel = new Label
            {
                Text = "活动网络连接",
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = Color.FromArgb(60, 60, 60),
                Location = new Point(20, 235),
                AutoSize = true
            };
            this.Controls.Add(connectionsLabel);

            _connectionsListView = new ListView
            {
                Location = new Point(20, 260),
                Size = new Size(660, 280),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                Font = new Font("微软雅黑", 9)
            };
            _connectionsListView.Columns.Add("协议", 50);
            _connectionsListView.Columns.Add("本地地址", 120);
            _connectionsListView.Columns.Add("本地端口", 70);
            _connectionsListView.Columns.Add("远程地址", 120);
            _connectionsListView.Columns.Add("远程端口", 70);
            _connectionsListView.Columns.Add("状态", 90);
            _connectionsListView.Columns.Add("进程", 100);
            this.Controls.Add(_connectionsListView);

            // 初始加载连接
            RefreshConnections();
        }

        private void RefreshConnections()
        {
            _connectionsListView.Items.Clear();
            var connections = _networkService.GetActiveConnections();

            foreach (var conn in connections)
            {
                var item = new ListViewItem(conn.Protocol);
                item.SubItems.Add(conn.LocalAddress);
                item.SubItems.Add(conn.LocalPort.ToString());
                item.SubItems.Add(conn.RemoteAddress);
                item.SubItems.Add(conn.RemotePort.ToString());
                item.SubItems.Add(conn.State);
                item.SubItems.Add(conn.ProcessName);
                item.Tag = conn;

                // 根据状态设置颜色
                if (conn.State == "Established")
                    item.ForeColor = Color.Green;
                else if (conn.State == "Listen")
                    item.ForeColor = Color.Blue;
                else if (conn.State == "TimeWait")
                    item.ForeColor = Color.Gray;

                _connectionsListView.Items.Add(item);
            }

            _connectionsLabel.Text = $"活动连接: {connections.Count}";
        }

        private void OnTrafficUpdated(object sender, NetworkTrafficEventArgs e)
        {
            if (this.InvokeRequired)
            {
                this.Invoke(new Action(() => OnTrafficUpdated(sender, e)));
                return;
            }

            _downloadSpeedLabel.Text = FormatSpeed(e.DownloadSpeed);
            _uploadSpeedLabel.Text = FormatSpeed(e.UploadSpeed);
            _connectionsLabel.Text = $"活动连接: {e.ActiveConnections}";

            // 更新进度条（假设最大10MB/s）
            var downloadPercent = (int)(e.DownloadSpeed / 1024 / 1024 / 10.0 * 1000);
            var uploadPercent = (int)(e.UploadSpeed / 1024 / 1024 / 10.0 * 1000);
            _downloadProgress.Value = Math.Min(1000, Math.Max(0, downloadPercent));
        }

        private void OnSuspiciousConnectionDetected(object sender, SuspiciousConnectionEventArgs e)
        {
            if (this.InvokeRequired)
            {
                this.Invoke(new Action(() => OnSuspiciousConnectionDetected(sender, e)));
                return;
            }

            var result = MessageBox.Show(
                $"⚠️ 检测到可疑网络连接!\n\n" +
                $"协议: {e.Connection.Protocol}\n" +
                $"本地: {e.Connection.LocalAddress}:{e.Connection.LocalPort}\n" +
                $"远程: {e.Connection.RemoteAddress}:{e.Connection.RemotePort}\n" +
                $"进程: {e.Connection.ProcessName}\n" +
                $"原因: {e.Reason}\n\n" +
                $"是否要终止此连接?",
                "可疑连接警告",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            // 注意: 终止连接需要更高级的权限和实现
        }

        private void SpeedTestButton_Click(object sender, EventArgs e)
        {
            _statusLabel.Text = "正在进行网速测试...";
            Application.DoEvents();

            var result = _networkService.TestNetworkSpeed();

            var message = "网络速度测试结果\n\n";
            
            if (result.Latency >= 0)
                message += $"延迟: {result.Latency} ms\n";
            else
                message += "延迟: 测试失败\n";

            message += $"DNS解析时间: {result.DNSResolutionTime} ms\n";
            message += $"当前下载速度: {FormatSpeed(result.DownloadSpeed)}\n";
            message += $"当前上传速度: {FormatSpeed(result.UploadSpeed)}\n";

            if (!string.IsNullOrEmpty(result.Error))
                message += $"\n错误: {result.Error}";

            MessageBox.Show(message, "网速测试", MessageBoxButtons.OK, MessageBoxIcon.Information);
            _statusLabel.Text = "网速测试完成";
        }

        private void CheckSuspiciousConnections(object sender, EventArgs e)
        {
            var suspicious = _networkService.GetSuspiciousConnections();

            if (suspicious.Count == 0)
            {
                MessageBox.Show("未检测到可疑网络连接", "检测结果", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var resultForm = new Form
            {
                Text = "可疑连接",
                Size = new Size(600, 400),
                StartPosition = FormStartPosition.CenterParent
            };

            var listView = new ListView
            {
                Location = new Point(20, 20),
                Size = new Size(540, 280),
                View = View.Details,
                FullRowSelect = true
            };
            listView.Columns.Add("本地地址", 120);
            listView.Columns.Add("远程地址", 120);
            listView.Columns.Add("端口", 60);
            listView.Columns.Add("进程", 100);
            listView.Columns.Add("原因", 100);

            foreach (var conn in suspicious)
            {
                var item = new ListViewItem($"{conn.LocalAddress}:{conn.LocalPort}");
                item.SubItems.Add($"{conn.RemoteAddress}:{conn.RemotePort}");
                item.SubItems.Add(conn.RemotePort.ToString());
                item.SubItems.Add(conn.ProcessName);
                item.SubItems.Add("可疑端口/IP");
                item.ForeColor = Color.Red;
                listView.Items.Add(item);
            }

            resultForm.Controls.Add(listView);
            resultForm.ShowDialog();
        }

        private void ViewHistoryButton_Click(object sender, EventArgs e)
        {
            var history = _networkService.GetTrafficHistory();

            if (history.Count == 0)
            {
                MessageBox.Show("暂无流量历史数据", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var historyForm = new Form
            {
                Text = "流量历史记录",
                Size = new Size(600, 400),
                StartPosition = FormStartPosition.CenterParent
            };

            var listView = new ListView
            {
                Location = new Point(20, 20),
                Size = new Size(540, 280),
                View = View.Details,
                FullRowSelect = true
            };
            listView.Columns.Add("时间", 120);
            listView.Columns.Add("下载速度", 100);
            listView.Columns.Add("上传速度", 100);
            listView.Columns.Add("下载数据", 100);
            listView.Columns.Add("上传数据", 100);

            foreach (var record in history.Skip(Math.Max(0, history.Count - 100)))
            {
                var item = new ListViewItem(record.Timestamp.ToString("HH:mm:ss"));
                item.SubItems.Add(FormatSpeed(record.DownloadSpeed));
                item.SubItems.Add(FormatSpeed(record.UploadSpeed));
                item.SubItems.Add(FormatBytes(record.DownloadedBytes));
                item.SubItems.Add(FormatBytes(record.UploadedBytes));
                listView.Items.Add(item);
            }

            historyForm.Controls.Add(listView);

            var closeButton = new Button
            {
                Text = "关闭",
                Location = new Point(250, 310),
                Size = new Size(100, 30),
                DialogResult = DialogResult.OK
            };
            historyForm.Controls.Add(closeButton);

            historyForm.ShowDialog();
        }

        private string FormatSpeed(long bytesPerSecond)
        {
            if (bytesPerSecond < 1024)
                return $"{bytesPerSecond} B/s";
            else if (bytesPerSecond < 1024 * 1024)
                return $"{bytesPerSecond / 1024.0:F1} KB/s";
            else if (bytesPerSecond < 1024 * 1024 * 1024)
                return $"{bytesPerSecond / 1024.0 / 1024.0:F2} MB/s";
            else
                return $"{bytesPerSecond / 1024.0 / 1024.0 / 1024.0:F2} GB/s";
        }

        private string FormatBytes(long bytes)
        {
            if (bytes < 1024)
                return $"{bytes} B";
            else if (bytes < 1024 * 1024)
                return $"{bytes / 1024.0:F1} KB";
            else if (bytes < 1024 * 1024 * 1024)
                return $"{bytes / 1024.0 / 1024.0:F2} MB";
            else
                return $"{bytes / 1024.0 / 1024.0 / 1024.0:F2} GB";
        }
    }
}
