// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;
using FireAntivirus.Data;

namespace FireAntivirus.Host
{
    public partial class CloudScannerPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;

        public CloudScannerPage()
        {
            InitializeComponent();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // CloudScannerPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "CloudScannerPage";
            this.Size = new System.Drawing.Size(700, 580);
            this.ResumeLayout(false);
        }

        public void ApplyTheme(Theme theme)
        {
            // 应用主题
            if (theme == Theme.Dark)
            {
                this.BackColor = Color.FromArgb(30, 30, 30);
            }
            else
            {
                this.BackColor = Color.White;
            }
        }

        private CloudScannerService cloudScannerService;

        private void UpdateUI()
        {
            // 清空现有控件
            this.Controls.Clear();

            // 创建标题
            var titleLabel = new Label
            {
                Text = "云查杀",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 创建描述
            var descriptionLabel = new Label
            {
                Text = "使用云服务进行文件扫描和URL安全检查",
                Font = new Font("微软雅黑", 12),
                ForeColor = Color.Gray,
                Location = new Point(20, 50),
                AutoSize = true
            };
            this.Controls.Add(descriptionLabel);

            // 创建功能区域
            var featurePanel = new Panel
            {
                Location = new Point(20, 80),
                Size = new Size(660, 480),
                BackColor = Color.Transparent
            };
            this.Controls.Add(featurePanel);

            // 云扫描
            var cloudScanGroup = new GroupBox
            {
                Text = "云扫描",
                Location = new Point(0, 0),
                Size = new Size(660, 200)
            };
            featurePanel.Controls.Add(cloudScanGroup);

            var fileScanButton = new Button
            {
                Text = "扫描文件",
                Location = new Point(100, 30),
                Size = new Size(120, 40),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            fileScanButton.FlatAppearance.BorderSize = 0;
            fileScanButton.Click += FileScanButton_Click;
            cloudScanGroup.Controls.Add(fileScanButton);

            var urlScanButton = new Button
            {
                Text = "扫描URL",
                Location = new Point(250, 30),
                Size = new Size(120, 40),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            urlScanButton.FlatAppearance.BorderSize = 0;
            urlScanButton.Click += UrlScanButton_Click;
            cloudScanGroup.Controls.Add(urlScanButton);

            var directoryScanButton = new Button
            {
                Text = "扫描目录",
                Location = new Point(400, 30),
                Size = new Size(120, 40),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            directoryScanButton.FlatAppearance.BorderSize = 0;
            directoryScanButton.Click += DirectoryScanButton_Click;
            cloudScanGroup.Controls.Add(directoryScanButton);

            // 应用按钮
            var applyButton = new Button
            {
                Text = "应用设置",
                Location = new Point(250, 220),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            applyButton.FlatAppearance.BorderSize = 0;
            applyButton.Click += ApplyButton_Click;
            featurePanel.Controls.Add(applyButton);

            // 初始化云扫描服务
            InitializeCloudScannerService();
        }

        private void InitializeCloudScannerService()
        {
            try
            {
                var dataManager = new DataManager();
                var antivirusEngine = new FireAntivirus.Engine.AntivirusEngine();
                cloudScannerService = new CloudScannerService(dataManager, antivirusEngine);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"初始化云扫描服务失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void FileScanButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 扫描文件
                using (var openFileDialog = new OpenFileDialog())
                {
                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        var result = await cloudScannerService.ScanFile(openFileDialog.FileName);
                        string status = result.IsInfected ? "感染" : "安全";
                        MessageBox.Show("扫描结果: " + status, "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"文件扫描失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void UrlScanButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 扫描URL
                var urlForm = new Form
                {
                    Text = "输入URL",
                    Size = new Size(400, 150)
                };
                
                var urlLabel = new Label
                {
                    Text = "URL:",
                    Location = new Point(20, 30),
                    AutoSize = true
                };
                urlForm.Controls.Add(urlLabel);
                
                var urlTextBox = new TextBox
                {
                    Location = new Point(60, 30),
                    Size = new Size(300, 20)
                };
                urlForm.Controls.Add(urlTextBox);
                
                var scanButton = new Button
                {
                    Text = "扫描",
                    Location = new Point(150, 70),
                    Size = new Size(100, 30)
                };
                scanButton.Click += async (s, args) =>
                {
                    try
                    {
                        var result = await cloudScannerService.ScanUrl(urlTextBox.Text);
                        string status = result.IsInfected ? "恶意" : "安全";
                        MessageBox.Show("URL扫描结果: " + status, "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        urlForm.Close();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"URL扫描失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                };
                urlForm.Controls.Add(scanButton);
                
                urlForm.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"URL扫描失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void DirectoryScanButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 扫描目录
                using (var folderBrowser = new FolderBrowserDialog())
                {
                    if (folderBrowser.ShowDialog() == DialogResult.OK)
                    {
                        var result = await cloudScannerService.ScanDirectory(folderBrowser.SelectedPath);
                        string status = result.IsInfected ? "发现病毒" : "未发现病毒";
                        MessageBox.Show("目录扫描结果: " + status, "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"目录扫描失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ApplyButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 应用设置
                var dataManager = new DataManager();
                dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "CloudScannerSettings",
                    Message = "云查杀设置已更新",
                    Details = "云查杀设置已应用"
                });
                
                MessageBox.Show("云查杀设置已应用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}