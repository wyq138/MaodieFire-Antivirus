// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;
using FireAntivirus.Data;

namespace FireAntivirus.Host
{
    public partial class ApplicationMonitorPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;

        public ApplicationMonitorPage()
        {
            InitializeComponent();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // ApplicationMonitorPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "ApplicationMonitorPage";
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

        private ApplicationMonitor applicationMonitor;

        private void UpdateUI()
        {
            // 清空现有控件
            this.Controls.Clear();

            // 创建标题
            var titleLabel = new Label
            {
                Text = "应用监控",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 创建描述
            var descriptionLabel = new Label
            {
                Text = "监控应用程序的行为和资源使用",
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

            // 应用监控
            var monitorGroup = new GroupBox
            {
                Text = "应用监控",
                Location = new Point(0, 0),
                Size = new Size(660, 200)
            };
            featurePanel.Controls.Add(monitorGroup);

            var startMonitoringButton = new Button
            {
                Text = "开始监控",
                Location = new Point(250, 30),
                Size = new Size(120, 40),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 10, FontStyle.Bold)
            };
            startMonitoringButton.FlatAppearance.BorderSize = 0;
            startMonitoringButton.Click += StartMonitoringButton_Click;
            monitorGroup.Controls.Add(startMonitoringButton);

            var viewApplicationsButton = new Button
            {
                Text = "查看应用程序",
                Location = new Point(250, 80),
                Size = new Size(120, 40),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            viewApplicationsButton.FlatAppearance.BorderSize = 0;
            viewApplicationsButton.Click += ViewApplicationsButton_Click;
            monitorGroup.Controls.Add(viewApplicationsButton);

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

            // 初始化应用监控
            InitializeApplicationMonitor();
        }

        private void InitializeApplicationMonitor()
        {
            try
            {
                var dataManager = new DataManager();
                applicationMonitor = new ApplicationMonitor(dataManager);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"初始化应用监控失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StartMonitoringButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 开始监控
                applicationMonitor.Start();
                MessageBox.Show("应用监控已开始", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"开始监控失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ViewApplicationsButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 查看应用程序
                var appListForm = new Form
                {
                    Text = "运行中的应用程序",
                    Size = new Size(500, 400)
                };
                
                var listBox = new ListBox
                {
                    Dock = DockStyle.Fill
                };
                
                // 获取真实的应用程序列表
                var applications = applicationMonitor.GetRunningProcesses();
                foreach (var app in applications)
                {
                    listBox.Items.Add($"{app.ProcessName} (PID: {app.ProcessId})");
                }
                
                appListForm.Controls.Add(listBox);
                appListForm.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"查看应用程序失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                    Type = "ApplicationMonitorSettings",
                    Message = "应用监控设置已更新",
                    Details = "应用监控设置已应用"
                });
                
                MessageBox.Show("应用监控设置已应用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}