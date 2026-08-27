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
    public partial class BehaviorAnalysisPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;

        public BehaviorAnalysisPage()
        {
            InitializeComponent();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // BehaviorAnalysisPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "BehaviorAnalysisPage";
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

        private BehaviorAnalysisService behaviorAnalysisService;

        private void UpdateUI()
        {
            // 清空现有控件
            this.Controls.Clear();

            // 创建标题
            var titleLabel = new Label
            {
                Text = "行为分析",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 创建描述
            var descriptionLabel = new Label
            {
                Text = "分析应用程序的行为，检测可疑活动",
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

            // 行为分析
            var analysisGroup = new GroupBox
            {
                Text = "行为分析",
                Location = new Point(0, 0),
                Size = new Size(660, 200)
            };
            featurePanel.Controls.Add(analysisGroup);

            var startAnalysisButton = new Button
            {
                Text = "开始分析",
                Location = new Point(250, 30),
                Size = new Size(120, 40),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("微软雅黑", 10, FontStyle.Bold)
            };
            startAnalysisButton.FlatAppearance.BorderSize = 0;
            startAnalysisButton.Click += StartAnalysisButton_Click;
            analysisGroup.Controls.Add(startAnalysisButton);

            var viewResultsButton = new Button
            {
                Text = "查看分析结果",
                Location = new Point(250, 80),
                Size = new Size(120, 40),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            viewResultsButton.FlatAppearance.BorderSize = 0;
            viewResultsButton.Click += ViewResultsButton_Click;
            analysisGroup.Controls.Add(viewResultsButton);

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

            // 初始化行为分析服务
            InitializeBehaviorAnalysisService();
        }

        private void InitializeBehaviorAnalysisService()
        {
            try
            {
                var dataManager = new DataManager();
                behaviorAnalysisService = new BehaviorAnalysisService(dataManager);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"初始化行为分析服务失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StartAnalysisButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 开始分析
                behaviorAnalysisService.Start();
                MessageBox.Show("行为分析已开始", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"开始分析失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ViewResultsButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 查看分析结果
                var resultsForm = new Form
                {
                    Text = "行为分析结果",
                    Size = new Size(500, 400)
                };
                
                var listBox = new ListBox
                {
                    Dock = DockStyle.Fill
                };
                
                // 获取真实的分析结果
                var behaviors = behaviorAnalysisService.GetProcessBehaviors();
                foreach (var behavior in behaviors)
                {
                    listBox.Items.Add($"进程: {behavior.ProcessName} (PID: {behavior.ProcessId})");
                    if (behavior.FileSystemEvents != null && behavior.FileSystemEvents.Count > 0)
                    {
                        listBox.Items.Add($"  文件系统访问: {behavior.FileSystemEvents.Count} 次");
                    }
                    if (behavior.RegistryEvents != null && behavior.RegistryEvents.Count > 0)
                    {
                        listBox.Items.Add($"  注册表访问: {behavior.RegistryEvents.Count} 次");
                    }
                    if (behavior.NetworkEvents != null && behavior.NetworkEvents.Count > 0)
                    {
                        listBox.Items.Add($"  网络访问: {behavior.NetworkEvents.Count} 次");
                    }
                }
                
                resultsForm.Controls.Add(listBox);
                resultsForm.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"查看分析结果失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                    Type = "BehaviorAnalysisSettings",
                    Message = "行为分析设置已更新",
                    Details = "行为分析设置已应用"
                });
                
                MessageBox.Show("行为分析设置已应用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}