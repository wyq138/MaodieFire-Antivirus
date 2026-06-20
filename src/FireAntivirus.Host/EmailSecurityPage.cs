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
    public partial class EmailSecurityPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;

        public EmailSecurityPage()
        {
            InitializeComponent();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // EmailSecurityPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "EmailSecurityPage";
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

        private CheckBox enableAttachmentScanCheckBox;
        private CheckBox scanAllAttachmentsCheckBox;
        private CheckBox enablePhishingDetectionCheckBox;
        private CheckBox blockSuspiciousLinksCheckBox;

        private void UpdateUI()
        {
            // 清空现有控件
            this.Controls.Clear();

            // 创建标题
            var titleLabel = new Label
            {
                Text = "邮件安全",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 创建描述
            var descriptionLabel = new Label
            {
                Text = "保护您的电子邮件免受恶意附件和钓鱼邮件",
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

            // 邮件附件扫描
            var attachmentScanGroup = new GroupBox
            {
                Text = "邮件附件扫描",
                Location = new Point(0, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(attachmentScanGroup);

            enableAttachmentScanCheckBox = new CheckBox
            {
                Text = "启用邮件附件扫描",
                Location = new Point(10, 30),
                AutoSize = true
            };
            attachmentScanGroup.Controls.Add(enableAttachmentScanCheckBox);

            scanAllAttachmentsCheckBox = new CheckBox
            {
                Text = "扫描所有附件类型",
                Location = new Point(30, 55),
                AutoSize = true
            };
            attachmentScanGroup.Controls.Add(scanAllAttachmentsCheckBox);

            // 钓鱼邮件检测
            var phishingGroup = new GroupBox
            {
                Text = "钓鱼邮件检测",
                Location = new Point(340, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(phishingGroup);

            enablePhishingDetectionCheckBox = new CheckBox
            {
                Text = "启用钓鱼邮件检测",
                Location = new Point(10, 30),
                AutoSize = true
            };
            phishingGroup.Controls.Add(enablePhishingDetectionCheckBox);

            blockSuspiciousLinksCheckBox = new CheckBox
            {
                Text = "阻止可疑链接",
                Location = new Point(30, 55),
                AutoSize = true
            };
            phishingGroup.Controls.Add(blockSuspiciousLinksCheckBox);

            // 应用按钮
            var applyButton = new Button
            {
                Text = "应用设置",
                Location = new Point(250, 200),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            applyButton.FlatAppearance.BorderSize = 0;
            applyButton.Click += ApplyButton_Click;
            featurePanel.Controls.Add(applyButton);

            // 加载当前设置
            LoadCurrentSettings();
        }

        private void LoadCurrentSettings()
        {
            try
            {
                // 从后端加载当前设置
                var dataManager = new DataManager();
                var emailSecurity = new EmailSecurity(dataManager, new FireAntivirus.Engine.AntivirusEngine());
                // 这里可以添加加载设置的逻辑
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ApplyButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 应用设置到后端
                var dataManager = new DataManager();
                var emailSecurity = new EmailSecurity(dataManager, new FireAntivirus.Engine.AntivirusEngine());
                
                // 更新设置
                emailSecurity.UpdateSettings(
                    enableAttachmentScanCheckBox.Checked,
                    enablePhishingDetectionCheckBox.Checked,
                    scanAllAttachmentsCheckBox.Checked
                );
                
                // 启动邮件安全服务
                emailSecurity.Start();
                
                MessageBox.Show("邮件安全设置已应用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}