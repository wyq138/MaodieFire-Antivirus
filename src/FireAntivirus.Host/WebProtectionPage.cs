// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;
using FireAntivirus.Services;
using FireAntivirus.Data;

namespace FireAntivirus.Host
{
    public partial class WebProtectionPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;

        public WebProtectionPage()
        {
            InitializeComponent();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // WebProtectionPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "WebProtectionPage";
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

        private CheckBox enableWebsiteBlockCheckBox;
        private CheckBox blockPhishingCheckBox;
        private CheckBox blockMalwareCheckBox;
        private CheckBox enableAdBlockCheckBox;
        private CheckBox blockPopupsCheckBox;
        private CheckBox blockTrackersCheckBox;

        private void UpdateUI()
        {
            // 清空现有控件
            this.Controls.Clear();

            // 创建标题
            var titleLabel = new Label
            {
                Text = "网页防护",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 创建描述
            var descriptionLabel = new Label
            {
                Text = "保护您的浏览器免受恶意网站和网络威胁",
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

            // 恶意网站拦截
            var websiteBlockGroup = new GroupBox
            {
                Text = "恶意网站拦截",
                Location = new Point(0, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(websiteBlockGroup);

            enableWebsiteBlockCheckBox = new CheckBox
            {
                Text = "启用恶意网站拦截",
                Location = new Point(10, 30),
                AutoSize = true
            };
            websiteBlockGroup.Controls.Add(enableWebsiteBlockCheckBox);

            blockPhishingCheckBox = new CheckBox
            {
                Text = "阻止钓鱼网站",
                Location = new Point(30, 55),
                AutoSize = true
            };
            websiteBlockGroup.Controls.Add(blockPhishingCheckBox);

            blockMalwareCheckBox = new CheckBox
            {
                Text = "阻止恶意软件网站",
                Location = new Point(30, 80),
                AutoSize = true
            };
            websiteBlockGroup.Controls.Add(blockMalwareCheckBox);

            // 广告拦截
            var adBlockGroup = new GroupBox
            {
                Text = "广告拦截",
                Location = new Point(340, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(adBlockGroup);

            enableAdBlockCheckBox = new CheckBox
            {
                Text = "启用广告拦截",
                Location = new Point(10, 30),
                AutoSize = true
            };
            adBlockGroup.Controls.Add(enableAdBlockCheckBox);

            blockPopupsCheckBox = new CheckBox
            {
                Text = "阻止弹出窗口",
                Location = new Point(30, 55),
                AutoSize = true
            };
            adBlockGroup.Controls.Add(blockPopupsCheckBox);

            blockTrackersCheckBox = new CheckBox
            {
                Text = "阻止跟踪器",
                Location = new Point(30, 80),
                AutoSize = true
            };
            adBlockGroup.Controls.Add(blockTrackersCheckBox);

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
                var webProtection = new WebProtection(dataManager, new FireAntivirus.Engine.AntivirusEngine());
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
                var webProtection = new WebProtection(dataManager, new FireAntivirus.Engine.AntivirusEngine());
                
                // 准备被阻止的网站和广告域名列表
                var blockedWebsites = new List<string>();
                if (blockPhishingCheckBox.Checked) blockedWebsites.Add("phishing");
                if (blockMalwareCheckBox.Checked) blockedWebsites.Add("malware");
                
                var adDomains = new List<string>();
                if (blockPopupsCheckBox.Checked) adDomains.Add("popup");
                if (blockTrackersCheckBox.Checked) adDomains.Add("tracker");
                
                // 更新设置
                webProtection.UpdateSettings(
                    enableWebsiteBlockCheckBox.Checked,
                    enableAdBlockCheckBox.Checked,
                    blockedWebsites,
                    adDomains
                );
                
                // 启动网页防护服务
                webProtection.Start();
                
                MessageBox.Show("网页防护设置已应用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}