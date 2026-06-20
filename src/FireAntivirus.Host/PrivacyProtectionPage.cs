using System;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host
{
    public class PrivacyProtectionPage : UserControl
    {
        private readonly LanguageManager _languageManager;
        private FlowLayoutPanel flowLayoutPanel1;
        private Label titleLabel;
        private Label descriptionLabel;
        private Button scanButton;
        private Button cleanupButton;
        private Button settingsButton;

        public PrivacyProtectionPage()
        {
            _languageManager = LanguageManager.Instance;
            InitializeComponent();
            UpdateUI();
            LanguageManager.GlobalLanguageChanged += (sender, e) => { UpdateUI(); };
        }

        private void InitializeComponent()
        {
            flowLayoutPanel1 = new FlowLayoutPanel();
            titleLabel = new Label();
            descriptionLabel = new Label();
            scanButton = new Button();
            cleanupButton = new Button();
            settingsButton = new Button();
            SuspendLayout();
            // 
            // flowLayoutPanel1
            // 
            flowLayoutPanel1.Dock = DockStyle.Fill;
            flowLayoutPanel1.FlowDirection = FlowDirection.TopDown;
            flowLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            flowLayoutPanel1.Name = "flowLayoutPanel1";
            flowLayoutPanel1.Padding = new Padding(20);
            flowLayoutPanel1.Size = new System.Drawing.Size(800, 600);
            flowLayoutPanel1.TabIndex = 0;
            // 
            // titleLabel
            // 
            titleLabel.AutoSize = true;
            titleLabel.Font = new System.Drawing.Font("Microsoft YaHei", 24F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            titleLabel.Location = new System.Drawing.Point(23, 20);
            titleLabel.Name = "titleLabel";
            titleLabel.Size = new System.Drawing.Size(180, 41);
            titleLabel.TabIndex = 0;
            // 
            // descriptionLabel
            // 
            descriptionLabel.AutoSize = true;
            descriptionLabel.Font = new System.Drawing.Font("Microsoft YaHei", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            descriptionLabel.Location = new System.Drawing.Point(23, 70);
            descriptionLabel.Name = "descriptionLabel";
            descriptionLabel.Size = new System.Drawing.Size(400, 21);
            descriptionLabel.TabIndex = 1;
            // 
            // scanButton
            // 
            scanButton.Font = new System.Drawing.Font("Microsoft YaHei", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            scanButton.Location = new System.Drawing.Point(23, 100);
            scanButton.Name = "scanButton";
            scanButton.Size = new System.Drawing.Size(150, 40);
            scanButton.TabIndex = 2;
            scanButton.Click += new System.EventHandler(scanButton_Click);
            // 
            // cleanupButton
            // 
            cleanupButton.Font = new System.Drawing.Font("Microsoft YaHei", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            cleanupButton.Location = new System.Drawing.Point(180, 100);
            cleanupButton.Name = "cleanupButton";
            cleanupButton.Size = new System.Drawing.Size(150, 40);
            cleanupButton.TabIndex = 3;
            cleanupButton.Click += new System.EventHandler(cleanupButton_Click);
            // 
            // settingsButton
            // 
            settingsButton.Font = new System.Drawing.Font("Microsoft YaHei", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            settingsButton.Location = new System.Drawing.Point(337, 100);
            settingsButton.Name = "settingsButton";
            settingsButton.Size = new System.Drawing.Size(150, 40);
            settingsButton.TabIndex = 4;
            settingsButton.Click += new System.EventHandler(settingsButton_Click);
            // 
            // PrivacyProtectionPage
            // 
            Controls.Add(flowLayoutPanel1);
            flowLayoutPanel1.Controls.Add(titleLabel);
            flowLayoutPanel1.Controls.Add(descriptionLabel);
            flowLayoutPanel1.Controls.Add(scanButton);
            flowLayoutPanel1.Controls.Add(cleanupButton);
            flowLayoutPanel1.Controls.Add(settingsButton);
            Name = "PrivacyProtectionPage";
            Size = new System.Drawing.Size(800, 600);
            ResumeLayout(false);
            PerformLayout();
        }

        private void UpdateUI()
        {
            titleLabel.Text = _languageManager.GetString("PrivacyProtection");
            descriptionLabel.Text = _languageManager.GetString("PrivacyProtectionDescription");
            scanButton.Text = _languageManager.GetString("Scan");
            cleanupButton.Text = _languageManager.GetString("Cleanup");
            settingsButton.Text = _languageManager.GetString("PrivacySettings");
        }

        private void scanButton_Click(object sender, EventArgs e)
        {
            // 执行隐私扫描
            MessageBox.Show(_languageManager.GetString("ScanStarted"), _languageManager.GetString("PrivacyProtection"), MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void cleanupButton_Click(object sender, EventArgs e)
        {
            // 执行隐私清理
            MessageBox.Show(_languageManager.GetString("CleanupStarted"), _languageManager.GetString("PrivacyProtection"), MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void settingsButton_Click(object sender, EventArgs e)
        {
            // 打开隐私设置
            MessageBox.Show(_languageManager.GetString("SettingsOpened"), _languageManager.GetString("PrivacyProtection"), MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}