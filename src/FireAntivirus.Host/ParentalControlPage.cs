using System;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host
{
    public class ParentalControlPage : UserControl
    {
        private readonly LanguageManager _languageManager;
        private FlowLayoutPanel flowLayoutPanel1;
        private Label titleLabel;
        private Label descriptionLabel;
        private Button settingsButton;
        private Button monitorButton;

        public ParentalControlPage()
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
            settingsButton = new Button();
            monitorButton = new Button();
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
            // settingsButton
            // 
            settingsButton.Font = new System.Drawing.Font("Microsoft YaHei", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            settingsButton.Location = new System.Drawing.Point(23, 100);
            settingsButton.Name = "settingsButton";
            settingsButton.Size = new System.Drawing.Size(150, 40);
            settingsButton.TabIndex = 2;
            settingsButton.Click += new System.EventHandler(settingsButton_Click);
            // 
            // monitorButton
            // 
            monitorButton.Font = new System.Drawing.Font("Microsoft YaHei", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(134)));
            monitorButton.Location = new System.Drawing.Point(180, 100);
            monitorButton.Name = "monitorButton";
            monitorButton.Size = new System.Drawing.Size(150, 40);
            monitorButton.TabIndex = 3;
            monitorButton.Click += new System.EventHandler(monitorButton_Click);
            // 
            // ParentalControlPage
            // 
            Controls.Add(flowLayoutPanel1);
            flowLayoutPanel1.Controls.Add(titleLabel);
            flowLayoutPanel1.Controls.Add(descriptionLabel);
            flowLayoutPanel1.Controls.Add(settingsButton);
            flowLayoutPanel1.Controls.Add(monitorButton);
            Name = "ParentalControlPage";
            Size = new System.Drawing.Size(800, 600);
            ResumeLayout(false);
            PerformLayout();
        }

        private void UpdateUI()
        {
            titleLabel.Text = _languageManager.GetString("ParentalControl");
            descriptionLabel.Text = _languageManager.GetString("ParentalControlDescription");
            settingsButton.Text = _languageManager.GetString("Settings");
            monitorButton.Text = _languageManager.GetString("Monitor");
        }

        private void settingsButton_Click(object sender, EventArgs e)
        {
            // 打开家长控制设置
            MessageBox.Show(_languageManager.GetString("SettingsOpened"), _languageManager.GetString("ParentalControl"), MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void monitorButton_Click(object sender, EventArgs e)
        {
            // 启动监控
            MessageBox.Show(_languageManager.GetString("MonitoringStarted"), _languageManager.GetString("ParentalControl"), MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}