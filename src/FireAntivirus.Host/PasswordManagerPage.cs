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
    public partial class PasswordManagerPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;

        public PasswordManagerPage()
        {
            InitializeComponent();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // PasswordManagerPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "PasswordManagerPage";
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

        private NumericUpDown passwordLengthUpDown;
        private CheckBox enablePasswordStorageCheckBox;

        private void UpdateUI()
        {
            // 清空现有控件
            this.Controls.Clear();

            // 创建标题
            var titleLabel = new Label
            {
                Text = "密码管理",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 创建描述
            var descriptionLabel = new Label
            {
                Text = "安全管理和生成强密码",
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

            // 密码生成器
            var passwordGeneratorGroup = new GroupBox
            {
                Text = "密码生成器",
                Location = new Point(0, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(passwordGeneratorGroup);

            var passwordLengthLabel = new Label
            {
                Text = "密码长度:",
                Location = new Point(10, 30),
                AutoSize = true
            };
            passwordGeneratorGroup.Controls.Add(passwordLengthLabel);

            passwordLengthUpDown = new NumericUpDown
            {
                Location = new Point(80, 28),
                Size = new Size(60, 20),
                Minimum = 8,
                Maximum = 32,
                Value = 16
            };
            passwordGeneratorGroup.Controls.Add(passwordLengthUpDown);

            var generateButton = new Button
            {
                Text = "生成密码",
                Location = new Point(10, 60),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            generateButton.FlatAppearance.BorderSize = 0;
            generateButton.Click += GenerateButton_Click;
            passwordGeneratorGroup.Controls.Add(generateButton);

            // 密码存储
            var passwordStorageGroup = new GroupBox
            {
                Text = "密码存储",
                Location = new Point(340, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(passwordStorageGroup);

            enablePasswordStorageCheckBox = new CheckBox
            {
                Text = "启用密码存储",
                Location = new Point(10, 30),
                AutoSize = true
            };
            passwordStorageGroup.Controls.Add(enablePasswordStorageCheckBox);

            var viewPasswordsButton = new Button
            {
                Text = "查看已存储密码",
                Location = new Point(10, 60),
                Size = new Size(120, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            viewPasswordsButton.FlatAppearance.BorderSize = 0;
            viewPasswordsButton.Click += ViewPasswordsButton_Click;
            passwordStorageGroup.Controls.Add(viewPasswordsButton);

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
                var passwordManager = new PasswordManager(dataManager);
                // 这里可以添加加载设置的逻辑
            }
            catch (Exception ex)
            {
                MessageBox.Show($"加载设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void GenerateButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 生成密码
                int length = (int)passwordLengthUpDown.Value;
                var passwordManager = new PasswordManager(new DataManager());
                string password = passwordManager.GeneratePassword(length);
                
                MessageBox.Show($"生成的密码: {password}", "密码生成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成密码失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ViewPasswordsButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 查看密码
                var passwordManager = new PasswordManager(new DataManager());
                var passwords = passwordManager.GetPasswords();
                
                var passwordListForm = new Form
                {
                    Text = "已存储的密码",
                    Size = new Size(500, 400)
                };
                
                var listBox = new ListBox
                {
                    Dock = DockStyle.Fill
                };
                
                foreach (var password in passwords)
                {
                    listBox.Items.Add($"{password.Website} - {password.Username}");
                }
                
                passwordListForm.Controls.Add(listBox);
                passwordListForm.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"查看密码失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ApplyButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 应用设置到后端
                var dataManager = new DataManager();
                var passwordManager = new PasswordManager(dataManager);
                
                // 更新设置
                passwordManager.UpdateSettings(enablePasswordStorageCheckBox.Checked);
                
                // 启动密码管理服务
                passwordManager.Start();
                
                MessageBox.Show("密码管理设置已应用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}