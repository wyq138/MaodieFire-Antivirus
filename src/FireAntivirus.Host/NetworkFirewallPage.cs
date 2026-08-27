// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;
using FireAntivirus.Data;
using FireAntivirus.Services;
using FireAntivirus.Engine;

namespace FireAntivirus.Host
{
    public partial class NetworkFirewallPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;

        public NetworkFirewallPage()
        {
            InitializeComponent();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // NetworkFirewallPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "NetworkFirewallPage";
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

        private CheckBox enableFirewallCheckBox;
        private CheckBox blockIncomingCheckBox;
        private FirewallManager networkFirewall;

        private void UpdateUI()
        {
            // 清空现有控件
            this.Controls.Clear();

            // 创建标题
            var titleLabel = new Label
            {
                Text = "网络防火墙",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 创建描述
            var descriptionLabel = new Label
            {
                Text = "保护您的网络安全，阻止未经授权的访问",
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

            // 防火墙设置
            var firewallGroup = new GroupBox
            {
                Text = "防火墙设置",
                Location = new Point(0, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(firewallGroup);

            enableFirewallCheckBox = new CheckBox
            {
                Text = "启用网络防火墙",
                Location = new Point(10, 30),
                AutoSize = true
            };
            firewallGroup.Controls.Add(enableFirewallCheckBox);

            blockIncomingCheckBox = new CheckBox
            {
                Text = "阻止入站连接",
                Location = new Point(30, 55),
                AutoSize = true
            };
            firewallGroup.Controls.Add(blockIncomingCheckBox);

            // 应用规则
            var rulesGroup = new GroupBox
            {
                Text = "应用规则",
                Location = new Point(340, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(rulesGroup);

            var viewRulesButton = new Button
            {
                Text = "查看规则",
                Location = new Point(10, 30),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            viewRulesButton.FlatAppearance.BorderSize = 0;
            viewRulesButton.Click += ViewRulesButton_Click;
            rulesGroup.Controls.Add(viewRulesButton);

            var addRuleButton = new Button
            {
                Text = "添加规则",
                Location = new Point(10, 70),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            addRuleButton.FlatAppearance.BorderSize = 0;
            addRuleButton.Click += AddRuleButton_Click;
            rulesGroup.Controls.Add(addRuleButton);

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

            // 初始化网络防火墙服务
            InitializeNetworkFirewall();
        }

        private void InitializeNetworkFirewall()
        {
            try
            {
                var dataManager = new DataManager();
                var antivirusEngine = new AntivirusEngine();
                networkFirewall = new FirewallManager(dataManager, antivirusEngine);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"初始化网络防火墙服务失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ViewRulesButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 查看规则
                var rulesForm = new Form
                {
                    Text = "防火墙规则",
                    Size = new Size(500, 400)
                };
                
                var listBox = new ListBox
                {
                    Dock = DockStyle.Fill
                };
                
                // 获取真实的规则列表
                var rules = networkFirewall.GetRules();
                foreach (var rule in rules)
                {
                    listBox.Items.Add($"{rule.Action} [{rule.Direction}] {rule.Name} - {(string.IsNullOrEmpty(rule.ApplicationPath) ? rule.RemoteIP ?? rule.LocalPort : rule.ApplicationPath)}");
                }
                
                rulesForm.Controls.Add(listBox);
                rulesForm.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"查看规则失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AddRuleButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 添加规则
                var ruleForm = new Form
                {
                    Text = "添加防火墙规则",
                    Size = new Size(400, 250)
                };
                
                var typeLabel = new Label
                {
                    Text = "规则类型:",
                    Location = new Point(20, 30),
                    AutoSize = true
                };
                ruleForm.Controls.Add(typeLabel);
                
                var typeComboBox = new ComboBox
                {
                    Location = new Point(100, 30),
                    Size = new Size(250, 20)
                };
                typeComboBox.Items.AddRange(new string[] { "阻止应用", "阻止IP", "阻止端口" });
                typeComboBox.SelectedIndex = 0;
                ruleForm.Controls.Add(typeComboBox);
                
                var valueLabel = new Label
                {
                    Text = "应用路径/IP/端口:",
                    Location = new Point(20, 70),
                    AutoSize = true
                };
                ruleForm.Controls.Add(valueLabel);
                
                var valueTextBox = new TextBox
                {
                    Location = new Point(100, 70),
                    Size = new Size(250, 20)
                };
                ruleForm.Controls.Add(valueTextBox);
                
                var addButton = new Button
                {
                    Text = "添加",
                    Location = new Point(150, 120),
                    Size = new Size(100, 30)
                };
                addButton.Click += (s, args) =>
                {
                    try
                    {
                        string type = typeComboBox.SelectedItem.ToString();
                        string value = valueTextBox.Text;
                        
                        if (string.IsNullOrEmpty(value))
                        {
                            MessageBox.Show("请输入规则值", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                            return;
                        }
                        
                        // 根据规则类型调用相应的后端方法
                        switch (type)
                        {
                            case "阻止应用":
                                networkFirewall.BlockApplication(value);
                                break;
                            case "阻止IP":
                                networkFirewall.BlockIPAddress(value, "手动添加");
                                break;
                            case "阻止端口":
                                if (int.TryParse(value, out int port))
                                    networkFirewall.BlockPort(port);
                                else
                                    MessageBox.Show("请输入有效的端口号", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                break;
                        }
                        
                        MessageBox.Show("规则添加成功", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        ruleForm.Close();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"添加规则失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                };
                ruleForm.Controls.Add(addButton);
                
                ruleForm.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"添加规则失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ApplyButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 应用设置到后端
                if (networkFirewall != null)
                {
                    networkFirewall.SetBlockAllIncoming(blockIncomingCheckBox.Checked);
                    
                    // 启动或停止网络防火墙服务
                    if (enableFirewallCheckBox.Checked)
                    {
                        networkFirewall.Start();
                    }
                    else
                    {
                        networkFirewall.Stop();
                    }
                }
                
                MessageBox.Show("网络防火墙设置已应用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}