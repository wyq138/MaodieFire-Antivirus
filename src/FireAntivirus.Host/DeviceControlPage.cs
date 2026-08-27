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
    public partial class DeviceControlPage : UserControl, IThemed
    {
        private LanguageManager _languageManager = LanguageManager.Instance;

        public DeviceControlPage()
        {
            InitializeComponent();
            UpdateUI();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            
            // DeviceControlPage
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Name = "DeviceControlPage";
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

        private CheckBox enableDeviceControlCheckBox;
        private CheckBox blockUSBCheckBox;
        private CheckBox blockBluetoothCheckBox;
        private DeviceControlService deviceControlService;

        private void UpdateUI()
        {
            // 清空现有控件
            this.Controls.Clear();

            // 创建标题
            var titleLabel = new Label
            {
                Text = "设备控制",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.FromArgb(25, 118, 210),
                Location = new Point(20, 20),
                AutoSize = true
            };
            this.Controls.Add(titleLabel);

            // 创建描述
            var descriptionLabel = new Label
            {
                Text = "管理和控制设备访问权限",
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

            // 设备管理
            var deviceGroup = new GroupBox
            {
                Text = "设备管理",
                Location = new Point(0, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(deviceGroup);

            enableDeviceControlCheckBox = new CheckBox
            {
                Text = "启用设备控制",
                Location = new Point(10, 30),
                AutoSize = true
            };
            deviceGroup.Controls.Add(enableDeviceControlCheckBox);

            var viewDevicesButton = new Button
            {
                Text = "查看设备",
                Location = new Point(10, 60),
                Size = new Size(100, 30),
                BackColor = Color.FromArgb(25, 118, 210),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            viewDevicesButton.FlatAppearance.BorderSize = 0;
            viewDevicesButton.Click += ViewDevicesButton_Click;
            deviceGroup.Controls.Add(viewDevicesButton);

            // 设备权限
            var permissionGroup = new GroupBox
            {
                Text = "设备权限",
                Location = new Point(340, 0),
                Size = new Size(320, 180)
            };
            featurePanel.Controls.Add(permissionGroup);

            blockUSBCheckBox = new CheckBox
            {
                Text = "阻止USB设备",
                Location = new Point(10, 30),
                AutoSize = true
            };
            permissionGroup.Controls.Add(blockUSBCheckBox);

            blockBluetoothCheckBox = new CheckBox
            {
                Text = "阻止蓝牙设备",
                Location = new Point(10, 55),
                AutoSize = true
            };
            permissionGroup.Controls.Add(blockBluetoothCheckBox);

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

            // 初始化设备控制服务
            InitializeDeviceControlService();
        }

        private void InitializeDeviceControlService()
        {
            try
            {
                var dataManager = new DataManager();
                deviceControlService = new DeviceControlService(dataManager);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"初始化设备控制服务失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ViewDevicesButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 查看设备
                var devicesForm = new Form
                {
                    Text = "连接的设备",
                    Size = new Size(500, 400)
                };
                
                var listBox = new ListBox
                {
                    Dock = DockStyle.Fill
                };
                
                // 获取真实的设备列表
                var devices = deviceControlService.GetDevices();
                foreach (var device in devices)
                {
                    listBox.Items.Add($"设备: {device.Name}, 类型: {device.Type}, 状态: {device.Status}");
                }
                
                devicesForm.Controls.Add(listBox);
                devicesForm.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"查看设备失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ApplyButton_Click(object sender, EventArgs e)
        {
            try
            {
                // 应用设置到后端
                deviceControlService.UpdateSettings(
                    enableDeviceControlCheckBox.Checked,
                    blockUSBCheckBox.Checked,
                    blockBluetoothCheckBox.Checked
                );
                
                // 启动或停止设备控制服务
                if (enableDeviceControlCheckBox.Checked)
                {
                    deviceControlService.Start();
                }
                else
                {
                    deviceControlService.Stop();
                }
                
                MessageBox.Show("设备控制设置已应用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"应用设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}