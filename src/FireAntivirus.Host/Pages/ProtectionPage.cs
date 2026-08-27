using System;
using System.Drawing;
using System.Windows.Forms;
using FireAntivirus.Services;

namespace FireAntivirus.Host
{
    public class ProtectionPage : UserControl, IThemed
    {
        private Panel protectionListPanel;
        private Theme currentTheme = Theme.Light;
        private NamedPipeClient pipeClient;

        public ProtectionPage(NamedPipeClient pipeClient = null)
        {
            try
            {
                this.pipeClient = pipeClient;
                // 只执行必要的UI初始化操作
                InitializeComponents();
            }
            catch (Exception ex)
            {
                // 记录错误并避免应用程序崩溃
                Console.WriteLine($"Error initializing ProtectionPage: {ex.Message}");
            }
        }

        private void InitializeComponents()
        {
            this.Dock = DockStyle.Fill;
            this.AutoScroll = true;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1,
                BackColor = GetThemeColor(ThemeColor.BgPrimary)
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var headerPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                Padding = new Padding(20, 15, 20, 15)
            };

            var titleLabel = new Label
            {
                Text = "实时防护",
                Font = new Font("微软雅黑", 16, FontStyle.Bold),
                ForeColor = Color.White,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Margin = new Padding(0, 0, 0, 0)
            };

            headerPanel.Controls.Add(titleLabel);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            protectionListPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(20),
                AutoScroll = true
            };

            var protectionLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                RowCount = 11,
                ColumnCount = 1,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                BackColor = Color.Transparent
            };

            for (int i = 0; i < 11; i++)
            {
                protectionLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
            }
            
            // 设置最小高度，确保所有内容都能显示
            protectionLayout.MinimumSize = new Size(0, 880);

            var protectionItems = new[]
            {
                new { Name = "文件实时防护", Description = "监控文件创建、修改、复制、移动等行为", Enabled = true },
                new { Name = "进程防护", Description = "拦截恶意进程启动、进程注入、内存篡改", Enabled = true },
                new { Name = "U盘防护", Description = "自动扫描插入的U盘、移动硬盘、存储卡", Enabled = true },
                new { Name = "注册表防护", Description = "拦截恶意修改注册表启动项、系统关键项", Enabled = true },
                new { Name = "浏览器防护", Description = "锁定浏览器主页、默认搜索引擎，禁止劫持", Enabled = true },
                new { Name = "脚本防护", Description = "拦截恶意JS、VBS、BAT、CMD、PowerShell脚本", Enabled = true },
                new { Name = "主动防御", Description = "通过行为分析识别未知病毒、新型木马", Enabled = true },
                new { Name = "分区表防护", Description = "检测并拦截恶意修改磁盘分区表行为", Enabled = true },
                new { Name = "UEFI/BIOS防护", Description = "监控UEFI引导项、BIOS设置修改，防止固件级攻击", Enabled = true },
                new { Name = "内核防护", Description = "保护系统内核，拦截驱动加载、内核模块篡改", Enabled = true },
                new { Name = "文档防护", Description = "防止批量篡改用户文档、文件加密勒索行为", Enabled = true }
            };

            for (int i = 0; i < protectionItems.Length; i++)
            {
                var item = protectionItems[i];
                var itemPanel = CreateProtectionItem(item.Name, item.Description, item.Enabled);
                protectionLayout.Controls.Add(itemPanel, 0, i);
            }

            protectionListPanel.Controls.Add(protectionLayout);
            mainLayout.Controls.Add(protectionListPanel, 0, 1);

            this.Controls.Add(mainLayout);
        }

        private Panel CreateProtectionItem(string name, string description, bool enabled)
        {
            var panel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.CardBg),
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 8, 0, 8)
            };

            var nameLabel = new Label
            {
                Text = name,
                Font = new Font("微软雅黑", 12, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                AutoSize = true,
                Location = new Point(20, 15)
            };

            var descLabel = new Label
            {
                Text = description,
                Font = new Font("微软雅黑", 9),
                ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                AutoSize = true,
                Location = new Point(20, 35)
            };

            var toggleSwitch = new ToggleSwitch
            {
                Location = new Point(0, 20),
                IsEnabled = enabled,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Size = new Size(60, 30),
                Enabled = true
            };
            
            // 监听面板大小变化事件，确保toggleSwitch位置始终正确
            panel.SizeChanged += (s, e) =>
            {
                toggleSwitch.Location = new Point(panel.ClientSize.Width - toggleSwitch.Width - 20, 20);
            };

            toggleSwitch.EnabledChanged += (s, e) =>
            {
                // 实际的防护开关逻辑
                var isEnabled = ((ToggleSwitch)s).IsEnabled;
                
                // 发送消息到后台，控制防护功能的开启和关闭
                if (pipeClient != null && pipeClient.IsConnected)
                {
                    Message message = new Message();
                    message.type = 4; // 防护控制消息
                    
                    // 根据防护名称设置威胁类型
                    switch (name)
                    {
                        case "文件实时防护":
                            message.threatInfo.type = NativeSecurityCoreWrapper.ConvertToThreatType(NativeThreatType.FILE_MALICIOUS);
                            break;
                        case "进程防护":
                            message.threatInfo.type = NativeSecurityCoreWrapper.ConvertToThreatType(NativeThreatType.PROCESS_MALICIOUS);
                            break;
                        case "U盘防护":
                            message.threatInfo.type = NativeSecurityCoreWrapper.ConvertToThreatType(NativeThreatType.DEVICE_UNAUTHORIZED);
                            break;
                        case "注册表防护":
                            message.threatInfo.type = NativeSecurityCoreWrapper.ConvertToThreatType(NativeThreatType.REGISTRY_TAMPERING);
                            break;
                        case "脚本防护":
                            message.threatInfo.type = NativeSecurityCoreWrapper.ConvertToThreatType(NativeThreatType.SCRIPT_MALICIOUS);
                            break;
                        case "主动防御":
                            message.threatInfo.type = NativeSecurityCoreWrapper.ConvertToThreatType(NativeThreatType.BEHAVIOR_MALICIOUS);
                            break;
                        case "文档防护":
                            message.threatInfo.type = NativeSecurityCoreWrapper.ConvertToThreatType(NativeThreatType.DOCUMENT_ENCRYPTION);
                            break;
                        case "分区表防护":
                        case "UEFI/BIOS防护":
                        case "内核防护":
                            message.threatInfo.type = NativeSecurityCoreWrapper.ConvertToThreatType(NativeThreatType.DISK_TAMPERING);
                            break;
                        default:
                            message.threatInfo.type = NativeSecurityCoreWrapper.ConvertToThreatType(NativeThreatType.FILE_MALICIOUS);
                            break;
                    }
                    
                    // 设置操作类型
                    message.action = isEnabled ? ThreatAction.ALLOW : ThreatAction.BLOCK;
                    
                    // 发送消息
                    pipeClient.SendMessage(message);
                }
                
                // 显示防护状态变更弹窗
                if (isEnabled)
                {
                    ShowProtectionAlert($"{name}已开启", $"{description}\n\n保护您的系统安全");
                }
                else
                {
                    ShowProtectionAlert($"{name}已关闭", $"{description}\n\n系统可能面临安全风险", true);
                }
            };

            panel.Controls.Add(nameLabel);
            panel.Controls.Add(descLabel);
            panel.Controls.Add(toggleSwitch);

            return panel;
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            
            // 更新所有子控件的样式
            UpdateControlsTheme(this);
        }
        
        private void UpdateControlsTheme(Control control)
        {
            foreach (Control child in control.Controls)
            {
                if (child is Panel panel)
                {
                    if (panel.BorderStyle != BorderStyle.None)
                    {
                        panel.BackColor = GetThemeColor(ThemeColor.CardBg);
                    }
                    else
                    {
                        panel.BackColor = GetThemeColor(ThemeColor.BgPrimary);
                    }
                }
                else if (child is Label label)
                {
                    // 确保使用微软雅黑字体
                    if (label.Font.Name != "微软雅黑")
                    {
                        label.Font = new Font("微软雅黑", label.Font.Size, label.Font.Style);
                    }
                    
                    if (label.Font.Bold)
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                    }
                    else
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
                    }
                }
                else if (child is ToggleSwitch toggle)
                {
                    toggle.Invalidate();
                }
                
                // 递归更新子控件
                UpdateControlsTheme(child);
            }
        }

        private void ShowProtectionAlert(string title, string message, bool isWarning = false)
        {
            // 在UI线程中显示弹窗
            this.BeginInvoke((Action)(() => {
                try
                {
                    using (var alertForm = new Form())
                    {
                        alertForm.Text = title;
                        alertForm.Size = new Size(400, 200);
                        alertForm.StartPosition = FormStartPosition.Manual;
                        // 设置弹窗位置为右下角
                        alertForm.Location = new Point(
                            Screen.PrimaryScreen.WorkingArea.Width - alertForm.Width - 10,
                            Screen.PrimaryScreen.WorkingArea.Height - alertForm.Height - 10
                        );
                        alertForm.FormBorderStyle = FormBorderStyle.FixedDialog;
                        alertForm.MaximizeBox = false;
                        alertForm.MinimizeBox = false;
                        
                        var label = new Label
                        {
                            Text = message,
                            Font = new Font("微软雅黑", 10),
                            Dock = DockStyle.Fill,
                            TextAlign = ContentAlignment.MiddleCenter,
                            Padding = new Padding(20)
                        };
                        
                        var button = new Button
                        {
                            Text = "确定",
                            DialogResult = DialogResult.OK,
                            Dock = DockStyle.Bottom,
                            Height = 40,
                            Font = new Font("微软雅黑", 10)
                        };
                        
                        if (isWarning)
                        {
                            alertForm.BackColor = Color.FromArgb(255, 248, 220);
                            label.ForeColor = Color.FromArgb(138, 83, 9);
                        }
                        else
                        {
                            alertForm.BackColor = Color.FromArgb(230, 245, 208);
                            label.ForeColor = Color.FromArgb(50, 96, 14);
                        }
                        
                        alertForm.Controls.Add(label);
                        alertForm.Controls.Add(button);
                        
                        alertForm.AcceptButton = button;
                        alertForm.ShowDialog();
                    }
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ProtectionPage.cs 捕获异常", ex.Message); }
            }));
        }

        private Color GetThemeColor(ThemeColor colorType)
        {
            if (currentTheme == Theme.Dark)
            {
                switch (colorType)
                {
                    case ThemeColor.TextPrimary:
                        return Color.White;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.FromArgb(30, 30, 30);
                    case ThemeColor.CardBg:
                        return Color.FromArgb(45, 45, 45);
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(60, 60, 60);
                    default:
                        return Color.Black;
                }
            }
            else
            {
                switch (colorType)
                {
                    case ThemeColor.TextPrimary:
                        return Color.Black;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.White;
                    case ThemeColor.CardBg:
                        return Color.White;
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(229, 231, 235);
                    default:
                        return Color.White;
                }
            }
        }

        public void UpdateProtectionStatus(System.Collections.Generic.Dictionary<string, bool> status)
        {
            try
            {
                // 遍历所有防护项，更新开关状态
                UpdateProtectionItemsStatus(status);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Update protection items error: {ex.Message}");
            }
        }

        private void UpdateProtectionItemsStatus(System.Collections.Generic.Dictionary<string, bool> status)
        {
            try
            {
                // 遍历保护列表面板中的所有控件
                foreach (Control control in protectionListPanel.Controls)
                {
                    if (control is TableLayoutPanel protectionLayout)
                    {
                        foreach (Control itemPanel in protectionLayout.Controls)
                        {
                            if (itemPanel is Panel)
                            {
                                // 查找面板中的标签和开关
                                Label nameLabel = null;
                                ToggleSwitch toggleSwitch = null;

                                foreach (Control child in itemPanel.Controls)
                                {
                                    if (child is Label label && label.Font.Bold)
                                    {
                                        nameLabel = label;
                                    }
                                    else if (child is ToggleSwitch toggle)
                                    {
                                        toggleSwitch = toggle;
                                    }
                                }

                                if (nameLabel != null && toggleSwitch != null)
                                {
                                    // 根据防护名称查找对应的状态
                                    string protectionName = nameLabel.Text;
                                    bool enabled = GetProtectionStatusByName(protectionName, status);

                                    // 更新开关状态
                                    toggleSwitch.IsEnabled = enabled;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Update protection items status error: {ex.Message}");
            }
        }

        private bool GetProtectionStatusByName(string protectionName, System.Collections.Generic.Dictionary<string, bool> status)
        {
            // 根据防护名称查找对应的状态
            switch (protectionName)
            {
                case "文件实时防护":
                    return status.TryGetValue("FileProtection", out bool fileEnabled) ? fileEnabled : true;
                case "进程防护":
                    return status.TryGetValue("ProcessProtection", out bool processEnabled) ? processEnabled : true;
                case "U盘防护":
                    return status.TryGetValue("USBProtection", out bool usbEnabled) ? usbEnabled : true;
                case "注册表防护":
                    return status.TryGetValue("RegistryProtection", out bool registryEnabled) ? registryEnabled : true;
                case "浏览器防护":
                    return status.TryGetValue("BrowserProtection", out bool browserEnabled) ? browserEnabled : true;
                case "脚本防护":
                    return status.TryGetValue("ScriptProtection", out bool scriptEnabled) ? scriptEnabled : true;
                case "主动防御":
                    return status.TryGetValue("BehaviorProtection", out bool behaviorEnabled) ? behaviorEnabled : true;
                case "分区表防护":
                    return status.TryGetValue("PartitionTableProtection", out bool partitionEnabled) ? partitionEnabled : true;
                case "UEFI/BIOS防护":
                    return status.TryGetValue("UEFIProtection", out bool uefiEnabled) ? uefiEnabled : true;
                case "内核防护":
                    return status.TryGetValue("KernelProtection", out bool kernelEnabled) ? kernelEnabled : true;
                case "文档防护":
                    return status.TryGetValue("DocumentProtection", out bool documentEnabled) ? documentEnabled : true;
                default:
                    return true;
            }
        }

    }

    public class ToggleSwitch : UserControl
    {
        private bool isEnabled;
        public new event EventHandler EnabledChanged;

        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
        public bool IsEnabled
        {
            get { return isEnabled; }
            set
            {
                if (isEnabled != value)
                {
                    isEnabled = value;
                    EnabledChanged?.Invoke(this, EventArgs.Empty);
                    this.Invalidate();
                }
            }
        }

        public ToggleSwitch()
        {
            this.Size = new Size(60, 30);
            this.Cursor = Cursors.Hand;
            this.Enabled = true;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            var g = e.Graphics;
            var rect = new Rectangle(0, 0, this.Width - 1, this.Height - 1);
            var switchRect = new Rectangle(isEnabled ? 30 : 5, 5, 20, 20);

            // 绘制背景
            g.FillRectangle(new SolidBrush(isEnabled ? Color.Green : Color.Gray), rect);
            g.DrawRectangle(new Pen(Color.Black), rect);

            // 绘制开关
            g.FillRectangle(new SolidBrush(Color.White), switchRect);
            g.DrawRectangle(new Pen(Color.Black), switchRect);
        }

        protected override void OnClick(EventArgs e)
        {
            base.OnClick(e);
            IsEnabled = !IsEnabled;
        }
    }
}