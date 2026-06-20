// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host
{
    public class HomePage : UserControl, IThemed
    {
        private Panel statusPanel;
        private Panel quickActionsPanel;
        private Panel protectionStatusLabel;
        private Panel virusDatabaseLabel;
        private Panel systemStatusLabel;
        private Button quickScanBtn;
        private Button fullScanBtn;
        private Button updateBtn;
        private Theme currentTheme = Theme.Light;
        private LanguageManager _languageManager = LanguageManager.Instance;

        private static readonly string LogFilePath = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "homepage.log");

        public HomePage()
        {
            try
            {
                Log("HomePage initializing...");
                InitializeComponents();
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) =>
                {
                    InitializeComponents();
                };
                Log("HomePage initialized successfully");
            }
            catch (Exception ex)
            {
                Log($"Error initializing HomePage: {ex.Message}");
                // 不重新抛出异常，避免应用程序崩溃
            }
        }

        private void Log(string message)
        {
            try
            {
                string logMessage = $"[{DateTime.Now}] {message}\n";
                System.IO.File.AppendAllText(LogFilePath, logMessage);
                Console.WriteLine(logMessage);
            }
            catch
            {
                // 静默处理日志错误
            }
        }

        private void InitializeComponents()
        {
            try
            {
                this.Dock = DockStyle.Fill;
                this.AutoScroll = true;
                this.MinimumSize = new Size(600, 500);

                var mainLayout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    RowCount = 4,
                    ColumnCount = 1,
                    MinimumSize = new Size(580, 700),
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    Padding = new Padding(0, 30, 0, 30)
                };

                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 150));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 220));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 180));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

                // 英雄区域
                var heroPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    Padding = new Padding(30, 20, 30, 20)
                };

                var heroLayout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    ColumnCount = 2,
                    RowCount = 1,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary)
                };
                heroLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70));
                heroLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));

                var titlePanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary)
                };

                try
                {
                    var titleLabel = new Label
                    {
                        Text = _languageManager.GetString("AppTitle"),
                        Font = new Font("微软雅黑", 22, FontStyle.Bold),
                        ForeColor = GetThemeColor(ThemeColor.PrimaryColor),
                        Dock = DockStyle.Top,
                        TextAlign = ContentAlignment.MiddleLeft,
                        Margin = new Padding(0, 10, 0, 10),
                        Height = 50
                    };

                    var subtitleLabel = new Label
                    {
                        Text = _languageManager.GetString("HomeSubtitle"),
                        Font = new Font("微软雅黑", 11),
                        ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                        Dock = DockStyle.Top,
                        TextAlign = ContentAlignment.MiddleLeft,
                        Margin = new Padding(0, 5, 0, 10),
                        Height = 25
                    };

                    titlePanel.Controls.Add(titleLabel);
                    titlePanel.Controls.Add(subtitleLabel);
                    Log("Title labels created");
                }
                catch (Exception ex)
                {
                    Log($"Error creating title labels: {ex.Message}");
                }

                var logoPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    Padding = new Padding(20)
                };

                try
                {
                    var logoPictureBox = new PictureBox
                    {
                        Dock = DockStyle.Fill,
                        SizeMode = PictureBoxSizeMode.Zoom,
                        Image = GetAntivirusLogo()
                    };

                    logoPanel.Controls.Add(logoPictureBox);
                    Log("Logo picture box created");
                }
                catch (Exception ex)
                {
                    Log($"Error creating logo picture box: {ex.Message}");
                }

                heroLayout.Controls.Add(titlePanel, 0, 0);
                heroLayout.Controls.Add(logoPanel, 1, 0);
                heroPanel.Controls.Add(heroLayout);
                mainLayout.Controls.Add(heroPanel, 0, 0);
                Log("Hero panel added");

                // 状态面板
                statusPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    Padding = new Padding(20)
                };

                var statusLayout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    ColumnCount = 3,
                    RowCount = 1,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary)
                };
                statusLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
                statusLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
                statusLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));

                try
                {
                    protectionStatusLabel = CreateStatusCard(_languageManager.GetString("ProtectionStatus"), _languageManager.GetString("ProtectionStatusEnabled"), "🛡️", GetThemeColor(ThemeColor.PrimaryColor));
                    virusDatabaseLabel = CreateStatusCard(_languageManager.GetString("VirusDatabase"), _languageManager.GetString("VirusDatabaseUpToDate"), "📦", GetThemeColor(ThemeColor.PrimaryColor));
                    systemStatusLabel = CreateStatusCard(_languageManager.GetString("SystemStatus"), _languageManager.GetString("SystemStatusSafe"), "✅", GetThemeColor(ThemeColor.PrimaryColor));

                    statusLayout.Controls.Add(protectionStatusLabel, 0, 0);
                    statusLayout.Controls.Add(virusDatabaseLabel, 1, 0);
                    statusLayout.Controls.Add(systemStatusLabel, 2, 0);
                    Log("Status cards created and added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating status cards: {ex.Message}");
                }

                statusPanel.Controls.Add(statusLayout);
                mainLayout.Controls.Add(statusPanel, 0, 1);
                Log("Status panel added");

                // 快速操作面板
                quickActionsPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    Padding = new Padding(20)
                };

                var actionsLayout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    ColumnCount = 3,
                    RowCount = 1,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary)
                };
                actionsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
                actionsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
                actionsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));

                try
                {
                    quickScanBtn = CreateActionButton(_languageManager.GetString("QuickScan"), "🔍", QuickScan);
                    fullScanBtn = CreateActionButton(_languageManager.GetString("FullScan"), "📁", FullScan);
                    updateBtn = CreateActionButton(_languageManager.GetString("CheckUpdate"), "🔄", CheckUpdate);

                    actionsLayout.Controls.Add(quickScanBtn, 0, 0);
                    actionsLayout.Controls.Add(fullScanBtn, 1, 0);
                    actionsLayout.Controls.Add(updateBtn, 2, 0);
                    Log("Action buttons created and added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating action buttons: {ex.Message}");
                }

                quickActionsPanel.Controls.Add(actionsLayout);
                mainLayout.Controls.Add(quickActionsPanel, 0, 2);
                Log("Quick actions panel added");

                this.Controls.Add(mainLayout);
                Log("Main layout added to form");
            }
            catch (Exception ex)
            {
                Log($"Error in InitializeComponents: {ex.Message}");
                throw;
            }
        }

        private Panel CreateStatusCard(string title, string value, string icon, Color valueColor)
        {
            var card = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.CardBg),
                Margin = new Padding(10),
                BorderStyle = BorderStyle.None
            };

            var cardLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                BackColor = GetThemeColor(ThemeColor.CardBg)
            };
            cardLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 60));
            cardLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 20));
            cardLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 20));

            var iconLabel = new Label
            {
                Text = icon,
                Font = new Font("微软雅黑", 28),
                ForeColor = GetThemeColor(ThemeColor.PrimaryColor),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Margin = new Padding(0)
            };

            var titleLabel = new Label
            {
                Text = title,
                Font = new Font("微软雅黑", 10),
                ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Margin = new Padding(0)
            };

            // 直接设置文本，避免乱码
            var valueLabel = new Label
            {
                Text = value,
                Font = new Font("微软雅黑", 12, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Margin = new Padding(0)
            };

            cardLayout.Controls.Add(iconLabel, 0, 0);
            cardLayout.Controls.Add(titleLabel, 0, 1);
            cardLayout.Controls.Add(valueLabel, 0, 2);
            card.Controls.Add(cardLayout);

            return card;
        }

        private Button CreateActionButton(string text, string icon, Action action)
        {
            var btn = new Button
            {
                Text = $"{icon}\n{text}",
                Dock = DockStyle.Fill,
                Font = new Font("微软雅黑", 12),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.PrimaryColor),
                ForeColor = Color.White,
                Cursor = Cursors.Hand,
                Margin = new Padding(10),
                TextAlign = ContentAlignment.MiddleCenter
            };
            btn.FlatAppearance.BorderSize = 0;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(0, 180, 220);
            btn.FlatAppearance.MouseDownBackColor = Color.FromArgb(0, 160, 200);
            btn.Click += (s, e) => action();
            return btn;
        }

        private Image GetAntivirusLogo()
        {
            try
            {
                // 尝试从内嵌资源加载图片
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                string resourceName = "FireAntivirus.Host.Resources.cat_logo.png";
                
                using (var stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream != null)
                    {
                        using (var bitmap = new Bitmap(stream))
                        {
                            // 调整图片大小为100x100
                            var resizedBitmap = new Bitmap(bitmap, new Size(100, 100));
                            return resizedBitmap;
                        }
                    }
                }

                // 如果找不到图标文件，创建一个默认图标
                var defaultBitmap = new Bitmap(100, 100);
                using (var graphics = Graphics.FromImage(defaultBitmap))
                {
                    graphics.Clear(Color.Transparent);
                    var brush = new SolidBrush(Color.FromArgb(255, 240, 180)); // 橘黄色
                    graphics.FillEllipse(brush, 10, 10, 80, 80);
                    brush.Dispose();
                }
                return defaultBitmap;
            }
            catch
            {
                // 如果创建默认图标也失败，返回空图片
                return new Bitmap(100, 100);
            }
        }

        private void QuickScan()
        {
            // 快速扫描逻辑
            var mainForm = FindForm() as MainForm;
            if (mainForm != null)
            {
                mainForm.LoadPage("scan");
            }
        }

        private void FullScan()
        {
            // 全盘扫描逻辑
            var mainForm = FindForm() as MainForm;
            if (mainForm != null)
            {
                mainForm.LoadPage("scan");
            }
        }

        private void CheckUpdate()
        {
            // 更新ClamAV病毒库
            try
            {
                var dataManager = new FireAntivirus.Data.DataManager();
                var antivirusEngine = new FireAntivirus.Engine.AntivirusEngine();
                var clamAVEngine = new FireAntivirus.Services.ClamAVEngine(dataManager, antivirusEngine);

                // 显示更新进度
                var updateForm = new Form
                {
                    Text = "更新病毒库",
                    Size = new Size(400, 150),
                    StartPosition = FormStartPosition.CenterScreen
                };

                var label = new Label
                {
                    Text = "正在更新ClamAV病毒库...",
                    Location = new Point(20, 30),
                    AutoSize = true
                };
                updateForm.Controls.Add(label);

                var progressBar = new ProgressBar
                {
                    Location = new Point(20, 60),
                    Size = new Size(350, 20),
                    Style = ProgressBarStyle.Marquee
                };
                updateForm.Controls.Add(progressBar);

                // 异步更新病毒库
                System.Threading.Tasks.Task.Run(() =>
                {
                    bool success = clamAVEngine.UpdateVirusDatabase();
                    updateForm.Invoke(new Action(() =>
                    {
                        updateForm.Close();
                        if (success)
                        {
                            MessageBox.Show("ClamAV病毒库更新成功", _languageManager.GetString("Info"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                        else
                        {
                            MessageBox.Show("ClamAV病毒库更新失败", _languageManager.GetString("Error"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }));
                });

                updateForm.ShowDialog();
            }
            catch (Exception ex)
            {
                Log($"更新病毒库失败: {ex.Message}");
                MessageBox.Show("更新病毒库时发生错误", _languageManager.GetString("Error"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public void UpdateProtectionStatus(bool isProtected)
        {
            try
            {
                UpdateStatusCardValue(protectionStatusLabel, isProtected ? "已启用" : "未启用");
                UpdateStatusCardIcon(protectionStatusLabel, isProtected ? "🛡️" : "⚠️");
            }
            catch (Exception ex)
            {
                Log($"Error updating protection status: {ex.Message}");
            }
        }

        public void UpdateVirusDatabaseStatus(string version, bool isUpToDate)
        {
            try
            {
                UpdateStatusCardValue(virusDatabaseLabel, isUpToDate ? $"已更新 ({version})" : $"需更新 ({version})");
            }
            catch (Exception ex)
            {
                Log($"Error updating virus database status: {ex.Message}");
            }
        }

        private void UpdateStatusCardValue(Panel card, string newValue)
        {
            try
            {
                foreach (Control child in card.Controls)
                {
                    if (child is TableLayoutPanel tlp)
                    {
                        foreach (Control cell in tlp.Controls)
                        {
                            if (cell is Label label && label.Font.Bold && label.Font.Size == 12)
                            {
                                label.Text = newValue;
                                return;
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private void UpdateStatusCardIcon(Panel card, string newIcon)
        {
            try
            {
                foreach (Control child in card.Controls)
                {
                    if (child is TableLayoutPanel tlp)
                    {
                        foreach (Control cell in tlp.Controls)
                        {
                            if (cell is Label label && label.Font.Size >= 22)
                            {
                                label.Text = newIcon;
                                return;
                            }
                        }
                    }
                }
            }
            catch { }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            
            // 更新所有子控件的颜色
            UpdateControlsTheme(this);
        }
        
        private void UpdateControlsTheme(Control control)
        {
            foreach (Control child in control.Controls)
            {
                if (child is Panel panel)
                {
                    // 检查是否是状态卡片
                    if (panel.Margin == new Padding(10) && panel.BorderStyle == BorderStyle.None)
                    {
                        panel.BackColor = GetThemeColor(ThemeColor.CardBg);
                    }
                    else
                    {
                        panel.BackColor = GetThemeColor(ThemeColor.BgPrimary);
                    }
                }
                else if (child is TableLayoutPanel tlp)
                {
                    tlp.BackColor = GetThemeColor(ThemeColor.BgPrimary);
                }
                else if (child is Label label)
                {
                    // 确保使用微软雅黑字体
                    if (label.Font.Name != "微软雅黑")
                    {
                        label.Font = new Font("微软雅黑", label.Font.Size, label.Font.Style);
                    }
                    
                    // 检查是否是图标标签
                    if (label.Font.Size >= 22)
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.PrimaryColor);
                    }
                    // 检查是否是副标题标签
                    else if ((label.Font.Size == 12 || label.Font.Size == 11) && label.Text == "全方位保护您的电脑安全")
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
                    }
                    // 检查是否是状态卡片的标题
                    else if (label.Font.Size == 10)
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
                    }
                    else
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                    }
                }
                else if (child is Button button)
                {
                    // 确保使用微软雅黑字体
                    if (button.Font.Name != "微软雅黑")
                    {
                        button.Font = new Font("微软雅黑", button.Font.Size, button.Font.Style);
                    }
                    
                    button.BackColor = GetThemeColor(ThemeColor.PrimaryColor);
                    button.ForeColor = Color.White;
                    button.FlatAppearance.MouseOverBackColor = Color.FromArgb(0, 180, 220);
                    button.FlatAppearance.MouseDownBackColor = Color.FromArgb(0, 160, 200);
                }
                else if (child is PictureBox pictureBox)
                {
                    // 重新生成logo以适应主题变化
                    pictureBox.Image = GetAntivirusLogo();
                }
                
                // 递归更新子控件
                UpdateControlsTheme(child);
            }
        }

        private Color GetThemeColor(ThemeColor colorType)
        {
            if (currentTheme == Theme.Dark)
            {
                switch (colorType)
                {
                    case ThemeColor.PrimaryColor:
                        return Color.FromArgb(0, 212, 255);
                    case ThemeColor.TextPrimary:
                        return Color.White;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.FromArgb(30, 30, 30);
                    case ThemeColor.BgSecondary:
                        return Color.FromArgb(40, 40, 40);
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(50, 50, 50);
                    case ThemeColor.BgHover:
                        return Color.FromArgb(60, 60, 60);
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(60, 60, 60);
                    case ThemeColor.CardBg:
                        return Color.FromArgb(45, 45, 45);
                    default:
                        return Color.Black;
                }
            }
            else
            {
                switch (colorType)
                {
                    case ThemeColor.PrimaryColor:
                        return Color.FromArgb(37, 99, 235);
                    case ThemeColor.TextPrimary:
                        return Color.Black;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.White;
                    case ThemeColor.BgSecondary:
                        return Color.FromArgb(249, 250, 251);
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(243, 244, 246);
                    case ThemeColor.BgHover:
                        return Color.FromArgb(229, 231, 235);
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(229, 231, 235);
                    case ThemeColor.CardBg:
                        return Color.White;
                    default:
                        return Color.White;
                }
            }
        }
    }
}