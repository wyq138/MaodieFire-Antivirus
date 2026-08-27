// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using FireAntivirus.Services;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host
{
    public class SettingsPage : UserControl, IThemed
    {
        private Panel settingsPanel;
        private TabControl settingsTabControl;
        private Theme currentTheme = Theme.Light;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public SettingsPage()
        {
            try
            {
                InitializeComponents();
                
                // 订阅更新服务事件
                UpdateService.UpdateAvailable += UpdateService_UpdateAvailable;
                UpdateService.UpdateProgress += UpdateService_UpdateProgress;
                UpdateService.UpdateCompleted += UpdateService_UpdateCompleted;
                
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) =>
                {
                    UpdateUI();
                };
            }
            catch (Exception ex)
            {
                // 记录错误但不重新抛出，避免应用程序崩溃
                Console.WriteLine($"Error initializing SettingsPage: {ex.Message}");
            }
        }
        
        private void UpdateService_UpdateAvailable(object sender, UpdateAvailableEventArgs e)
        {
            this.Invoke((Action)(() =>
            {
                var result = MessageBox.Show(
                    $"{_languageManager.GetString("UpdateAvailableMessage", e.Version, e.UpdateInfo)}",
                    _languageManager.GetString("UpdateAvailable"),
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Information
                );
                
                if (result == DialogResult.Yes)
                {
                    // 显示更新进度对话框
                    var progressForm = new Form
                    {
                        Text = _languageManager.GetString("UpdateProgress"),
                        Size = new Size(400, 150),
                        StartPosition = FormStartPosition.CenterScreen,
                        FormBorderStyle = FormBorderStyle.FixedDialog,
                        MaximizeBox = false,
                        MinimizeBox = false
                    };
                    
                    var progressBar = new ProgressBar
                    {
                        Dock = DockStyle.Top,
                        Height = 30,
                        Margin = new Padding(20, 20, 20, 10)
                    };
                    
                    var statusLabel = new Label
                    {
                        Text = _languageManager.GetString("PreparingDownload"),
                        Dock = DockStyle.Top,
                        Height = 30,
                        TextAlign = ContentAlignment.MiddleCenter,
                        Font = new Font("微软雅黑", 10)
                    };
                    
                    progressForm.Controls.Add(statusLabel);
                    progressForm.Controls.Add(progressBar);
                    
                    // 异步下载并安装更新
                    Task.Run(async () =>
                    {
                        await UpdateService.DownloadAndInstallUpdateAsync(e.Version);
                        progressForm.Invoke((Action)(() => progressForm.Close()));
                    });
                    
                    progressForm.ShowDialog();
                }
            }));
        }
        
        private void UpdateService_UpdateProgress(object sender, UpdateProgressEventArgs e)
        {
            // 可以在这里更新进度条
        }
        
        private void UpdateService_UpdateCompleted(object sender, UpdateCompletedEventArgs e)
        {
            this.Invoke((Action)(() =>
            {
                if (e.Success)
                {
                    MessageBox.Show(
                    _languageManager.GetString("UpdateSuccess"),
                    _languageManager.GetString("Success"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
                }
                else
                {
                    MessageBox.Show(
                        _languageManager.GetString("UpdateFailed", e.ErrorMessage),
                        _languageManager.GetString("Error"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                }
            }));
        }
        
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // 取消订阅事件
                UpdateService.UpdateAvailable -= UpdateService_UpdateAvailable;
                UpdateService.UpdateProgress -= UpdateService_UpdateProgress;
                UpdateService.UpdateCompleted -= UpdateService_UpdateCompleted;
            }
            base.Dispose(disposing);
        }

        private TableLayoutPanel mainLayout;
        private Panel headerPanel;

        private void InitializeComponents()
        {
            this.Dock = DockStyle.Fill;
            this.AutoScroll = true;

            mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            headerPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(20, 15, 20, 15)
            };

            var titleLabel = new Label
            {
                Text = _languageManager.GetString("Settings"),
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            headerPanel.Controls.Add(titleLabel);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            settingsPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(20)
            };

            settingsTabControl = new TabControl
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Font = new Font("微软雅黑", 9)
            };

            CreateTabs();

            settingsPanel.Controls.Add(settingsTabControl);
            mainLayout.Controls.Add(settingsPanel, 0, 1);
            this.Controls.Add(mainLayout);
        }
        
        private void CreateTabs()
        {
            settingsTabControl.TabPages.Clear();
            
            var appearanceTab = new TabPage(_languageManager.GetString("Appearance"))
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var scanTab = new TabPage(_languageManager.GetString("ScanSettings"))
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var protectionTab = new TabPage(_languageManager.GetString("ProtectionSettings"))
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var networkTab = new TabPage(_languageManager.GetString("NetworkSettings"))
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var systemTab = new TabPage(_languageManager.GetString("SystemSettings"))
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            var updateTab = new TabPage(_languageManager.GetString("UpdateSettings"))
            {
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                Font = new Font("微软雅黑", 9)
            };

            CreateAppearanceSettings(appearanceTab);
            CreateScanSettings(scanTab);
            CreateProtectionSettings(protectionTab);
            CreateNetworkSettings(networkTab);
            CreateSystemSettings(systemTab);
            CreateUpdateSettings(updateTab);

            settingsTabControl.TabPages.Add(appearanceTab);
            settingsTabControl.TabPages.Add(scanTab);
            settingsTabControl.TabPages.Add(protectionTab);
            settingsTabControl.TabPages.Add(networkTab);
            settingsTabControl.TabPages.Add(systemTab);
            settingsTabControl.TabPages.Add(updateTab);
        }
        
        private void UpdateUI()
        {
            // 更新标题
            var titleLabel = headerPanel.Controls[0] as Label;
            if (titleLabel != null)
            {
                titleLabel.Text = _languageManager.GetString("Settings");
            }
            
            // 重新创建标签页
            CreateTabs();
        }

        private void CreateAppearanceSettings(TabPage tabPage)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 4,
                ColumnCount = 1,
                Padding = new Padding(20),
                CellBorderStyle = TableLayoutPanelCellBorderStyle.None
            };

            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));

            var themeLabel = new Label
            {
                Text = _languageManager.GetString("Appearance"),
                Font = new Font("微软雅黑", 14, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            layout.Controls.Add(themeLabel, 0, 0);

            var themeRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            themeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            themeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var themeLabel2 = new Label
            {
                Text = _languageManager.GetString("Theme"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var themePanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var lightThemeBtn = CreateThemeButton(_languageManager.GetString("LightTheme"), Theme.Light);
            var darkThemeBtn = CreateThemeButton(_languageManager.GetString("DarkTheme"), Theme.Dark);

            lightThemeBtn.Location = new Point(0, 0);
            darkThemeBtn.Location = new Point(100, 0);

            themePanel.Controls.Add(lightThemeBtn);
            themePanel.Controls.Add(darkThemeBtn);
            themeRow.Controls.Add(themeLabel2, 0, 0);
            themeRow.Controls.Add(themePanel, 1, 0);
            layout.Controls.Add(themeRow, 0, 1);

            var scrollBarRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            scrollBarRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            scrollBarRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var scrollBarLabel = new Label
            {
                Text = _languageManager.GetString("ScrollBarColor"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var scrollBarPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var scrollBarSyncBtn = CreateToggleButton(_languageManager.GetString("FollowTheme"), true);
            scrollBarSyncBtn.Location = new Point(0, 10);
            scrollBarPanel.Controls.Add(scrollBarSyncBtn);
            scrollBarRow.Controls.Add(scrollBarLabel, 0, 0);
            scrollBarRow.Controls.Add(scrollBarPanel, 1, 0);
            layout.Controls.Add(scrollBarRow, 0, 2);

            // 语言选择
            var languageRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            languageRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            languageRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var languageLabel = new Label
            {
                Text = _languageManager.GetString("Language"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var languagePanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var languageComboBox = new ComboBox
            {
                Width = 150,
                Height = 30,
                Font = new Font("微软雅黑", 10),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary)
            };

            // 添加语言选项
            var languages = new Dictionary<string, string>
            {
                { "zh-CN", _languageManager.GetString("SimplifiedChinese") },
                { "en-US", _languageManager.GetString("English") },
                { "fr-FR", _languageManager.GetString("French") },
                { "zh-TW", _languageManager.GetString("TraditionalChinese") },
                { "ko-KR", _languageManager.GetString("Korean") },
                { "ja-JP", _languageManager.GetString("Japanese") }
            };

            foreach (var lang in languages)
            {
                languageComboBox.Items.Add(lang.Value);
            }
            languageComboBox.SelectedIndex = 0; // 默认选择简体中文

            // 语言选择事件
            languageComboBox.SelectedIndexChanged += (sender, e) =>
            {
                var selectedLang = languages.ElementAt(languageComboBox.SelectedIndex).Key;
                _languageManager.CurrentLanguage = selectedLang;
            };

            // 订阅全局语言变更事件
            LanguageManager.GlobalLanguageChanged += (sender, e) =>
            {
                UpdateUI();
            };

            languageComboBox.Location = new Point(0, 10);
            languagePanel.Controls.Add(languageComboBox);
            languageRow.Controls.Add(languageLabel, 0, 0);
            languageRow.Controls.Add(languagePanel, 1, 0);
            layout.Controls.Add(languageRow, 0, 3);

            tabPage.Controls.Add(layout);
        }

        private Button CreateToggleButton(string text, bool isEnabled)
        {
            var btn = new Button
            {
                Text = isEnabled ? _languageManager.GetString("TurnOn") : _languageManager.GetString("TurnOff"),
                Width = 80,
                Height = 30,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = isEnabled ? GetThemeColor(ThemeColor.PrimaryColor) : GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = isEnabled ? Color.White : GetThemeColor(ThemeColor.TextPrimary),
                Cursor = Cursors.Hand,
                Dock = DockStyle.Right,
                Margin = new Padding(0, 5, 0, 5)
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            btn.Click += (s, e) =>
            {
                btn.Text = btn.Text == _languageManager.GetString("TurnOn") ? _languageManager.GetString("TurnOff") : _languageManager.GetString("TurnOn");
                btn.BackColor = btn.Text == _languageManager.GetString("TurnOn") ? GetThemeColor(ThemeColor.PrimaryColor) : GetThemeColor(ThemeColor.BgTertiary);
                btn.ForeColor = btn.Text == _languageManager.GetString("TurnOn") ? Color.White : GetThemeColor(ThemeColor.TextPrimary);
            };
            return btn;
        }

        private Button CreateThemeButton(string text, Theme theme)
        {
            var btn = new Button
            {
                Text = text,
                Width = 100,
                Height = 40,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Tag = theme,
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            btn.Click += (s, e) =>
            {
                // 实际的主题切换逻辑
                currentTheme = theme;
                // 通知主窗体切换主题
                var mainForm = FindForm() as MainForm;
                if (mainForm != null)
                {
                    // 调用MainForm的方法来切换主题
                    mainForm.ApplyTheme(theme);
                }
            };
            return btn;
        }

        private void CreateScanSettings(TabPage tabPage)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 4,
                ColumnCount = 1,
                Padding = new Padding(20),
                CellBorderStyle = TableLayoutPanelCellBorderStyle.None
            };

            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));

            var scanLabel = new Label
            {
                Text = _languageManager.GetString("ScanSettings"),
                Font = new Font("微软雅黑", 14, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            layout.Controls.Add(scanLabel, 0, 0);

            var threadsRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            threadsRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            threadsRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var threadsLabel = new Label
            {
                Text = _languageManager.GetString("ScanThreads"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var threadsPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var threadsBtn = new Button
            {
                Text = "4",
                Width = 80,
                Height = 30,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Cursor = Cursors.Hand
            };
            threadsBtn.FlatAppearance.BorderSize = 1;
            threadsBtn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            threadsPanel.Controls.Add(threadsBtn);
            threadsRow.Controls.Add(threadsLabel, 0, 0);
            threadsRow.Controls.Add(threadsPanel, 1, 0);
            layout.Controls.Add(threadsRow, 0, 1);

            var fileTypesRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            fileTypesRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            fileTypesRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var fileTypesLabel = new Label
            {
                Text = _languageManager.GetString("ScanFileTypes"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var fileTypesPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var fileTypesBtn = CreateToggleButton(_languageManager.GetString("AllTypes"), true);
            fileTypesBtn.Location = new Point(0, 10);
            fileTypesPanel.Controls.Add(fileTypesBtn);
            fileTypesRow.Controls.Add(fileTypesLabel, 0, 0);
            fileTypesRow.Controls.Add(fileTypesPanel, 1, 0);
            layout.Controls.Add(fileTypesRow, 0, 2);

            var quickScanRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            quickScanRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            quickScanRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var quickScanLabel = new Label
            {
                Text = _languageManager.GetString("QuickScan"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var quickScanPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var quickScanBtn = CreateToggleButton(_languageManager.GetString("Enable"), true);
            quickScanBtn.Location = new Point(0, 10);
            quickScanPanel.Controls.Add(quickScanBtn);
            quickScanRow.Controls.Add(quickScanLabel, 0, 0);
            quickScanRow.Controls.Add(quickScanPanel, 1, 0);
            layout.Controls.Add(quickScanRow, 0, 3);

            tabPage.Controls.Add(layout);
        }

        private void CreateProtectionSettings(TabPage tabPage)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 4,
                ColumnCount = 1,
                Padding = new Padding(20),
                CellBorderStyle = TableLayoutPanelCellBorderStyle.None
            };

            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));

            var protectionLabel = new Label
            {
                Text = _languageManager.GetString("ProtectionSettings"),
                Font = new Font("微软雅黑", 14, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            layout.Controls.Add(protectionLabel, 0, 0);

            var startupRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            startupRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            startupRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var startupLabel = new Label
            {
                Text = _languageManager.GetString("StartupProtection"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var startupPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var startupBtn = CreateToggleButton("启用", true);
            startupBtn.Location = new Point(0, 10);
            startupPanel.Controls.Add(startupBtn);
            startupRow.Controls.Add(startupLabel, 0, 0);
            startupRow.Controls.Add(startupPanel, 1, 0);
            layout.Controls.Add(startupRow, 0, 1);

            var alertRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            alertRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            alertRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var alertLabel = new Label
            {
                Text = _languageManager.GetString("ProtectionAlerts"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var alertPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var alertBtn = CreateToggleButton(_languageManager.GetString("PopupAlerts"), true);
            alertBtn.Location = new Point(0, 10);
            alertPanel.Controls.Add(alertBtn);
            alertRow.Controls.Add(alertLabel, 0, 0);
            alertRow.Controls.Add(alertPanel, 1, 0);
            layout.Controls.Add(alertRow, 0, 2);

            var realTimeRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            realTimeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            realTimeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var realTimeLabel = new Label
            {
                Text = _languageManager.GetString("RealTimeProtection"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var realTimePanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var realTimeBtn = CreateToggleButton("启用", true);
            realTimeBtn.Location = new Point(0, 10);
            realTimePanel.Controls.Add(realTimeBtn);
            realTimeRow.Controls.Add(realTimeLabel, 0, 0);
            realTimeRow.Controls.Add(realTimePanel, 1, 0);
            layout.Controls.Add(realTimeRow, 0, 3);

            tabPage.Controls.Add(layout);
        }

        private void CreateNetworkSettings(TabPage tabPage)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 4,
                ColumnCount = 1,
                Padding = new Padding(20),
                CellBorderStyle = TableLayoutPanelCellBorderStyle.None
            };

            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));

            var networkLabel = new Label
            {
                Text = _languageManager.GetString("NetworkSettings"),
                Font = new Font("微软雅黑", 14, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            layout.Controls.Add(networkLabel, 0, 0);

            var firewallRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            firewallRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            firewallRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var firewallLabel = new Label
            {
                Text = _languageManager.GetString("Firewall"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var firewallPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var firewallBtn = CreateToggleButton("启用", true);
            firewallBtn.Location = new Point(0, 10);
            firewallPanel.Controls.Add(firewallBtn);
            firewallRow.Controls.Add(firewallLabel, 0, 0);
            firewallRow.Controls.Add(firewallPanel, 1, 0);
            layout.Controls.Add(firewallRow, 0, 1);

            var networkModeRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            networkModeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            networkModeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var networkModeLabel = new Label
            {
                Text = _languageManager.GetString("NetworkMode"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var networkModePanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var networkModeBtn = new Button
            {
                Text = _languageManager.GetString("SmartMode"),
                Width = 100,
                Height = 30,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Cursor = Cursors.Hand
            };
            networkModeBtn.FlatAppearance.BorderSize = 1;
            networkModeBtn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            networkModePanel.Controls.Add(networkModeBtn);
            networkModeRow.Controls.Add(networkModeLabel, 0, 0);
            networkModeRow.Controls.Add(networkModePanel, 1, 0);
            layout.Controls.Add(networkModeRow, 0, 2);

            var networkMonitorRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            networkMonitorRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            networkMonitorRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var networkMonitorLabel = new Label
            {
                Text = _languageManager.GetString("NetworkMonitor"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var networkMonitorPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var networkMonitorBtn = CreateToggleButton("启用", true);
            networkMonitorBtn.Location = new Point(0, 10);
            networkMonitorPanel.Controls.Add(networkMonitorBtn);
            networkMonitorRow.Controls.Add(networkMonitorLabel, 0, 0);
            networkMonitorRow.Controls.Add(networkMonitorPanel, 1, 0);
            layout.Controls.Add(networkMonitorRow, 0, 3);

            tabPage.Controls.Add(layout);
        }

        private void CreateSystemSettings(TabPage tabPage)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 5,
                ColumnCount = 1,
                Padding = new Padding(20),
                CellBorderStyle = TableLayoutPanelCellBorderStyle.None
            };

            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));

            var systemLabel = new Label
            {
                Text = "系统设置",
                Font = new Font("微软雅黑", 14, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            layout.Controls.Add(systemLabel, 0, 0);

            var selfProtectRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            selfProtectRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            selfProtectRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var selfProtectLabel = new Label
            {
                Text = "自我保护",
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var selfProtectPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var selfProtectBtn = CreateToggleButton("启用", true);
            selfProtectBtn.Location = new Point(0, 10);
            selfProtectPanel.Controls.Add(selfProtectBtn);
            selfProtectRow.Controls.Add(selfProtectLabel, 0, 0);
            selfProtectRow.Controls.Add(selfProtectPanel, 1, 0);
            layout.Controls.Add(selfProtectRow, 0, 1);

            var backgroundProtectRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            backgroundProtectRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            backgroundProtectRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var backgroundProtectLabel = new Label
            {
                Text = "后台防护",
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var backgroundProtectPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var backgroundProtectBtn = CreateToggleButton("启用", true);
            backgroundProtectBtn.Location = new Point(0, 10);
            backgroundProtectPanel.Controls.Add(backgroundProtectBtn);
            backgroundProtectRow.Controls.Add(backgroundProtectLabel, 0, 0);
            backgroundProtectRow.Controls.Add(backgroundProtectPanel, 1, 0);
            layout.Controls.Add(backgroundProtectRow, 0, 2);

            var passwordProtectRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            passwordProtectRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            passwordProtectRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var passwordProtectLabel = new Label
            {
                Text = "密码保护",
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var passwordProtectPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var passwordProtectBtn = CreateToggleButton("未设置", false);
            passwordProtectBtn.Location = new Point(0, 10);
            passwordProtectPanel.Controls.Add(passwordProtectBtn);
            passwordProtectRow.Controls.Add(passwordProtectLabel, 0, 0);
            passwordProtectRow.Controls.Add(passwordProtectPanel, 1, 0);
            layout.Controls.Add(passwordProtectRow, 0, 3);

            var startupManagerRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            startupManagerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            startupManagerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var startupManagerLabel = new Label
            {
                Text = "启动项管理",
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var startupManagerPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var startupManagerBtn = new Button
            {
                Text = "管理",
                Width = 80,
                Height = 30,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.PrimaryColor),
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };
            startupManagerBtn.FlatAppearance.BorderSize = 0;
            startupManagerPanel.Controls.Add(startupManagerBtn);
            startupManagerRow.Controls.Add(startupManagerLabel, 0, 0);
            startupManagerRow.Controls.Add(startupManagerPanel, 1, 0);
            layout.Controls.Add(startupManagerRow, 0, 4);

            tabPage.Controls.Add(layout);
        }

        private void CreateUpdateSettings(TabPage tabPage)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 4,
                ColumnCount = 1,
                Padding = new Padding(20),
                CellBorderStyle = TableLayoutPanelCellBorderStyle.None
            };

            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 70));

            var updateLabel = new Label
            {
                Text = "更新设置",
                Font = new Font("微软雅黑", 14, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            layout.Controls.Add(updateLabel, 0, 0);

            var autoUpdateRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            autoUpdateRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            autoUpdateRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var autoUpdateLabel = new Label
            {
                Text = "自动更新",
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var autoUpdatePanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var autoUpdateBtn = CreateToggleButton("启用", true);
            autoUpdateBtn.Location = new Point(0, 10);
            autoUpdatePanel.Controls.Add(autoUpdateBtn);
            autoUpdateRow.Controls.Add(autoUpdateLabel, 0, 0);
            autoUpdateRow.Controls.Add(autoUpdatePanel, 1, 0);
            layout.Controls.Add(autoUpdateRow, 0, 1);

            var updateFreqRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            updateFreqRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            updateFreqRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var updateFreqLabel = new Label
            {
                Text = "更新频率",
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var updateFreqPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var updateFreqBtn = new Button
            {
                Text = "每天检查",
                Width = 100,
                Height = 30,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Cursor = Cursors.Hand
            };
            updateFreqBtn.FlatAppearance.BorderSize = 1;
            updateFreqBtn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            updateFreqPanel.Controls.Add(updateFreqBtn);
            updateFreqRow.Controls.Add(updateFreqLabel, 0, 0);
            updateFreqRow.Controls.Add(updateFreqPanel, 1, 0);
            layout.Controls.Add(updateFreqRow, 0, 2);

            var updateNowRow = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            updateNowRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            updateNowRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            var updateNowLabel = new Label
            {
                Text = "立即更新",
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var updateNowPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var updateNowBtn = new Button
            {
                Text = "检查更新",
                Width = 100,
                Height = 30,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.PrimaryColor),
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };
            updateNowBtn.FlatAppearance.BorderSize = 0;
            updateNowBtn.Click += async (s, e) =>
            {
                updateNowBtn.Enabled = false;
                updateNowBtn.Text = "检查中...";
                
                try
                {
                    await UpdateService.CheckForUpdatesAsync();
                }
                finally
                {
                    updateNowBtn.Enabled = true;
                    updateNowBtn.Text = "检查更新";
                }
            };
            updateNowPanel.Controls.Add(updateNowBtn);
            updateNowRow.Controls.Add(updateNowLabel, 0, 0);
            updateNowRow.Controls.Add(updateNowPanel, 1, 0);
            layout.Controls.Add(updateNowRow, 0, 3);

            tabPage.Controls.Add(layout);
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            settingsTabControl.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            settingsTabControl.ForeColor = GetThemeColor(ThemeColor.TextPrimary);

            // 更新头部面板和其子控件
            if (headerPanel != null)
            {
                foreach (Control control in headerPanel.Controls)
                {
                    UpdateControlTheme(control);
                }
            }

            // 更新标签页和其子控件
            foreach (TabPage tabPage in settingsTabControl.TabPages)
            {
                tabPage.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                foreach (Control control in tabPage.Controls)
                {
                    UpdateControlTheme(control);
                }
            }
        }

        private void UpdateControlTheme(Control control)
        {
            if (control is Label label)
            {
                // 确保使用微软雅黑字体
                if (label.Font.Name != "微软雅黑")
                {
                    label.Font = new Font("微软雅黑", label.Font.Size, label.Font.Style);
                }
                label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
            }
            else if (control is Button button)
            {
                button.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                button.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                button.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            }
            else if (control is Panel panel)
            {
                panel.BackColor = Color.Transparent;
                foreach (Control child in panel.Controls)
                {
                    UpdateControlTheme(child);
                }
            }
            else if (control is TableLayoutPanel tableLayoutPanel)
            {
                // 递归更新TableLayoutPanel中的所有控件
                foreach (Control child in tableLayoutPanel.Controls)
                {
                    UpdateControlTheme(child);
                }
            }
            else if (control is FlowLayoutPanel flowLayoutPanel)
            {
                // 递归更新FlowLayoutPanel中的所有控件
                foreach (Control child in flowLayoutPanel.Controls)
                {
                    UpdateControlTheme(child);
                }
            }
            else if (control is TabPage tabPage)
            {
                tabPage.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                foreach (Control child in tabPage.Controls)
                {
                    UpdateControlTheme(child);
                }
            }
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
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(50, 50, 50);
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(60, 60, 60);
                    case ThemeColor.PrimaryColor:
                        return Color.FromArgb(0, 120, 215);
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
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(243, 244, 246);
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(229, 231, 235);
                    case ThemeColor.PrimaryColor:
                        return Color.FromArgb(0, 120, 215);
                    default:
                        return Color.White;
                }
            }
        }
    }
}