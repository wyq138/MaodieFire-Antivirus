// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using FireAntivirus.Engine;
using System.Collections.Generic;
using FireAntivirus.Common.Localization;
using System.IO;

namespace FireAntivirus.Host
{
    public class ScanPage : UserControl, IThemed
    {
        private Panel scanTypePanel;
        private Panel scanControlPanel;
        private Button quickScanBtn;
        private Button fullScanBtn;
        private Button deepScanBtn;
        private Button customScanBtn;
        private Button startScanBtn;
        private Button pauseScanBtn;
        private Button stopScanBtn;
        private ProgressBar scanProgressBar;
        private Label progressLabel;
        private Label statusLabel;
        private ListBox scanResultsList;
        private Theme currentTheme = Theme.Light;
        private FireAntivirus.Engine.ScanType selectedScanType;
        private bool isScanTypeSelected = false; // 跟踪用户是否已经选择了扫描类型
        private FireAntivirus.Services.ClamAVEngine _clamAVEngine;
        private FireAntivirus.Engine.AntivirusEngine _antivirusEngine;
        
        private FireAntivirus.Services.ClamAVEngine clamAVEngine
        {
            get
            {
                if (_clamAVEngine == null)
                {
                    var dataManager = new FireAntivirus.Data.DataManager();
                    _antivirusEngine = new FireAntivirus.Engine.AntivirusEngine();
                    _clamAVEngine = new FireAntivirus.Services.ClamAVEngine(dataManager, _antivirusEngine);
                    _clamAVEngine.Initialize();
                }
                return _clamAVEngine;
            }
        }
        
        private FireAntivirus.Engine.AntivirusEngine antivirusEngine
        {
            get
            {
                if (_antivirusEngine == null)
                {
                    var _ = clamAVEngine; // 触发 clamAVEngine 初始化，同时初始化 _antivirusEngine
                }
                return _antivirusEngine;
            }
        }
        private System.Threading.CancellationTokenSource cts;
        private LanguageManager _languageManager = LanguageManager.Instance;

        private static readonly string LogFilePath = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "scanpage.log");

        public ScanPage()
        {
            try
            {
                Log("ScanPage initializing...");
                // 只执行必要的UI初始化操作
                InitializeComponents();
                Log("ScanPage initialized successfully");
            }
            catch (Exception ex)
            {
                Log($"Error initializing ScanPage: {ex.Message}");
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
                this.AutoScroll = false;
                this.MinimumSize = new Size(600, 500);
                this.BackColor = GetThemeColor(ThemeColor.BgPrimary);

                var mainLayout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    RowCount = 4,
                    ColumnCount = 1,
                    MinimumSize = new Size(580, 480),
                    BackColor = GetThemeColor(ThemeColor.BgPrimary)
                };

                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 160));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

                var headerPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    Padding = new Padding(20, 15, 20, 15)
                };

                try
                {
                    var titleLabel = new Label
                    {
                        Text = _languageManager.GetString("VirusScan"),
                        Font = new Font("微软雅黑", 18, FontStyle.Bold),
                        ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                        Dock = DockStyle.Fill,
                        TextAlign = ContentAlignment.MiddleLeft,
                        Margin = new Padding(0, 5, 0, 5)
                    };

                    headerPanel.Controls.Add(titleLabel);
                    mainLayout.Controls.Add(headerPanel, 0, 0);
                    Log("Header panel added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating header panel: {ex.Message}");
                }

                scanTypePanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    Padding = new Padding(20)
                };

                var scanTypeLayout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    ColumnCount = 4,
                    RowCount = 1,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary)
                };
                scanTypeLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
                scanTypeLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
                scanTypeLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
                scanTypeLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));
                scanTypeLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

                try
                {
                    quickScanBtn = CreateScanTypeButton(_languageManager.GetString("QuickScan"), "🔍", ScanType.Quick);
                    fullScanBtn = CreateScanTypeButton(_languageManager.GetString("FullScan"), "📁", ScanType.Full);
                    deepScanBtn = CreateScanTypeButton(_languageManager.GetString("DeepScan"), "🔬", ScanType.Deep);
                    customScanBtn = CreateScanTypeButton(_languageManager.GetString("CustomScan"), "✏️", ScanType.Custom);

                    quickScanBtn.Dock = DockStyle.Fill;
                    fullScanBtn.Dock = DockStyle.Fill;
                    deepScanBtn.Dock = DockStyle.Fill;
                    customScanBtn.Dock = DockStyle.Fill;

                    scanTypeLayout.Controls.Add(quickScanBtn, 0, 0);
                    scanTypeLayout.Controls.Add(fullScanBtn, 1, 0);
                    scanTypeLayout.Controls.Add(deepScanBtn, 2, 0);
                    scanTypeLayout.Controls.Add(customScanBtn, 3, 0);

                    scanTypePanel.Controls.Add(scanTypeLayout);
                    mainLayout.Controls.Add(scanTypePanel, 0, 1);
                    Log("Scan type panel added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating scan type panel: {ex.Message}");
                }

                scanControlPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    Padding = new Padding(20)
                };

                var controlLayout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    RowCount = 4,
                    ColumnCount = 1,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary)
                };

                controlLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
                controlLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
                controlLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
                controlLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

                var buttonPanel = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    ColumnCount = 3,
                    RowCount = 1
                };
                buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
                buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
                buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));

                try
                {
                    startScanBtn = CreateControlButton(_languageManager.GetString("ScanNow"), StartScan);
                    pauseScanBtn = CreateControlButton(_languageManager.GetString("PauseScan"), () => PauseScan(null, null));
                    stopScanBtn = CreateControlButton(_languageManager.GetString("StopScan"), StopScan);

                    startScanBtn.Dock = DockStyle.Fill;
                    pauseScanBtn.Dock = DockStyle.Fill;
                    stopScanBtn.Dock = DockStyle.Fill;

                    pauseScanBtn.Enabled = false;
                    stopScanBtn.Enabled = false;

                    buttonPanel.Controls.Add(startScanBtn, 0, 0);
                    buttonPanel.Controls.Add(pauseScanBtn, 1, 0);
                    buttonPanel.Controls.Add(stopScanBtn, 2, 0);

                    controlLayout.Controls.Add(buttonPanel, 0, 0);
                    Log("Control buttons added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating control buttons: {ex.Message}");
                }

                try
                {
                    scanProgressBar = new ProgressBar
                    {
                        Dock = DockStyle.Fill,
                        Minimum = 0,
                        Maximum = 100,
                        Value = 0,
                        Margin = new Padding(0, 10, 0, 10),
                        BackColor = GetThemeColor(ThemeColor.BgTertiary),
                        ForeColor = GetThemeColor(ThemeColor.PrimaryColor)
                    };

                    controlLayout.Controls.Add(scanProgressBar, 0, 1);
                    Log("Progress bar added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating progress bar: {ex.Message}");
                }

                try
                {
                    progressLabel = new Label
                    {
                        Text = "已扫描: 0 个文件，发现: 0 个风险",
                        Font = new Font("微软雅黑", 10),
                        ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                        Dock = DockStyle.Fill,
                        TextAlign = ContentAlignment.MiddleLeft
                    };

                    controlLayout.Controls.Add(progressLabel, 0, 2);
                    Log("Progress label added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating progress label: {ex.Message}");
                }

                try
                {
                    statusLabel = new Label
                    {
                        Text = _languageManager.GetString("StatusReady"),
                        Font = new Font("微软雅黑", 12),
                        ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                        Dock = DockStyle.Fill,
                        TextAlign = ContentAlignment.MiddleLeft
                    };

                    controlLayout.Controls.Add(statusLabel, 0, 3);
                    Log("Status label added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating status label: {ex.Message}");
                }

                scanControlPanel.Controls.Add(controlLayout);
                mainLayout.Controls.Add(scanControlPanel, 0, 2);
                Log("Control panel added");

                var resultsPanel = new Panel
                {
                    Dock = DockStyle.Fill,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary),
                    Padding = new Padding(20)
                };

                var resultsLayout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    RowCount = 2,
                    ColumnCount = 1,
                    BackColor = GetThemeColor(ThemeColor.BgPrimary)
                };

                resultsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
                resultsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

                try
                {
                    var resultsTitle = new Label
                    {
                        Text = _languageManager.GetString("ScanCompleted"),
                        Font = new Font("微软雅黑", 14, FontStyle.Bold),
                        ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                        Dock = DockStyle.Fill,
                        TextAlign = ContentAlignment.MiddleLeft
                    };

                    resultsLayout.Controls.Add(resultsTitle, 0, 0);
                    Log("Results title added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating results title: {ex.Message}");
                }

                try
                {
                    scanResultsList = new ListBox
                    {
                        Dock = DockStyle.Fill,
                        Font = new Font("微软雅黑", 10),
                        BackColor = GetThemeColor(ThemeColor.BgTertiary),
                        ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                        BorderStyle = BorderStyle.FixedSingle
                    };

                    resultsLayout.Controls.Add(scanResultsList, 0, 1);
                    resultsPanel.Controls.Add(resultsLayout);
                    mainLayout.Controls.Add(resultsPanel, 0, 3);
                    Log("Results panel added");
                }
                catch (Exception ex)
                {
                    Log($"Error creating results panel: {ex.Message}");
                }

                this.Controls.Add(mainLayout);
                Log("Main layout added to form");
            }
            catch (Exception ex)
            {
                Log($"Error in InitializeComponents: {ex.Message}");
                throw;
            }
        }

        private Button CreateScanTypeButton(string text, string icon, FireAntivirus.Engine.ScanType type)
        {
            var btn = new Button
            {
                Text = $"{icon} {text}",
                Width = 200,
                Height = 80,
                Font = new Font("微软雅黑", 11),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Margin = new Padding(10),
                Tag = type,
                Cursor = Cursors.Hand,
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            btn.Click += (s, e) => SelectScanType(type);
            return btn;
        }

        private Button CreateControlButton(string text, Action action)
        {
            var btn = new Button
            {
                Text = text,
                Width = 120,
                Height = 40,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Margin = new Padding(5),
                Cursor = Cursors.Hand,
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            btn.Click += (s, e) => action();
            return btn;
        }

        private void SelectScanType(FireAntivirus.Engine.ScanType type)
        {
            selectedScanType = type;
            isScanTypeSelected = true; // 标记用户已经选择了扫描类型

            foreach (Control control in scanTypePanel.Controls[0].Controls)
            {
                if (control is Button btn)
                {
                    var btnType = (FireAntivirus.Engine.ScanType)btn.Tag;
                    if (btnType == type)
                    {
                        btn.BackColor = GetThemeColor(ThemeColor.PrimaryColor);
                        btn.ForeColor = Color.White;
                    }
                    else
                    {
                        btn.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                        btn.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                    }
                }
            }
        }

        private void StartScan()
        {
            // 检查是否已经选择了扫描类型
            if (!isScanTypeSelected)
            {
                // 提示用户先选择扫描类型
                MessageBox.Show("请先选择扫描类型", _languageManager.GetString("Info"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            
            if (selectedScanType == FireAntivirus.Engine.ScanType.Custom)
            {
                using (var fbd = new FolderBrowserDialog())
                {
                    if (fbd.ShowDialog() == DialogResult.OK)
                    {
                        // 开始自定义扫描
                        StartScanProcess(fbd.SelectedPath);
                    }
                }
            }
            else
            {
                // 使用当前选择的扫描类型
                StartScanProcess(null);
            }
        }

        private void StartScanProcess(string path = null)
        {
            // 快速更新UI状态
            statusLabel.Text = "正在初始化扫描引擎...";
            startScanBtn.Enabled = false;
            pauseScanBtn.Enabled = true;
            stopScanBtn.Enabled = true;
            scanResultsList.Items.Clear();
            scanProgressBar.Value = 0;
            progressLabel.Text = "已扫描: 0 个文件，发现: 0 个风险";
            cts = new System.Threading.CancellationTokenSource();

            // 使用ClamAVEngine进行扫描
            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    // 初始化扫描引擎
                    this.BeginInvoke((Action)(() =>
                    {
                        statusLabel.Text = "正在准备扫描选项...";
                    }));

                    // 获取扫描路径
                    List<string> scanPaths = new List<string>();
                    if (path != null)
                    {
                        scanPaths.Add(path);
                    }
                    else
                    {
                        switch (selectedScanType)
                        {
                            case FireAntivirus.Engine.ScanType.Quick:
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.System));
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
                                break;
                            case FireAntivirus.Engine.ScanType.Full:
                                foreach (var drive in DriveInfo.GetDrives())
                                {
                                    if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                                    {
                                        scanPaths.Add(drive.RootDirectory.FullName);
                                    }
                                }
                                break;
                            case FireAntivirus.Engine.ScanType.Deep:
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.System));
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
                                scanPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
                                break;
                        }
                    }

                    this.BeginInvoke((Action)(() =>
                    {
                        statusLabel.Text = "正在扫描...";
                    }));

                    // 使用 AntivirusEngine 进行扫描
                    var engine = antivirusEngine;
                    
                    // 注册进度事件
                    engine.ScanProgress += OnScanProgress;
                    // 注册威胁检测事件
                    engine.ThreatDetected += OnThreatDetected;

                    // 收集所有扫描结果
                    var scanOptions = new FireAntivirus.Engine.ScanOptions
                    {
                        ScanType = selectedScanType,
                        ScanMemory = true,
                        ScanRegistry = true,
                        ScanStartupItems = true,
                        ScanProcesses = true
                    };

                    int totalInfected = 0;
                    foreach (string scanPath in scanPaths)
                    {
                        if (Directory.Exists(scanPath))
                        {
                            try
                            {
                                var results = engine.ScanDirectory(scanPath, scanOptions);
                                if (results != null)
                                {
                                    totalInfected += results.Count(r => r.IsInfected);
                                }
                            }
                            catch (Exception ex)
                            {
                                Log($"扫描目录失败: {scanPath}, 错误: {ex.Message}");
                            }
                        }
                    }

                    // 移除事件处理器
                    engine.ScanProgress -= OnScanProgress;
                    engine.ThreatDetected -= OnThreatDetected;

                    // 快速更新UI状态
                    int finalInfected = totalInfected;
                    this.BeginInvoke((Action)(() =>
                    {
                        statusLabel.Text = $"扫描完成，发现 {finalInfected} 个风险";
                        startScanBtn.Enabled = true;
                        pauseScanBtn.Enabled = false;
                        stopScanBtn.Enabled = false;
                        scanProgressBar.Value = 100;
                        progressLabel.Text = $"扫描完成，发现: {finalInfected} 个风险";
                    }));

                    Log($"扫描完成: 发现 {totalInfected} 个风险");
                }
                catch (Exception ex)
                {
                    Log($"扫描过程中发生错误: {ex.Message}");
                    this.BeginInvoke((Action)(() =>
                    {
                        statusLabel.Text = "扫描过程中发生错误";
                        startScanBtn.Enabled = true;
                        pauseScanBtn.Enabled = false;
                        stopScanBtn.Enabled = false;
                    }));
                }
                finally
                {
                    cts?.Dispose();
                }
            });
        }

        private void OnScanProgress(object sender, ScanProgressEventArgs e)
        {
            // 使用BeginInvoke避免阻塞扫描线程
            this.BeginInvoke((Action)(() =>
            {
                try
                {
                    if (scanProgressBar != null)
                        scanProgressBar.Value = Math.Min(100, Math.Max(0, (int)e.Progress));
                    if (progressLabel != null)
                        progressLabel.Text = $"已扫描: {e.FilesScanned} / {e.TotalFiles} 个文件，发现: {scanResultsList?.Items.Count ?? 0} 个风险";
                }
                catch { }
            }));
        }

        private void OnThreatDetected(object sender, ThreatDetectedEventArgs e)
        {
            // 使用BeginInvoke避免阻塞扫描线程
            this.BeginInvoke((Action)(() =>
            {
                try
                {
                    if (scanResultsList != null && e?.Threat != null)
                    {
                        string threatInfo = $"发现风险文件: {e.Threat.FilePath} - 病毒类型: {e.Threat.ThreatType}";
                        // 限制结果数量，避免UI卡顿
                        if (scanResultsList.Items.Count < 100)
                        {
                            scanResultsList.Items.Add(threatInfo);
                        }
                        if (progressLabel != null)
                            progressLabel.Text = $"已扫描: 多个文件，发现: {scanResultsList.Items.Count} 个风险";
                    }
                }
                catch { }
            }));
        }

        private void PauseScan(object sender, EventArgs e)
        {
            statusLabel.Text = _languageManager.GetString("ScanPaused");
            pauseScanBtn.Text = _languageManager.GetString("ResumeScan");
            pauseScanBtn.Click -= PauseScan;
            pauseScanBtn.Click += ResumeScan;
        }

        private void ResumeScan(object sender, EventArgs e)
        {
            statusLabel.Text = "正在扫描...";
            pauseScanBtn.Text = "暂停扫描";
            pauseScanBtn.Click -= ResumeScan;
            pauseScanBtn.Click += PauseScan;
        }

        private void StopScan()
        {
            if (cts != null)
            {
                cts.Cancel();
            }
            
            statusLabel.Text = "扫描已停止";
            startScanBtn.Enabled = true;
            pauseScanBtn.Enabled = false;
            stopScanBtn.Enabled = false;
            pauseScanBtn.Text = "暂停扫描";
            pauseScanBtn.Click -= ResumeScan;
            pauseScanBtn.Click += PauseScan;
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
            
            if (statusLabel != null)
                statusLabel.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
            if (progressLabel != null)
                progressLabel.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
            if (scanResultsList != null)
            {
                scanResultsList.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                scanResultsList.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
            }
            if (scanProgressBar != null)
            {
                scanProgressBar.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                scanProgressBar.ForeColor = GetThemeColor(ThemeColor.PrimaryColor);
            }
            if (quickScanBtn != null)
                UpdateButtonTheme(quickScanBtn);
            if (fullScanBtn != null)
                UpdateButtonTheme(fullScanBtn);
            if (deepScanBtn != null)
                UpdateButtonTheme(deepScanBtn);
            if (customScanBtn != null)
                UpdateButtonTheme(customScanBtn);
            if (startScanBtn != null)
                UpdateButtonTheme(startScanBtn);
            if (pauseScanBtn != null)
                UpdateButtonTheme(pauseScanBtn);
            if (stopScanBtn != null)
                UpdateButtonTheme(stopScanBtn);
        }
        
        private void UpdateControlsTheme(Control control)
        {
            foreach (Control child in control.Controls)
            {
                if (child is Panel panel)
                {
                    panel.BackColor = GetThemeColor(ThemeColor.BgPrimary);
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
                    
                    if (label.Font.Bold)
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                    }
                    else
                    {
                        label.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
                    }
                }
                else if (child is Button button)
                {
                    // 按钮的主题在UpdateButtonTheme中更新
                }
                
                // 递归更新子控件
                UpdateControlsTheme(child);
            }
        }

        private void UpdateButtonTheme(Button btn)
        {
            if (btn == null)
                return;
            // 检查按钮是否是当前选中的扫描类型
            bool isSelectedScanType = false;
            if (btn.Tag is FireAntivirus.Engine.ScanType)
            {
                isSelectedScanType = (FireAntivirus.Engine.ScanType)btn.Tag == selectedScanType;
            }
            if (isSelectedScanType)
            {
                btn.BackColor = GetThemeColor(ThemeColor.PrimaryColor);
                btn.ForeColor = Color.White;
            }
            else
            {
                btn.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                btn.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
            }
            btn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
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
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(50, 50, 50);
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
                    case ThemeColor.PrimaryColor:
                        return Color.FromArgb(37, 99, 235);
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
                    default:
                        return Color.White;
                }
            }
        }
    }
}