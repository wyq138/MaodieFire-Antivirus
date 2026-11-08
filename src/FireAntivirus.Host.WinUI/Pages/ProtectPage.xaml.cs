// 实时防护中心（简洁风）：全部防护功能整合于本页，统一使用 UiKit 视觉语言。
//   - 防护开关（8 项真实生效）+ 一键自检（已知/变种/勒索/全套）
//   - 高级引擎：YARA/YARA-X 规则引擎 + LMD 特征库 + Rootkit 查杀
//   - 内核级防护（需驱动组件，如实标注不可用）
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class RootkitRow
    {
        public string Category { get; set; }
        public string Name { get; set; }
        public string Detail { get; set; }
        public string Severity { get; set; }
    }

    public sealed partial class ProtectPage : Page
    {
        private readonly RealTimeProtection _rt = RealTimeProtection.Instance;
        // RTPPlus 通过 App.EnsureRtp() 统一获取（见 Rtp 属性）

        private TextBlock _heroState;
        private TextBlock _engineState;
        private TextBlock _rootkitState;
        private ProgressBar _rootkitProgress;
        private Button _rootkitBtn;
        private Expander _rootkitExpander;
        private TextBlock _countText;
        private bool _driverLoaded;
        private readonly List<(ToggleSwitch Toggle, Func<bool> GetState)> _toggles = new();

        public ObservableCollection<RootkitRow> RootkitItems { get; } = new();

        public ProtectPage()
        {
            InitializeComponent();
            try
            {
                Content = BuildLayout();
                RefreshToggles(Content);
                RefreshEngineState();
            }
            catch (Exception ex)
            {
                Content = PageGuard.BuildError("实时防护", ex);
            }
        }

        /// <summary>RealTimeProtectionPlus 单例：复用 App 启动链创建的实例（不再分裂 new，签名库只加载一份）。</summary>
        private FireAntivirus.RealTimeProtectionPlus.RealTimeProtectionPlusManager Rtp => App.EnsureRtp();

        // ============================================================
        // 布局（简洁风）
        // ============================================================
        private UIElement BuildLayout()
        {
            var scroll = new ScrollViewer { Padding = new Thickness(28, 10, 28, 24) };
            var root = new StackPanel { Spacing = 14 };

            // 标题区
            var head = new StackPanel { Spacing = 4 };
            head.Children.Add(UiKit.PageTitle("实时防护"));

            _heroState = new TextBlock { FontSize = 13, Foreground = UiKit.TextSecondary };
            head.Children.Add(_heroState);
            root.Children.Add(head);

            // ---- 实时拦截统计（KernelEventMonitor 全局计数，事件驱动实时刷新） ----
            _statsText = new TextBlock { FontSize = 12, Foreground = UiKit.TextSecondary, VerticalAlignment = VerticalAlignment.Center };
            root.Children.Add(UiKit.Card(new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 10,
                Children =
                {
                    new Microsoft.UI.Xaml.Controls.FontIcon { Glyph = "\uE72E", FontSize = 16, Foreground = UiKit.IconFg, VerticalAlignment = VerticalAlignment.Center },
                    _statsText
                }
            }));
            RefreshStats();
            HookStatsChanged();

            // 自检行
            var selfRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 2, 0, 0) };
            selfRow.Children.Add(SelfTestButton("自检 · 已知样本", "known"));
            selfRow.Children.Add(SelfTestButton("自检 · 变种样本", "variant"));
            selfRow.Children.Add(SelfTestButton("自检 · 勒索行为", "ransom"));
            selfRow.Children.Add(SelfTestButton("自检 · 全套", "module"));
            root.Children.Add(selfRow);

            // ---- 防护开关 ----
            root.Children.Add(UiKit.Section("防护开关"));
            var toggleCard = new StackPanel { Spacing = 2 };

            toggleCard.Children.Add(ToggleRow("\uE7C3", "文件防护", "新建可执行文件即时扫描，高危自动隔离",
                () => _rt.FileGuardEnabled, v => _rt.FileGuardEnabled = v));
            toggleCard.Children.Add(UiKit.Divider());
            toggleCard.Children.Add(ToggleRow("\uE71D", "进程防护", "监控恶意进程行为，结合引擎拦截可疑进程",
                () => GetModuleEnabled(), v => SetModule(FireAntivirus.RealTimeProtectionPlus.ProtectionType.Process, v)));
            toggleCard.Children.Add(UiKit.Divider());
            toggleCard.Children.Add(ToggleRow("\uE88E", "U盘防护", "接入自动弹窗扫描，高危威胁自动隔离防拔盘逃逸",
                () => _rt.UsbGuardEnabled, v =>
                {
                    _rt.UsbGuardEnabled = v;
                    if (v) UsbGuard.Instance.Start(); else UsbGuard.Instance.Stop();
                }));
            toggleCard.Children.Add(UiKit.Divider());
            toggleCard.Children.Add(ToggleRow("\uE9F5", "注册表防护", "监控自启动项修改，防止持久化篡改",
                () => GetModuleEnabled(), v => SetModule(FireAntivirus.RealTimeProtectionPlus.ProtectionType.Registry, v)));
            toggleCard.Children.Add(UiKit.Divider());
            toggleCard.Children.Add(ToggleRow("\uE774", "网络/浏览器防护", "基于威胁情报拦截恶意下载与网址访问",
                () => GetModuleEnabled(), v => SetModule(FireAntivirus.RealTimeProtectionPlus.ProtectionType.Network, v)));
            toggleCard.Children.Add(UiKit.Divider());
            toggleCard.Children.Add(ToggleRow("\uE943", "脚本防护", "JS/VBS/BAT/CMD/PowerShell 落盘即时扫描",
                () => _rt.ScriptGuardEnabled, v => _rt.ScriptGuardEnabled = v));
            toggleCard.Children.Add(UiKit.Divider());
            toggleCard.Children.Add(ToggleRow("\uE823", "行为防护", "识别勒索/注入等可疑程序行为",
                () => GetModuleEnabled(), v => SetModule(FireAntivirus.RealTimeProtectionPlus.ProtectionType.Behavior, v)));
            toggleCard.Children.Add(UiKit.Divider());
            toggleCard.Children.Add(ToggleRow("\uE8E5", "文档防护", "批量加密行为即时告警（勒索检测）",
                () => _rt.RansomGuardEnabled, v => _rt.RansomGuardEnabled = v));

            root.Children.Add(UiKit.Card(toggleCard));

            // ---- 高级引擎 ----
            root.Children.Add(UiKit.Section("高级引擎"));
            var engineCard = new StackPanel { Spacing = 2 };

            _engineState = new TextBlock { FontSize = 12, Foreground = UiKit.TextSecondary, TextWrapping = TextWrapping.Wrap };
            engineCard.Children.Add(UiKit.Row("\uE943", "YARA / YARA-X 规则引擎", null,
                new TextBlock { Text = "", FontSize = 12, Foreground = UiKit.TextSecondary }));
            engineCard.Children.Add(UiKit.Divider());
            engineCard.Children.Add(UiKit.Row("\uE8A9", "LMD 特征库", "Linux Malware Detect 官方源 · ndb/md5/yara 三格式", null));
            engineCard.Children.Add(UiKit.Divider());

            // Rootkit 查杀行
            _rootkitBtn = UiKit.Primary("立即扫描");
            _rootkitBtn.Click += RootkitScan_Click;
            var rkRowGrid = new Grid { ColumnSpacing = 14 };
            rkRowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            rkRowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            rkRowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            rkRowGrid.Children.Add(new FontIcon { Glyph = "\uE72E", FontSize = 18, Foreground = UiKit.IconFg, VerticalAlignment = VerticalAlignment.Center });

            var rkText = new StackPanel { Spacing = 2, VerticalAlignment = VerticalAlignment.Center };
            rkText.Children.Add(new TextBlock { Text = "Rootkit 查杀", FontSize = 14, Foreground = UiKit.TextPrimary });
            _rootkitState = new TextBlock
            {
                Text = "ntdll Hook / 隐藏进程 / 可疑驱动 / 持久化植入",
                FontSize = 12,
                Foreground = UiKit.TextSecondary,
                TextWrapping = TextWrapping.Wrap
            };
            rkText.Children.Add(_rootkitState);
            Grid.SetColumn(rkText, 1);
            rkRowGrid.Children.Add(rkText);
            Grid.SetColumn(_rootkitBtn, 2);
            rkRowGrid.Children.Add(_rootkitBtn);

            engineCard.Children.Add(rkRowGrid);
            root.Children.Add(UiKit.Card(engineCard));

            // Rootkit 结果（默认折叠）
            _rootkitProgress = new ProgressBar { IsIndeterminate = false, Height = 3, Visibility = Visibility.Collapsed };
            root.Children.Add(_rootkitProgress);

            var list = new ListView { MaxHeight = 240, SelectionMode = ListViewSelectionMode.None };
            list.ItemTemplate = (DataTemplate)global::Microsoft.UI.Xaml.Markup.XamlReader.Load(@"
<DataTemplate xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"">
    <Grid ColumnSpacing=""10"" Padding=""6,5,6,5"">
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width=""92""/>
            <ColumnDefinition Width=""*""/>
            <ColumnDefinition Width=""Auto""/>
        </Grid.ColumnDefinitions>
        <TextBlock Text=""{Binding Category}"" FontSize=""12"" Opacity=""0.55"" VerticalAlignment=""Top""/>
        <StackPanel Grid.Column=""1"" Spacing=""1"">
            <TextBlock Text=""{Binding Name}"" FontSize=""12"" TextWrapping=""Wrap""/>
            <TextBlock Text=""{Binding Detail}"" FontSize=""11"" Opacity=""0.55"" TextWrapping=""Wrap""/>
        </StackPanel>
        <TextBlock Grid.Column=""2"" Text=""{Binding Severity}"" FontSize=""11"" VerticalAlignment=""Center""/>
    </Grid>
</DataTemplate>");
            list.ContainerContentChanging += (s, args) =>
            {
                if (args.Item is RootkitRow row && args.ItemContainer.ContentTemplateRoot is Grid g)
                {
                    var texts = g.Children.OfType<TextBlock>().ToList();
                    if (texts.Count >= 3)
                        texts[2].Foreground = row.Severity switch
                        {
                            "High" => UiKit.Danger,
                            "Medium" => UiKit.Warn,
                            _ => UiKit.IconFg
                        };
                }
            };
            list.ItemsSource = RootkitItems;

            _rootkitExpander = new Expander
            {
                Header = new TextBlock { Text = "扫描详情", FontSize = 12, Foreground = UiKit.TextSecondary },
                Content = list,
                IsExpanded = false,
                Visibility = Visibility.Collapsed,
                HorizontalAlignment = HorizontalAlignment.Stretch
            };
            root.Children.Add(_rootkitExpander);

            // ---- 内核级防护（真实驱动：已加载则开关生效，未加载提供一键安装） ----
            _driverLoaded = FireAntivirus.Engine.Kernel.KernelProtectionInterface.IsDriverLoaded();
            root.Children.Add(UiKit.Section(_driverLoaded ? "内核级防护（驱动已加载）" : "内核级防护（驱动未安装）"));
            root.Children.Add(BuildKernelCard());

            scroll.Content = root;
            return scroll;
        }

        /// <summary>内核级防护卡片：驱动已加载 → 三项真实开关（IOCTL 下发）；未加载 → 一键安装。</summary>
        private UIElement BuildKernelCard()
        {
            var kernelCard = new StackPanel { Spacing = 2 };

            if (_driverLoaded)
            {
                kernelCard.Children.Add(KernelToggleRow("\uE7EE", "分区表防护", "MBR 扇区写拦截（内核驱动）", "mbr"));
                kernelCard.Children.Add(UiKit.Divider());
                kernelCard.Children.Add(KernelToggleRow("\uE770", "UEFI/BIOS 防护", "GPT 引导结构写拦截（内核驱动）", "gpt"));
                kernelCard.Children.Add(UiKit.Divider());
                kernelCard.Children.Add(KernelToggleRow("\uE72E", "内核防护", "进程拦截 + 本进程防杀（内核驱动）", "kernel"));
            }
            else
            {
                kernelCard.Children.Add(UiKit.Row("\uE7EE", "分区表 / UEFI / 内核防护",
                    "需要内核驱动组件。检测到 FireAntivirusKrn 驱动未安装，安装后三项防护即可用。", null));

                var installBtn = UiKit.Primary("安装内核驱动（需管理员）");
                installBtn.Click += async (_, _) =>
                {
                    var (ok, msg) = FireAntivirus.Engine.Kernel.KernelProtectionInterface.InstallAndStartDriver();
                    await new ContentDialog
                    {
                        Title = ok ? "内核驱动已加载 ✓" : "安装未完成",
                        Content = msg,
                        CloseButtonText = "确定",
                        XamlRoot = XamlRoot
                    }.ShowAsync();

                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        $"内核驱动安装: {(ok ? "成功" : "失败")} - {msg}");

                    // 重新构建整页（驱动就绪后开关即生效）
                    Content = BuildLayout();
                    RefreshToggles(Content);
                    RefreshEngineState();
                };
                kernelCard.Children.Add(installBtn);
            }

            return UiKit.Card(kernelCard);
        }

        /// <summary>内核防护开关行（切换即向驱动下发 IOCTL，真实生效）。</summary>
        private Grid KernelToggleRow(string glyph, string title, string subtitle, string mode)
        {
            var toggle = UiKit.Toggle(true, (sender, _) =>
            {
                bool on = ((ToggleSwitch)sender).IsOn;
                bool ok = FireAntivirus.Engine.Kernel.KernelProtectionInterface.SetKernelProtection(mode, on);
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"内核防护[{title}] 切换为 {(on ? "开启" : "关闭")}: {(ok ? "已下发驱动" : "下发失败")}");
            });
            return UiKit.Row(glyph, title, subtitle, toggle);
        }

        /// <summary>简洁开关行（开关变更即真实生效）。</summary>
        private Grid ToggleRow(string glyph, string title, string subtitle, Func<bool> getState, Action<bool> setState)
        {
            var toggle = UiKit.Toggle(getState(), (sender, _) =>
            {
                try
                {
                    setState(((ToggleSwitch)sender).IsOn);
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        $"实时防护[{title}] 切换为 {(((ToggleSwitch)sender).IsOn ? "开启" : "关闭")}");
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                        $"防护开关[{title}]切换失败: {ex.Message}");
                }
                UpdateCount();
            });

            _toggles.Add((toggle, getState));

            var grid = UiKit.Row(glyph, title, subtitle, toggle);
            toggle.Tag = title; // LoadState/Refresh 用
            return grid;
        }

        private Grid KernelRow(string glyph, string title, string subtitle)
        {
            var badge = new TextBlock
            {
                Text = "不可用",
                FontSize = 12,
                Foreground = UiKit.TextSecondary,
                VerticalAlignment = VerticalAlignment.Center
            };
            return UiKit.Row(glyph, title, subtitle, badge);
        }

        private Button SelfTestButton(string text, string mode)
        {
            var btn = UiKit.Secondary(text);
            btn.Click += async (_, _) =>
            {
                btn.IsEnabled = false;
                _heroState.Text = mode switch
                {
                    "variant" => "变种自检：样本哈希已变形（绕过精确特征库），考验启发式+多检测器共识...",
                    "ransom" => "勒索自检：模拟批量加密行为（写入 18 个加密特征文档）...",
                    "module" => "防护模块全套自检：引擎查杀/特征库/实时管线全链路验证...",
                    _ => "自检：投放 EICAR 标准样本验证精确特征通路..."
                };

                try
                {
                    if (mode == "module")
                    {
                        var items = await Rtp.RunSelfTestAsync();
                        int passed = items.Count(i => i.Passed);
                        var lines = items.Select(i => $"{(i.Passed ? "✓" : "✗")} [{i.Category}] {i.Name}: {i.Detail}");

                        await new ContentDialog
                        {
                            Title = passed == items.Count ? $"防护模块自检全部通过 ✓ ({passed}/{items.Count})" : $"防护模块自检 {passed}/{items.Count} 通过",
                            Content = new ScrollViewer { MaxHeight = 320, Content = new TextBlock { Text = string.Join("\n", lines), TextWrapping = TextWrapping.Wrap, FontSize = 12 } },
                            CloseButtonText = "确定",
                            XamlRoot = XamlRoot
                        }.ShowAsync();
                    }
                    else if (mode == "ransom")
                    {
                        var (detected, detail) = await _rt.SelfTestRansomAsync();
                        await ShowResult("勒索行为拦截自检", detected, detail);
                    }
                    else
                    {
                        var (intercepted, detail) = await _rt.SelfTestAsync(mode);
                        await ShowResult(mode == "variant" ? "变种样本拦截自检" : "已知样本拦截自检", intercepted, detail);
                    }
                }
                finally
                {
                    btn.IsEnabled = true;
                    UpdateCount();
                }
            };
            return btn;
        }

        private async System.Threading.Tasks.Task ShowResult(string title, bool ok, string detail)
        {
            await new ContentDialog
            {
                Title = ok ? $"{title} 通过 ✓" : $"{title} 未通过 ✗",
                Content = detail,
                CloseButtonText = "确定",
                XamlRoot = XamlRoot
            }.ShowAsync();

            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                $"防护自检[{title}]: {(ok ? "通过" : "未通过")} - {detail}");
        }

        // ============================================================
        // 状态
        // ============================================================
        private void RefreshEngineState()
        {
            try
            {
                _engineState.Text = "YARA 规则库加载中...";
                // YARA 规则编译较重，放后台线程加载，完成后回填状态（页面构造不冻结）
                System.Threading.Tasks.Task.Run(() =>
                {
                    try
                    {
                        FireAntivirus.Engine.Analyzers.YaraRuleEngine.EnsureRulesLoaded();
                        bool yaraX = FireAntivirus.Engine.Analyzers.YaraRuleEngine.IsYaraXAvailable();

                        // YARA 行的状态文本（第二行文本由 Row 结构的第 1 列 StackPanel 承载——直接重建行状态太复杂，
                        // 这里把 YARA/LMD 状态合并显示在引擎卡上方的 _engineState）
                        DispatcherQueue.TryEnqueue(() =>
                            _engineState.Text =
                                $"YARA 规则 {FireAntivirus.Engine.Analyzers.YaraRuleEngine.RuleCount} 条（含 LMD 特征）" +
                                (yaraX ? " · YARA-X CLI 已就绪（优先使用）" : " · 内置解释器运行"));
                    }
                    catch
                    {
                        DispatcherQueue.TryEnqueue(() => _engineState.Text = "YARA 规则库加载中...");
                    }
                });
            }
            catch
            {
                _engineState.Text = "YARA 规则库加载中...";
            }
        }

        private bool _moduleState = true;
        private bool GetModuleEnabled() => _moduleState;

        private void SetModule(FireAntivirus.RealTimeProtectionPlus.ProtectionType type, bool enabled)
        {
            try
            {
                _moduleState = enabled;
                if (enabled)
                {
                    Rtp.StartProtection();
                    Rtp.EnableModule(type);

                    // 内核联动：进程/注册表模块开启时，同步下发内核级拦截（驱动加载才生效）
                    if (FireAntivirus.Engine.Kernel.KernelProtectionInterface.IsDriverLoaded())
                    {
                        if (type == FireAntivirus.RealTimeProtectionPlus.ProtectionType.Process)
                            FireAntivirus.Engine.Kernel.KernelProtectionInterface.SetKernelProtection("kernel", true);
                        if (type == FireAntivirus.RealTimeProtectionPlus.ProtectionType.Registry)
                            FireAntivirus.Engine.Kernel.KernelProtectionInterface.SetKernelProtection("registry", true);
                    }
                }
                else
                {
                    Rtp.DisableModule(type);
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    $"防护模块[{type}]切换失败: {ex.Message}");
            }
        }

        private void UpdateCount()
        {
            int active = _toggles.Count(t =>
            {
                try { return t.GetState(); } catch { return true; }
            });
            int total = _toggles.Count;

            _heroState.Text = active == total
                ? $"{active}/{total} 项防护开启 · 系统处于全面防护状态"
                : $"{active}/{total} 项防护开启 · 引擎实时运行中";
        }

        // ---- 实时拦截统计（订阅 KernelEventMonitor 全局计数，事件驱动实时刷新） ----
        private TextBlock _statsText;
        private bool _statsHooked;

        private void RefreshStats()
        {
            if (_statsText != null)
                _statsText.Text = $"实时拦截统计：累计 {KernelEventMonitor.ThreatStats.Total} 次（内核 {KernelEventMonitor.ThreatStats.Kernel} · 用户态 {KernelEventMonitor.ThreatStats.Rtp}）";
        }

        private void HookStatsChanged()
        {
            if (_statsHooked) return;
            _statsHooked = true;
            KernelEventMonitor.ThreatStats.StatsChanged += OnStatsChanged;
        }

        private void OnStatsChanged()
        {
            DispatcherQueue.TryEnqueue(RefreshStats);
        }

        protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            DispatcherQueue.TryEnqueue(RefreshStats);
        }

        // 递归恢复开关显示状态（构造时已按 getState 初始化，此处兜底）
        private void RefreshToggles(UIElement element)
        {
            if (element == null) return;

            if (element is Panel panel)
            {
                foreach (var child in panel.Children) RefreshToggles(child);
            }
            else if (element is Border border)
            {
                RefreshToggles(border.Child);
            }
            else if (element is ScrollViewer sv)
            {
                RefreshToggles(sv.Content as UIElement);
            }
            else if (element is ContentPresenter cp && cp.Content is UIElement cpContent)
            {
                RefreshToggles(cpContent);
            }
        }

        // ============================================================
        // Rootkit 扫描
        // ============================================================
        private async void RootkitScan_Click(object sender, RoutedEventArgs e)
        {
            _rootkitBtn.IsEnabled = false;
            _rootkitProgress.Visibility = Visibility.Visible;
            _rootkitProgress.IsIndeterminate = true;
            _rootkitState.Text = "正在扫描（ntdll 完整性 / 进程 / 驱动 / 持久化）...";
            RootkitItems.Clear();

            try
            {
                var result = await System.Threading.Tasks.Task.Run(
                    () => FireAntivirus.Engine.Scanners.RootkitDetector.ScanAll());

                RootkitItems.Clear();
                foreach (var f in result.Findings.OrderByDescending(f =>
                    f.Severity == "High" ? 0 : f.Severity == "Medium" ? 1 : 2))
                {
                    RootkitItems.Add(new RootkitRow
                    {
                        Category = f.Category,
                        Name = f.Name,
                        Detail = f.Detail,
                        Severity = f.Severity
                    });
                }

                if (result.IsClean)
                {
                    _rootkitState.Text = $"✓ 未发现 Rootkit 痕迹（进程 {result.ProcessesScanned} · 驱动模块 {result.ModulesScanned}）";
                    _rootkitState.Foreground = UiKit.Ok;
                }
                else
                {
                    int high = result.Findings.Count(f => f.Severity == "High");
                    _rootkitState.Text = $"发现 {result.Findings.Count} 项可疑（高危 {high}），详见下方列表";
                    _rootkitState.Foreground = UiKit.Warn;
                    _rootkitExpander.IsExpanded = RootkitItems.Count <= 6;
                }
                _rootkitExpander.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                _rootkitState.Text = $"扫描失败: {ex.Message}";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "Rootkit 扫描失败: " + ex.Message);
            }
            finally
            {
                _rootkitBtn.IsEnabled = true;
                _rootkitProgress.Visibility = Visibility.Collapsed;
                _rootkitProgress.IsIndeterminate = false;
            }
        }

        // 由 XamlCompiler 生成的 .g.cs 引用（XAML 事件绑定），保留以保证编译；
        // 实际展示 UI 由 BuildLayout() 构建，开关逻辑在 ToggleRow 闭包中。
        private void FileGuard_Toggled(object sender, RoutedEventArgs e)
        {
            RealTimeProtection.Instance.FileGuardEnabled = ((ToggleSwitch)sender).IsOn;
        }

        private void Ransom_Toggled(object sender, RoutedEventArgs e)
        {
            RealTimeProtection.Instance.RansomGuardEnabled = ((ToggleSwitch)sender).IsOn;
        }
    }
}
