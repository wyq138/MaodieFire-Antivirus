// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class ProtectionPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private Dictionary<string, CheckBox> protectionSwitches;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public ProtectionPage()
        {
            try
            {
                InitializeComponent();
                protectionSwitches = new Dictionary<string, CheckBox>();
                
                // 页面加载时初始化
                Loaded += (s, e) => InitializeProtectionItems();
                
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error initializing ProtectionPage: " + ex.Message);
            }
        }

        private void InitializeProtectionItems()
        {
            if (ProtectionList.Children.Count > 0) return;
            
            var protectionItems = new[]
            {
                new { Name = "文件防护", Description = "监控文件系统，防止恶意文件操作", Key = "FileProtection" },
                new { Name = "进程防护", Description = "监控系统进程，阻止恶意进程运行", Key = "ProcessProtection" },
                new { Name = "U盘防护", Description = "监控U盘插入，自动扫描移动设备", Key = "USBProtection" },
                new { Name = "注册表防护", Description = "监控注册表修改，防止系统被篡改", Key = "RegistryProtection" },
                new { Name = "浏览器防护", Description = "保护浏览器安全，拦截恶意网站", Key = "BrowserProtection" },
                new { Name = "脚本防护", Description = "监控JS、VBS、BAT、CMD、PowerShell脚本", Key = "ScriptProtection" },
                new { Name = "行为防护", Description = "分析程序行为，识别可疑操作", Key = "BehaviorProtection" },
                new { Name = "分区表防护", Description = "保护硬盘分区表，防止恶意擦除", Key = "PartitionTableProtection" },
                new { Name = "UEFI/BIOS防护", Description = "监控UEFI固件和BIOS设置变化", Key = "UEFIProtection" },
                new { Name = "内核防护", Description = "保护系统内核，防止驱动级攻击", Key = "KernelProtection" },
                new { Name = "文档防护", Description = "保护重要文档，防止被加密删除", Key = "DocumentProtection" }
            };

            foreach (var item in protectionItems)
            {
                var border = CreateProtectionItem(item.Name, item.Description, item.Key);
                ProtectionList.Children.Add(border);
            }
        }

        private Border CreateProtectionItem(string name, string description, string key)
        {
            var border = new Border
            {
                Background = (Brush)Application.Current.Resources["CardBg"],
                BorderBrush = (Brush)Application.Current.Resources["BorderColor"],
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Margin = new Thickness(0, 0, 0, 8),
                Padding = new Thickness(15)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var textStack = new StackPanel();
            
            var nameBlock = new TextBlock
            {
                Text = name,
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Foreground = (Brush)Application.Current.Resources["TextPrimary"]
            };
            textStack.Children.Add(nameBlock);

            var descBlock = new TextBlock
            {
                Text = description,
                FontSize = 11,
                Foreground = (Brush)Application.Current.Resources["TextSecondary"],
                Margin = new Thickness(0, 5, 0, 0),
                TextWrapping = TextWrapping.Wrap
            };
            textStack.Children.Add(descBlock);

            Grid.SetColumn(textStack, 0);
            grid.Children.Add(textStack);

            var toggle = new CheckBox();
            toggle.IsChecked = true;
            toggle.Margin = new Thickness(10, 0, 0, 0);
            toggle.VerticalAlignment = VerticalAlignment.Center;

            Grid.SetColumn(toggle, 1);
            grid.Children.Add(toggle);

            protectionSwitches[key] = toggle;

            border.Child = grid;
            return border;
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark)
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            }
            else
            {
                MainGrid.Background = Brushes.White;
            }
        }

        private void UpdateLanguage()
        {
            // 语言已是中文，无需更新
        }
    }
}
