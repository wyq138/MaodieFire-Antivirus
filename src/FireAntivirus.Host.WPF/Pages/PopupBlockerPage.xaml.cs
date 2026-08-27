// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Xml.Serialization;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    /// <summary>
    /// 弹窗拦截页面 - 从WinForms转换
    /// </summary>
    public partial class PopupBlockerPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private PopupRuleManager ruleManager;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public PopupBlockerPage()
        {
            try
            {
                ruleManager = new PopupRuleManager();
                InitializeComponent();
                LoadPopupRules();
                
                // 订阅语言变更事件
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing PopupBlockerPage: {ex.Message}");
            }
        }

        private void LoadPopupRules_Click(object sender, RoutedEventArgs e)
        {
            LoadPopupRules();
        }

        private void LoadPopupRules()
        {
            try
            {
                var rules = ruleManager.GetRules();
                PopupRulesGrid.ItemsSource = null;
                PopupRulesGrid.ItemsSource = rules;
            }
            catch
            {
                // 如果读取失败，显示空列表
                PopupRulesGrid.ItemsSource = new List<PopupRule>();
            }
        }

        private void AddPopupRule_Click(object sender, RoutedEventArgs e)
        {
            // 创建添加规则窗口
            var addWindow = new Window
            {
                Title = "添加弹窗规则",
                Width = 500,
                Height = 300,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                ResizeMode = ResizeMode.NoResize
            };

            var mainGrid = new Grid { Margin = new Thickness(20) };
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // 应用名称
            var appNamePanel = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            appNamePanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
            appNamePanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            
            var appNameLabel = new TextBlock { Text = "应用名称:", VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(appNameLabel, 0);
            appNamePanel.Children.Add(appNameLabel);
            
            var appNameTextBox = new TextBox { Height = 30, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(appNameTextBox, 1);
            appNamePanel.Children.Add(appNameTextBox);
            mainGrid.Children.Add(appNamePanel);
            Grid.SetRow(appNamePanel, 0);

            // 路径
            var pathPanel = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            pathPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
            pathPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            
            var pathLabel = new TextBlock { Text = "路径:", VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(pathLabel, 0);
            pathPanel.Children.Add(pathLabel);
            
            var pathTextBox = new TextBox { Height = 30, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(pathTextBox, 1);
            pathPanel.Children.Add(pathTextBox);
            mainGrid.Children.Add(pathPanel);
            Grid.SetRow(pathPanel, 1);

            // 规则
            var rulePanel = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            rulePanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
            rulePanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            
            var ruleLabel = new TextBlock { Text = "规则:", VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(ruleLabel, 0);
            rulePanel.Children.Add(ruleLabel);
            
            var ruleComboBox = new ComboBox { Height = 30, VerticalAlignment = VerticalAlignment.Center };
            ruleComboBox.Items.Add("广告弹窗");
            ruleComboBox.Items.Add("推广弹窗");
            ruleComboBox.Items.Add("新闻弹窗");
            ruleComboBox.Items.Add("更新弹窗");
            ruleComboBox.Items.Add("其他弹窗");
            ruleComboBox.SelectedIndex = 0;
            Grid.SetColumn(ruleComboBox, 1);
            rulePanel.Children.Add(ruleComboBox);
            mainGrid.Children.Add(rulePanel);
            Grid.SetRow(rulePanel, 2);

            // 按钮
            var buttonPanel = new StackPanel 
            { 
                Orientation = Orientation.Horizontal, 
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 20, 0, 0)
            };
            
            var okButton = new Button 
            { 
                Content = "确定", 
                Width = 100, 
                Height = 40,
                Margin = new Thickness(10, 0, 10, 0)
            };
            
            var cancelButton = new Button 
            { 
                Content = "取消", 
                Width = 100, 
                Height = 40,
                Margin = new Thickness(10, 0, 10, 0)
            };
            
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            mainGrid.Children.Add(buttonPanel);
            Grid.SetRow(buttonPanel, 4);

            addWindow.Content = mainGrid;

            okButton.Click += (s, args) =>
            {
                if (!string.IsNullOrEmpty(appNameTextBox.Text) && !string.IsNullOrEmpty(pathTextBox.Text))
                {
                    var newRule = new PopupRule
                    {
                        AppName = appNameTextBox.Text,
                        Path = pathTextBox.Text,
                        Rule = ruleComboBox.SelectedItem?.ToString() ?? "其他弹窗",
                        Count = 0
                    };
                    ruleManager.AddRule(newRule);
                    LoadPopupRules();
                }
                addWindow.Close();
            };

            cancelButton.Click += (s, args) => addWindow.Close();

            addWindow.ShowDialog();
        }

        private void DeletePopupRule_Click(object sender, RoutedEventArgs e)
        {
            if (PopupRulesGrid.SelectedItem is PopupRule selectedRule)
            {
                ruleManager.RemoveRule(selectedRule);
                LoadPopupRules();
            }
        }

        private void ClearPopupRules_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("确定要清空所有弹窗规则吗？", "确认", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                ruleManager.ClearRules();
                LoadPopupRules();
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            if (currentTheme == Theme.Dark)
            {
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
                PopupRulesGrid.Background = new SolidColorBrush(Color.FromRgb(50, 50, 50));
            }
            else
            {
                MainGrid.Background = new SolidColorBrush(Colors.White);
                PopupRulesGrid.Background = new SolidColorBrush(Color.FromRgb(243, 244, 246));
            }
        }

        private void UpdateLanguage()
        {
            try
            {
                TitleText.Text = _languageManager.GetString("PopupBlocker", "弹窗拦截");
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PopupBlockerPage.xaml.cs 捕获异常", ex.Message); }
        }
    }

    // 弹窗规则类
    public class PopupRule
    {
        public string AppName { get; set; }
        public string Path { get; set; }
        public string Rule { get; set; }
        public int Count { get; set; }
    }

    // 弹窗规则管理器
    public class PopupRuleManager
    {
        private static string RulesFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "FireAntivirus", "popup_rules.xml");

        private List<PopupRule> rules = new List<PopupRule>();

        public PopupRuleManager()
        {
            LoadRules();
        }

        public void LoadRules()
        {
            try
            {
                if (File.Exists(RulesFile))
                {
                    using (var reader = new StreamReader(RulesFile))
                    {
                        var serializer = new XmlSerializer(typeof(List<PopupRule>));
                        rules = (List<PopupRule>)serializer.Deserialize(reader);
                    }
                }
                else
                {
                    rules = new List<PopupRule>();
                    SaveRules();
                }
            }
            catch
            {
                rules = new List<PopupRule>();
            }
        }

        public void SaveRules()
        {
            try
            {
                var dir = Path.GetDirectoryName(RulesFile);
                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                using (var writer = new StreamWriter(RulesFile))
                {
                    var serializer = new XmlSerializer(typeof(List<PopupRule>));
                    serializer.Serialize(writer, rules);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PopupBlockerPage.xaml.cs 捕获异常", ex.Message); }
        }

        public List<PopupRule> GetRules()
        {
            return rules;
        }

        public void AddRule(PopupRule rule)
        {
            rules.Add(rule);
            SaveRules();
        }

        public void RemoveRule(PopupRule rule)
        {
            rules.Remove(rule);
            SaveRules();
        }

        public void ClearRules()
        {
            rules.Clear();
            SaveRules();
        }

        public void IncrementCount(string path)
        {
            var rule = rules.Find(r => r.Path == path);
            if (rule != null)
            {
                rule.Count++;
                SaveRules();
            }
        }
    }
}