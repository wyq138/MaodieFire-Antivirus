// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Common.Localization;
using FireAntivirus.ParentalControl;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class ParentalControlPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private ParentalControlManager parentalControl;
        private DataManager dataManager;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private ObservableCollection<string> users = new ObservableCollection<string>();

        public ParentalControlPage()
        {
            InitializeComponent();                
            // 延迟加载：将数据加载逻辑移到Loaded事件中
            Loaded += (s, e) =>
            {
                InitializeService();
                SetupEventHandlers();
            };
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
        }

        private void InitializeService()
        {
            try
            {
                dataManager = new DataManager();
                parentalControl = new ParentalControlManager(dataManager);
                
                // 加载用户列表
                users.Add("默认用户");
                UsersListBox.ItemsSource = users;
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControlPage.xaml.cs 捕获异常", ex.Message); }
        }

        private void SetupEventHandlers()
        {
            AddUserBtn.Click += AddUser_Click;
            RemoveUserBtn.Click += RemoveUser_Click;
            SaveBtn.Click += SaveSettings_Click;
        }

        private void AddUser_Click(object sender, RoutedEventArgs e)
        {
            var input = Microsoft.VisualBasic.Interaction.InputBox("请输入用户名:", "添加用户", "");
            if (!string.IsNullOrEmpty(input) && !users.Contains(input))
            {
                users.Add(input);
            }
        }

        private void RemoveUser_Click(object sender, RoutedEventArgs e)
        {
            if (UsersListBox.SelectedItem is string selected)
            {
                users.Remove(selected);
            }
        }

        private void SaveSettings_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 获取时间限制
                var limitText = (DailyLimitComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "无限制";
                
                // 解析小时数
                int hours = limitText switch
                {
                    "30分钟" => 0,
                    "1小时" => 1,
                    "2小时" => 2,
                    "3小时" => 3,
                    "4小时" => 4,
                    _ => 0
                };
                
                // 获取内容过滤设置
                bool blockAdult = BlockAdultContent.IsChecked == true;
                bool blockGambling = BlockGamblingContent.IsChecked == true;
                bool blockViolence = BlockViolenceContent.IsChecked == true;
                bool blockSocial = BlockSocialMedia.IsChecked == true;
                bool blockGames = BlockGames.IsChecked == true;
                
                // 创建设置
                var settings = parentalControl?.GetSettings();
                if (settings != null)
                {
                    settings.EnableTimeLimit = hours > 0;
                    settings.DailyTimeLimitMinutes = hours * 60;
                    settings.EnableContentFilter = blockAdult || blockGambling || blockViolence;
                    
                    parentalControl?.UpdateSettings(settings);
                }
                
                MessageBox.Show("家长控制设置已保存", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            if (theme == Theme.Dark)
                MainGrid.Background = new SolidColorBrush(Color.FromRgb(30, 30, 30));
            else
                MainGrid.Background = new SolidColorBrush(Colors.White);
        }

        private void UpdateLanguage()
        {
            try { TitleText.Text = _languageManager.GetString("ParentalControl", "家长控制"); }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ParentalControlPage.xaml.cs 捕获异常", ex.Message); }
        }
    }
}