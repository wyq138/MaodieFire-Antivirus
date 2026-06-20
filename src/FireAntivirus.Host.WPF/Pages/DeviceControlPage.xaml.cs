// 抖音用户 耙耋杀毒软件 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using FireAntivirus.Services;
using FireAntivirus.Data;
using FireAntivirus.Common.Localization;

using FireAntivirus.Host.WPF;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class DeviceControlPage : Page, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private DeviceControlService deviceControl;
        private DataManager dataManager;
        private LanguageManager _languageManager = LanguageManager.Instance;
        private ObservableCollection<DeviceInfoItem> connectedDevices = new ObservableCollection<DeviceInfoItem>();
        private ObservableCollection<string> trustedDevices = new ObservableCollection<string>();

        public DeviceControlPage()
        {
            InitializeComponent();
            SetupEventHandlers();
            _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
        }

        private void InitializeService()
        {
            try
            {
                dataManager = new DataManager();
                deviceControl = new DeviceControlService(dataManager);
                
                // 加载数据
                DevicesGrid.ItemsSource = connectedDevices;
                TrustedDevicesList.ItemsSource = trustedDevices;
            }
            catch { }
        }

        private void SetupEventHandlers()
        {
            RefreshDevicesBtn.Click += RefreshDevices_Click;
            AddTrustedBtn.Click += AddTrusted_Click;
            RemoveTrustedBtn.Click += RemoveTrusted_Click;
            
            EnableDeviceControl.Checked += (s, e) => UpdateSettings();
            EnableDeviceControl.Unchecked += (s, e) => UpdateSettings();
            BlockUSB.Checked += (s, e) => { deviceControl?.SetBlockUSB(true); };
            BlockUSB.Unchecked += (s, e) => { deviceControl?.SetBlockUSB(false); };
            BlockBluetooth.Checked += (s, e) => { deviceControl?.SetBlockBluetooth(true); };
            BlockBluetooth.Unchecked += (s, e) => { deviceControl?.SetBlockBluetooth(false); };
        }

        private void UpdateSettings()
        {
            // 更新设置
        }

        private void RefreshDevices_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                connectedDevices.Clear();
                var devices = deviceControl?.GetDevices();
                if (devices != null)
                {
                    foreach (var d in devices)
                    {
                        connectedDevices.Add(new DeviceInfoItem
                        {
                            DeviceName = d.Name,
                            Type = d.Type,
                            Status = trustedDevices.Contains(d.DeviceId) ? "信任" : "正常"
                        });
                    }
                }
                
                MessageBox.Show($"已刷新，发现 {connectedDevices.Count} 个设备", "设备控制", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"刷新失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AddTrusted_Click(object sender, RoutedEventArgs e)
        {
            if (DevicesGrid.SelectedItem is DeviceInfoItem selected)
            {
                var deviceId = Microsoft.VisualBasic.Interaction.InputBox("请输入设备ID:", "添加信任设备", "");
                if (!string.IsNullOrEmpty(deviceId) && !trustedDevices.Contains(deviceId))
                {
                    deviceControl?.TrustDevice(deviceId);
                    trustedDevices.Add(deviceId);
                }
            }
            else
            {
                var deviceId = Microsoft.VisualBasic.Interaction.InputBox("请输入设备ID:", "添加信任设备", "");
                if (!string.IsNullOrEmpty(deviceId) && !trustedDevices.Contains(deviceId))
                {
                    deviceControl?.TrustDevice(deviceId);
                    trustedDevices.Add(deviceId);
                }
            }
        }

        private void RemoveTrusted_Click(object sender, RoutedEventArgs e)
        {
            if (TrustedDevicesList.SelectedItem is string selected)
            {
                deviceControl?.UntrustDevice(selected);
                trustedDevices.Remove(selected);
            }
            else
            {
                MessageBox.Show("请先选择一个设备", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
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
            try { TitleText.Text = _languageManager.GetString("DeviceControl", "设备控制"); }
            catch { }
        }
    }

    // 设备信息项
    public class DeviceInfoItem
    {
        public string DeviceName { get; set; }
        public string Type { get; set; }
        public string Status { get; set; }
    }
}
