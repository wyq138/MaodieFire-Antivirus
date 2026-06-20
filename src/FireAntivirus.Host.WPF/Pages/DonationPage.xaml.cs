// 抖音用户 耄耋杀毒软件 开发，严禁非法反编译
using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;

namespace FireAntivirus.Host.WPF.Pages
{
    public partial class DonationPage : Page, IThemed
    {
        public DonationPage()
        {
            InitializeComponent();
            LoadQRCodeImage();
        }

        private void LoadQRCodeImage()
        {
            try
            {
                string[] possiblePaths = new string[]
                {
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "收款码.jpg"),
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "收款码.jpg"),
                    Path.Combine(Directory.GetCurrentDirectory(), "Resources", "收款码.jpg"),
                    Path.Combine(Directory.GetCurrentDirectory(), "收款码.jpg")
                };

                foreach (var path in possiblePaths)
                {
                    string fullPath = Path.GetFullPath(path);
                    if (File.Exists(fullPath))
                    {
                        var bitmap = new BitmapImage();
                        bitmap.BeginInit();
                        bitmap.CacheOption = BitmapCacheOption.OnLoad;
                        bitmap.UriSource = new Uri(fullPath);
                        bitmap.DecodePixelWidth = 600;
                        bitmap.EndInit();
                        QRCodeImage.Source = bitmap;
                        return;
                    }
                }
            }
            catch { }
        }

        public void ApplyTheme(Theme theme)
        {
            if (theme == Theme.Dark)
            {
                MainGrid.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 30, 30));
            }
            else
            {
                MainGrid.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(245, 245, 245));
            }
        }
    }
}
