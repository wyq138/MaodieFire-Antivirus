using Microsoft.UI.Xaml.Controls;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed partial class AboutPage : Page
    {
        public AboutPage()
        {
            InitializeComponent();
            _ = LoadCatImageAsync();
        }

        private async System.Threading.Tasks.Task LoadCatImageAsync()
        {
            var image = await UiKit.LoadAssetAsync("cat_home.png");
            if (image != null) AboutCatImage.Source = image;
        }
    }
}