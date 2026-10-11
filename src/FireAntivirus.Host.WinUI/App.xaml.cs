// 耄耋软件工作室 开发，严禁非法反编译
using Microsoft.UI.Xaml;

namespace FireAntivirus.Host.WinUI
{
    public partial class App : Application
    {
        public static Window MainWindow { get; private set; }

        public App()
        {
            InitializeComponent();
        }

        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            MainWindow = new MainWindow();
            MainWindow.Activate();
        }
    }
}
