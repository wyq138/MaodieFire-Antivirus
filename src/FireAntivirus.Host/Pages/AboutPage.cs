// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Drawing;
using System.Windows.Forms;
using FireAntivirus.Common.Localization;

namespace FireAntivirus.Host
{
    public class AboutPage : UserControl, IThemed
    {
        private Theme currentTheme = Theme.Light;
        private LanguageManager _languageManager = LanguageManager.Instance;

        public AboutPage()
        {
            try
            {
                // 只执行必要的UI初始化操作
                InitializeComponents();
                // 订阅语言变化事件
                _languageManager.LanguageChanged += (sender, e) => UpdateLanguage();
            }
            catch (Exception ex)
            {
                // 记录错误但不重新抛出，避免应用程序崩溃
                Console.WriteLine($"Error initializing AboutPage: {ex.Message}");
            }
        }
        
        private void UpdateLanguage()
        {
            // 重新初始化组件以更新语言
            try
            {
                this.Controls.Clear();
                InitializeComponents();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating language: {ex.Message}");
            }
        }

        private void InitializeComponents()
        {
            this.Dock = DockStyle.Fill;
            this.AutoScroll = false;
            this.MinimumSize = new Size(600, 500);
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 3,
                ColumnCount = 1,
                MinimumSize = new Size(580, 480),
                BackColor = GetThemeColor(ThemeColor.BgPrimary)
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

            var headerPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                Padding = new Padding(20, 15, 20, 15)
            };

            var titleLabel = new Label
            {
                Text = _languageManager.GetString("AboutTitle"),
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Margin = new Padding(0, 5, 0, 5)
            };

            headerPanel.Controls.Add(titleLabel);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            var contentPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                Padding = new Padding(20)
            };

            var contentLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 1,
                ColumnCount = 2,
                BackColor = GetThemeColor(ThemeColor.BgPrimary)
            };

            contentLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
            contentLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            // 添加猫脸图标
            var logoPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                Padding = new Padding(20)
            };

            var logoPictureBox = new PictureBox
            {
                Dock = DockStyle.Fill,
                SizeMode = PictureBoxSizeMode.Zoom,
                Image = GetAntivirusLogo()
            };

            logoPanel.Controls.Add(logoPictureBox);

            // 添加文本内容面板
            var textPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary)
            };

            var textLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 6,
                ColumnCount = 1,
                BackColor = GetThemeColor(ThemeColor.BgPrimary)
            };

            textLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            textLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            textLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            textLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            textLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 140));
            textLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var versionLabel = new Label
                {
                    Text = _languageManager.GetString("Version", "1.0.3"),
                    Font = new Font("微软雅黑", 12),
                    ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                    Dock = DockStyle.Fill,
                    TextAlign = ContentAlignment.MiddleLeft
                };

            var developerLabel = new Label
            {
                Text = _languageManager.GetString("Developer"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var phoneLabel = new Label
            {
                Text = _languageManager.GetString("Phone"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var emailLabel = new Label
            {
                Text = _languageManager.GetString("Email"),
                Font = new Font("微软雅黑", 12),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            var descriptionLabel = new Label
            {
                Text = _languageManager.GetString("Description"),
                Font = new Font("微软雅黑", 10),
                ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.TopLeft,
                AutoSize = false,
                Height = 120
            };

            textLayout.Controls.Add(versionLabel, 0, 0);
            textLayout.Controls.Add(developerLabel, 0, 1);
            textLayout.Controls.Add(phoneLabel, 0, 2);
            textLayout.Controls.Add(emailLabel, 0, 3);
            textLayout.Controls.Add(descriptionLabel, 0, 4);

            textPanel.Controls.Add(textLayout);

            contentLayout.Controls.Add(logoPanel, 0, 0);
            contentLayout.Controls.Add(textPanel, 1, 0);

            contentPanel.Controls.Add(contentLayout);
            mainLayout.Controls.Add(contentPanel, 0, 1);

            var copyrightLabel = new Label
            {
                Text = _languageManager.GetString("Copyright"),
                Font = new Font("微软雅黑", 9),
                ForeColor = GetThemeColor(ThemeColor.TextDisabled),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            mainLayout.Controls.Add(copyrightLabel, 0, 2);

            this.Controls.Add(mainLayout);
        }

        public void ApplyTheme(Theme theme)
        {
            currentTheme = theme;
            UpdateTheme();
        }

        private void UpdateTheme()
        {
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);

            // 递归更新所有子控件
            UpdateControlsTheme(this);
        }

        private void UpdateControlsTheme(Control control)
        {
            if (control is Panel panel)
            {
                panel.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            }
            else if (control is TableLayoutPanel tableLayoutPanel)
            {
                tableLayoutPanel.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            }
            else if (control is Label label)
            {
                // 确保使用微软雅黑字体
                if (label.Font.Name != "微软雅黑")
                {
                    label.Font = new Font("微软雅黑", label.Font.Size, label.Font.Style);
                }
                
                if (label.Text.Contains("版本:") || label.Text.Contains("开发者:") || label.Text.Contains("电话:") || label.Text.Contains("意见/bug反馈邮箱:"))
                {
                    label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                }
                else if (label.Text.Contains("哈基咪杀毒是一款功能强大的安全防护软件"))
                {
                    label.ForeColor = GetThemeColor(ThemeColor.TextSecondary);
                }
                else if (label.Text.Contains("© 2026 哈基咪杀毒"))
                {
                    label.ForeColor = GetThemeColor(ThemeColor.TextDisabled);
                }
                else if (label.Text.Contains("关于 哈基咪杀毒"))
                {
                    label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                }
            }

            // 递归更新子控件
            foreach (Control childControl in control.Controls)
            {
                UpdateControlsTheme(childControl);
            }
        }

        private Color GetThemeColor(ThemeColor colorType)
        {
            if (currentTheme == Theme.Dark)
            {
                switch (colorType)
                {
                    case ThemeColor.BgPrimary:
                        return Color.FromArgb(30, 30, 30);
                    case ThemeColor.TextPrimary:
                        return Color.White;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.TextDisabled:
                        return Color.DarkGray;
                    case ThemeColor.PrimaryColor:
                        return Color.FromArgb(0, 212, 255);
                    default:
                        return Color.Black;
                }
            }
            else
            {
                switch (colorType)
                {
                    case ThemeColor.BgPrimary:
                        return Color.White;
                    case ThemeColor.TextPrimary:
                        return Color.Black;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.TextDisabled:
                        return Color.LightGray;
                    case ThemeColor.PrimaryColor:
                        return Color.FromArgb(37, 99, 235);
                    default:
                        return Color.White;
                }
            }
        }

        private Image GetAntivirusLogo()
        {
            try
            {
                // 尝试从内嵌资源加载图片
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                string resourceName = "FireAntivirus.Host.Resources.cat_logo.png";
                
                using (var stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream != null)
                    {
                        using (var bitmap = new Bitmap(stream))
                        {
                            // 调整图片大小为100x100
                            var resizedBitmap = new Bitmap(bitmap, new Size(100, 100));
                            return resizedBitmap;
                        }
                    }
                }

                // 如果找不到图标文件，创建一个默认图标
                var defaultBitmap = new Bitmap(100, 100);
                using (var graphics = Graphics.FromImage(defaultBitmap))
                {
                    graphics.Clear(Color.Transparent);
                    var brush = new SolidBrush(Color.FromArgb(255, 240, 180)); // 橘黄色
                    graphics.FillEllipse(brush, 10, 10, 80, 80);
                    brush.Dispose();
                }
                return defaultBitmap;
            }
            catch
            {
                // 如果创建默认图标也失败，返回空图片
                return new Bitmap(100, 100);
            }
        }
    }
}