using System;
using System.Drawing;
using System.Windows.Forms;

namespace FireAntivirus.Host
{
    public class ToolsPage : UserControl, IThemed
    {
        private Panel toolsPanel;
        private Theme currentTheme = Theme.Light;

        public ToolsPage()
        {
            try
            {
                // 只执行必要的UI初始化操作
                InitializeComponents();
            }
            catch (Exception ex)
            {
                // 记录错误但不重新抛出，避免应用程序崩溃
                Console.WriteLine($"Error initializing ToolsPage: {ex.Message}");
            }
        }

        private void InitializeComponents()
        {
            this.Dock = DockStyle.Fill;
            this.AutoScroll = false;
            this.MinimumSize = new Size(600, 500);

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1,
                MinimumSize = new Size(580, 480)
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var headerPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.BgPrimary),
                Padding = new Padding(20, 15, 20, 15)
            };

            var titleLabel = new Label
            {
                Text = "系统工具",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Margin = new Padding(0, 5, 0, 5)
            };

            headerPanel.Controls.Add(titleLabel);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            toolsPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(10)
            };

            var toolsLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 3,
                BackColor = Color.Transparent,
                Padding = new Padding(10),
                AutoScroll = true
            };
            toolsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            toolsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            toolsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 180));
            toolsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 180));
            toolsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 180));

            var toolItems = new[]
            {
                new { Name = "启动项管理", Icon = "🚀", Description = "管理开机启动项、计划任务、系统服务" },
                new { Name = "文件粉碎", Icon = "💥", Description = "彻底删除文件/文件夹，不可恢复" },
                new { Name = "右键菜单管理", Icon = "🖱️", Description = "清理和管理右键菜单项" },
                new { Name = "垃圾清理", Icon = "🗑️", Description = "清理系统垃圾、缓存、日志文件" },
                new { Name = "系统修复", Icon = "🔧", Description = "修复系统文件损坏、快捷方式异常" },
                new { Name = "漏洞修复", Icon = "🔓", Description = "扫描和修复系统高危漏洞" }
            };

            for (int i = 0; i < toolItems.Length; i++)
            {
                var tool = toolItems[i];
                var toolCard = CreateToolCard(tool.Name, tool.Icon, tool.Description);
                int row = i / 2;
                int col = i % 2;
                toolsLayout.Controls.Add(toolCard, col, row);
            }

            toolsPanel.Controls.Add(toolsLayout);
            mainLayout.Controls.Add(toolsPanel, 0, 1);

            this.Controls.Add(mainLayout);
        }

        private Panel CreateToolCard(string name, string icon, string description)
        {
            var card = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = GetThemeColor(ThemeColor.CardBg),
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(5)
            };

            var cardLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(15)
            };
            cardLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            cardLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 25));
            cardLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 35));
            cardLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 25));

            var iconLabel = new Label
            {
                Text = icon,
                Font = new Font("微软雅黑", 24),
                ForeColor = GetThemeColor(ThemeColor.PrimaryColor),
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill,
                AutoSize = false
            };

            var nameLabel = new Label
            {
                Text = name,
                Font = new Font("微软雅黑", 10, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill,
                AutoSize = false
            };

            var descLabel = new Label
            {
                Text = description,
                Font = new Font("微软雅黑", 8),
                ForeColor = GetThemeColor(ThemeColor.TextSecondary),
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill,
                AutoSize = false
            };

            var runBtn = new Button
            {
                Text = "运行",
                Font = new Font("微软雅黑", 9),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.PrimaryColor),
                ForeColor = Color.White,
                Cursor = Cursors.Hand,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            runBtn.FlatAppearance.BorderSize = 0;
            runBtn.Click += (s, e) => RunTool(name);

            cardLayout.Controls.Add(iconLabel, 0, 0);
            cardLayout.Controls.Add(nameLabel, 0, 1);
            cardLayout.Controls.Add(descLabel, 0, 2);
            cardLayout.Controls.Add(runBtn, 0, 3);
            card.Controls.Add(cardLayout);

            return card;
        }

        private void RunTool(string toolName)
        {
            // 实际的工具运行逻辑
            switch (toolName)
            {
                case "启动项管理":
                    var startupForm = new StartupManagerForm();
                    startupForm.ShowDialog();
                    break;
                case "文件粉碎":
                    var fileShredForm = new FileShredderForm();
                    fileShredForm.ShowDialog();
                    break;
                case "右键菜单管理":
                    var contextMenuForm = new ContextMenuManagerForm();
                    contextMenuForm.ShowDialog();
                    break;
                case "垃圾清理":
                    var cleanForm = new CleanForm();
                    cleanForm.ShowDialog();
                    break;
                case "系统修复":
                    var repairForm = new SystemRepairForm();
                    repairForm.ShowDialog();
                    break;
                case "漏洞修复":
                    var vulnForm = new VulnerabilityForm();
                    vulnForm.ShowDialog();
                    break;
            }
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
                    button.BackColor = GetThemeColor(ThemeColor.PrimaryColor);
                    button.ForeColor = Color.White;
                }
                
                // 递归更新子控件
                UpdateControlsTheme(child);
            }
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
                    case ThemeColor.CardBg:
                        return Color.FromArgb(45, 45, 45);
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
                    case ThemeColor.CardBg:
                        return Color.White;
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(229, 231, 235);
                    default:
                        return Color.White;
                }
            }
        }
    }
}