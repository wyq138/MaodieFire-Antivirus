using System;
using System.Drawing;
using System.Windows.Forms;

namespace FireAntivirus.Host
{
    public class TrustPage : UserControl, IThemed
    {
        private Panel trustPanel;
        private DataGridView trustListGrid;
        private Theme currentTheme = Theme.Light;

        public TrustPage()
        {
            try
            {
                InitializeComponents();
            }
            catch (Exception ex)
            {
                // 记录错误但不重新抛出，避免应用程序崩溃
                Console.WriteLine($"Error initializing TrustPage: {ex.Message}");
            }
        }

        private void InitializeComponents()
        {
            this.Dock = DockStyle.Fill;
            this.AutoScroll = false;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var headerPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(20, 15, 20, 15)
            };

            var titleLabel = new Label
            {
                Text = "信任区",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            headerPanel.Controls.Add(titleLabel);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            trustPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(20)
            };

            var trustLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1
            };

            trustLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
            trustLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var controlPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var addFileBtn = CreateControlButton("添加文件", AddTrustFile);
            var addFolderBtn = CreateControlButton("添加文件夹", AddTrustFolder);
            var deleteBtn = CreateControlButton("删除信任项", DeleteTrustItem);

            addFileBtn.Location = new Point(0, 10);
            addFolderBtn.Location = new Point(120, 10);
            deleteBtn.Location = new Point(240, 10);

            controlPanel.Controls.Add(addFileBtn);
            controlPanel.Controls.Add(addFolderBtn);
            controlPanel.Controls.Add(deleteBtn);

            trustLayout.Controls.Add(controlPanel, 0, 0);

            trustListGrid = new DataGridView
            {
                Dock = DockStyle.Fill,
                AutoGenerateColumns = false,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                BorderStyle = BorderStyle.FixedSingle,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                Font = new Font("微软雅黑", 9)
            };

            trustListGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Type",
                HeaderText = "类型",
                DataPropertyName = "Type",
                Width = 100
            });

            trustListGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Path",
                HeaderText = "路径",
                DataPropertyName = "Path",
                Width = 600
            });

            trustListGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "AddTime",
                HeaderText = "添加时间",
                DataPropertyName = "AddTime",
                Width = 150
            });

            trustLayout.Controls.Add(trustListGrid, 0, 1);
            trustPanel.Controls.Add(trustLayout);
            mainLayout.Controls.Add(trustPanel, 0, 1);

            this.Controls.Add(mainLayout);
            LoadTrustList();
        }

        private Button CreateControlButton(string text, Action action)
        {
            var btn = new Button
            {
                Text = text,
                Width = 100,
                Height = 40,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
            btn.Click += (s, e) => action();
            return btn;
        }

        private void LoadTrustList()
        {
            trustListGrid.Rows.Clear();

            // 从文件中读取信任列表
            try
            {
                string trustListPath = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "哈基咪杀毒", "trustlist.txt");
                
                if (System.IO.File.Exists(trustListPath))
                {
                    string[] lines = System.IO.File.ReadAllLines(trustListPath);
                    foreach (string line in lines)
                    {
                        if (!string.IsNullOrEmpty(line))
                        {
                            string[] parts = line.Split('|');
                            if (parts.Length >= 3)
                            {
                                trustListGrid.Rows.Add(parts[0], parts[1], parts[2]);
                            }
                        }
                    }
                }
            }
            catch
            {
                // 如果读取失败，显示空列表
            }
        }

        private void AddTrustFile()
        {
            using (var ofd = new OpenFileDialog())
            {
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    // 实际的添加信任文件逻辑
                    string addTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                    trustListGrid.Rows.Add("文件", ofd.FileName, addTime);
                    SaveTrustItem("文件", ofd.FileName, addTime);
                    MessageBox.Show($"文件 {System.IO.Path.GetFileName(ofd.FileName)} 已添加到信任区", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void AddTrustFolder()
        {
            using (var fbd = new FolderBrowserDialog())
            {
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    // 实际的添加信任文件夹逻辑
                    string addTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
                    trustListGrid.Rows.Add("文件夹", fbd.SelectedPath, addTime);
                    SaveTrustItem("文件夹", fbd.SelectedPath, addTime);
                    MessageBox.Show($"文件夹 {System.IO.Path.GetFileName(fbd.SelectedPath)} 已添加到信任区", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void SaveTrustItem(string type, string path, string addTime)
        {
            try
            {
                string trustListPath = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "哈基咪杀毒", "trustlist.txt");
                
                // 确保目录存在
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(trustListPath));
                
                // 追加到文件
                using (System.IO.StreamWriter writer = System.IO.File.AppendText(trustListPath))
                {
                    writer.WriteLine($"{type}|{path}|{addTime}");
                }
            }
            catch
            {
                // 保存失败时忽略错误
            }
        }

        private void DeleteTrustItem()
        {
            if (trustListGrid.SelectedRows.Count > 0)
            {
                var selectedRow = trustListGrid.SelectedRows[0];
                var path = selectedRow.Cells["Path"].Value.ToString();
                // 实际的删除信任项逻辑
                trustListGrid.Rows.Remove(selectedRow);
                MessageBox.Show($"信任项 {path} 已删除", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
            trustListGrid.BackColor = GetThemeColor(ThemeColor.BgTertiary);
            trustListGrid.ForeColor = GetThemeColor(ThemeColor.TextPrimary);

            // 重新创建所有控件以更新主题
            this.Controls.Clear();
            InitializeComponents();
        }

        private Color GetThemeColor(ThemeColor colorType)
        {
            if (currentTheme == Theme.Dark)
            {
                switch (colorType)
                {
                    case ThemeColor.TextPrimary:
                        return Color.White;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.FromArgb(30, 30, 30);
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(50, 50, 50);
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
                    case ThemeColor.TextPrimary:
                        return Color.Black;
                    case ThemeColor.TextSecondary:
                        return Color.Gray;
                    case ThemeColor.BgPrimary:
                        return Color.White;
                    case ThemeColor.BgTertiary:
                        return Color.FromArgb(243, 244, 246);
                    case ThemeColor.BorderColor:
                        return Color.FromArgb(229, 231, 235);
                    default:
                        return Color.White;
                }
            }
        }
    }
}