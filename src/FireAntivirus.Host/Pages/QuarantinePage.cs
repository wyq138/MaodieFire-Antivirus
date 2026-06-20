using System;
using System.Drawing;
using System.Windows.Forms;
using FireAntivirus.Data;

namespace FireAntivirus.Host
{
    public class QuarantinePage : UserControl, IThemed
    {
        private Panel quarantinePanel;
        private DataGridView quarantineGrid;
        private Theme currentTheme = Theme.Light;
        private DataManager dataManager;

        public QuarantinePage()
        {
            try
            {
                dataManager = new DataManager();
                InitializeComponents();
            }
            catch (Exception ex)
            {
                // 记录错误但不重新抛出，避免应用程序崩溃
                Console.WriteLine($"Error initializing QuarantinePage: {ex.Message}");
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
                Text = "隔离区",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            headerPanel.Controls.Add(titleLabel);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            quarantinePanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(20)
            };

            var quarantineLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1
            };

            quarantineLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
            quarantineLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var controlPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var restoreBtn = CreateControlButton("恢复文件", RestoreSelectedFiles);
            var deleteBtn = CreateControlButton("删除文件", DeleteSelectedFiles);
            var clearBtn = CreateControlButton("清空隔离区", ClearQuarantine);
            var refreshBtn = CreateControlButton("刷新", LoadQuarantineFiles);

            restoreBtn.Location = new Point(0, 10);
            deleteBtn.Location = new Point(120, 10);
            clearBtn.Location = new Point(240, 10);
            refreshBtn.Location = new Point(360, 10);

            controlPanel.Controls.Add(restoreBtn);
            controlPanel.Controls.Add(deleteBtn);
            controlPanel.Controls.Add(clearBtn);
            controlPanel.Controls.Add(refreshBtn);

            quarantineLayout.Controls.Add(controlPanel, 0, 0);

            quarantineGrid = new DataGridView
            {
                Dock = DockStyle.Fill,
                AutoGenerateColumns = false,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                BorderStyle = BorderStyle.FixedSingle,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                Font = new Font("微软雅黑", 9)
            };

            quarantineGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "FileName",
                HeaderText = "文件名",
                DataPropertyName = "FileName",
                Width = 200
            });

            quarantineGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "OriginalPath",
                HeaderText = "原始路径",
                DataPropertyName = "OriginalPath",
                Width = 400
            });

            quarantineGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "ThreatType",
                HeaderText = "威胁类型",
                DataPropertyName = "ThreatType",
                Width = 150
            });

            quarantineGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "QuarantineTime",
                HeaderText = "隔离时间",
                DataPropertyName = "QuarantineTime",
                Width = 150
            });

            quarantineGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Size",
                HeaderText = "大小",
                DataPropertyName = "Size",
                Width = 100
            });

            quarantineLayout.Controls.Add(quarantineGrid, 0, 1);
            quarantinePanel.Controls.Add(quarantineLayout);
            mainLayout.Controls.Add(quarantinePanel, 0, 1);

            this.Controls.Add(mainLayout);
            LoadQuarantineFiles();
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

        private void LoadQuarantineFiles()
        {
            quarantineGrid.Rows.Clear();

            try
            {
                var quarantineItems = dataManager.LoadQuarantine();
                foreach (var item in quarantineItems)
                {
                    quarantineGrid.Rows.Add(
                        item.FileName,
                        item.OriginalPath,
                        item.ThreatType,
                        item.QuarantineTime.ToString("yyyy-MM-dd HH:mm"),
                        FormatFileSize(item.Size)
                    );
                    // 存储项目ID到行的Tag属性
                    quarantineGrid.Rows[quarantineGrid.Rows.Count - 1].Tag = item.Id;
                }
            }
            catch
            {
                // 如果读取失败，显示空列表
            }
        }

        private string FormatFileSize(long sizeInBytes)
        {
            if (sizeInBytes < 1024)
            {
                return $"{sizeInBytes} B";
            }
            else if (sizeInBytes < 1024 * 1024)
            {
                double sizeInKB = sizeInBytes / 1024.0;
                return $"{sizeInKB:F1} KB";
            }
            else
            {
                double sizeInMB = sizeInBytes / (1024.0 * 1024.0);
                return $"{sizeInMB:F1} MB";
            }
        }

        private void RestoreSelectedFiles()
        {
            if (quarantineGrid.SelectedRows.Count > 0)
            {
                var selectedRow = quarantineGrid.SelectedRows[0];
                var quarantineItemId = selectedRow.Tag as string;
                var fileName = selectedRow.Cells["FileName"].Value.ToString();
                
                if (!string.IsNullOrEmpty(quarantineItemId))
                {
                    bool success = dataManager.RestoreFile(quarantineItemId);
                    if (success)
                    {
                        quarantineGrid.Rows.Remove(selectedRow);
                        MessageBox.Show($"文件 {fileName} 已恢复到原路径", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show($"恢复文件 {fileName} 失败", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void DeleteSelectedFiles()
        {
            if (quarantineGrid.SelectedRows.Count > 0)
            {
                var selectedRow = quarantineGrid.SelectedRows[0];
                var quarantineItemId = selectedRow.Tag as string;
                var fileName = selectedRow.Cells["FileName"].Value.ToString();
                
                if (!string.IsNullOrEmpty(quarantineItemId))
                {
                    bool success = dataManager.DeleteFromQuarantine(quarantineItemId);
                    if (success)
                    {
                        quarantineGrid.Rows.Remove(selectedRow);
                        MessageBox.Show($"文件 {fileName} 已从隔离区删除", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show($"删除文件 {fileName} 失败", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void ClearQuarantine()
        {
            if (MessageBox.Show("确定要清空整个隔离区吗？", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                dataManager.ClearQuarantine();
                quarantineGrid.Rows.Clear();
                MessageBox.Show("隔离区已清空", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
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
            quarantineGrid.BackColor = GetThemeColor(ThemeColor.BgTertiary);
            quarantineGrid.ForeColor = GetThemeColor(ThemeColor.TextPrimary);

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