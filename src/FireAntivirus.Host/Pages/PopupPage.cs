using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using System.Xml.Serialization;

namespace FireAntivirus.Host
{
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
                    // 首次运行，不添加默认规则
                    rules = new List<PopupRule>();
                    SaveRules();
                }
            }
            catch
            {
                // 如果加载失败，使用空规则列表
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
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PopupPage.cs 捕获异常", ex.Message); }
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

    public class PopupPage : UserControl, IThemed
    {
        private Panel popupControlPanel;
        private DataGridView popupRulesGrid;
        private Theme currentTheme = Theme.Light;
        private PopupRuleManager ruleManager;

        public PopupPage()
        {
            try
            {
                ruleManager = new PopupRuleManager();
                InitializeComponents();
            }
            catch (Exception ex)
            {
                // 记录错误但不重新抛出，避免应用程序崩溃
                Console.WriteLine($"Error initializing PopupPage: {ex.Message}");
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
                Text = "弹窗拦截",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            headerPanel.Controls.Add(titleLabel);
            mainLayout.Controls.Add(headerPanel, 0, 0);

            popupControlPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent,
                Padding = new Padding(20)
            };

            var popupLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1
            };

            popupLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
            popupLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var controlPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.Transparent
            };

            var addRuleBtn = CreateControlButton("添加规则", AddPopupRule);
            var deleteRuleBtn = CreateControlButton("删除规则", DeletePopupRule);
            var clearRulesBtn = CreateControlButton("清空规则", ClearPopupRules);
            var refreshBtn = CreateControlButton("刷新", LoadPopupRules);

            addRuleBtn.Location = new Point(0, 10);
            deleteRuleBtn.Location = new Point(120, 10);
            clearRulesBtn.Location = new Point(240, 10);
            refreshBtn.Location = new Point(360, 10);

            controlPanel.Controls.Add(addRuleBtn);
            controlPanel.Controls.Add(deleteRuleBtn);
            controlPanel.Controls.Add(clearRulesBtn);
            controlPanel.Controls.Add(refreshBtn);

            popupLayout.Controls.Add(controlPanel, 0, 0);

            popupRulesGrid = new DataGridView
            {
                Dock = DockStyle.Fill,
                AutoGenerateColumns = false,
                BackColor = GetThemeColor(ThemeColor.BgTertiary),
                ForeColor = GetThemeColor(ThemeColor.TextPrimary),
                BorderStyle = BorderStyle.FixedSingle,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                Font = new Font("微软雅黑", 9)
            };

            popupRulesGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "AppName",
                HeaderText = "应用名称",
                DataPropertyName = "AppName",
                Width = 200
            });

            popupRulesGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Path",
                HeaderText = "路径",
                DataPropertyName = "Path",
                Width = 400
            });

            popupRulesGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Rule",
                HeaderText = "规则",
                DataPropertyName = "Rule",
                Width = 200
            });

            popupRulesGrid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = "Count",
                HeaderText = "拦截次数",
                DataPropertyName = "Count",
                Width = 100
            });

            popupLayout.Controls.Add(popupRulesGrid, 0, 1);
            popupControlPanel.Controls.Add(popupLayout);
            mainLayout.Controls.Add(popupControlPanel, 0, 1);

            this.Controls.Add(mainLayout);
            LoadPopupRules();
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

        private void LoadPopupRules()
        {
            popupRulesGrid.Rows.Clear();

            var rules = ruleManager.GetRules();
            foreach (var rule in rules)
            {
                popupRulesGrid.Rows.Add(rule.AppName, rule.Path, rule.Rule, rule.Count);
            }
        }

        private void AddPopupRule()
        {
            // 创建一个简单的添加规则窗体
            using (var form = new Form())
            {
                form.Text = "添加弹窗规则";
                form.Size = new Size(500, 300);
                form.StartPosition = FormStartPosition.CenterScreen;
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.MinimizeBox = false;

                var layout = new TableLayoutPanel
                {
                    Dock = DockStyle.Fill,
                    RowCount = 5,
                    ColumnCount = 2,
                    Padding = new Padding(20)
                };

                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
                layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
                layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));

                layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
                layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

                // 应用名称
                var appNameLabel = new Label
                {
                    Text = "应用名称:",
                    Font = new Font("微软雅黑", 10),
                    Dock = DockStyle.Fill,
                    TextAlign = ContentAlignment.MiddleLeft
                };
                var appNameTextBox = new TextBox
                {
                    Dock = DockStyle.Fill,
                    Font = new Font("微软雅黑", 10)
                };

                // 路径
                var pathLabel = new Label
                {
                    Text = "路径:",
                    Font = new Font("微软雅黑", 10),
                    Dock = DockStyle.Fill,
                    TextAlign = ContentAlignment.MiddleLeft
                };
                var pathTextBox = new TextBox
                {
                    Dock = DockStyle.Fill,
                    Font = new Font("微软雅黑", 10)
                };

                // 规则
                var ruleLabel = new Label
                {
                    Text = "规则:",
                    Font = new Font("微软雅黑", 10),
                    Dock = DockStyle.Fill,
                    TextAlign = ContentAlignment.MiddleLeft
                };
                var ruleComboBox = new ComboBox
                {
                    Dock = DockStyle.Fill,
                    Font = new Font("微软雅黑", 10)
                };
                ruleComboBox.Items.AddRange(new string[] { "广告弹窗", "推广弹窗", "新闻弹窗", "更新弹窗", "其他弹窗" });
                ruleComboBox.SelectedIndex = 0;

                // 按钮
                var buttonPanel = new Panel
                {
                    Dock = DockStyle.Fill
                };

                var okButton = new Button
                {
                    Text = "确定",
                    DialogResult = DialogResult.OK,
                    Width = 100,
                    Height = 40,
                    Font = new Font("微软雅黑", 10),
                    FlatStyle = FlatStyle.Flat
                };
                okButton.FlatAppearance.BorderSize = 1;
                okButton.Location = new Point(150, 10);

                var cancelButton = new Button
                {
                    Text = "取消",
                    DialogResult = DialogResult.Cancel,
                    Width = 100,
                    Height = 40,
                    Font = new Font("微软雅黑", 10),
                    FlatStyle = FlatStyle.Flat
                };
                cancelButton.FlatAppearance.BorderSize = 1;
                cancelButton.Location = new Point(270, 10);

                buttonPanel.Controls.Add(okButton);
                buttonPanel.Controls.Add(cancelButton);

                layout.Controls.Add(appNameLabel, 0, 0);
                layout.Controls.Add(appNameTextBox, 1, 0);
                layout.Controls.Add(pathLabel, 0, 1);
                layout.Controls.Add(pathTextBox, 1, 1);
                layout.Controls.Add(ruleLabel, 0, 2);
                layout.Controls.Add(ruleComboBox, 1, 2);
                layout.Controls.Add(new Label(), 0, 3);
                layout.Controls.Add(new Label(), 1, 3);
                layout.SetColumnSpan(buttonPanel, 2);
                layout.Controls.Add(buttonPanel, 0, 4);

                form.Controls.Add(layout);
                form.AcceptButton = okButton;
                form.CancelButton = cancelButton;

                if (form.ShowDialog() == DialogResult.OK)
                {
                    if (!string.IsNullOrEmpty(appNameTextBox.Text) && !string.IsNullOrEmpty(pathTextBox.Text))
                    {
                        var newRule = new PopupRule
                        {
                            AppName = appNameTextBox.Text,
                            Path = pathTextBox.Text,
                            Rule = ruleComboBox.SelectedItem.ToString(),
                            Count = 0
                        };
                        ruleManager.AddRule(newRule);
                        LoadPopupRules();
                    }
                }
            }
        }

        private void DeletePopupRule()
        {
            if (popupRulesGrid.SelectedRows.Count > 0)
            {
                var selectedRow = popupRulesGrid.SelectedRows[0];
                var path = selectedRow.Cells["Path"].Value.ToString();
                var rules = ruleManager.GetRules();
                var ruleToRemove = rules.Find(r => r.Path == path);
                if (ruleToRemove != null)
                {
                    ruleManager.RemoveRule(ruleToRemove);
                    LoadPopupRules();
                }
            }
        }

        private void ClearPopupRules()
        {
            if (MessageBox.Show("确定要清空所有弹窗规则吗？", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
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
            this.BackColor = GetThemeColor(ThemeColor.BgPrimary);
            popupRulesGrid.BackColor = GetThemeColor(ThemeColor.BgTertiary);
            popupRulesGrid.ForeColor = GetThemeColor(ThemeColor.TextPrimary);

            // 更新所有子控件的颜色
            UpdateControlsTheme(this);
        }

        private void UpdateControlsTheme(Control control)
        {
            foreach (Control child in control.Controls)
            {
                if (child is Panel panel)
                {
                    panel.BackColor = Color.Transparent;
                }
                else if (child is TableLayoutPanel tlp)
                {
                    tlp.BackColor = Color.Transparent;
                }
                else if (child is Label label)
                {
                    // 确保使用微软雅黑字体
                    if (label.Font.Name != "微软雅黑")
                    {
                        label.Font = new Font("微软雅黑", label.Font.Size, label.Font.Style);
                    }
                    label.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                }
                else if (child is Button button)
                {
                    // 确保使用微软雅黑字体
                    if (button.Font.Name != "微软雅黑")
                    {
                        button.Font = new Font("微软雅黑", button.Font.Size, button.Font.Style);
                    }
                    button.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                    button.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                    button.FlatAppearance.BorderColor = GetThemeColor(ThemeColor.BorderColor);
                }
                else if (child is DataGridView dgv)
                {
                    dgv.BackColor = GetThemeColor(ThemeColor.BgTertiary);
                    dgv.ForeColor = GetThemeColor(ThemeColor.TextPrimary);
                }
                else if (child is TextBox textBox)
                {
                    // 确保使用微软雅黑字体
                    if (textBox.Font.Name != "微软雅黑")
                    {
                        textBox.Font = new Font("微软雅黑", textBox.Font.Size, textBox.Font.Style);
                    }
                }
                else if (child is ComboBox comboBox)
                {
                    // 确保使用微软雅黑字体
                    if (comboBox.Font.Name != "微软雅黑")
                    {
                        comboBox.Font = new Font("微软雅黑", comboBox.Font.Size, comboBox.Font.Style);
                    }
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