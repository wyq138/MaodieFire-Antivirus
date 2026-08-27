using System;
using System.Drawing;
using System.Windows.Forms;
using System.Collections.Generic;

namespace FireAntivirus.Host
{
    public class StartupManagerForm : Form
    {
        public StartupManagerForm()
        {
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            this.Text = "启动项管理 - 哈基咪杀毒";
            this.Size = new Size(800, 600);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Icon = SystemIcons.Shield;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 2,
                ColumnCount = 1
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var titleLabel = new Label
            {
                Text = "启动项管理",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = Color.Black,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            mainLayout.Controls.Add(titleLabel, 0, 0);

            var tabControl = new TabControl
            {
                Dock = DockStyle.Fill
            };

            var startupTab = new TabPage("开机启动")
            {
                BackColor = Color.White
            };

            var taskTab = new TabPage("计划任务")
            {
                BackColor = Color.White
            };

            var serviceTab = new TabPage("系统服务")
            {
                BackColor = Color.White
            };

            var startupList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                GridLines = true,
                FullRowSelect = true
            };

            startupList.Columns.Add("名称", 200);
            startupList.Columns.Add("发布者", 200);
            startupList.Columns.Add("路径", 300);
            startupList.Columns.Add("状态", 100);

            // 添加加载项
            var loadingItem = new ListViewItem("正在检测启动项...");
            loadingItem.SubItems.Add("");
            loadingItem.SubItems.Add("");
            loadingItem.SubItems.Add("");
            startupList.Items.Add(loadingItem);

            // 异步检测启动项，避免UI卡顿
            System.Threading.Tasks.Task.Run(() =>
            {
                var items = new List<ListViewItem>();
                
                try
                {
                    // 检查注册表启动项
                    CheckRegistryStartupItems(items);
                    
                    // 检查启动文件夹
                    CheckStartupFolders(items);
                    
                    // 检查计划任务
                    CheckScheduledTasks(items);
                    
                    if (items.Count == 0)
                    {
                        var item = new ListViewItem("无启动项");
                        item.SubItems.Add("");
                        item.SubItems.Add("");
                        item.SubItems.Add("");
                        items.Add(item);
                    }
                }
                catch (Exception ex)
                {
                    var item = new ListViewItem("检测失败");
                    item.SubItems.Add("");
                    item.SubItems.Add("");
                    item.SubItems.Add($"无法检测启动项: {ex.Message}");
                    items.Add(item);
                }
                
                // 更新UI
                this.Invoke((Action)(() =>
                {
                    startupList.Items.Clear();
                    foreach (var item in items)
                    {
                        startupList.Items.Add(item);
                    }
                }));
            });

            // 添加按钮面板
            var buttonPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 60,
                BackColor = Color.White
            };

            var disableButton = new Button
            {
                Text = "禁用",
                Width = 100,
                Height = 40,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Orange,
                ForeColor = Color.White,
                Location = new Point(100, 10)
            };

            var enableButton = new Button
            {
                Text = "启用",
                Width = 100,
                Height = 40,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Green,
                ForeColor = Color.White,
                Location = new Point(220, 10)
            };

            var deleteButton = new Button
            {
                Text = "删除",
                Width = 100,
                Height = 40,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Red,
                ForeColor = Color.White,
                Location = new Point(340, 10)
            };

            var refreshButton = new Button
            {
                Text = "刷新",
                Width = 100,
                Height = 40,
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Blue,
                ForeColor = Color.White,
                Location = new Point(460, 10)
            };

            disableButton.Click += (s, e) => DisableStartupItem(startupList);
            enableButton.Click += (s, e) => EnableStartupItem(startupList);
            deleteButton.Click += (s, e) => DeleteStartupItem(startupList);
            refreshButton.Click += (s, e) =>
            {
                // 刷新时显示加载状态
                startupList.Items.Clear();
                var loadingItem = new ListViewItem("正在刷新启动项...");
                loadingItem.SubItems.Add("");
                loadingItem.SubItems.Add("");
                loadingItem.SubItems.Add("");
                startupList.Items.Add(loadingItem);
                
                // 异步刷新
                System.Threading.Tasks.Task.Run(() =>
                {
                    var items = new List<ListViewItem>();
                    
                    try
                    {
                        // 检查注册表启动项
                        CheckRegistryStartupItems(items);
                        
                        // 检查启动文件夹
                        CheckStartupFolders(items);
                        
                        // 检查计划任务
                        CheckScheduledTasks(items);
                        
                        if (items.Count == 0)
                        {
                            var item = new ListViewItem("无启动项");
                            item.SubItems.Add("");
                            item.SubItems.Add("");
                            item.SubItems.Add("");
                            items.Add(item);
                        }
                    }
                    catch (Exception ex)
                    {
                        var item = new ListViewItem("检测失败");
                        item.SubItems.Add("");
                        item.SubItems.Add("");
                        item.SubItems.Add($"无法检测启动项: {ex.Message}");
                        items.Add(item);
                    }
                    
                    // 更新UI
                    this.Invoke((Action)(() =>
                    {
                        startupList.Items.Clear();
                        foreach (var item in items)
                        {
                            startupList.Items.Add(item);
                        }
                    }));
                });
            };

            buttonPanel.Controls.Add(disableButton);
            buttonPanel.Controls.Add(enableButton);
            buttonPanel.Controls.Add(deleteButton);
            buttonPanel.Controls.Add(refreshButton);

            startupTab.Controls.Add(buttonPanel);
            startupTab.Controls.Add(startupList);
            tabControl.TabPages.Add(startupTab);
            tabControl.TabPages.Add(taskTab);
            tabControl.TabPages.Add(serviceTab);

            mainLayout.Controls.Add(tabControl, 0, 1);
            this.Controls.Add(mainLayout);
        }
        
        // 辅助方法：检查注册表启动项
        private void CheckRegistryStartupItems(List<ListViewItem> items)
        {
            try
            {
                // 检查当前用户的启动项
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
                {
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            var path = key.GetValue(valueName) as string;
                            if (!string.IsNullOrEmpty(path))
                            {
                                var item = new ListViewItem(valueName);
                                item.SubItems.Add(GetPublisherFromPath(path));
                                item.SubItems.Add(path);
                                item.SubItems.Add("已启用");
                                items.Add(item);
                            }
                        }
                    }
                }
                
                // 检查本地机器的启动项
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
                {
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            var path = key.GetValue(valueName) as string;
                            if (!string.IsNullOrEmpty(path))
                            {
                                var item = new ListViewItem(valueName);
                                item.SubItems.Add(GetPublisherFromPath(path));
                                item.SubItems.Add(path);
                                item.SubItems.Add("已启用");
                                items.Add(item);
                            }
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManagerForm.cs 捕获异常", ex.Message); }
        }
        
        // 辅助方法：检查启动文件夹
        private void CheckStartupFolders(List<ListViewItem> items)
        {
            try
            {
                // 检查当前用户的启动文件夹
                string userStartupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                CheckFolderForStartupItems(items, userStartupFolder);
                
                // 检查公共启动文件夹
                string commonStartupFolder = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
                CheckFolderForStartupItems(items, commonStartupFolder);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManagerForm.cs 捕获异常", ex.Message); }
        }
        
        // 辅助方法：检查文件夹中的启动项
        private void CheckFolderForStartupItems(List<ListViewItem> items, string folderPath)
        {
            try
            {
                if (System.IO.Directory.Exists(folderPath))
                {
                    var files = System.IO.Directory.GetFiles(folderPath);
                    foreach (var file in files)
                    {
                        var fileName = System.IO.Path.GetFileNameWithoutExtension(file);
                        var item = new ListViewItem(fileName);
                        item.SubItems.Add(GetPublisherFromPath(file));
                        item.SubItems.Add(file);
                        item.SubItems.Add("已启用");
                        items.Add(item);
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManagerForm.cs 捕获异常", ex.Message); }
        }
        
        // 辅助方法：检查计划任务
        private void CheckScheduledTasks(List<ListViewItem> items)
        {
            try
            {
                // 使用schtasks命令获取计划任务
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = "/query /fo LIST /v",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(3000); // 3秒超时
                
                // 解析输出，查找启动时运行的任务
                // 这里可以添加更复杂的解析逻辑
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "StartupManagerForm.cs 捕获异常", ex.Message); }
        }



        private void DisableStartupItem(ListView listView)
        {
            if (listView.SelectedItems.Count > 0)
            {
                var selectedItem = listView.SelectedItems[0];
                string name = selectedItem.SubItems[0].Text;
                string path = selectedItem.SubItems[2].Text;
                string status = selectedItem.SubItems[3].Text;

                if (status == "已启用")
                {
                    try
                    {
                        // 尝试禁用注册表启动项
                        bool disabled = DisableRegistryStartupItem(name);
                        if (disabled)
                        {
                            selectedItem.SubItems[3].Text = "已禁用";
                            MessageBox.Show($"启动项 {name} 已禁用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                        else
                        {
                            MessageBox.Show($"无法禁用启动项 {name}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"禁用启动项时出错: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
                else
                {
                    MessageBox.Show("该启动项已经是禁用状态", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void EnableStartupItem(ListView listView)
        {
            if (listView.SelectedItems.Count > 0)
            {
                var selectedItem = listView.SelectedItems[0];
                string name = selectedItem.SubItems[0].Text;
                string path = selectedItem.SubItems[2].Text;
                string status = selectedItem.SubItems[3].Text;

                if (status == "已禁用")
                {
                    try
                    {
                        // 尝试启用注册表启动项
                        bool enabled = EnableRegistryStartupItem(name, path);
                        if (enabled)
                        {
                            selectedItem.SubItems[3].Text = "已启用";
                            MessageBox.Show($"启动项 {name} 已启用", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                        else
                        {
                            MessageBox.Show($"无法启用启动项 {name}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"启用启动项时出错: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
                else
                {
                    MessageBox.Show("该启动项已经是启用状态", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void DeleteStartupItem(ListView listView)
        {
            if (listView.SelectedItems.Count > 0)
            {
                var selectedItem = listView.SelectedItems[0];
                string name = selectedItem.SubItems[0].Text;

                if (MessageBox.Show($"确定要删除启动项 {name} 吗？", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                {
                    try
                    {
                        // 尝试删除注册表启动项
                        bool deleted = DeleteRegistryStartupItem(name);
                        if (deleted)
                        {
                            listView.Items.Remove(selectedItem);
                            MessageBox.Show($"启动项 {name} 已删除", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                        else
                        {
                            MessageBox.Show($"无法删除启动项 {name}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"删除启动项时出错: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private bool DisableRegistryStartupItem(string name)
        {
            try
            {
                // 尝试在当前用户的启动项中禁用
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    if (key != null && key.GetValue(name) != null)
                    {
                        string value = key.GetValue(name) as string;
                        key.DeleteValue(name);
                        // 可以选择将禁用的启动项保存到其他位置
                        return true;
                    }
                }

                // 尝试在本地机器的启动项中禁用
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    if (key != null && key.GetValue(name) != null)
                    {
                        string value = key.GetValue(name) as string;
                        key.DeleteValue(name);
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private bool EnableRegistryStartupItem(string name, string path)
        {
            try
            {
                // 尝试在当前用户的启动项中启用
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    if (key != null)
                    {
                        key.SetValue(name, path);
                        return true;
                    }
                }

                // 尝试在本地机器的启动项中启用
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    if (key != null)
                    {
                        key.SetValue(name, path);
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private bool DeleteRegistryStartupItem(string name)
        {
            return DisableRegistryStartupItem(name); // 删除和禁用使用相同的逻辑
        }

        private string GetPublisherFromPath(string path)
        {
            try
            {
                // 尝试从文件信息中获取发布者
                // 这里可以使用文件版本信息或数字签名来获取发布者
                // 暂时使用简单的实现
                if (System.IO.File.Exists(path))
                {
                    var fileInfo = new System.IO.FileInfo(path);
                    var directoryName = fileInfo.Directory.Name;
                    return directoryName;
                }
                return "未知";
            }
            catch
            {
                return "未知";
            }
        }
    }
}