using System;
using System.Drawing;
using System.Windows.Forms;

namespace FireAntivirus.Host
{
    public class ContextMenuManagerForm : Form
    {
        public ContextMenuManagerForm()
        {
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            this.Text = "右键菜单管理 - 哈基咪杀毒";
            this.Size = new Size(700, 500);
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
                Text = "右键菜单管理",
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

            var fileTab = new TabPage("文件右键")
            {
                BackColor = Color.White
            };

            var folderTab = new TabPage("文件夹右键")
            {
                BackColor = Color.White
            };

            var desktopTab = new TabPage("桌面右键")
            {
                BackColor = Color.White
            };

            var fileList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                GridLines = true,
                FullRowSelect = true
            };

            fileList.Columns.Add("菜单项", 200);
            fileList.Columns.Add("命令", 400);
            fileList.Columns.Add("状态", 100);

            // 检测真实的右键菜单项
            DetectFileContextMenuItems(fileList);

            fileTab.Controls.Add(fileList);
            
            // 文件夹右键菜单项
            var folderList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                GridLines = true,
                FullRowSelect = true
            };

            folderList.Columns.Add("菜单项", 200);
            folderList.Columns.Add("命令", 400);
            folderList.Columns.Add("状态", 100);
            
            DetectFolderContextMenuItems(folderList);
            folderTab.Controls.Add(folderList);
            
            // 桌面右键菜单项
            var desktopList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                GridLines = true,
                FullRowSelect = true
            };

            desktopList.Columns.Add("菜单项", 200);
            desktopList.Columns.Add("命令", 400);
            desktopList.Columns.Add("状态", 100);
            
            DetectDesktopContextMenuItems(desktopList);
            desktopTab.Controls.Add(desktopList);

            tabControl.TabPages.Add(fileTab);
            tabControl.TabPages.Add(folderTab);
            tabControl.TabPages.Add(desktopTab);

            mainLayout.Controls.Add(tabControl, 0, 1);
            this.Controls.Add(mainLayout);
        }

        private void DetectFileContextMenuItems(ListView listView)
        {
            try
            {
                listView.Items.Clear();
                
                // 检查文件右键菜单项（通过注册表）
                CheckRegistryContextMenuItems(listView, "*\\shell");
                CheckRegistryContextMenuItems(listView, "*\\shellex\\ContextMenuHandlers");
                
                // 检查常见文件类型的右键菜单
                string[] fileTypes = {".txt", ".exe", ".jpg", ".pdf", ".doc", ".docx"};
                foreach (var fileType in fileTypes)
                {
                    CheckRegistryContextMenuItems(listView, fileType + "\\shell");
                    CheckRegistryContextMenuItems(listView, fileType + "\\shellex\\ContextMenuHandlers");
                }
                
                if (listView.Items.Count == 0)
                {
                    var item = new ListViewItem("未发现右键菜单项");
                    item.SubItems.Add("");
                    item.SubItems.Add("");
                    listView.Items.Add(item);
                }
            }
            catch (Exception ex)
            {
                var item = new ListViewItem("检测失败");
                item.SubItems.Add("");
                item.SubItems.Add("无法检测右键菜单项: " + ex.Message);
                listView.Items.Add(item);
            }
        }

        private void DetectFolderContextMenuItems(ListView listView)
        {
            try
            {
                listView.Items.Clear();
                
                // 检查文件夹右键菜单项
                CheckRegistryContextMenuItems(listView, "Folder\\shell");
                CheckRegistryContextMenuItems(listView, "Folder\\shellex\\ContextMenuHandlers");
                CheckRegistryContextMenuItems(listView, "Directory\\shell");
                CheckRegistryContextMenuItems(listView, "Directory\\shellex\\ContextMenuHandlers");
                
                if (listView.Items.Count == 0)
                {
                    var item = new ListViewItem("未发现右键菜单项");
                    item.SubItems.Add("");
                    item.SubItems.Add("");
                    listView.Items.Add(item);
                }
            }
            catch (Exception ex)
            {
                var item = new ListViewItem("检测失败");
                item.SubItems.Add("");
                item.SubItems.Add("无法检测右键菜单项: " + ex.Message);
                listView.Items.Add(item);
            }
        }

        private void DetectDesktopContextMenuItems(ListView listView)
        {
            try
            {
                listView.Items.Clear();
                
                // 检查桌面右键菜单项
                CheckRegistryContextMenuItems(listView, "DesktopBackground\\shell");
                CheckRegistryContextMenuItems(listView, "DesktopBackground\\shellex\\ContextMenuHandlers");
                
                if (listView.Items.Count == 0)
                {
                    var item = new ListViewItem("未发现右键菜单项");
                    item.SubItems.Add("");
                    item.SubItems.Add("");
                    listView.Items.Add(item);
                }
            }
            catch (Exception ex)
            {
                var item = new ListViewItem("检测失败");
                item.SubItems.Add("");
                item.SubItems.Add("无法检测右键菜单项: " + ex.Message);
                listView.Items.Add(item);
            }
        }

        private void CheckRegistryContextMenuItems(ListView listView, string registryPath)
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(registryPath))
                {
                    if (key != null)
                    {
                        foreach (var subKeyName in key.GetSubKeyNames())
                        {
                            try
                            {
                                using (var subKey = key.OpenSubKey(subKeyName))
                                {
                                    if (subKey != null)
                                    {
                                        string menuName = subKeyName;
                                        string command = string.Empty;
                                        string status = "已启用";
                                        
                                        // 尝试获取显示名称
                                        var muivVerb = subKey.GetValue("MUIVerb");
                                        if (muivVerb != null)
                                        {
                                            menuName = muivVerb.ToString();
                                        }
                                        else
                                        {
                                            // 尝试获取默认值
                                            var defaultValue = subKey.GetValue("(Default)");
                                            if (defaultValue != null)
                                            {
                                                menuName = defaultValue.ToString();
                                            }
                                        }
                                        
                                        // 尝试获取命令
                                        var commandValue = subKey.GetValue("command") ?? subKey.GetValue("(Default)");
                                        if (commandValue != null)
                                        {
                                            command = commandValue.ToString();
                                        }
                                        
                                        var item = new ListViewItem(menuName);
                                        item.SubItems.Add(command);
                                        item.SubItems.Add(status);
                                        listView.Items.Add(item);
                                    }
                                }
                            }
                            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ContextMenuManagerForm.cs 捕获异常", ex.Message); }
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ContextMenuManagerForm.cs 捕获异常", ex.Message); }
        }
    }
}