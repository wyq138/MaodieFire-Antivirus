using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using FireAntivirus.Data;
using FireAntivirus.Engine;

namespace FireAntivirus.Services
{
    public class ContextMenuManager
    {
        private DataManager dataManager;
        private AntivirusEngine antivirusEngine;

        public ContextMenuManager(DataManager dataManager, AntivirusEngine antivirusEngine)
        {
            this.dataManager = dataManager;
            this.antivirusEngine = antivirusEngine;
        }

        public List<ContextMenuItem> GetContextMenuItems()
        {
            List<ContextMenuItem> items = new List<ContextMenuItem>();

            try
            {
                items.AddRange(GetFileContextMenuItems());
                items.AddRange(GetFolderContextMenuItems());

                dataManager.LogInfo($"成功获取 {items.Count} 个右键菜单项");
            }
            catch (Exception ex)
            {
                dataManager.LogError($"获取右键菜单项失败: {ex.Message}");
            }

            return items;
        }

        private List<ContextMenuItem> GetFileContextMenuItems()
        {
            List<ContextMenuItem> items = new List<ContextMenuItem>();

            try
            {
                string[] fileExtensions = { ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi" };
                string iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "icon.ico");

                foreach (string extension in fileExtensions)
                {
                    string command = $"FireAntivirus.ScanFile \"%1\"";

                    items.Add(new ContextMenuItem
                    {
                        Name = "扫描文件",
                        Command = command,
                        Icon = iconPath,
                        Type = ContextMenuType.File,
                        Extension = extension,
                        Enabled = true
                    });

                    string quarantineCommand = $"FireAntivirus.Quarantine \"%1\"";
                    items.Add(new ContextMenuItem
                    {
                        Name = "隔离文件",
                        Command = quarantineCommand,
                        Icon = iconPath,
                        Type = ContextMenuType.File,
                        Extension = extension,
                        Enabled = true
                    });
                }

                string allFilesCommand = "FireAntivirus.ScanFile";
                items.Add(new ContextMenuItem
                {
                    Name = "扫描所有文件",
                    Command = allFilesCommand,
                    Icon = iconPath,
                    Type = ContextMenuType.File,
                    Extension = "*",
                    Enabled = true
                });
            }
            catch (Exception ex)
            {
                dataManager.LogError($"获取文件右键菜单项失败: {ex.Message}");
            }

            return items;
        }

        private List<ContextMenuItem> GetFolderContextMenuItems()
        {
            List<ContextMenuItem> items = new List<ContextMenuItem>();

            try
            {
                string scanCommand = "FireAntivirus.ScanFolder";
                string iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "icon.ico");

                items.Add(new ContextMenuItem
                {
                    Name = "扫描文件夹",
                    Command = scanCommand,
                    Icon = iconPath,
                    Type = ContextMenuType.Folder,
                    Enabled = true
                });

                items.Add(new ContextMenuItem
                {
                    Name = "快速扫描",
                    Command = "FireAntivirus.QuickScan",
                    Icon = iconPath,
                    Type = ContextMenuType.Folder,
                    Enabled = true
                });

                items.Add(new ContextMenuItem
                {
                    Name = "完整扫描",
                    Command = "FireAntivirus.FullScan",
                    Icon = iconPath,
                    Type = ContextMenuType.Folder,
                    Enabled = true
                });
            }
            catch (Exception ex)
            {
                dataManager.LogError($"获取文件夹右键菜单项失败: {ex.Message}");
            }

            return items;
        }

        public bool InstallContextMenu()
        {
            try
            {
                List<ContextMenuItem> items = GetContextMenuItems();

                foreach (var item in items)
                {
                    if (!item.Enabled) continue;

                    string commandKey = $"*\\{item.Extension}\\shell\\{item.Name}";
                    string commandKeyPath = $"*\\{item.Extension}\\shell\\{item.Name}\\command";

                    using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(commandKey, true))
                    {
                        if (key != null)
                        {
                            using (RegistryKey commandKey2 = key.CreateSubKey("command", true))
                            {
                                commandKey2.SetValue("", item.Command);
                            }
                        }
                    }

                    using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(commandKeyPath, true))
                    {
                        if (key != null)
                        {
                            key.SetValue("", item.Command);
                        }
                    }
                }

                dataManager.LogInfo($"右键菜单安装成功: {items.Count} 个菜单项");
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"安装右键菜单失败: {ex.Message}");
                return false;
            }
        }

        public bool UninstallContextMenu()
        {
            try
            {
                List<ContextMenuItem> items = GetContextMenuItems();

                foreach (var item in items)
                {
                    string commandKey = $"*\\{item.Extension}\\shell\\{item.Name}";
                    string commandKeyPath = $"*\\{item.Extension}\\shell\\{item.Name}\\command";

                    Registry.ClassesRoot.DeleteSubKeyTree(commandKey);
                    Registry.ClassesRoot.DeleteSubKeyTree(commandKeyPath);
                }

                dataManager.LogInfo($"右键菜单卸载成功: {items.Count} 个菜单项");
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"卸载右键菜单失败: {ex.Message}");
                return false;
            }
        }

        public bool EnableContextMenuItem(ContextMenuItem item)
        {
            try
            {
                string commandKey = $"*\\{item.Extension}\\shell\\{item.Name}";
                string commandKeyPath = $"*\\{item.Extension}\\shell\\{item.Name}\\command";

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(commandKey, true))
                {
                    if (key != null)
                    {
                        using (RegistryKey commandKey2 = key.CreateSubKey("command", true))
                            {
                                commandKey2.SetValue("", item.Command);
                            }
                    }
                }

                using (RegistryKey key = Registry.ClassesRoot.OpenSubKey(commandKeyPath, true))
                {
                    if (key != null)
                    {
                        key.SetValue("", item.Command);
                    }
                }

                item.Enabled = true;
                dataManager.LogInfo($"已启用右键菜单项: {item.Name}");
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"启用右键菜单项失败: {ex.Message}");
                return false;
            }
        }

        public bool DisableContextMenuItem(ContextMenuItem item)
        {
            try
            {
                string commandKey = $"*\\{item.Extension}\\shell\\{item.Name}";
                string commandKeyPath = $"*\\{item.Extension}\\shell\\{item.Name}\\command";

                Registry.ClassesRoot.DeleteSubKey(commandKey);
                Registry.ClassesRoot.DeleteSubKeyTree(commandKeyPath);

                item.Enabled = false;
                dataManager.LogInfo($"已禁用右键菜单项: {item.Name}");
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"禁用右键菜单项失败: {ex.Message}");
                return false;
            }
        }

        public bool AddCustomContextMenuItem(ContextMenuItem item)
        {
            try
            {
                string commandKey = $"*\\{item.Extension}\\shell\\{item.Name}";
                string commandKeyPath = $"*\\{item.Extension}\\shell\\{item.Name}\\command";

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(commandKey, true))
                {
                    using (RegistryKey commandKey2 = key.CreateSubKey("command", true))
                    {
                        commandKey2.SetValue("", item.Command);
                    }
                }

                using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(commandKeyPath, true))
                {
                    key.SetValue("", item.Command);
                }

                dataManager.LogInfo($"已添加自定义右键菜单项: {item.Name}");
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"添加自定义右键菜单项失败: {ex.Message}");
                return false;
            }
        }

        public bool RemoveContextMenuItem(ContextMenuItem item)
        {
            try
            {
                string commandKey = $"*\\{item.Extension}\\shell\\{item.Name}";
                string commandKeyPath = $"*\\{item.Extension}\\shell\\{item.Name}\\command";

                Registry.ClassesRoot.DeleteSubKey(commandKey);
                Registry.ClassesRoot.DeleteSubKeyTree(commandKeyPath);

                dataManager.LogInfo($"已移除右键菜单项: {item.Name}");
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"移除右键菜单项失败: {ex.Message}");
                return false;
            }
        }

        public bool RestoreDefaultContextMenu()
        {
            try
            {
                UninstallContextMenu();
                InstallContextMenu();

                dataManager.LogInfo("已恢复默认右键菜单");
                return true;
            }
            catch (Exception ex)
            {
                dataManager.LogError($"恢复默认右键菜单失败: {ex.Message}");
                return false;
            }
        }
    }

    public class ContextMenuItem
    {
        public string Name { get; set; }
        public string Command { get; set; }
        public string Icon { get; set; }
        public ContextMenuType Type { get; set; }
        public string Extension { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }

    public enum ContextMenuType
    {
        File,
        Folder
    }
}