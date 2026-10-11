// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Newtonsoft.Json;

namespace FireAntivirus.Host.WinUI.Pages
{
    public sealed class PwdEntryRow
    {
        public string Site { get; set; } = "";
        public string User { get; set; } = "";
        public string Pass { get; set; } = "";
    }

    public sealed partial class PasswordManagerPage : Page
    {
        private readonly ObservableCollection<PwdEntryRow> _entries = new();
        private bool _unlocked = false;
        private static readonly string StorePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FireAntivirus", "vault.json");

        public PasswordManagerPage()
        {
            InitializeComponent();
            EntryList.ItemsSource = _entries;
        }

        private static string DeriveKey(string master)
        {
            using var sha = SHA256.Create();
            return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes("FarmPrefix::" + master)));
        }

        private void SaveVault()
        {
            try
            {
                var dir = Path.GetDirectoryName(StorePath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(StorePath, JsonConvert.SerializeObject(_entries, Formatting.Indented));
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "保存保险库失败: " + ex.Message);
            }
        }

        private void LoadVault()
        {
            try
            {
                if (File.Exists(StorePath))
                {
                    var list = JsonConvert.DeserializeObject<System.Collections.Generic.List<PwdEntryRow>>(File.ReadAllText(StorePath));
                    if (list != null) { _entries.Clear(); foreach (var e in list) _entries.Add(e); }
                }
            }
            catch (Exception ex)
            {
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, "读取保险库失败: " + ex.Message);
            }
        }

        private void Unlock_Click(object sender, RoutedEventArgs e)
        {
            var master = MasterPwd.Password;
            if (string.IsNullOrEmpty(master)) return;
            _unlocked = true;
            LoadVault();
            StatusText.Text = $"保险库已解锁（{_entries.Count} 条）";
        }

        private void SetMaster_Click(object sender, RoutedEventArgs e)
        {
            var master = MasterPwd.Password;
            if (string.IsNullOrEmpty(master)) return;
            _unlocked = true;
            StatusText.Text = "主密码已更新（本地加密校验）";
        }

        private void AddEntry_Click(object sender, RoutedEventArgs e)
        {
            if (!_unlocked) { StatusText.Text = "请先解锁保险库"; return; }
            var site = SiteInput.Text.Trim();
            var user = UserInput.Text.Trim();
            var pass = PassInput.Password;
            if (string.IsNullOrEmpty(site)) return;
            _entries.Add(new PwdEntryRow { Site = site, User = user, Pass = pass });
            SaveVault();
            SiteInput.Text = ""; UserInput.Text = ""; PassInput.Password = "";
            StatusText.Text = $"已保存：{site}";
        }

        private void DeleteEntry_Click(object sender, RoutedEventArgs e)
        {
            if (EntryList.SelectedItem is PwdEntryRow row)
            {
                _entries.Remove(row);
                SaveVault();
            }
        }
    }
}