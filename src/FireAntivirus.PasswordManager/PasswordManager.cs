using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.PasswordManager
{
    public class StoredPassword
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Url { get; set; }
        public string Notes { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }

    public class PasswordManager
    {
        private DataManager _dataManager;
        private string _passwordStorePath;
        private List<PasswordEntry> _passwordEntries;

        public PasswordManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _passwordStorePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Passwords");
            _passwordEntries = new List<PasswordEntry>();
            InitializePasswordManager();
        }

        private void InitializePasswordManager()
        {
            Directory.CreateDirectory(_passwordStorePath);
            LoadPasswords();
        }

        private void LoadPasswords()
        {
            // 从加密文件加载密码
            LoadPasswordsFromFile();

            // 如果没有保存的密码，才添加默认示例
            if (_passwordEntries.Count == 0)
            {
                _passwordEntries.Add(new PasswordEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Title = "示例: Gmail",
                    Username = "user@gmail.com",
                    Password = "", // 不存储实际密码
                    Url = "https://mail.google.com",
                    Notes = "这是示例条目，请添加您自己的密码",
                    CreatedAt = DateTime.Now,
                    UpdatedAt = DateTime.Now
                });
            }
        }

        public void AddPassword(PasswordEntry entry)
        {
            entry.Id = Guid.NewGuid().ToString();
            entry.CreatedAt = DateTime.Now;
            entry.UpdatedAt = DateTime.Now;
            _passwordEntries.Add(entry);
            SavePasswords();
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "PasswordAdded",
                Message = "密码已添加",
                Details = $"标题: {entry.Title}"
            });
        }

        public void UpdatePassword(PasswordEntry entry)
        {
            var existingEntry = _passwordEntries.FirstOrDefault(e => e.Id == entry.Id);
            if (existingEntry != null)
            {
                existingEntry.Title = entry.Title;
                existingEntry.Username = entry.Username;
                existingEntry.Password = entry.Password;
                existingEntry.Url = entry.Url;
                existingEntry.Notes = entry.Notes;
                existingEntry.UpdatedAt = DateTime.Now;
                SavePasswords();
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "PasswordUpdated",
                    Message = "密码已更新",
                    Details = $"标题: {entry.Title}"
                });
            }
        }

        public void DeletePassword(string id)
        {
            var entry = _passwordEntries.FirstOrDefault(e => e.Id == id);
            if (entry != null)
            {
                _passwordEntries.Remove(entry);
                SavePasswords();
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "PasswordDeleted",
                    Message = "密码已删除",
                    Details = $"标题: {entry.Title}"
                });
            }
        }

        public List<PasswordEntry> GetPasswordEntries()
        {
            return _passwordEntries;
        }

        public List<StoredPassword> GetPasswords()
        {
            return _passwordEntries.Select(e => new StoredPassword
            {
                Id = e.Id,
                Title = e.Title,
                Username = e.Username,
                Password = e.Password,
                Url = e.Url,
                Notes = e.Notes,
                CreatedAt = e.CreatedAt,
                UpdatedAt = e.UpdatedAt
            }).ToList();
        }

        public PasswordEntry GetPassword(string id)
        {
            return _passwordEntries.FirstOrDefault(e => e.Id == id);
        }

        public string GeneratePassword(int length = 16, bool includeUppercase = true, bool includeLowercase = true, bool includeNumbers = true, bool includeSpecialChars = true)
        {
            const string uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
            const string numberChars = "0123456789";
            const string specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

            string chars = "";
            if (includeUppercase) chars += uppercaseChars;
            if (includeLowercase) chars += lowercaseChars;
            if (includeNumbers) chars += numberChars;
            if (includeSpecialChars) chars += specialChars;

            if (string.IsNullOrEmpty(chars))
            {
                chars = lowercaseChars; // 默认至少包含小写字母
            }

            StringBuilder password = new StringBuilder();
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] randomBytes = new byte[length];
                rng.GetBytes(randomBytes);
                for (int i = 0; i < length; i++)
                {
                    password.Append(chars[randomBytes[i] % chars.Length]);
                }
            }

            return password.ToString();
        }

        public PasswordStrength CheckPasswordStrength(string password)
        {
            int score = 0;

            // 检查长度
            if (password.Length >= 8) score++;
            if (password.Length >= 12) score++;
            if (password.Length >= 16) score++;

            // 检查是否包含大写字母
            if (password.Any(char.IsUpper)) score++;

            // 检查是否包含小写字母
            if (password.Any(char.IsLower)) score++;

            // 检查是否包含数字
            if (password.Any(char.IsDigit)) score++;

            // 检查是否包含特殊字符
            if (password.Any(c => !char.IsLetterOrDigit(c))) score++;

            // 评估密码强度
            if (score < 3)
                return PasswordStrength.Weak;
            else if (score < 5)
                return PasswordStrength.Medium;
            else if (score < 7)
                return PasswordStrength.Strong;
            else
                return PasswordStrength.VeryStrong;
        }

        private void SavePasswords()
        {
            try
            {
                string passwordFile = Path.Combine(_passwordStorePath, "passwords.dat");

                // 使用DPAPI加密存储
                var entries = _passwordEntries.Select(e => new PasswordEntryDto
                {
                    Id = e.Id,
                    Title = e.Title,
                    Username = e.Username,
                    EncryptedPassword = ProtectedData.Protect(
                        Encoding.UTF8.GetBytes(e.Password),
                        null,
                        DataProtectionScope.CurrentUser),
                    Url = e.Url,
                    Notes = e.Notes,
                    CreatedAt = e.CreatedAt,
                    UpdatedAt = e.UpdatedAt
                }).ToList();

                var json = System.Text.Json.JsonSerializer.Serialize(entries);
                var encryptedData = ProtectedData.Protect(
                    Encoding.UTF8.GetBytes(json),
                    null,
                    DataProtectionScope.CurrentUser);

                File.WriteAllBytes(passwordFile, encryptedData);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[PasswordManager] 保存密码失败: " + ex.Message);
            }
        }

        private void LoadPasswordsFromFile()
        {
            try
            {
                string passwordFile = Path.Combine(_passwordStorePath, "passwords.dat");
                if (!File.Exists(passwordFile))
                    return;

                var encryptedData = File.ReadAllBytes(passwordFile);
                var json = Encoding.UTF8.GetString(ProtectedData.Unprotect(
                    encryptedData,
                    null,
                    DataProtectionScope.CurrentUser));

                var entries = System.Text.Json.JsonSerializer.Deserialize<List<PasswordEntryDto>>(json);
                if (entries == null)
                    return;

                _passwordEntries = entries.Select(e => new PasswordEntry
                {
                    Id = e.Id,
                    Title = e.Title,
                    Username = e.Username,
                    Password = Encoding.UTF8.GetString(ProtectedData.Unprotect(
                        e.EncryptedPassword,
                        null,
                        DataProtectionScope.CurrentUser)),
                    Url = e.Url,
                    Notes = e.Notes,
                    CreatedAt = e.CreatedAt,
                    UpdatedAt = e.UpdatedAt
                }).ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[PasswordManager] 加载密码失败: " + ex.Message);
            }
        }
    }

    // 数据传输对象
    internal class PasswordEntryDto
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Username { get; set; }
        public byte[] EncryptedPassword { get; set; }
        public string Url { get; set; }
        public string Notes { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}