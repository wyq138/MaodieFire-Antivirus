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
            // 模拟加载密码条目
            _passwordEntries.Add(new PasswordEntry
            {
                Id = Guid.NewGuid().ToString(),
                Title = "Gmail",
                Username = "user@gmail.com",
                Password = "********", // 实际存储时应该加密
                Url = "https://mail.google.com",
                Notes = "个人邮箱",
                CreatedAt = DateTime.Now.AddDays(-30),
                UpdatedAt = DateTime.Now.AddDays(-10)
            });

            _passwordEntries.Add(new PasswordEntry
            {
                Id = Guid.NewGuid().ToString(),
                Title = "GitHub",
                Username = "username",
                Password = "********",
                Url = "https://github.com",
                Notes = "代码仓库",
                CreatedAt = DateTime.Now.AddDays(-45),
                UpdatedAt = DateTime.Now.AddDays(-5)
            });
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
            // 模拟保存密码到文件
            string passwordFile = Path.Combine(_passwordStorePath, "passwords.json");
            // 实际实现中应该加密存储
        }
    }
}