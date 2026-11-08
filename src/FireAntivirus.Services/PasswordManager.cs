using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using FireAntivirus.Data;
using FireAntivirus.Common.Notification;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 密码管理服务 - 使用AES-256加密安全存储密码
    /// </summary>
    public class PasswordManager : IMonitor
    {
        private Thread _monitorThread;
        private bool _isRunning;
        private DataManager _dataManager;
        private List<StoredPassword> _passwords;
        private bool _enablePasswordStorage = true;
        private bool _isUnlocked = false;
        private string? _masterPasswordHash;
        private byte[]? _encryptionKey;
        private byte[]? _encryptionIV;
        
        // 加密常量
        private const int KeySize = 256; // AES-256
        private const int BlockSize = 128;
        private const int Iterations = 100000; // PBKDF2迭代次数
        private const int SaltSize = 32;
        
        public bool IsRunning => _isRunning;
        public bool IsUnlocked => _isUnlocked;
        public int PasswordCount => _passwords?.Count ?? 0;

        public PasswordManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _passwords = new List<StoredPassword>();
            LoadMasterPasswordHash();
            LoadPasswords();
        }

        public void Start()
        {
            if (_isRunning) return;
            
            _isRunning = true;
            _monitorThread = new Thread(MonitorPasswords);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "PasswordManagerStart",
                Message = "密码管理服务已启动"
            });
        }

        public void Stop()
        {
            if (!_isRunning) return;
            
            _isRunning = false;
            
            // 锁定并保存
            Lock();
            SavePasswords();
            
            _monitorThread?.Join(2000);

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "PasswordManagerStop",
                Message = "密码管理服务已停止"
            });
        }

        #region 主密码管理

        /// <summary>
        /// 设置主密码
        /// </summary>
        public bool SetMasterPassword(string masterPassword)
        {
            if (string.IsNullOrEmpty(masterPassword) || masterPassword.Length < 8)
            {
                NotificationService.Instance.ShowNotification(
                    "密码管理",
                    "主密码长度必须至少为8个字符",
                    NotificationType.Warning
                );
                return false;
            }

            try
            {
                // 生成盐
                var salt = GenerateRandomBytes(SaltSize);
                
                // 使用PBKDF2派生密钥
                var hash = Rfc2898DeriveBytes.Pbkdf2(masterPassword, salt, Iterations, HashAlgorithmName.SHA256, 32); // 256位哈希
                
                // 存储盐和哈希
                var hashData = new Data.MasterPasswordHashData
                {
                    Salt = Convert.ToBase64String(salt),
                    Hash = Convert.ToBase64String(hash),
                    Iterations = Iterations,
                    CreatedAt = DateTime.Now.ToString("O")
                };
                
                _dataManager.SaveMasterPasswordHash(hashData);
                _masterPasswordHash = hashData.Hash;
                
                // 派生加密密钥
                DeriveEncryptionKey(masterPassword, salt);
                
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "MasterPasswordSet",
                    Message = "主密码已设置"
                });
                
                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "MasterPasswordError",
                    Message = "设置主密码失败",
                    Details = ex.Message
                });
                return false;
            }
        }

        /// <summary>
        /// 验证主密码并解锁
        /// </summary>
        public bool Unlock(string masterPassword)
        {
            if (string.IsNullOrEmpty(masterPassword))
                return false;

            try
            {
                var hashData = _dataManager.LoadMasterPasswordHash();
                if (hashData == null)
                {
                    // 没有设置主密码，首次使用
                    return SetMasterPassword(masterPassword);
                }

                var salt = Convert.FromBase64String(hashData.Salt);
                var storedHash = Convert.FromBase64String(hashData.Hash);
                
                // 验证密码
                var computedHash = Rfc2898DeriveBytes.Pbkdf2(masterPassword, salt, hashData.Iterations, HashAlgorithmName.SHA256, 32);
                
                if (computedHash.SequenceEqual(storedHash))
                {
                    // 密码正确，派生加密密钥
                    DeriveEncryptionKey(masterPassword, salt);
                    _isUnlocked = true;
                    
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "PasswordManagerUnlocked",
                        Message = "密码管理器已解锁"
                    });
                    
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UnlockError",
                    Message = "解锁失败",
                    Details = ex.Message
                });
                return false;
            }
        }

        /// <summary>
        /// 锁定密码管理器
        /// </summary>
        public void Lock()
        {
            _isUnlocked = false;
            _encryptionKey = null;
            _encryptionIV = null;
            
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "PasswordManagerLocked",
                Message = "密码管理器已锁定"
            });
        }

        /// <summary>
        /// 检查是否已设置主密码
        /// </summary>
        public bool HasMasterPassword()
        {
            var hashData = _dataManager.LoadMasterPasswordHash();
            return hashData != null && !string.IsNullOrEmpty(hashData.Hash);
        }

        private void DeriveEncryptionKey(string password, byte[] salt)
        {
            byte[] derived = Rfc2898DeriveBytes.Pbkdf2(password + "_encryption", salt, Iterations, HashAlgorithmName.SHA256, (KeySize + BlockSize) / 8);
            _encryptionKey = derived[..(KeySize / 8)]; // 32字节 = 256位
            _encryptionIV = derived[(KeySize / 8)..];  // 16字节 = 128位
        }

        private void LoadMasterPasswordHash()
        {
            try
            {
                var hashData = _dataManager.LoadMasterPasswordHash();
                if (hashData != null)
                {
                    _masterPasswordHash = hashData.Hash;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PasswordManager.cs 捕获异常", ex.Message); }
        }

        #endregion

        #region AES-256 加密/解密

        private byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// 使用AES-256加密数据
        /// </summary>
        private string EncryptString(string plainText)
        {
            if (_encryptionKey == null || _encryptionIV == null)
                throw new InvalidOperationException("密码管理器未解锁");

            try
            {
                using var aes = Aes.Create();
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Key = _encryptionKey;
                aes.IV = _encryptionIV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using var encryptor = aes.CreateEncryptor();
                var plainBytes = Encoding.UTF8.GetBytes(plainText);
                var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                
                return Convert.ToBase64String(cipherBytes);
            }
            catch (Exception ex)
            {
                throw new Exception($"加密失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 使用AES-256解密数据
        /// </summary>
        private string DecryptString(string cipherText)
        {
            if (_encryptionKey == null || _encryptionIV == null)
                throw new InvalidOperationException("密码管理器未解锁");

            try
            {
                using var aes = Aes.Create();
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Key = _encryptionKey;
                aes.IV = _encryptionIV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using var decryptor = aes.CreateDecryptor();
                var cipherBytes = Convert.FromBase64String(cipherText);
                var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                throw new Exception($"解密失败: {ex.Message}");
            }
        }

        #endregion

        #region 密码存储管理

        /// <summary>
        /// 存储新密码
        /// </summary>
        public bool StorePassword(string website, string username, string password, string notes = "", string category = "General")
        {
            if (!_isUnlocked)
            {
                NotificationService.Instance.ShowNotification(
                    "密码管理",
                    "请先解锁密码管理器",
                    NotificationType.Warning
                );
                return false;
            }

            if (string.IsNullOrEmpty(website) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                NotificationService.Instance.ShowNotification(
                    "密码管理",
                    "请填写完整的密码信息",
                    NotificationType.Warning
                );
                return false;
            }

            try
            {
                var encryptedPassword = EncryptString(password);
                var encryptedNotes = !string.IsNullOrEmpty(notes) ? EncryptString(notes) : "";

                var storedPassword = new StoredPassword
                {
                    Id = Guid.NewGuid().ToString(),
                    Website = website,
                    Username = username,
                    Password = encryptedPassword,
                    Notes = encryptedNotes,
                    Category = category,
                    CreatedAt = DateTime.Now,
                    LastUpdated = DateTime.Now,
                    ExpiryDate = DateTime.Now.AddMonths(6),
                    Strength = CalculatePasswordStrength(password)
                };

                _passwords.Add(storedPassword);
                SavePasswords();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "PasswordStored",
                    Message = "密码已存储",
                    Details = $"网站: {website}"
                });

                return true;
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "PasswordStoreError",
                    Message = "存储密码失败",
                    Details = ex.Message
                });
                return false;
            }
        }

        /// <summary>
        /// 获取解密后的密码列表
        /// </summary>
        public List<StoredPassword> GetPasswords()
        {
            if (!_isUnlocked)
                return new List<StoredPassword>();

            var decryptedPasswords = new List<StoredPassword>();
            
            foreach (var password in _passwords)
            {
                try
                {
                    var decrypted = new StoredPassword
                    {
                        Id = password.Id,
                        Website = password.Website,
                        Username = password.Username,
                        Password = DecryptString(password.Password),
                        Notes = !string.IsNullOrEmpty(password.Notes) ? DecryptString(password.Notes) : "",
                        Category = password.Category,
                        CreatedAt = password.CreatedAt,
                        LastUpdated = password.LastUpdated,
                        ExpiryDate = password.ExpiryDate,
                        Strength = password.Strength
                    };
                    decryptedPasswords.Add(decrypted);
                }
                catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PasswordManager.cs 捕获异常", ex.Message); }
            }
            
            return decryptedPasswords;
        }

        /// <summary>
        /// 获取单个密码
        /// </summary>
        public StoredPassword? GetPassword(string id)
        {
            if (!_isUnlocked)
                return null;

            var password = _passwords.FirstOrDefault(p => p.Id == id);
            if (password == null)
                return null;

            try
            {
                return new StoredPassword
                {
                    Id = password.Id,
                    Website = password.Website,
                    Username = password.Username,
                    Password = DecryptString(password.Password),
                    Notes = !string.IsNullOrEmpty(password.Notes) ? DecryptString(password.Notes) : "",
                    Category = password.Category,
                    CreatedAt = password.CreatedAt,
                    LastUpdated = password.LastUpdated,
                    ExpiryDate = password.ExpiryDate,
                    Strength = password.Strength
                };
            }
            catch { return null; }
        }

        /// <summary>
        /// 更新密码
        /// </summary>
        public bool UpdatePassword(string id, string website, string username, string password, string notes = "", string category = "General")
        {
            if (!_isUnlocked) return false;

            var existing = _passwords.FirstOrDefault(p => p.Id == id);
            if (existing == null) return false;

            try
            {
                existing.Website = website;
                existing.Username = username;
                existing.Password = EncryptString(password);
                existing.Notes = !string.IsNullOrEmpty(notes) ? EncryptString(notes) : "";
                existing.Category = category;
                existing.LastUpdated = DateTime.Now;
                existing.ExpiryDate = DateTime.Now.AddMonths(6);
                existing.Strength = CalculatePasswordStrength(password);

                SavePasswords();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "PasswordUpdated",
                    Message = "密码已更新",
                    Details = $"网站: {website}"
                });

                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// 删除密码
        /// </summary>
        public bool DeletePassword(string id)
        {
            var password = _passwords.FirstOrDefault(p => p.Id == id);
            if (password == null) return false;

            _passwords.Remove(password);
            SavePasswords();

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "PasswordDeleted",
                Message = "密码已删除",
                Details = $"网站: {password.Website}"
            });

            return true;
        }

        #endregion

        #region 密码生成器

        /// <summary>
        /// 生成安全密码
        /// </summary>
        public string GeneratePassword(int length = 16, bool includeUppercase = true, bool includeLowercase = true, 
            bool includeNumbers = true, bool includeSpecialChars = true, bool excludeAmbiguous = true)
        {
            const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowercase = "abcdefghijklmnopqrstuvwxyz";
            const string numbers = "0123456789";
            const string specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
            const string ambiguous = "Il1O0";

            var charSet = new StringBuilder();
            
            if (includeUppercase)
            {
                charSet.Append(excludeAmbiguous ? uppercase.Replace("I", "").Replace("L", "").Replace("O", "") : uppercase);
            }
            if (includeLowercase)
            {
                charSet.Append(excludeAmbiguous ? lowercase.Replace("l", "").Replace("o", "") : lowercase);
            }
            if (includeNumbers)
            {
                charSet.Append(excludeAmbiguous ? numbers.Replace("0", "").Replace("1", "") : numbers);
            }
            if (includeSpecialChars)
            {
                charSet.Append(specialChars);
            }

            if (charSet.Length == 0)
            {
                charSet.Append(lowercase);
                charSet.Append(numbers);
            }

            var password = new StringBuilder(length);
            using var rng = RandomNumberGenerator.Create();
            var randomBytes = new byte[length];
            rng.GetBytes(randomBytes);

            for (int i = 0; i < length; i++)
            {
                var index = randomBytes[i] % charSet.Length;
                password.Append(charSet[index]);
            }

            return password.ToString();
        }

        #endregion

        #region 密码强度检测

        /// <summary>
        /// 计算密码强度 (0-5)
        /// </summary>
        public int CalculatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return 0;

            int strength = 0;
            
            // 长度检查
            if (password.Length >= 8) strength++;
            if (password.Length >= 12) strength++;
            if (password.Length >= 16) strength++;
            
            // 复杂性检查
            if (password.Any(char.IsUpper)) strength++;
            if (password.Any(char.IsLower)) strength++;
            if (password.Any(char.IsDigit)) strength++;
            if (password.Any(ch => !char.IsLetterOrDigit(ch))) strength++;
            
            // 检查常见模式
            if (!HasCommonPatterns(password)) strength++;
            
            return Math.Min(5, strength);
        }

        /// <summary>
        /// 获取密码强度描述
        /// </summary>
        public string GetPasswordStrengthDescription(int strength)
        {
            return strength switch
            {
                0 => "非常弱",
                1 => "弱",
                2 => "一般",
                3 => "中等",
                4 => "强",
                5 => "非常强",
                _ => "未知"
            };
        }

        private bool HasCommonPatterns(string password)
        {
            var patterns = new[] { "123", "234", "345", "456", "567", "678", "789", 
                "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij",
                "password", "qwerty", "asdf", "zxcv", "admin", "login" };
            
            var lower = password.ToLower();
            return patterns.Any(p => lower.Contains(p));
        }

        #endregion

        #region 监控

        private void MonitorPasswords()
        {
            while (_isRunning)
            {
                try
                {
                    if (_isUnlocked)
                    {
                        CheckPasswordStrength();
                        CheckPasswordExpiry();
                    }
                }
                catch (Exception ex)
                {
                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "PasswordManagerError",
                        Message = "密码管理服务错误",
                        Details = ex.Message
                    });
                }

                Thread.Sleep(600000); // 每10分钟检查一次
            }
        }

        private void CheckPasswordStrength()
        {
            foreach (var password in _passwords)
            {
                if (password.Strength < 3)
                {
                    NotificationService.Instance.ShowNotification(
                        "密码强度提醒",
                        $"您的 {password.Website} 密码强度较弱，建议更新",
                        NotificationType.Warning
                    );
                }
            }
        }

        private void CheckPasswordExpiry()
        {
            var now = DateTime.Now;
            
            foreach (var password in _passwords)
            {
                if (password.ExpiryDate <= now)
                {
                    NotificationService.Instance.ShowNotification(
                        "密码过期提醒",
                        $"您的 {password.Website} 密码已过期，请更新",
                        NotificationType.Warning
                    );
                }
                else if (password.ExpiryDate <= now.AddDays(7))
                {
                    NotificationService.Instance.ShowNotification(
                        "密码即将过期",
                        $"您的 {password.Website} 密码将在7天内过期",
                        NotificationType.Info
                    );
                }
            }
        }

        #endregion

        #region 数据持久化

        private void LoadPasswords()
        {
            try
            {
                var data = _dataManager.LoadStoredPasswords();
                if (data != null)
                {
                    _passwords = data.Select(p => new StoredPassword
                    {
                        Id = p.Id,
                        Website = p.Website,
                        Username = p.Username,
                        Password = p.Password,
                        Notes = p.Notes,
                        Category = p.Category,
                        CreatedAt = DateTime.TryParse(p.CreatedAt, out var ca) ? ca : DateTime.Now,
                        LastUpdated = DateTime.TryParse(p.LastUpdated, out var lu) ? lu : DateTime.Now,
                        ExpiryDate = DateTime.TryParse(p.ExpiryDate, out var ed) ? ed : DateTime.Now.AddMonths(6),
                        Strength = p.Strength
                    }).ToList();
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PasswordManager.cs 捕获异常", ex.Message); }
        }

        private void SavePasswords()
        {
            try
            {
                var data = _passwords.Select(p => new Data.StoredPasswordData
                {
                    Id = p.Id,
                    Website = p.Website,
                    Username = p.Username,
                    Password = p.Password,
                    Notes = p.Notes,
                    Category = p.Category,
                    CreatedAt = p.CreatedAt.ToString("O"),
                    LastUpdated = p.LastUpdated.ToString("O"),
                    ExpiryDate = p.ExpiryDate.ToString("O"),
                    Strength = p.Strength
                }).ToList();
                _dataManager.SaveStoredPasswords(data);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "PasswordManager.cs 捕获异常", ex.Message); }
        }

        public void UpdateSettings(bool enablePasswordStorage)
        {
            _enablePasswordStorage = enablePasswordStorage;

            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "PasswordManagerSettingsUpdated",
                Message = "密码管理设置已更新",
                Details = $"密码存储: {enablePasswordStorage}"
            });
        }

        #endregion
    }

    public class StoredPassword
    {
        public string Id { get; set; } = "";
        public string Website { get; set; } = "";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Notes { get; set; } = "";
        public string Category { get; set; } = "General";
        public DateTime CreatedAt { get; set; }
        public DateTime LastUpdated { get; set; }
        public DateTime ExpiryDate { get; set; }
        public int Strength { get; set; }
    }
}