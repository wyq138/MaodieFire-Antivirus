// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace FireAntivirus.Engine.Analyzers.Whitelist
{
    /// <summary>
    /// 白名单分析器 - 管理文件、进程、网络等白名单
    /// </summary>
    public class WhitelistAnalyzer
    {
        private readonly WhitelistManager _fileWhitelist;
        private readonly WhitelistManager _processWhitelist;
        private readonly WhitelistManager _networkWhitelist;
        private readonly WhitelistManager _registryWhitelist;
        private readonly WhitelistManager _certificateWhitelist;
        private readonly WhitelistManager _hashWhitelist;

        public WhitelistAnalyzer()
        {
            _fileWhitelist = new WhitelistManager("File");
            _processWhitelist = new WhitelistManager("Process");
            _networkWhitelist = new WhitelistManager("Network");
            _registryWhitelist = new WhitelistManager("Registry");
            _certificateWhitelist = new WhitelistManager("Certificate");
            _hashWhitelist = new WhitelistManager("Hash");

            InitializeDefaultWhitelists();
        }

        private void InitializeDefaultWhitelists()
        {
            // 系统文件白名单
            _fileWhitelist.AddPath(Environment.GetFolderPath(Environment.SpecialFolder.System));
            _fileWhitelist.AddPath(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            _fileWhitelist.AddPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            _fileWhitelist.AddPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

            // 系统进程白名单
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "System",
                Description = "系统进程"
            });
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "svchost",
                Description = "服务主机进程"
            });
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "explorer",
                Description = "Windows资源管理器"
            });
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "csrss",
                Description = "客户端/服务器运行时子系统"
            });
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "lsass",
                Description = "本地安全机构子系统服务"
            });
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "winlogon",
                Description = "Windows登录管理"
            });
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "smss",
                Description = "会话管理器子系统"
            });
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "services",
                Description = "服务控制管理器"
            });
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "dwm",
                Description = "桌面窗口管理器"
            });
            _processWhitelist.Add(new WhitelistEntry
            {
                Value = "ntoskrnl",
                Description = "Windows内核"
            });

            // 可信发布者白名单
            _certificateWhitelist.Add(new WhitelistEntry
            {
                Value = "Microsoft Corporation",
                Description = "Microsoft Corporation"
            });
            _certificateWhitelist.Add(new WhitelistEntry
            {
                Value = "Google LLC",
                Description = "Google LLC"
            });
            _certificateWhitelist.Add(new WhitelistEntry
            {
                Value = "Apple Inc.",
                Description = "Apple Inc."
            });
            _certificateWhitelist.Add(new WhitelistEntry
            {
                Value = "Mozilla Corporation",
                Description = "Mozilla Corporation"
            });
            _certificateWhitelist.Add(new WhitelistEntry
            {
                Value = "Adobe Inc.",
                Description = "Adobe Inc."
            });
        }

        public WhitelistResult CheckFile(string filePath)
        {
            var result = new WhitelistResult
            {
                Item = filePath,
                Type = "File",
                IsWhitelisted = false,
                MatchReasons = new List<string>()
            };

            try
            {
                // 检查路径白名单
                if (_fileWhitelist.ContainsPath(filePath))
                {
                    result.IsWhitelisted = true;
                    result.MatchReasons.Add("路径在白名单中");
                }

                // 检查哈希白名单
                if (File.Exists(filePath))
                {
                    var hash = ComputeFileHash(filePath);
                    if (_hashWhitelist.Contains(hash))
                    {
                        result.IsWhitelisted = true;
                        result.MatchReasons.Add("文件哈希在白名单中");
                    }

                    // 检查签名白名单
                    var publisher = GetFilePublisher(filePath);
                    if (!string.IsNullOrEmpty(publisher) && _certificateWhitelist.Contains(publisher))
                    {
                        result.IsWhitelisted = true;
                        result.MatchReasons.Add($"发布者在信任列表中: {publisher}");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        public WhitelistResult CheckProcess(string processName)
        {
            var result = new WhitelistResult
            {
                Item = processName,
                Type = "Process",
                IsWhitelisted = false,
                MatchReasons = new List<string>()
            };

            try
            {
                var name = Path.GetFileNameWithoutExtension(processName);
                if (_processWhitelist.Contains(name))
                {
                    result.IsWhitelisted = true;
                    result.MatchReasons.Add("进程在白名单中");
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        public WhitelistResult CheckNetwork(string address)
        {
            var result = new WhitelistResult
            {
                Item = address,
                Type = "Network",
                IsWhitelisted = false,
                MatchReasons = new List<string>()
            };

            try
            {
                if (_networkWhitelist.Contains(address))
                {
                    result.IsWhitelisted = true;
                    result.MatchReasons.Add("网络地址在白名单中");
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        public WhitelistResult CheckRegistry(string keyPath)
        {
            var result = new WhitelistResult
            {
                Item = keyPath,
                Type = "Registry",
                IsWhitelisted = false,
                MatchReasons = new List<string>()
            };

            try
            {
                if (_registryWhitelist.Contains(keyPath))
                {
                    result.IsWhitelisted = true;
                    result.MatchReasons.Add("注册表项在白名单中");
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        public void AddFileToWhitelist(string filePath)
        {
            _fileWhitelist.AddPath(filePath);
            if (File.Exists(filePath))
            {
                var hash = ComputeFileHash(filePath);
                _hashWhitelist.Add(new WhitelistEntry { Value = hash, Description = filePath });
            }
        }

        public void AddProcessToWhitelist(string processName)
        {
            _processWhitelist.Add(new WhitelistEntry { Value = processName });
        }

        public void AddNetworkToWhitelist(string address)
        {
            _networkWhitelist.Add(new WhitelistEntry { Value = address });
        }

        public void AddRegistryToWhitelist(string keyPath)
        {
            _registryWhitelist.Add(new WhitelistEntry { Value = keyPath });
        }

        public void AddCertificateToWhitelist(string publisher)
        {
            _certificateWhitelist.Add(new WhitelistEntry { Value = publisher });
        }

        public void RemoveFromWhitelist(string type, string value)
        {
            switch (type.ToLower())
            {
                case "file":
                    _fileWhitelist.Remove(value);
                    break;
                case "process":
                    _processWhitelist.Remove(value);
                    break;
                case "network":
                    _networkWhitelist.Remove(value);
                    break;
                case "registry":
                    _registryWhitelist.Remove(value);
                    break;
                case "certificate":
                    _certificateWhitelist.Remove(value);
                    break;
                case "hash":
                    _hashWhitelist.Remove(value);
                    break;
            }
        }

        public List<WhitelistEntry> GetAllWhitelistEntries(string type)
        {
            return type.ToLower() switch
            {
                "file" => _fileWhitelist.GetAll(),
                "process" => _processWhitelist.GetAll(),
                "network" => _networkWhitelist.GetAll(),
                "registry" => _registryWhitelist.GetAll(),
                "certificate" => _certificateWhitelist.GetAll(),
                "hash" => _hashWhitelist.GetAll(),
                _ => new List<WhitelistEntry>()
            };
        }

        private string ComputeFileHash(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "").ToLower();
            }
            catch
            {
                return "";
            }
        }

        private string GetFilePublisher(string filePath)
        {
            try
            {
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
                if (cert != null)
                {
                    var cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert);
                    return cert2.Subject;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WhitelistAnalyzer.cs 捕获异常", ex.Message); }
            return "";
        }

        public void SaveToFile(string filePath)
        {
            try
            {
                var data = new Dictionary<string, List<WhitelistEntry>>
                {
                    { "File", _fileWhitelist.GetAll() },
                    { "Process", _processWhitelist.GetAll() },
                    { "Network", _networkWhitelist.GetAll() },
                    { "Registry", _registryWhitelist.GetAll() },
                    { "Certificate", _certificateWhitelist.GetAll() },
                    { "Hash", _hashWhitelist.GetAll() }
                };

                var json = Newtonsoft.Json.JsonConvert.SerializeObject(data, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(filePath, json);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WhitelistAnalyzer.cs 捕获异常", ex.Message); }
        }

        public void LoadFromFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;

                var json = File.ReadAllText(filePath);
                var data = Newtonsoft.Json.JsonConvert.DeserializeObject<Dictionary<string, List<WhitelistEntry>>>(json);

                if (data != null)
                {
                    foreach (var entry in data)
                    {
                        foreach (var item in entry.Value)
                        {
                            switch (entry.Key.ToLower())
                            {
                                case "file":
                                    _fileWhitelist.Add(item);
                                    break;
                                case "process":
                                    _processWhitelist.Add(item);
                                    break;
                                case "network":
                                    _networkWhitelist.Add(item);
                                    break;
                                case "registry":
                                    _registryWhitelist.Add(item);
                                    break;
                                case "certificate":
                                    _certificateWhitelist.Add(item);
                                    break;
                                case "hash":
                                    _hashWhitelist.Add(item);
                                    break;
                            }
                        }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "WhitelistAnalyzer.cs 捕获异常", ex.Message); }
        }
    }

    public class WhitelistManager
    {
        private readonly string _type;
        private readonly HashSet<string> _entries;
        private readonly HashSet<string> _paths;
        private readonly Dictionary<string, WhitelistEntry> _entryDetails;

        public WhitelistManager(string type)
        {
            _type = type;
            _entries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _entryDetails = new Dictionary<string, WhitelistEntry>(StringComparer.OrdinalIgnoreCase);
        }

        public void Add(WhitelistEntry entry)
        {
            _entries.Add(entry.Value);
            _entryDetails[entry.Value] = entry;
        }

        public void AddPath(string path)
        {
            _paths.Add(path);
        }

        public void Remove(string value)
        {
            _entries.Remove(value);
            _paths.Remove(value);
            _entryDetails.Remove(value);
        }

        public bool Contains(string value)
        {
            return _entries.Contains(value);
        }

        public bool ContainsPath(string path)
        {
            foreach (var p in _paths)
            {
                if (path.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        public List<WhitelistEntry> GetAll()
        {
            return _entryDetails.Values.ToList();
        }
    }

    public class WhitelistEntry
    {
        public string Value { get; set; }
        public string Description { get; set; }
        public DateTime AddedTime { get; set; } = DateTime.Now;
        public string AddedBy { get; set; }
    }

    public class WhitelistResult
    {
        public string Item { get; set; }
        public string Type { get; set; }
        public bool IsWhitelisted { get; set; }
        public List<string> MatchReasons { get; set; }
        public string Error { get; set; }
    }
}