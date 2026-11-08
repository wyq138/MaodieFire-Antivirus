using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.ParentalControl
{
    public class ParentalControlSettings
    {
        public bool EnableTimeLimit { get; set; }
        public int DailyTimeLimitMinutes { get; set; }
        public bool EnableContentFilter { get; set; }
    }

    public class ParentalControlManager
    {
        private DataManager _dataManager;
        private List<User> _users;
        private List<TimeRestriction> _timeRestrictions;
        private List<ContentFilter> _contentFilters;
        private List<Tuple<string, ContentAction>> _customBlockedDomains;

        public ParentalControlManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _users = new List<User>();
            _timeRestrictions = new List<TimeRestriction>();
            _contentFilters = new List<ContentFilter>();
            _customBlockedDomains = new List<Tuple<string, ContentAction>>();
            InitializeParentalControl();
        }

        private void InitializeParentalControl()
        {
            LoadUsers();
            LoadTimeRestrictions();
            LoadContentFilters();
            LoadBlockedDomains();
        }

        private void LoadBlockedDomains()
        {
            // 从配置文件加载自定义域名黑名单，每行格式: domain 或 domain|Block/Warn/Allow
            _customBlockedDomains.Clear();
            try
            {
                var file = Path.Combine(GetConfigDirectory(), "blocked_domains.txt");
                if (!File.Exists(file)) return;

                foreach (var line in File.ReadLines(file))
                {
                    var trimmed = line.Trim();
                    if (trimmed.Length == 0 || trimmed.StartsWith("#")) continue;

                    var parts = trimmed.Split('|');
                    var domain = parts[0].Trim();
                    if (domain.Length == 0) continue;

                    var action = ContentAction.Block;
                    if (parts.Length > 1 && Enum.TryParse(parts[1].Trim(), true, out ContentAction parsed))
                        action = parsed;

                    _customBlockedDomains.Add(Tuple.Create(domain, action));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"加载域名黑名单失败: {ex.Message}");
            }
        }

        private string GetConfigDirectory()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 
                "FireAntivirus", "ParentalControl");
        }

        private void LoadUsers()
        {
            // 从文件加载用户列表
            try
            {
                string configDir = GetConfigDirectory();
                Directory.CreateDirectory(configDir);
                string usersFile = Path.Combine(configDir, "users.json");

                if (File.Exists(usersFile))
                {
                    var json = File.ReadAllText(usersFile);
                    var loaded = Newtonsoft.Json.JsonConvert.DeserializeObject<List<User>>(json);
                    if (loaded != null && loaded.Count > 0)
                    {
                        _users = loaded;
                        return;
                    }
                }
            }
            catch { }

            // 文件不存在或加载失败时，添加默认用户
            _users.Add(new User
            {
                Id = Guid.NewGuid().ToString(),
                Name = "Child User",
                Type = UserType.Child,
                Enabled = true
            });

            _users.Add(new User
            {
                Id = Guid.NewGuid().ToString(),
                Name = "Parent User",
                Type = UserType.Parent,
                Enabled = true
            });
        }

        private void LoadTimeRestrictions()
        {
            try
            {
                string configDir = GetConfigDirectory();
                string restrictionsFile = Path.Combine(configDir, "time_restrictions.json");

                if (File.Exists(restrictionsFile))
                {
                    var json = File.ReadAllText(restrictionsFile);
                    var loaded = Newtonsoft.Json.JsonConvert.DeserializeObject<List<TimeRestriction>>(json);
                    if (loaded != null && loaded.Count > 0)
                    {
                        _timeRestrictions = loaded;
                        return;
                    }
                }
            }
            catch { }

            // 添加默认时间限制
            var childUser = _users.FirstOrDefault(u => u.Type == UserType.Child);
            if (childUser != null)
            {
                _timeRestrictions.Add(new TimeRestriction
                {
                    Id = Guid.NewGuid().ToString(),
                    UserId = childUser.Id,
                    DayOfWeek = DayOfWeek.Monday,
                    StartTime = new TimeSpan(8, 0, 0),
                    EndTime = new TimeSpan(18, 0, 0),
                    Enabled = true
                });
            }
        }

        private void LoadContentFilters()
        {
            try
            {
                string configDir = GetConfigDirectory();
                string filtersFile = Path.Combine(configDir, "content_filters.json");

                if (File.Exists(filtersFile))
                {
                    var json = File.ReadAllText(filtersFile);
                    var loaded = Newtonsoft.Json.JsonConvert.DeserializeObject<List<ContentFilter>>(json);
                    if (loaded != null && loaded.Count > 0)
                    {
                        _contentFilters = loaded;
                        return;
                    }
                }
            }
            catch { }

            // 添加默认内容过滤器
            _contentFilters.Add(new ContentFilter
            {
                Id = Guid.NewGuid().ToString(),
                Name = "阻止成人内容",
                Description = "阻止访问成人网站",
                Category = ContentCategory.Adult,
                Action = ContentAction.Block,
                Enabled = true
            });

            _contentFilters.Add(new ContentFilter
            {
                Id = Guid.NewGuid().ToString(),
                Name = "阻止暴力内容",
                Description = "阻止访问暴力网站",
                Category = ContentCategory.Violence,
                Action = ContentAction.Block,
                Enabled = true
            });

            _contentFilters.Add(new ContentFilter
            {
                Id = Guid.NewGuid().ToString(),
                Name = "允许教育内容",
                Description = "允许访问教育网站",
                Category = ContentCategory.Education,
                Action = ContentAction.Allow,
                Enabled = true
            });
        }

        public List<User> GetUsers()
        {
            return _users;
        }

        public User GetUser(string userId)
        {
            return _users.FirstOrDefault(u => u.Id == userId);
        }

        public UserResult AddUser(User user)
        {
            try
            {
                user.Id = Guid.NewGuid().ToString();
                _users.Add(user);
                SaveUsers();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UserAdded",
                    Message = "用户已添加",
                    Details = $"名称: {user.Name}, 类型: {user.Type}"
                });

                return new UserResult
                {
                    Success = true,
                    Message = "用户添加成功",
                    User = user
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UserError",
                    Message = "用户添加错误",
                    Details = $"错误: {ex.Message}"
                });

                return new UserResult
                {
                    Success = false,
                    Message = $"用户添加失败: {ex.Message}"
                };
            }
        }

        public UserResult UpdateUser(User user)
        {
            try
            {
                var existingUser = _users.FirstOrDefault(u => u.Id == user.Id);
                if (existingUser != null)
                {
                    existingUser.Name = user.Name;
                    existingUser.Type = user.Type;
                    existingUser.Enabled = user.Enabled;
                    SaveUsers();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "UserUpdated",
                        Message = "用户已更新",
                        Details = $"名称: {user.Name}"
                    });

                    return new UserResult
                    {
                        Success = true,
                        Message = "用户更新成功",
                        User = existingUser
                    };
                }
                else
                {
                    return new UserResult
                    {
                        Success = false,
                        Message = "用户不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UserError",
                    Message = "用户更新错误",
                    Details = $"错误: {ex.Message}"
                });

                return new UserResult
                {
                    Success = false,
                    Message = $"用户更新失败: {ex.Message}"
                };
            }
        }

        public UserResult DeleteUser(string userId)
        {
            try
            {
                var user = _users.FirstOrDefault(u => u.Id == userId);
                if (user != null)
                {
                    _users.Remove(user);
                    SaveUsers();

                    // 同时删除相关的时间限制
                    _timeRestrictions.RemoveAll(tr => tr.UserId == userId);
                    SaveTimeRestrictions();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "UserDeleted",
                        Message = "用户已删除",
                        Details = $"名称: {user.Name}"
                    });

                    return new UserResult
                    {
                        Success = true,
                        Message = "用户删除成功"
                    };
                }
                else
                {
                    return new UserResult
                    {
                        Success = false,
                        Message = "用户不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "UserError",
                    Message = "用户删除错误",
                    Details = $"错误: {ex.Message}"
                });

                return new UserResult
                {
                    Success = false,
                    Message = $"用户删除失败: {ex.Message}"
                };
            }
        }

        public List<TimeRestriction> GetTimeRestrictions(string userId)
        {
            return _timeRestrictions.Where(tr => tr.UserId == userId).ToList();
        }

        public TimeRestrictionResult AddTimeRestriction(TimeRestriction restriction)
        {
            try
            {
                restriction.Id = Guid.NewGuid().ToString();
                _timeRestrictions.Add(restriction);
                SaveTimeRestrictions();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "TimeRestrictionAdded",
                    Message = "时间限制已添加",
                    Details = $"用户: {_users.First(u => u.Id == restriction.UserId).Name}, 星期: {restriction.DayOfWeek}, 开始时间: {restriction.StartTime}, 结束时间: {restriction.EndTime}"
                });

                return new TimeRestrictionResult
                {
                    Success = true,
                    Message = "时间限制添加成功",
                    Restriction = restriction
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "TimeRestrictionError",
                    Message = "时间限制添加错误",
                    Details = $"错误: {ex.Message}"
                });

                return new TimeRestrictionResult
                {
                    Success = false,
                    Message = $"时间限制添加失败: {ex.Message}"
                };
            }
        }

        public TimeRestrictionResult UpdateTimeRestriction(TimeRestriction restriction)
        {
            try
            {
                var existingRestriction = _timeRestrictions.FirstOrDefault(tr => tr.Id == restriction.Id);
                if (existingRestriction != null)
                {
                    existingRestriction.UserId = restriction.UserId;
                    existingRestriction.DayOfWeek = restriction.DayOfWeek;
                    existingRestriction.StartTime = restriction.StartTime;
                    existingRestriction.EndTime = restriction.EndTime;
                    existingRestriction.Enabled = restriction.Enabled;
                    SaveTimeRestrictions();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "TimeRestrictionUpdated",
                        Message = "时间限制已更新",
                        Details = $"用户: {_users.First(u => u.Id == restriction.UserId).Name}, 星期: {restriction.DayOfWeek}"
                    });

                    return new TimeRestrictionResult
                    {
                        Success = true,
                        Message = "时间限制更新成功",
                        Restriction = existingRestriction
                    };
                }
                else
                {
                    return new TimeRestrictionResult
                    {
                        Success = false,
                        Message = "时间限制不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "TimeRestrictionError",
                    Message = "时间限制更新错误",
                    Details = $"错误: {ex.Message}"
                });

                return new TimeRestrictionResult
                {
                    Success = false,
                    Message = $"时间限制更新失败: {ex.Message}"
                };
            }
        }

        public TimeRestrictionResult DeleteTimeRestriction(string restrictionId)
        {
            try
            {
                var restriction = _timeRestrictions.FirstOrDefault(tr => tr.Id == restrictionId);
                if (restriction != null)
                {
                    _timeRestrictions.Remove(restriction);
                    SaveTimeRestrictions();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "TimeRestrictionDeleted",
                        Message = "时间限制已删除",
                        Details = $"用户: {_users.First(u => u.Id == restriction.UserId).Name}, 星期: {restriction.DayOfWeek}"
                    });

                    return new TimeRestrictionResult
                    {
                        Success = true,
                        Message = "时间限制删除成功"
                    };
                }
                else
                {
                    return new TimeRestrictionResult
                    {
                        Success = false,
                        Message = "时间限制不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "TimeRestrictionError",
                    Message = "时间限制删除错误",
                    Details = $"错误: {ex.Message}"
                });

                return new TimeRestrictionResult
                {
                    Success = false,
                    Message = $"时间限制删除失败: {ex.Message}"
                };
            }
        }

        public List<ContentFilter> GetContentFilters()
        {
            return _contentFilters;
        }

        public ContentFilterResult AddContentFilter(ContentFilter filter)
        {
            try
            {
                filter.Id = Guid.NewGuid().ToString();
                _contentFilters.Add(filter);
                SaveContentFilters();

                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ContentFilterAdded",
                    Message = "内容过滤器已添加",
                    Details = $"名称: {filter.Name}, 类别: {filter.Category}, 动作: {filter.Action}"
                });

                return new ContentFilterResult
                {
                    Success = true,
                    Message = "内容过滤器添加成功",
                    Filter = filter
                };
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ContentFilterError",
                    Message = "内容过滤器添加错误",
                    Details = $"错误: {ex.Message}"
                });

                return new ContentFilterResult
                {
                    Success = false,
                    Message = $"内容过滤器添加失败: {ex.Message}"
                };
            }
        }

        public ContentFilterResult UpdateContentFilter(ContentFilter filter)
        {
            try
            {
                var existingFilter = _contentFilters.FirstOrDefault(cf => cf.Id == filter.Id);
                if (existingFilter != null)
                {
                    existingFilter.Name = filter.Name;
                    existingFilter.Description = filter.Description;
                    existingFilter.Category = filter.Category;
                    existingFilter.Action = filter.Action;
                    existingFilter.Enabled = filter.Enabled;
                    SaveContentFilters();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ContentFilterUpdated",
                        Message = "内容过滤器已更新",
                        Details = $"名称: {filter.Name}"
                    });

                    return new ContentFilterResult
                    {
                        Success = true,
                        Message = "内容过滤器更新成功",
                        Filter = existingFilter
                    };
                }
                else
                {
                    return new ContentFilterResult
                    {
                        Success = false,
                        Message = "内容过滤器不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ContentFilterError",
                    Message = "内容过滤器更新错误",
                    Details = $"错误: {ex.Message}"
                });

                return new ContentFilterResult
                {
                    Success = false,
                    Message = $"内容过滤器更新失败: {ex.Message}"
                };
            }
        }

        public ContentFilterResult DeleteContentFilter(string filterId)
        {
            try
            {
                var filter = _contentFilters.FirstOrDefault(cf => cf.Id == filterId);
                if (filter != null)
                {
                    _contentFilters.Remove(filter);
                    SaveContentFilters();

                    _dataManager.AddLog(new LogEntry
                    {
                        Id = Guid.NewGuid().ToString(),
                        Time = DateTime.Now,
                        Type = "ContentFilterDeleted",
                        Message = "内容过滤器已删除",
                        Details = $"名称: {filter.Name}"
                    });

                    return new ContentFilterResult
                    {
                        Success = true,
                        Message = "内容过滤器删除成功"
                    };
                }
                else
                {
                    return new ContentFilterResult
                    {
                        Success = false,
                        Message = "内容过滤器不存在"
                    };
                }
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "ContentFilterError",
                    Message = "内容过滤器删除错误",
                    Details = $"错误: {ex.Message}"
                });

                return new ContentFilterResult
                {
                    Success = false,
                    Message = $"内容过滤器删除失败: {ex.Message}"
                };
            }
        }

        public bool IsUserAllowed(string userId)
        {
            var user = _users.FirstOrDefault(u => u.Id == userId);
            if (user == null || !user.Enabled)
            {
                return false;
            }

            if (user.Type == UserType.Parent)
            {
                return true;
            }

            var now = DateTime.Now;
            var dayOfWeek = now.DayOfWeek;
            var currentTime = now.TimeOfDay;

            var restrictions = _timeRestrictions.Where(tr => tr.UserId == userId && tr.DayOfWeek == dayOfWeek && tr.Enabled).ToList();
            if (restrictions.Count == 0)
            {
                return false; // 没有时间限制，默认不允许
            }

            foreach (var restriction in restrictions)
            {
                if (currentTime >= restriction.StartTime && currentTime <= restriction.EndTime)
                {
                    return true;
                }
            }

            return false;
        }

        public ContentAction GetContentAction(string url)
        {
            // 真实内容过滤：自定义域名黑名单（最高优先级）+ 按类别的关键词库匹配
            if (string.IsNullOrWhiteSpace(url)) return ContentAction.Allow;

            var lowerUrl = url.ToLowerInvariant();

            // 1. 用户自定义域名黑名单
            foreach (var entry in _customBlockedDomains)
            {
                if (lowerUrl.Contains(entry.Item1.ToLowerInvariant()))
                {
                    return entry.Item2;
                }
            }

            // 2. 启用的过滤规则按类别关键词匹配
            var categoryKeywords = BuildCategoryKeywords();
            foreach (var filter in _contentFilters.Where(f => f.Enabled))
            {
                if (categoryKeywords.TryGetValue(filter.Category, out var keywords))
                {
                    foreach (var keyword in keywords)
                    {
                        if (lowerUrl.Contains(keyword))
                        {
                            return filter.Action;
                        }
                    }
                }
            }

            return ContentAction.Allow; // 默认允许
        }

        private static Dictionary<ContentCategory, string[]> BuildCategoryKeywords()
        {
            // 内置关键词库（覆盖全部内容类别，含中文站点常见关键词）
            return new Dictionary<ContentCategory, string[]>
            {
                [ContentCategory.Adult] = new[] { "porn", "adult", "xxx", "sex", "nude", "hentai", "sese", "caoliu" },
                [ContentCategory.Violence] = new[] { "gore", "violence", "beheading", "snuff", "brutal" },
                [ContentCategory.Gambling] = new[] { "casino", "poker", "betting", "gambling", "slot", "bet365", "博彩", "棋牌" },
                [ContentCategory.Drugs] = new[] { "narcotics", "cocaine", "marijuana", "heroin", "methamphetamine" },
                [ContentCategory.SocialMedia] = new[] { "facebook.com", "twitter.com", "instagram.com", "tiktok.com", "weibo.com", "douyin.com" },
                [ContentCategory.Education] = new[] { "education", "school", "khanacademy", "coursera", "mooc", "xuexi" },
                [ContentCategory.Entertainment] = new[] { "youtube.com", "bilibili.com", "iqiyi.com", "youku.com", "netflix.com" }
            };
        }

        private void SaveUsers()
        {
            try
            {
                string configDir = GetConfigDirectory();
                Directory.CreateDirectory(configDir);
                string usersFile = Path.Combine(configDir, "users.json");
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(_users, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(usersFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存用户失败: {ex.Message}");
            }
        }

        private void SaveTimeRestrictions()
        {
            try
            {
                string configDir = GetConfigDirectory();
                Directory.CreateDirectory(configDir);
                string restrictionsFile = Path.Combine(configDir, "time_restrictions.json");
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(_timeRestrictions, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(restrictionsFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存时间限制失败: {ex.Message}");
            }
        }

        private void SaveContentFilters()
        {
            try
            {
                string configDir = GetConfigDirectory();
                Directory.CreateDirectory(configDir);
                string filtersFile = Path.Combine(configDir, "content_filters.json");
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(_contentFilters, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(filtersFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"保存内容过滤器失败: {ex.Message}");
            }
        }

        public ParentalControlSettings GetSettings()
        {
            return new ParentalControlSettings
            {
                EnableTimeLimit = _timeRestrictions.Any(r => r.Enabled),
                DailyTimeLimitMinutes = 0,
                EnableContentFilter = _contentFilters.Any(f => f.Enabled)
            };
        }

        public void UpdateSettings(ParentalControlSettings settings)
        {
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "ParentalControlSettingsUpdated",
                Message = "家长控制设置已更新",
                Details = $"时间限制: {settings.EnableTimeLimit}, 内容过滤: {settings.EnableContentFilter}"
            });
        }
    }
}