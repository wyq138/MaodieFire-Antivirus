// 耄耋软件工作室 开发，严禁非法反编译
// 耄耋软件工作室 开发，严禁非法反编译
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Management;
using System.Configuration;
using System.Threading;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Data;
using System.Data.SQLite;
using System.Reflection;
using System.Threading.Tasks;
using System.ServiceProcess;
using System.IO.Compression;


namespace FireAntivirus.Common
{
    public static class FileHelper
    {
        public static string GetFileHash(string filePath)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLower();
                }
            }
        }

        public static bool InitializeVirusDatabase(string sourcePath, string destPath)
        {
            try
            {
                return true;
            }
            catch
            {
                return true;
            }
        }

        public static void SafeDelete(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    File.SetAttributes(filePath, FileAttributes.Normal);
                    File.Delete(filePath);
                }
            }
            catch
            {
            }
        }

        public static void SafeCopy(string source, string destination)
        {
            try
            {
                if (File.Exists(source))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(destination));
                    File.Copy(source, destination, true);
                }
            }
            catch
            {
            }
        }
    }

    public static class StringHelper
    {
        public static bool ContainsAny(this string str, params string[] keywords)
        {
            foreach (var keyword in keywords)
            {
                if (str.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static string Truncate(this string str, int maxLength)
        {
            if (string.IsNullOrEmpty(str))
                return str;
            return str.Length <= maxLength ? str : str.Substring(0, maxLength) + "...";
        }

        public static string SanitizeFileName(string fileName)
        {
            string invalidChars = new string(Path.GetInvalidFileNameChars());
            string invalidPathChars = new string(Path.GetInvalidPathChars());
            string invalid = invalidChars + invalidPathChars;

            foreach (char c in invalid)
            {
                fileName = fileName.Replace(c.ToString(), "");
            }

            return fileName;
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }
    }

    public static class PathHelper
    {
        public static string GetAppDataPath()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FireAntivirus");
        }

        public static string GetDataPath()
        {
            return Path.Combine(GetAppDataPath(), "Data");
        }

        public static string GetDatabasePath()
        {
            return Path.Combine(GetDataPath(), "Database");
        }

        public static string GetLogsPath()
        {
            return Path.Combine(GetDataPath(), "Logs");
        }

        public static string GetQuarantinePath()
        {
            return Path.Combine(GetDataPath(), "Quarantine");
        }

        public static string GetBackupsPath()
        {
            return Path.Combine(GetDataPath(), "Backups");
        }

        public static string GetTempPath()
        {
            return Path.Combine(GetDataPath(), "Temp");
        }

        public static void EnsureDirectories()
        {
            Directory.CreateDirectory(GetDataPath());
            Directory.CreateDirectory(GetDatabasePath());
            Directory.CreateDirectory(GetLogsPath());
            Directory.CreateDirectory(GetQuarantinePath());
            Directory.CreateDirectory(GetBackupsPath());
            Directory.CreateDirectory(GetTempPath());
        }

        public static string GetSystemPath()
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.System);
        }

        public static string GetWindowsPath()
        {
            return Path.GetDirectoryName(GetSystemPath());
        }

        public static string GetProgramFilesPath()
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        }

        public static string GetProgramFilesX86Path()
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        }

        public static string GetCommonAppDataPath()
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        }
    }

    public static class CryptoHelper
    {
        private static readonly string EncryptionKey = "FireAntivirusEncryptionKey2024";

        public static string Encrypt(string plainText)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(EncryptionKey.PadRight(32).Substring(0, 32));
                aes.IV = new byte[16];

                using (var encryptor = aes.CreateEncryptor())
                using (var msEncrypt = new MemoryStream())
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (var swEncrypt = new System.IO.StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                    swEncrypt.Flush();
                    csEncrypt.FlushFinalBlock();
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        public static string Decrypt(string cipherText)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(EncryptionKey.PadRight(32).Substring(0, 32));
                aes.IV = new byte[16];

                using (var decryptor = aes.CreateDecryptor())
                using (var msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var srDecrypt = new System.IO.StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }

        public static string GenerateRandomKey(int length = 32)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[length];
                rng.GetBytes(bytes);
                return BitConverter.ToString(bytes).Replace("-", "").Substring(0, length);
            }
        }
    }

    public static class NetworkHelper
    {
        public static bool IsInternetAvailable()
        {
            try
            {
                using (var client = new WebClient())
                {
                    using (client.OpenRead("http://www.msftconnecttest.com/connecttest.txt"))
                    {
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        public static string GetPublicIP()
        {
            try
            {
                using (var client = new WebClient())
                {
                    return client.DownloadString("http://ipinfo.io/ip").Trim();
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        public static bool PingHost(string hostNameOrAddress)
        {
            try
            {
                using (var ping = new System.Net.NetworkInformation.Ping())
                {
                    var reply = ping.Send(hostNameOrAddress, 1000);
                    return reply.Status == System.Net.NetworkInformation.IPStatus.Success;
                }
            }
            catch
            {
                return false;
            }
        }

        public static string DownloadString(string url)
        {
            using (var client = new WebClient())
            {
                client.Headers.Add("User-Agent", "FireAntivirus/1.0");
                return client.DownloadString(url);
            }
        }

        public static void DownloadFile(string url, string filePath)
        {
            using (var client = new WebClient())
            {
                client.Headers.Add("User-Agent", "FireAntivirus/1.0");
                client.DownloadFile(url, filePath);
            }
        }
    }

    public static class SystemHelper
    {
        public static string GetOSVersion()
        {
            return Environment.OSVersion.ToString();
        }

        public static string GetOSArchitecture()
        {
            return Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit";
        }

        public static int GetProcessorCount()
        {
            return Environment.ProcessorCount;
        }

        public static long GetTotalMemory()
        {
            return Environment.WorkingSet;
        }

        public static string GetComputerName()
        {
            return Environment.MachineName;
        }

        public static string GetUserName()
        {
            return Environment.UserName;
        }

        public static string GetDomainName()
        {
            return Environment.UserDomainName;
        }

        public static bool IsAdministrator()
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        public static bool IsProcessRunning(string processName)
        {
            return Process.GetProcessesByName(processName).Length > 0;
        }

        public static Process[] GetRunningProcesses()
        {
            return Process.GetProcesses();
        }

        public static bool KillProcess(int processId)
        {
            try
            {
                // 中央防误杀守护：系统进程/受信任签名进程禁止终止
                if (!TrustedProcessGuard.CanTerminate(processId)) return false;
                var process = Process.GetProcessById(processId);
                process.Kill();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static int KillProcess(string processName)
        {
            try
            {
                // 中央防误杀守护：按名终止时跳过所有受保护进程
                return TrustedProcessGuard.SafeTerminateByName(processName);
            }
            catch
            {
                return 0;
            }
        }

        public static string GetServiceStatus(string serviceName)
        {
            try
            {
                using (var scm = new System.ServiceProcess.ServiceController(serviceName))
                {
                    return scm.Status.ToString();
                }
            }
            catch
            {
                return "Unknown";
            }
        }

        public static bool StartService(string serviceName)
        {
            try
            {
                using (var service = new System.ServiceProcess.ServiceController(serviceName))
                {
                    if (service.Status == System.ServiceProcess.ServiceControllerStatus.Stopped)
                    {
                        service.Start();
                        service.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                        return true;
                    }
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool StopService(string serviceName)
        {
            try
            {
                using (var service = new System.ServiceProcess.ServiceController(serviceName))
                {
                    if (service.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                    {
                        service.Stop();
                        service.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        return true;
                    }
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
    }

    public static class LogHelper
    {
        private static readonly string LogDirectory = PathHelper.GetLogsPath();
        private static readonly object LogLock = new object();

        public enum LogLevel
        {
            Debug,
            Info,
            Warning,
            Error,
            Critical
        }

        public static void Log(LogLevel level, string message, string details = "")
        {
            lock (LogLock)
            {
                try
                {
                    Directory.CreateDirectory(LogDirectory);
                    string logFile = Path.Combine(LogDirectory, $"fireantivirus_{DateTime.Now:yyyy-MM-dd}.log");
                    string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
                    if (!string.IsNullOrEmpty(details))
                    {
                        logEntry += $"\nDetails: {details}";
                    }
                    File.AppendAllText(logFile, logEntry + "\n");
                }
                catch
                {
                }
            }
        }

        public static void Debug(string message, string details = "")
        {
            Log(LogLevel.Debug, message, details);
        }

        public static void Info(string message, string details = "")
        {
            Log(LogLevel.Info, message, details);
        }

        public static void Warning(string message, string details = "")
        {
            Log(LogLevel.Warning, message, details);
        }

        public static void Error(string message, string details = "")
        {
            Log(LogLevel.Error, message, details);
        }

        public static void Critical(string message, string details = "")
        {
            Log(LogLevel.Critical, message, details);
        }

        public static string[] GetLogFiles()
        {
            try
            {
                return Directory.GetFiles(LogDirectory, "*.log");
            }
            catch
            {
                return new string[0];
            }
        }

        public static string ReadLogFile(string filePath)
        {
            try
            {
                return File.ReadAllText(filePath);
            }
            catch
            {
                return "";
            }
        }

        public static void ClearLogs(int daysToKeep = 7)
        {
            try
            {
                string[] logFiles = Directory.GetFiles(LogDirectory, "*.log");
                foreach (string logFile in logFiles)
                {
                    FileInfo fileInfo = new FileInfo(logFile);
                    if (fileInfo.LastWriteTime < DateTime.Now.AddDays(-daysToKeep))
                    {
                        File.Delete(logFile);
                    }
                }
            }
            catch
            {
            }
        }
    }

    public static class ConfigHelper
    {
        private static readonly string ConfigFile = Path.Combine(PathHelper.GetDataPath(), "config.json");
        private static Dictionary<string, string> configCache;
        private static readonly object ConfigLock = new object();

        static ConfigHelper()
        {
            LoadConfig();
        }

        private static void LoadConfig()
        {
            lock (ConfigLock)
            {
                try
                {
                    if (File.Exists(ConfigFile))
                    {
                        string json = File.ReadAllText(ConfigFile);
                        configCache = Newtonsoft.Json.JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                    }
                    else
                    {
                        configCache = new Dictionary<string, string>();
                        SaveConfig();
                    }
                }
                catch
                {
                    configCache = new Dictionary<string, string>();
                }
            }
        }

        private static void SaveConfig()
        {
            lock (ConfigLock)
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(ConfigFile));
                    string json = Newtonsoft.Json.JsonConvert.SerializeObject(configCache, Newtonsoft.Json.Formatting.Indented);
                    File.WriteAllText(ConfigFile, json);
                }
                catch
                {
                }
            }
        }

        public static string Get(string key, string defaultValue = "")
        {
            lock (ConfigLock)
            {
                if (configCache.ContainsKey(key))
                {
                    return configCache[key];
                }
                return defaultValue;
            }
        }

        public static void Set(string key, string value)
        {
            lock (ConfigLock)
            {
                configCache[key] = value;
                SaveConfig();
            }
        }

        public static bool GetBool(string key, bool defaultValue = false)
        {
            string value = Get(key);
            if (bool.TryParse(value, out bool result))
            {
                return result;
            }
            return defaultValue;
        }

        public static void SetBool(string key, bool value)
        {
            Set(key, value.ToString());
        }

        public static int GetInt(string key, int defaultValue = 0)
        {
            string value = Get(key);
            if (int.TryParse(value, out int result))
            {
                return result;
            }
            return defaultValue;
        }

        public static void SetInt(string key, int value)
        {
            Set(key, value.ToString());
        }

        public static long GetLong(string key, long defaultValue = 0)
        {
            string value = Get(key);
            if (long.TryParse(value, out long result))
            {
                return result;
            }
            return defaultValue;
        }

        public static void SetLong(string key, long value)
        {
            Set(key, value.ToString());
        }

        public static double GetDouble(string key, double defaultValue = 0.0)
        {
            string value = Get(key);
            if (double.TryParse(value, out double result))
            {
                return result;
            }
            return defaultValue;
        }

        public static void SetDouble(string key, double value)
        {
            Set(key, value.ToString());
        }

        public static T GetObject<T>(string key, T defaultValue = default(T))
        {
            string value = Get(key);
            if (!string.IsNullOrEmpty(value))
            {
                try
                {
                    return Newtonsoft.Json.JsonConvert.DeserializeObject<T>(value);
                }
                catch
                {
                }
            }
            return defaultValue;
        }

        public static void SetObject<T>(string key, T value)
        {
            try
            {
                string json = Newtonsoft.Json.JsonConvert.SerializeObject(value);
                Set(key, json);
            }
            catch
            {
            }
        }

        public static void Remove(string key)
        {
            lock (ConfigLock)
            {
                if (configCache.ContainsKey(key))
                {
                    configCache.Remove(key);
                    SaveConfig();
                }
            }
        }

        public static void Clear()
        {
            lock (ConfigLock)
            {
                configCache.Clear();
                SaveConfig();
            }
        }

        public static Dictionary<string, string> GetAll()
        {
            lock (ConfigLock)
            {
                return new Dictionary<string, string>(configCache);
            }
        }
    }

    public static class PerformanceHelper
    {
        private static readonly Dictionary<string, Stopwatch> timers = new Dictionary<string, Stopwatch>();
        private static readonly object TimerLock = new object();

        public static void StartTimer(string name)
        {
            lock (TimerLock)
            {
                if (!timers.ContainsKey(name))
                {
                    timers[name] = new Stopwatch();
                }
                timers[name].Start();
            }
        }

        public static void StopTimer(string name)
        {
            lock (TimerLock)
            {
                if (timers.ContainsKey(name))
                {
                    timers[name].Stop();
                }
            }
        }

        public static long GetElapsedMilliseconds(string name)
        {
            lock (TimerLock)
            {
                if (timers.ContainsKey(name))
                {
                    return timers[name].ElapsedMilliseconds;
                }
                return 0;
            }
        }

        public static string GetElapsedTime(string name)
        {
            lock (TimerLock)
            {
                if (timers.ContainsKey(name))
                {
                    var elapsed = timers[name].Elapsed;
                    return $"{elapsed.Hours:00}:{elapsed.Minutes:00}:{elapsed.Seconds:00}.{elapsed.Milliseconds:000}";
                }
                return "00:00:00.000";
            }
        }

        public static void ResetTimer(string name)
        {
            lock (TimerLock)
            {
                if (timers.ContainsKey(name))
                {
                    timers[name].Reset();
                }
            }
        }

        public static void RemoveTimer(string name)
        {
            lock (TimerLock)
            {
                if (timers.ContainsKey(name))
                {
                    timers.Remove(name);
                }
            }
        }

        public static double GetCpuUsage()
        {
            try
            {
                var counter = new System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_");
                counter.NextValue();
                Thread.Sleep(100);
                return counter.NextValue();
            }
            catch
            {
                return 0;
            }
        }

        public static double GetMemoryUsage()
        {
            try
            {
                var counter = new System.Diagnostics.PerformanceCounter("Memory", "% Committed Bytes In Use");
                return counter.NextValue();
            }
            catch
            {
                return 0;
            }
        }

        public static long GetAvailableMemory()
        {
            return Environment.WorkingSet;
        }
    }

    public static class ExceptionHelper
    {
        public static void HandleException(Exception ex, string context = "")
        {
            LogHelper.Error($"Exception in {context}", $"Message: {ex.Message}\nStack Trace: {ex.StackTrace}\nInner Exception: {ex.InnerException?.Message}");
        }

        public static string GetExceptionDetails(Exception ex)
        {
            StringBuilder details = new StringBuilder();
            details.AppendLine($"Message: {ex.Message}");
            details.AppendLine($"Stack Trace: {ex.StackTrace}");
            details.AppendLine($"Source: {ex.Source}");
            details.AppendLine($"Target Site: {ex.TargetSite}");
            
            if (ex.InnerException != null)
            {
                details.AppendLine($"Inner Exception: {ex.InnerException.Message}");
                details.AppendLine($"Inner Stack Trace: {ex.InnerException.StackTrace}");
            }
            
            return details.ToString();
        }

        public static void LogUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                LogHelper.Critical("Unhandled Exception", GetExceptionDetails(ex));
            }
        }

        public static void LogThreadException(object sender, ThreadExceptionEventArgs e)
        {
            LogHelper.Critical("Thread Exception", GetExceptionDetails(e.Exception));
        }
    }

    public static class SerializationHelper
    {
        public static string Serialize(object obj)
        {
            try
            {
                return Newtonsoft.Json.JsonConvert.SerializeObject(obj, Newtonsoft.Json.Formatting.Indented);
            }
            catch
            {
                return "";
            }
        }

        public static T Deserialize<T>(string json)
        {
            try
            {
                return Newtonsoft.Json.JsonConvert.DeserializeObject<T>(json);
            }
            catch
            {
                return default(T);
            }
        }

        public static void SerializeToFile(object obj, string filePath)
        {
            try
            {
                string json = Serialize(obj);
                Directory.CreateDirectory(Path.GetDirectoryName(filePath));
                File.WriteAllText(filePath, json);
            }
            catch
            {
            }
        }

        public static T DeserializeFromFile<T>(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    string json = File.ReadAllText(filePath);
                    return Deserialize<T>(json);
                }
                return default(T);
            }
            catch
            {
                return default(T);
            }
        }
    }

    public static class CollectionHelper
    {
        public static void ForEach<T>(this IEnumerable<T> source, Action<T> action)
        {
            foreach (T item in source)
            {
                action(item);
            }
        }

        public static void ForEach<T>(this IEnumerable<T> source, Action<T, int> action)
        {
            int index = 0;
            foreach (T item in source)
            {
                action(item, index++);
            }
        }

        public static IEnumerable<T> WhereNotNull<T>(this IEnumerable<T> source)
        {
            return source.Where(item => item != null);
        }

        public static IEnumerable<T> DistinctBy<T, TKey>(this IEnumerable<T> source, Func<T, TKey> keySelector)
        {
            var seenKeys = new HashSet<TKey>();
            foreach (T item in source)
            {
                if (seenKeys.Add(keySelector(item)))
                {
                    yield return item;
                }
            }
        }

        public static T MaxBy<T, TKey>(this IEnumerable<T> source, Func<T, TKey> keySelector)
        {
            return source.OrderByDescending(keySelector).FirstOrDefault();
        }

        public static T MinBy<T, TKey>(this IEnumerable<T> source, Func<T, TKey> keySelector)
        {
            return source.OrderBy(keySelector).FirstOrDefault();
        }

        public static T RandomElement<T>(this IEnumerable<T> source)
        {
            var list = source.ToList();
            if (list.Count == 0)
                return default(T);
            var rng = new Random();
            return list[rng.Next(list.Count)];
        }

        // 耄耋软件工作室 开发，严禁非法反编译

        public static IEnumerable<T> Shuffle<T>(this IEnumerable<T> source)
        {
            var list = source.ToList();
            var rng = new Random();
            int n = list.Count;
            while (n > 1)
            {
                n--;
                int k = rng.Next(n + 1);
                T value = list[k];
                list[k] = list[n];
                list[n] = value;
            }
            return list;
        }
    }

    public static class DateTimeHelper
    {
        public static string FormatDateTime(DateTime dateTime)
        {
            return dateTime.ToString("yyyy-MM-dd HH:mm:ss");
        }

        public static string FormatDate(DateTime dateTime)
        {
            return dateTime.ToString("yyyy-MM-dd");
        }

        public static string FormatTime(DateTime dateTime)
        {
            return dateTime.ToString("HH:mm:ss");
        }

        public static string GetRelativeTime(DateTime dateTime)
        {
            var now = DateTime.Now;
            var diff = now - dateTime;

            if (diff.TotalSeconds < 60)
                return $"{diff.Seconds}秒前";
            else if (diff.TotalMinutes < 60)
                return $"{diff.Minutes}分钟前";
            else if (diff.TotalHours < 24)
                return $"{diff.Hours}小时前";
            else if (diff.TotalDays < 30)
                return $"{diff.Days}天前";
            else if (diff.TotalDays < 365)
                return $"{diff.Days / 30}个月前";
            else
                return $"{diff.Days / 365}年前";
        }

        public static bool IsToday(DateTime dateTime)
        {
            return dateTime.Date == DateTime.Today;
        }

        public static bool IsYesterday(DateTime dateTime)
        {
            return dateTime.Date == DateTime.Today.AddDays(-1);
        }

        public static bool IsThisWeek(DateTime dateTime)
        {
            var startOfWeek = DateTime.Today.AddDays(-(int)DateTime.Today.DayOfWeek);
            var endOfWeek = startOfWeek.AddDays(7);
            return dateTime >= startOfWeek && dateTime < endOfWeek;
        }

        public static bool IsThisMonth(DateTime dateTime)
        {
            return dateTime.Year == DateTime.Now.Year && dateTime.Month == DateTime.Now.Month;
        }

        public static bool IsThisYear(DateTime dateTime)
        {
            return dateTime.Year == DateTime.Now.Year;
        }
    }

    public static class ValidationHelper
    {
        public static bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        public static bool IsValidIPAddress(string ipAddress)
        {
            return System.Net.IPAddress.TryParse(ipAddress, out _);
        }

        public static bool IsValidUrl(string url)
        {
            return Uri.TryCreate(url, UriKind.Absolute, out _);
        }

        public static bool IsValidFilePath(string filePath)
        {
            try
            {
                Path.GetFullPath(filePath);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool IsValidFileName(string fileName)
        {
            string invalidChars = new string(Path.GetInvalidFileNameChars());
            return !fileName.Any(c => invalidChars.Contains(c));
        }

        public static bool IsValidDirectoryPath(string directoryPath)
        {
            try
            {
                Directory.GetParent(directoryPath);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool IsValidPort(int port)
        {
            return port >= 1 && port <= 65535;
        }

        public static bool IsValidProcessId(int processId)
        {
            try
            {
                Process.GetProcessById(processId);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public static class CompressionHelper
    {
        public static void CompressFile(string sourceFile, string compressedFile)
        {
            using (var sourceStream = new FileStream(sourceFile, FileMode.Open))
            using (var targetStream = File.Create(compressedFile))
            using (var gzipStream = new System.IO.Compression.GZipStream(targetStream, System.IO.Compression.CompressionMode.Compress))
            {
                sourceStream.CopyTo(gzipStream);
            }
        }

        public static void DecompressFile(string compressedFile, string targetFile)
        {
            using (var sourceStream = new FileStream(compressedFile, FileMode.Open))
            using (var targetStream = File.Create(targetFile))
            using (var gzipStream = new System.IO.Compression.GZipStream(sourceStream, System.IO.Compression.CompressionMode.Decompress))
            {
                gzipStream.CopyTo(targetStream);
            }
        }

        public static byte[] CompressBytes(byte[] data)
        {
            using (var memoryStream = new MemoryStream())
            using (var gzipStream = new System.IO.Compression.GZipStream(memoryStream, System.IO.Compression.CompressionMode.Compress))
            {
                gzipStream.Write(data, 0, data.Length);
                gzipStream.Flush();
                return memoryStream.ToArray();
            }
        }

        public static byte[] DecompressBytes(byte[] compressedData)
        {
            using (var memoryStream = new MemoryStream(compressedData))
            using (var gzipStream = new System.IO.Compression.GZipStream(memoryStream, System.IO.Compression.CompressionMode.Decompress))
            using (var outputStream = new MemoryStream())
            {
                gzipStream.CopyTo(outputStream);
                return outputStream.ToArray();
            }
        }

        public static void CompressDirectory(string sourceDirectory, string compressedFile)
        {
            System.IO.Compression.ZipFile.CreateFromDirectory(sourceDirectory, compressedFile);
        }

        public static void ExtractArchive(string archiveFile, string targetDirectory)
        {
            System.IO.Compression.ZipFile.ExtractToDirectory(archiveFile, targetDirectory);
        }
    }

    public static class CryptoHashHelper
    {
        public static string GetMD5Hash(string input)
        {
            using (var md5 = MD5.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hash = md5.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        public static string GetSHA1Hash(string input)
        {
            using (var sha1 = SHA1.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hash = sha1.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        public static string GetSHA256Hash(string input)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hash = sha256.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        public static string GetSHA512Hash(string input)
        {
            using (var sha512 = SHA512.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hash = sha512.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        public static string GetFileMD5(string filePath)
        {
            using (var md5 = MD5.Create())
            using (var stream = File.OpenRead(filePath))
            {
                var hash = md5.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        public static string GetFileSHA1(string filePath)
        {
            using (var sha1 = SHA1.Create())
            using (var stream = File.OpenRead(filePath))
            {
                var hash = sha1.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        public static string GetFileSHA256(string filePath)
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        public static string GetFileSHA512(string filePath)
        {
            using (var sha512 = SHA512.Create())
            using (var stream = File.OpenRead(filePath))
            {
                var hash = sha512.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }
    }

    public static class RegexHelper
    {
        public static bool IsMatch(string input, string pattern)
        {
            return System.Text.RegularExpressions.Regex.IsMatch(input, pattern);
        }

        public static string[] Matches(string input, string pattern)
        {
            var matches = System.Text.RegularExpressions.Regex.Matches(input, pattern);
            var result = new string[matches.Count];
            for (int i = 0; i < matches.Count; i++)
            {
                result[i] = matches[i].Value;
            }
            return result;
        }

        public static string Replace(string input, string pattern, string replacement)
        {
            return System.Text.RegularExpressions.Regex.Replace(input, pattern, replacement);
        }

        public static string Extract(string input, string pattern)
        {
            var match = System.Text.RegularExpressions.Regex.Match(input, pattern);
            return match.Success ? match.Value : string.Empty;
        }

        public static bool IsValidPhoneNumber(string phone)
        {
            return IsMatch(phone, @"^\d{10,15}$");
        }

        public static bool IsValidCreditCard(string cardNumber)
        {
            return IsMatch(cardNumber, @"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})$");
        }

        public static bool IsValidSocialSecurityNumber(string ssn)
        {
            return IsMatch(ssn, @"^\d{3}-?\d{2}-?\d{4}$");
        }
    }

    public static class ReflectionHelper
    {
        public static object CreateInstance(string typeName)
        {
            var type = Type.GetType(typeName);
            return type != null ? Activator.CreateInstance(type) : null;
        }

        public static object CreateInstance(Type type, params object[] parameters)
        {
            return Activator.CreateInstance(type, parameters);
        }

        public static T CreateInstance<T>(params object[] parameters)
        {
            return (T)Activator.CreateInstance(typeof(T), parameters);
        }

        public static MethodInfo GetMethod(Type type, string methodName)
        {
            return type.GetMethod(methodName);
        }

        public static MethodInfo GetMethod(Type type, string methodName, Type[] parameterTypes)
        {
            return type.GetMethod(methodName, parameterTypes);
        }

        public static object InvokeMethod(object instance, string methodName, params object[] parameters)
        {
            var method = instance.GetType().GetMethod(methodName);
            return method?.Invoke(instance, parameters);
        }

        public static T InvokeMethod<T>(object instance, string methodName, params object[] parameters)
        {
            var result = InvokeMethod(instance, methodName, parameters);
            return result != null ? (T)result : default(T);
        }

        public static PropertyInfo GetProperty(Type type, string propertyName)
        {
            return type.GetProperty(propertyName);
        }

        public static object GetPropertyValue(object instance, string propertyName)
        {
            var property = instance.GetType().GetProperty(propertyName);
            return property?.GetValue(instance);
        }

        public static void SetPropertyValue(object instance, string propertyName, object value)
        {
            var property = instance.GetType().GetProperty(propertyName);
            property?.SetValue(instance, value);
        }

        public static FieldInfo GetField(Type type, string fieldName)
        {
            return type.GetField(fieldName);
        }

        public static object GetFieldValue(object instance, string fieldName)
        {
            var field = instance.GetType().GetField(fieldName);
            return field?.GetValue(instance);
        }

        public static void SetFieldValue(object instance, string fieldName, object value)
        {
            var field = instance.GetType().GetField(fieldName);
            field?.SetValue(instance, value);
        }

        public static Type[] GetTypesInAssembly(Assembly assembly)
        {
            try
            {
                return assembly.GetTypes();
            }
            catch
            {
                return new Type[0];
            }
        }

        public static Type[] GetTypesInNamespace(Assembly assembly, string namespaceName)
        {
            return GetTypesInAssembly(assembly).Where(t => t.Namespace == namespaceName).ToArray();
        }

        public static IEnumerable<Type> GetTypesAssignableFrom<T>(Assembly assembly)
        {
            return GetTypesInAssembly(assembly).Where(t => typeof(T).IsAssignableFrom(t) && t != typeof(T));
        }
    }

    public static class ParallelHelper
    {
        public static void ForEachParallel<T>(IEnumerable<T> source, Action<T> action)
        {
            Parallel.ForEach(source, action);
        }

        public static void ForEachParallel<T>(IEnumerable<T> source, Action<T, ParallelLoopState, long> action)
        {
            Parallel.ForEach(source, action);
        }

        public static void ForParallel(int fromInclusive, int toExclusive, Action<int> body)
        {
            Parallel.For(fromInclusive, toExclusive, body);
        }

        public static void ForParallel(int fromInclusive, int toExclusive, Action<int, ParallelLoopState> body)
        {
            Parallel.For(fromInclusive, toExclusive, body);
        }

        public static TResult[] InvokeParallel<TResult>(params Func<TResult>[] functions)
        {
            return Task.WhenAll(functions.Select(f => Task.Run(f))).Result;
        }

        public static void InvokeParallel(params Action[] actions)
        {
            Parallel.Invoke(actions);
        }

        public static Task<T> RunAsync<T>(Func<T> function)
        {
            return Task.Run(function);
        }

        public static Task RunAsync(Action action)
        {
            return Task.Run(action);
        }

        public static Task<T> RunAsync<T>(Func<Task<T>> function)
        {
            return Task.Run(function);
        }

        public static Task RunAsync(Func<Task> function)
        {
            return Task.Run(function);
        }
    }

    public static class CacheHelper
    {
        private static readonly Dictionary<string, CacheItem> cache = new Dictionary<string, CacheItem>();
        private static readonly object cacheLock = new object();

        private class CacheItem
        {
            public object Value { get; set; }
            public DateTime Expiry { get; set; }
            public bool IsSliding { get; set; }
            public TimeSpan SlidingExpiry { get; set; }
        }

        public static void Set(string key, object value, TimeSpan expiry)
        {
            lock (cacheLock)
            {
                cache[key] = new CacheItem
                {
                    Value = value,
                    Expiry = DateTime.Now.Add(expiry),
                    IsSliding = false
                };
                CleanExpiredItems();
            }
        }

        public static void SetSliding(string key, object value, TimeSpan slidingExpiry)
        {
            lock (cacheLock)
            {
                cache[key] = new CacheItem
                {
                    Value = value,
                    Expiry = DateTime.Now.Add(slidingExpiry),
                    IsSliding = true,
                    SlidingExpiry = slidingExpiry
                };
                CleanExpiredItems();
            }
        }

        public static object Get(string key)
        {
            lock (cacheLock)
            {
                if (cache.TryGetValue(key, out var item))
                {
                    if (item.Expiry > DateTime.Now)
                    {
                        if (item.IsSliding)
                        {
                            item.Expiry = DateTime.Now.Add(item.SlidingExpiry);
                        }
                        return item.Value;
                    }
                    else
                    {
                        cache.Remove(key);
                    }
                }
                return null;
            }
        }

        public static T Get<T>(string key)
        {
            var value = Get(key);
            return value != null ? (T)value : default(T);
        }

        public static bool Contains(string key)
        {
            lock (cacheLock)
            {
                return cache.ContainsKey(key);
            }
        }

        public static void Remove(string key)
        {
            lock (cacheLock)
            {
                cache.Remove(key);
            }
        }

        public static void Clear()
        {
            lock (cacheLock)
            {
                cache.Clear();
            }
        }

        public static int Count
        {
            get
            {
                lock (cacheLock)
                {
                    CleanExpiredItems();
                    return cache.Count;
                }
            }
        }

        private static void CleanExpiredItems()
        {
            var expiredKeys = cache.Where(kv => kv.Value.Expiry <= DateTime.Now).Select(kv => kv.Key).ToArray();
            foreach (var key in expiredKeys)
            {
                cache.Remove(key);
            }
        }
    }

    public static class ThreadHelper
    {
        public static void StartThread(Action action)
        {
            var thread = new Thread(new ThreadStart(action));
            thread.Start();
        }

        public static void StartThread(ParameterizedThreadStart action, object parameter)
        {
            var thread = new Thread(action);
            thread.Start(parameter);
        }

        public static Thread StartBackgroundThread(Action action)
        {
            var thread = new Thread(new ThreadStart(action));
            thread.IsBackground = true;
            thread.Start();
            return thread;
        }

        public static Thread StartBackgroundThread(ParameterizedThreadStart action, object parameter)
        {
            var thread = new Thread(action);
            thread.IsBackground = true;
            thread.Start(parameter);
            return thread;
        }

        public static void Sleep(int milliseconds)
        {
            Thread.Sleep(milliseconds);
        }

        public static void Sleep(TimeSpan timeSpan)
        {
            Thread.Sleep(timeSpan);
        }

        public static void Yield()
        {
            Thread.Yield();
        }

        public static void SpinWait(int iterations)
        {
            Thread.SpinWait(iterations);
        }

        public static void WaitAll(params WaitHandle[] waitHandles)
        {
            WaitHandle.WaitAll(waitHandles);
        }

        public static void WaitAll(int millisecondsTimeout, params WaitHandle[] waitHandles)
        {
            WaitHandle.WaitAll(waitHandles, millisecondsTimeout);
        }

        public static bool WaitAny(params WaitHandle[] waitHandles)
        {
            return WaitHandle.WaitAny(waitHandles) >= 0;
        }

        public static bool WaitAny(int millisecondsTimeout, params WaitHandle[] waitHandles)
        {
            return WaitHandle.WaitAny(waitHandles, millisecondsTimeout) >= 0;
        }
    }

    public static class ResourceHelper
    {
        public static string GetStringResource(Assembly assembly, string resourceName)
        {
            using (var stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream != null)
                {
                    using (var reader = new StreamReader(stream))
                    {
                        return reader.ReadToEnd();
                    }
                }
                return string.Empty;
            }
        }

        public static byte[] GetBinaryResource(Assembly assembly, string resourceName)
        {
            using (var stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream != null)
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        stream.CopyTo(memoryStream);
                        return memoryStream.ToArray();
                    }
                }
                return new byte[0];
            }
        }

        public static Stream GetResourceStream(Assembly assembly, string resourceName)
        {
            return assembly.GetManifestResourceStream(resourceName);
        }

        public static string[] GetResourceNames(Assembly assembly)
        {
            return assembly.GetManifestResourceNames();
        }

        public static string[] GetResourceNames(Assembly assembly, string pattern)
        {
            return assembly.GetManifestResourceNames().Where(name => name.Contains(pattern)).ToArray();
        }
    }

    public static class MonitoringHelper
    {
        private static readonly Dictionary<string, PerformanceCounter> counters = new Dictionary<string, PerformanceCounter>();
        private static readonly object counterLock = new object();

        public static void CreateCounter(string categoryName, string counterName, string instanceName = "")
        {
            lock (counterLock)
            {
                var key = $"{categoryName}:{counterName}:{instanceName}";
                if (!counters.ContainsKey(key))
                {
                    counters[key] = new PerformanceCounter(categoryName, counterName, instanceName, false);
                }
            }
        }

        public static void IncrementCounter(string categoryName, string counterName, string instanceName = "")
        {
            lock (counterLock)
            {
                var key = $"{categoryName}:{counterName}:{instanceName}";
                if (counters.TryGetValue(key, out var counter))
                {
                    counter.Increment();
                }
            }
        }

        public static void IncrementCounterBy(string categoryName, string counterName, long value, string instanceName = "")
        {
            lock (counterLock)
            {
                var key = $"{categoryName}:{counterName}:{instanceName}";
                if (counters.TryGetValue(key, out var counter))
                {
                    counter.IncrementBy(value);
                }
            }
        }

        public static void SetCounterValue(string categoryName, string counterName, float value, string instanceName = "")
        {
            lock (counterLock)
            {
                var key = $"{categoryName}:{counterName}:{instanceName}";
                if (counters.TryGetValue(key, out var counter))
                {
                    counter.RawValue = (long)value;
                }
            }
        }

        public static float GetCounterValue(string categoryName, string counterName, string instanceName = "")
        {
            lock (counterLock)
            {
                var key = $"{categoryName}:{counterName}:{instanceName}";
                if (counters.TryGetValue(key, out var counter))
                {
                    return counter.NextValue();
                }
                return 0;
            }
        }

        public static void RemoveCounter(string categoryName, string counterName, string instanceName = "")
        {
            lock (counterLock)
            {
                var key = $"{categoryName}:{counterName}:{instanceName}";
                counters.Remove(key);
            }
        }

        public static void ClearCounters()
        {
            lock (counterLock)
            {
                counters.Clear();
            }
        }
    }

    public static class I18nHelper
    {
        private static readonly Dictionary<string, Dictionary<string, string>> translations = new Dictionary<string, Dictionary<string, string>>();
        private static string currentLanguage = "en";

        public static void LoadTranslations(string language, string filePath)
        {
            if (File.Exists(filePath))
            {
                var json = File.ReadAllText(filePath);
                var langTranslations = SerializationHelper.Deserialize<Dictionary<string, string>>(json);
                if (langTranslations != null)
                {
                    translations[language] = langTranslations;
                }
            }
        }

        public static void LoadTranslations(string language, Dictionary<string, string> langTranslations)
        {
            translations[language] = langTranslations;
        }

        public static string GetString(string key)
        {
            return GetString(key, currentLanguage);
        }

        public static string GetString(string key, string language)
        {
            if (translations.TryGetValue(language, out var langTranslations) && langTranslations.TryGetValue(key, out var value))
            {
                return value;
            }
            return key;
        }

        public static string GetString(string key, params object[] args)
        {
            return string.Format(GetString(key), args);
        }

        public static string GetString(string key, string language, params object[] args)
        {
            return string.Format(GetString(key, language), args);
        }

        public static void SetCurrentLanguage(string language)
        {
            currentLanguage = language;
        }

        public static string CurrentLanguage
        {
            get { return currentLanguage; }
        }

        public static string[] AvailableLanguages
        {
            get { return translations.Keys.ToArray(); }
        }
    }

    public static class SecurityHelper
    {
        public static bool IsRunningAsAdmin()
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        public static bool IsRunningAsSystem()
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }

        public static bool HasPermission(string filePath, FileSystemRights rights)
        {
            try
            {
                // 尝试打开文件来检查权限
                using (var stream = System.IO.File.Open(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool CanAccess(string filePath)
        {
            try
            {
                using (var stream = File.Open(filePath, FileMode.Open, FileAccess.Read))
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool CanWrite(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    using (var stream = File.Open(filePath, FileMode.Open, FileAccess.Write))
                    {
                        return true;
                    }
                }
                else
                {
                    using (var stream = File.Create(filePath))
                    {
                        stream.Close();
                        File.Delete(filePath);
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        public static bool CanDelete(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    File.Create(filePath).Close();
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }

    public static class DatabaseHelper
    {
        public static string GetConnectionString(string server, string database, string username, string password)
        {
            return $"Server={server};Database={database};User Id={username};Password={password};";
        }

        public static string GetConnectionString(string server, string database)
        {
            return $"Server={server};Database={database};Integrated Security=True;";
        }

        public static string GetSqliteConnectionString(string filePath)
        {
            return $"Data Source={filePath};Version=3;";
        }

        public static string GetMySqlConnectionString(string server, string database, string username, string password)
        {
            return $"Server={server};Database={database};Uid={username};Pwd={password};";
        }

        public static string GetPostgreSqlConnectionString(string server, string database, string username, string password)
        {
            return $"Host={server};Database={database};Username={username};Password={password};";
        }

        public static IDbConnection CreateConnection(string connectionString)
        {
            return new System.Data.SqlClient.SqlConnection(connectionString);
        }

        public static IDbConnection CreateSqliteConnection(string filePath)
        {
            // 耄耋软件工作室 开发，严禁非法反编译
            // 使用反射创建SQLiteConnection，避免直接依赖
            var assembly = Assembly.LoadFrom(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "System.Data.SQLite.dll"));
            var connectionType = assembly.GetType("System.Data.SQLite.SQLiteConnection");
            var connection = Activator.CreateInstance(connectionType, GetSqliteConnectionString(filePath)) as IDbConnection;
            return connection;
        }

        public static void ExecuteNonQuery(IDbConnection connection, string sql, params IDbDataParameter[] parameters)
        {
            using (var command = connection.CreateCommand())
            {
                command.CommandText = sql;
                if (parameters != null)
                {
                    foreach (var param in parameters)
                    {
                        command.Parameters.Add(param);
                    }
                }
                command.ExecuteNonQuery();
            }
        }

        public static object ExecuteScalar(IDbConnection connection, string sql, params IDbDataParameter[] parameters)
        {
            using (var command = connection.CreateCommand())
            {
                command.CommandText = sql;
                if (parameters != null)
                {
                    foreach (var param in parameters)
                    {
                        command.Parameters.Add(param);
                    }
                }
                return command.ExecuteScalar();
            }
        }

        public static IDataReader ExecuteReader(IDbConnection connection, string sql, params IDbDataParameter[] parameters)
        {
            using (var command = connection.CreateCommand())
            {
                command.CommandText = sql;
                if (parameters != null)
                {
                    foreach (var param in parameters)
                    {
                        command.Parameters.Add(param);
                    }
                }
                return command.ExecuteReader();
            }
        }
    }

    public static class InstallationHelper
    {
        public static bool InstallService(string serviceName, string displayName, string description, string executablePath, ServiceStartMode startMode = ServiceStartMode.Automatic)
        {
            try
            {
                // 检查现有服务并卸载
                using (var service = System.ServiceProcess.ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == serviceName))
                {
                    if (service != null)
                    {
                        if (service.Status != System.ServiceProcess.ServiceControllerStatus.Stopped)
                        {
                            service.Stop();
                            service.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        }
                        // 使用sc命令卸载服务
                        var process = new Process();
                        process.StartInfo.FileName = "sc";
                        process.StartInfo.Arguments = $"delete {serviceName}";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.StartInfo.RedirectStandardError = true;
                        process.Start();
                        process.WaitForExit();
                }
            }

            // 使用sc命令安装服务
            var installProcess = new Process();
            installProcess.StartInfo.FileName = "sc";
            installProcess.StartInfo.Arguments = $"create {serviceName} binPath= \"{executablePath}\" start= auto displayname= \"{serviceName}\"";
            installProcess.StartInfo.UseShellExecute = false;
            installProcess.StartInfo.RedirectStandardOutput = true;
            installProcess.StartInfo.RedirectStandardError = true;
            installProcess.Start();
            installProcess.WaitForExit();

            using (var newService = new System.ServiceProcess.ServiceController(serviceName))
            {
                newService.Start();
                newService.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                return true;
            }
        }
        catch
        {
            return false;
        }
    }

        public static bool UninstallService(string serviceName)
        {
            try
            {
                using (var service = System.ServiceProcess.ServiceController.GetServices().FirstOrDefault(s => s.ServiceName == serviceName))
                {
                    if (service != null)
                    {
                        try
                        {
                            if (service.Status != System.ServiceProcess.ServiceControllerStatus.Stopped)
                            {
                                service.Stop();
                                service.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                            }
                            // 使用sc命令卸载服务
                            var process = new Process();
                            process.StartInfo.FileName = "sc";
                            process.StartInfo.Arguments = $"delete {serviceName}";
                            process.StartInfo.UseShellExecute = false;
                            process.StartInfo.RedirectStandardOutput = true;
                            process.StartInfo.RedirectStandardError = true;
                            process.Start();
                            process.WaitForExit();
                            return true;
                        }
                        catch
                        {
                            return false;
                        }
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public static bool RegisterComObject(Type type, string progId)
        {
            try
            {
                var regasmPath = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "RegAsm.exe");
                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = regasmPath,
                    Arguments = $"/codebase /tlb:{type.Assembly.Location}.tlb {type.Assembly.Location}",
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                });
                process.WaitForExit();
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        public static bool UnregisterComObject(Type type)
        {
            try
            {
                var regasmPath = Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "RegAsm.exe");
                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = regasmPath,
                    Arguments = $"/u {type.Assembly.Location}",
                    Verb = "runas",
                    UseShellExecute = true,
                    CreateNoWindow = true
                });
                process.WaitForExit();
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }
    }

    public static class UninstallationHelper
    {
        public static void RemoveFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    File.SetAttributes(filePath, FileAttributes.Normal);
                    File.Delete(filePath);
                }
            }
            catch
            {
            }
        }

        public static void RemoveDirectory(string directoryPath)
        {
            try
            {
                if (Directory.Exists(directoryPath))
                {
                    Directory.Delete(directoryPath, true);
                }
            }
            catch
            {
            }
        }

        public static void RemoveRegistryKey(string keyPath)
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath, true) ?? Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree("", false);
                    }
                }
            }
            catch
            {
            }
        }

        public static void RemoveRegistryValue(string keyPath, string valueName)
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath, true) ?? Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, true))
                {
                    if (key != null)
                    {
                        key.DeleteValue(valueName, false);
                    }
                }
            }
            catch
            {
            }
        }

        public static void RemoveService(string serviceName)
        {
            InstallationHelper.UninstallService(serviceName);
        }

        public static void RemoveScheduledTask(string taskName)
        {
            try
            {
                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/delete /tn {taskName} /f",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                process?.WaitForExit();
            }
            catch
            {
            }
        }
    }

    public static class UpgradeHelper
    {
        public static bool CheckForUpdates(string updateUrl, out string latestVersion, out string downloadUrl)
        {
            try
            {
                var json = NetworkHelper.DownloadString(updateUrl);
                var updateInfo = SerializationHelper.Deserialize<Dictionary<string, string>>(json);
                if (updateInfo != null && updateInfo.TryGetValue("version", out latestVersion) && updateInfo.TryGetValue("downloadUrl", out downloadUrl))
                {
                    var currentVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
                    return new Version(latestVersion) > new Version(currentVersion);
                }
            }
            catch
            {
            }
            latestVersion = string.Empty;
            downloadUrl = string.Empty;
            return false;
        }

        public static bool DownloadUpdate(string downloadUrl, string targetPath)
        {
            try
            {
                NetworkHelper.DownloadFile(downloadUrl, targetPath);
                return File.Exists(targetPath);
            }
            catch
            {
                return false;
            }
        }

        public static bool InstallUpdate(string updateFilePath)
        {
            try
            {
                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = updateFilePath,
                    Arguments = "/silent /norestart",
                    UseShellExecute = true
                });
                process?.WaitForExit();
                return process?.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        public static bool BackupCurrentVersion(string backupPath)
        {
            try
            {
                var currentPath = Assembly.GetExecutingAssembly().Location;
                var directory = Path.GetDirectoryName(currentPath);
                CompressionHelper.CompressDirectory(directory, backupPath);
                return File.Exists(backupPath);
            }
            catch
            {
                return false;
            }
        }
    }

    public static class BackupHelper
    {
        public static void BackupFile(string sourceFile, string backupDirectory)
        {
            try
            {
                if (File.Exists(sourceFile))
                {
                    Directory.CreateDirectory(backupDirectory);
                    var backupFile = Path.Combine(backupDirectory, $"{Path.GetFileName(sourceFile)}.{DateTime.Now:yyyyMMddHHmmss}.bak");
                    File.Copy(sourceFile, backupFile, true);
                }
            }
            catch
            {
            }
        }

        public static void BackupDirectory(string sourceDirectory, string backupDirectory)
        {
            try
            {
                if (Directory.Exists(sourceDirectory))
                {
                    Directory.CreateDirectory(backupDirectory);
                    var backupFile = Path.Combine(backupDirectory, $"backup.{DateTime.Now:yyyyMMddHHmmss}.zip");
                    CompressionHelper.CompressDirectory(sourceDirectory, backupFile);
                }
            }
            catch
            {
            }
        }

        public static void BackupRegistry(string keyPath, string backupFile)
        {
            try
            {
                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = "reg.exe",
                    Arguments = $"export {keyPath} {backupFile} /y",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                process?.WaitForExit();
            }
            catch
            {
            }
        }

        public static void BackupDatabase(string connectionString, string backupFile)
        {
            try
            {
                using (var connection = DatabaseHelper.CreateConnection(connectionString))
                {
                    connection.Open();
                    var databaseName = new System.Data.SqlClient.SqlConnectionStringBuilder(connectionString).InitialCatalog;
                    var sql = $"BACKUP DATABASE [{databaseName}] TO DISK = '{backupFile}' WITH INIT";
                    DatabaseHelper.ExecuteNonQuery(connection, sql);
                }
            }
            catch
            {
            }
        }

        public static string[] GetBackupFiles(string backupDirectory, string pattern = "*")
        {
            try
            {
                return Directory.GetFiles(backupDirectory, pattern);
            }
            catch
            {
                return new string[0];
            }
        }

        public static void CleanupOldBackups(string backupDirectory, int daysToKeep)
        {
            try
            {
                var cutoffDate = DateTime.Now.AddDays(-daysToKeep);
                foreach (var file in Directory.GetFiles(backupDirectory))
                {
                    var fileInfo = new FileInfo(file);
                    if (fileInfo.LastWriteTime < cutoffDate)
                    {
                        File.Delete(file);
                    }
                }
            }
            catch
            {
            }
        }
    }

    public static class RestoreHelper
    {
        public static bool RestoreFile(string backupFile, string targetFile)
        {
            try
            {
                if (File.Exists(backupFile))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(targetFile));
                    File.Copy(backupFile, targetFile, true);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public static bool RestoreDirectory(string backupFile, string targetDirectory)
        {
            try
            {
                if (File.Exists(backupFile))
                {
                    Directory.CreateDirectory(targetDirectory);
                    CompressionHelper.ExtractArchive(backupFile, targetDirectory);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public static bool RestoreRegistry(string backupFile)
        {
            try
            {
                if (File.Exists(backupFile))
                {
                    var process = Process.Start(new ProcessStartInfo
                    {
                        FileName = "reg.exe",
                        Arguments = $"import {backupFile}",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                    process?.WaitForExit();
                    return process?.ExitCode == 0;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public static bool RestoreDatabase(string connectionString, string backupFile)
        {
            try
            {
                using (var connection = DatabaseHelper.CreateConnection(connectionString))
                {
                    connection.Open();
                    var databaseName = new System.Data.SqlClient.SqlConnectionStringBuilder(connectionString).InitialCatalog;
                    var sql = $"RESTORE DATABASE [{databaseName}] FROM DISK = '{backupFile}' WITH REPLACE";
                    DatabaseHelper.ExecuteNonQuery(connection, sql);
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }
    }

    public static class CleanupHelper
    {
        public static void CleanupTemporaryFiles(string tempDirectory = null)
        {
            try
            {
                var directories = new List<string>();
                if (tempDirectory != null)
                {
                    directories.Add(tempDirectory);
                }
                directories.Add(Path.GetTempPath());
                directories.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"));

                foreach (var directory in directories)
                {
                    if (Directory.Exists(directory))
                    {
                        foreach (var file in Directory.GetFiles(directory))
                        {
                            try
                            {
                                File.Delete(file);
                            }
                            catch
                            {
                            }
                        }
                        foreach (var subDir in Directory.GetDirectories(directory))
                        {
                            try
                            {
                                Directory.Delete(subDir, true);
                            }
                            catch
                            {
                            }
                        }
                    }
                }
            }
            catch
            {
            }
        }

        public static void CleanupLogFiles(string logDirectory, int daysToKeep = 7)
        {
            try
            {
                if (Directory.Exists(logDirectory))
                {
                    var cutoffDate = DateTime.Now.AddDays(-daysToKeep);
                    foreach (var file in Directory.GetFiles(logDirectory, "*.log"))
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.LastWriteTime < cutoffDate)
                        {
                            File.Delete(file);
                        }
                    }
                }
            }
            catch
            {
            }
        }

        public static void CleanupBackupFiles(string backupDirectory, int daysToKeep = 30)
        {
            BackupHelper.CleanupOldBackups(backupDirectory, daysToKeep);
        }

        public static void CleanupRegistry(string keyPath)
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(keyPath, true) ?? Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, true))
                {
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            try
                            {
                                key.DeleteValue(valueName);
                            }
                            catch
                            {
                            }
                        }
                    }
                }
            }
            catch
            {
            }
        }

        public static void CleanupInternetCache()
        {
            try
            {
                var cachePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.InternetCache), "Content.IE5");
                if (Directory.Exists(cachePath))
                {
                    foreach (var file in Directory.GetFiles(cachePath, "*", SearchOption.AllDirectories))
                    {
                        try
                        {
                            File.Delete(file);
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch
            {
            }
        }
    }

    public static class DiagnosticHelper
    {
        public static Dictionary<string, object> GetSystemInfo()
        {
            var info = new Dictionary<string, object>
            {
                { "OSVersion", SystemHelper.GetOSVersion() },
                { "Architecture", SystemHelper.GetOSArchitecture() },
                { "ProcessorCount", SystemHelper.GetProcessorCount() },
                { "ComputerName", SystemHelper.GetComputerName() },
                { "UserName", SystemHelper.GetUserName() },
                { "DomainName", SystemHelper.GetDomainName() },
                { "TotalMemory", SystemHelper.GetTotalMemory() },
                { "AvailableMemory", PerformanceHelper.GetAvailableMemory() },
                { "CpuUsage", PerformanceHelper.GetCpuUsage() },
                { "MemoryUsage", PerformanceHelper.GetMemoryUsage() }
            };
            return info;
        }

        public static Dictionary<string, object> GetApplicationInfo()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var info = new Dictionary<string, object>
            {
                { "ApplicationName", assembly.GetName().Name },
                { "Version", assembly.GetName().Version.ToString() },
                { "Description", assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyDescriptionAttribute), false).Cast<System.Reflection.AssemblyDescriptionAttribute>().FirstOrDefault()?.Description },
                { "Company", assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyCompanyAttribute), false).Cast<System.Reflection.AssemblyCompanyAttribute>().FirstOrDefault()?.Company },
                { "Product", assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyProductAttribute), false).Cast<System.Reflection.AssemblyProductAttribute>().FirstOrDefault()?.Product },
                { "Location", assembly.Location },
                { "WorkingDirectory", Environment.CurrentDirectory }
            };
            return info;
        }

        public static Dictionary<string, object> GetNetworkInfo()
        {
            var info = new Dictionary<string, object>
            {
                { "IsInternetAvailable", NetworkHelper.IsInternetAvailable() },
                { "PublicIP", NetworkHelper.GetPublicIP() },
                { "HostName", Dns.GetHostName() }
            };

            try
            {
                var addresses = Dns.GetHostAddresses(Dns.GetHostName());
                info["IPAddresses"] = addresses.Select(a => a.ToString()).ToArray();
            }
            catch
            {
                info["IPAddresses"] = new string[0];
            }

            return info;
        }

        public static string GenerateDiagnosticReport()
        {
            var report = new StringBuilder();
            report.AppendLine("=== System Information ===");
            foreach (var kv in GetSystemInfo())
            {
                report.AppendLine($"{kv.Key}: {kv.Value}");
            }

            report.AppendLine();
            report.AppendLine("=== Application Information ===");
            foreach (var kv in GetApplicationInfo())
            {
                report.AppendLine($"{kv.Key}: {kv.Value}");
            }

            report.AppendLine();
            report.AppendLine("=== Network Information ===");
            foreach (var kv in GetNetworkInfo())
            {
                report.AppendLine($"{kv.Key}: {kv.Value}");
            }

            report.AppendLine();
            report.AppendLine("=== Process Information ===");
            var processes = SystemHelper.GetRunningProcesses().Take(20);
            foreach (var process in processes)
            {
                report.AppendLine($"{process.ProcessName} (PID: {process.Id}, Memory: {process.WorkingSet64 / 1024 / 1024} MB)");
            }

            return report.ToString();
        }

        public static void SaveDiagnosticReport(string filePath)
        {
            var report = GenerateDiagnosticReport();
            File.WriteAllText(filePath, report);
        }
    }

    public static class ReportHelper
    {
        public static void GenerateSystemReport(string filePath)
        {
            var report = DiagnosticHelper.GenerateDiagnosticReport();
            File.WriteAllText(filePath, report);
        }

        public static void GenerateLogReport(string logDirectory, string filePath)
        {
            var report = new StringBuilder();
            report.AppendLine("=== Log Report ===");
            report.AppendLine($"Report Time: {DateTime.Now}");
            report.AppendLine();

            foreach (var logFile in Directory.GetFiles(logDirectory, "*.log").OrderByDescending(f => new FileInfo(f).LastWriteTime))
            {
                report.AppendLine($"=== Log File: {Path.GetFileName(logFile)} ===");
                report.AppendLine($"Last Modified: {new FileInfo(logFile).LastWriteTime}");
                report.AppendLine();
                try
                {
                    var content = File.ReadAllText(logFile);
                    report.AppendLine(content);
                }
                catch
                {
                    report.AppendLine("Unable to read log file");
                }
                report.AppendLine();
            }

            File.WriteAllText(filePath, report.ToString());
        }

        public static void GenerateQuarantineReport(string quarantineDirectory, string filePath)
        {
            var report = new StringBuilder();
            report.AppendLine("=== Quarantine Report ===");
            report.AppendLine($"Report Time: {DateTime.Now}");
            report.AppendLine();

            if (Directory.Exists(quarantineDirectory))
            {
                foreach (var file in Directory.GetFiles(quarantineDirectory))
                {
                    var fileInfo = new FileInfo(file);
                    report.AppendLine($"File: {Path.GetFileName(file)}");
                    report.AppendLine($"Size: {FormatFileSize(fileInfo.Length)}");
                    report.AppendLine($"Quarantined: {fileInfo.CreationTime}");
                    report.AppendLine();
                }
            }

            File.WriteAllText(filePath, report.ToString());
        }

    public static string FormatFileSize(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        double len = bytes;
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len = len / 1024;
        }
        return $"{len:0.##} {sizes[order]}";
    }
}

}



