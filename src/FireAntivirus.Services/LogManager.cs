using System;
using System.IO;
using System.Text;
using System.Threading;

namespace FireAntivirus.Services
{
    /// <summary>
    /// 日志级别
    /// </summary>
    public enum LogLevel
    {
        Trace,
        Debug,
        Info,
        Warning,
        Error,
        Critical,
        Fatal
    }

    /// <summary>
    /// 日志管理器
    /// </summary>
    public static class LogManager
    {
        private static string _logDirectory;
        private static string _logFile;
        private static readonly object _lock = new object();
        private static bool _initialized;

        /// <summary>
        /// 初始化日志管理器
        /// </summary>
        public static void Initialize()
        {
            if (_initialized)
            {
                return;
            }

            lock (_lock)
            {
                if (_initialized)
                {
                    return;
                }

                // 创建日志目录
                _logDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
                if (!Directory.Exists(_logDirectory))
                {
                    Directory.CreateDirectory(_logDirectory);
                }

                // 创建日志文件
                string date = DateTime.Now.ToString("yyyy-MM-dd");
                _logFile = Path.Combine(_logDirectory, $"fireantivirus_{date}.log");

                _initialized = true;
                LogInfo("Log manager initialized");
            }
        }

        /// <summary>
        /// 记录调试日志
        /// </summary>
        public static void LogDebug(string message)
        {
            Log(LogLevel.Debug, message);
        }

        /// <summary>
        /// 记录信息日志
        /// </summary>
        public static void LogInfo(string message)
        {
            Log(LogLevel.Info, message);
        }

        /// <summary>
        /// 记录警告日志
        /// </summary>
        public static void LogWarning(string message)
        {
            Log(LogLevel.Warning, message);
        }

        /// <summary>
        /// 记录错误日志
        /// </summary>
        public static void LogError(string message)
        {
            Log(LogLevel.Error, message);
        }

        /// <summary>
        /// 记录致命错误日志
        /// </summary>
        public static void LogFatal(string message)
        {
            Log(LogLevel.Fatal, message);
        }

        /// <summary>
        /// 记录日志
        /// </summary>
        private static void Log(LogLevel level, string message)
        {
            if (!_initialized)
            {
                Initialize();
            }

            try
            {
                lock (_lock)
                {
                    // 检查日志文件大小
                    CheckLogFileSize();

                    // 构建日志消息
                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                    string levelStr = level.ToString().ToUpper();
                    string logMessage = $"[{timestamp}] [{levelStr}] {message}";

                    // 写入日志文件
                    using (StreamWriter writer = new StreamWriter(_logFile, true, Encoding.UTF8))
                    {
                        writer.WriteLine(logMessage);
                    }

                    // 输出到控制台
                    Console.WriteLine(logMessage);
                }
            }
            catch (Exception ex)
            {
                // 日志记录失败，输出到控制台
                Console.WriteLine($"Failed to log message: {ex.Message}");
            }
        }

        /// <summary>
        /// 检查日志文件大小
        /// </summary>
        private static void CheckLogFileSize()
        {
            if (File.Exists(_logFile))
            {
                FileInfo fileInfo = new FileInfo(_logFile);
                // 如果日志文件超过10MB，创建新的日志文件
                if (fileInfo.Length > 10 * 1024 * 1024)
                {
                    string date = DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss");
                    string newLogFile = Path.Combine(_logDirectory, $"fireantivirus_{date}.log");
                    _logFile = newLogFile;
                }
            }
        }

        /// <summary>
        /// 获取日志目录
        /// </summary>
        public static string LogDirectory => _logDirectory;

        /// <summary>
        /// 获取当前日志文件
        /// </summary>
        public static string LogFile => _logFile;
    }
}