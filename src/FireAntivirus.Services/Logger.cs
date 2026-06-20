using System;

namespace FireAntivirus.Services
{
    public static class Logger
    {
        public static void Info(string message)
        {
            Console.WriteLine($"[INFO] {DateTime.Now}: {message}");
        }

        public static void Warning(string message)
        {
            Console.WriteLine($"[WARNING] {DateTime.Now}: {message}");
        }

        public static void Error(string message)
        {
            Console.WriteLine($"[ERROR] {DateTime.Now}: {message}");
        }
    }
}