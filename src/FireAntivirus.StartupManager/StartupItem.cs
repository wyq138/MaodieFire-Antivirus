using System;
using System.Collections.Generic;

namespace FireAntivirus.StartupManager
{
    public class StartupItem
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string Location { get; set; }
        public bool Enabled { get; set; }
        public string Type { get; set; }
        public string ShortcutPath { get; set; }
        public string ServiceName { get; set; }
        public string RiskLevel { get; set; }
        public DateTime LastModified { get; set; } = DateTime.Now;

        public StartupItem() { }

        public StartupItem(string name, string path, string location, bool enabled, string type)
        {
            Id = Guid.NewGuid().ToString();
            Name = name;
            Path = path;
            Location = location;
            Enabled = enabled;
            Type = type;
        }
    }

    public class StartupAnalysisResult
    {
        public int TotalItems { get; set; }
        public int EnabledItems { get; set; }
        public int DisabledItems { get; set; }
        public List<StartupItem> SuspiciousItems { get; set; } = new List<StartupItem>();
        public List<string> Recommendations { get; set; } = new List<string>();

        public StartupAnalysisResult() { }

        public StartupAnalysisResult(int totalItems, int enabledItems, int disabledItems)
        {
            TotalItems = totalItems;
            EnabledItems = enabledItems;
            DisabledItems = disabledItems;
        }
    }
}