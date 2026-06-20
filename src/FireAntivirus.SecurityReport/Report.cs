using System;
using System.Collections.Generic;

namespace FireAntivirus.SecurityReport
{
    public enum ReportType
    {
        Daily,
        Weekly,
        Monthly,
        Full
    }

    public class ReportSection
    {
        public string Title { get; set; }
        public string Content { get; set; }
        public string Status { get; set; } // Good, Medium, Poor, Critical

        public ReportSection() { }

        public ReportSection(string title, string content, string status)
        {
            Title = title;
            Content = content;
            Status = status;
        }
    }

    public class Report
    {
        public string Id { get; set; }
        public ReportType ReportType { get; set; }
        public DateTime GeneratedAt { get; set; }
        public TimeSpan TimeRange { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string OverallSecurityStatus { get; set; }
        public string Summary { get; set; }
        public List<ReportSection> Sections { get; set; } = new List<ReportSection>();

        public Report() { }

        public Report(ReportType reportType, TimeSpan timeRange)
        {
            Id = Guid.NewGuid().ToString();
            ReportType = reportType;
            GeneratedAt = DateTime.Now;
            TimeRange = timeRange;
            StartTime = DateTime.Now - timeRange;
            EndTime = DateTime.Now;
        }
    }
}