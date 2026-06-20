using System;

namespace FireAntivirus.ParentalControl
{
    public enum UserType
    {
        Parent,
        Child
    }

    public class User
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public UserType Type { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;

        public User() { }

        public User(string name, UserType type)
        {
            Id = Guid.NewGuid().ToString();
            Name = name;
            Type = type;
            Enabled = true;
        }
    }

    public class UserResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public User User { get; set; }
        public DateTime OperationTime { get; set; } = DateTime.Now;

        public UserResult() { }

        public UserResult(bool success, string message, User user = null)
        {
            Success = success;
            Message = message;
            User = user;
        }
    }

    public class TimeRestriction
    {
        public string Id { get; set; }
        public string UserId { get; set; }
        public DayOfWeek DayOfWeek { get; set; }
        public TimeSpan StartTime { get; set; }
        public TimeSpan EndTime { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;

        public TimeRestriction() { }

        public TimeRestriction(string userId, DayOfWeek dayOfWeek, TimeSpan startTime, TimeSpan endTime)
        {
            Id = Guid.NewGuid().ToString();
            UserId = userId;
            DayOfWeek = dayOfWeek;
            StartTime = startTime;
            EndTime = endTime;
            Enabled = true;
        }
    }

    public class TimeRestrictionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public TimeRestriction Restriction { get; set; }
        public DateTime OperationTime { get; set; } = DateTime.Now;

        public TimeRestrictionResult() { }

        public TimeRestrictionResult(bool success, string message, TimeRestriction restriction = null)
        {
            Success = success;
            Message = message;
            Restriction = restriction;
        }
    }

    public enum ContentCategory
    {
        Adult,
        Violence,
        Gambling,
        Drugs,
        SocialMedia,
        Education,
        Entertainment
    }

    public enum ContentAction
    {
        Allow,
        Block,
        Warn
    }

    public class ContentFilter
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public ContentCategory Category { get; set; }
        public ContentAction Action { get; set; }
        public bool Enabled { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;

        public ContentFilter() { }

        public ContentFilter(string name, string description, ContentCategory category, ContentAction action)
        {
            Id = Guid.NewGuid().ToString();
            Name = name;
            Description = description;
            Category = category;
            Action = action;
            Enabled = true;
        }
    }

    public class ContentFilterResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public ContentFilter Filter { get; set; }
        public DateTime OperationTime { get; set; } = DateTime.Now;

        public ContentFilterResult() { }

        public ContentFilterResult(bool success, string message, ContentFilter filter = null)
        {
            Success = success;
            Message = message;
            Filter = filter;
        }
    }
}