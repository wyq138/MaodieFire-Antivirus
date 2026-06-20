using System;

namespace FireAntivirus.PasswordManager
{
    public enum PasswordStrength
    {
        Weak,
        Medium,
        Strong,
        VeryStrong
    }

    public class PasswordEntry
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Url { get; set; }
        public string Notes { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }

        public PasswordEntry() { }

        public PasswordEntry(string title, string username, string password, string url = null, string notes = null)
        {
            Title = title;
            Username = username;
            Password = password;
            Url = url;
            Notes = notes;
            CreatedAt = DateTime.Now;
            UpdatedAt = DateTime.Now;
        }
    }
}