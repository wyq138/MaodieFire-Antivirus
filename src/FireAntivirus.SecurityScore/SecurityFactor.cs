using System;
using System.Collections.Generic;

namespace FireAntivirus.SecurityScore
{
    public class SecurityFactor
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public int Weight { get; set; }
        public int CurrentScore { get; set; }
        public DateTime LastUpdated { get; set; } = DateTime.Now;

        public SecurityFactor() { }

        public SecurityFactor(string name, string description, int weight, int currentScore)
        {
            Name = name;
            Description = description;
            Weight = weight;
            CurrentScore = currentScore;
        }
    }

    public class ScoreEntry
    {
        public DateTime Date { get; set; }
        public int Score { get; set; }

        public ScoreEntry() { }

        public ScoreEntry(DateTime date, int score)
        {
            Date = date;
            Score = score;
        }
    }

    public class SecurityScoreHistory
    {
        public int Days { get; set; }
        public List<ScoreEntry> Scores { get; set; } = new List<ScoreEntry>();

        public SecurityScoreHistory() { }

        public SecurityScoreHistory(int days, List<ScoreEntry> scores)
        {
            Days = days;
            Scores = scores;
        }
    }
}