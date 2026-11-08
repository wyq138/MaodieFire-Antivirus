// Melix 阈值校准（用真实样本集把误报率压到目标值）：
//   输入：良性/恶意两类的 EMBER 2568 维特征（来自样本文件或已提取数据集）；
//   流程：逐个阈值计算混淆矩阵 → 画出 ROC 工作点 → 在 FPR ≤ target 的约束下取 TPR 最高点；
//   输出：推荐阈值、该点 FPR/TPR/Precision、AUC 与完整工作曲线（可审计）。
// 校准结果可写回 melix_ember.json（Threshold 字段），Melix 推理实时生效（文件时间戳热更新）。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class CalibrationPoint
    {
        public double Threshold { get; set; }
        public double Tpr { get; set; }
        public double Fpr { get; set; }
        public double Precision { get; set; }
        public int Tp { get; set; }
        public int Fp { get; set; }
        public int Tn { get; set; }
        public int Fn { get; set; }
    }

    public sealed class CalibrationReport
    {
        public double TargetFpr { get; set; }
        public double RecommendedThreshold { get; set; }
        public double FprAtRecommended { get; set; }
        public double TprAtRecommended { get; set; }
        public double PrecisionAtRecommended { get; set; }
        public double Auc { get; set; }
        public int BenignCount { get; set; }
        public int MaliciousCount { get; set; }
        public List<CalibrationPoint> Curve { get; set; } = new List<CalibrationPoint>();
        public string Summary { get; set; }
    }

    public static class MelixThresholdCalibrator
    {
        public const double DefaultTargetFpr = 0.01;

        /// <summary>在给定特征集上校准（不读文件，便于复用训练/验证切分）。</summary>
        public static CalibrationReport Calibrate(
            IReadOnlyList<float[]> benignFeatures,
            IReadOnlyList<float[]> maliciousFeatures,
            double targetFpr = DefaultTargetFpr)
        {
            var report = new CalibrationReport
            {
                TargetFpr = targetFpr,
                BenignCount = benignFeatures?.Count ?? 0,
                MaliciousCount = maliciousFeatures?.Count ?? 0
            };
            if (report.BenignCount == 0 || report.MaliciousCount == 0)
            {
                report.Summary = "样本不足：需要良性/恶意各有样本才能校准";
                report.RecommendedThreshold = MelixEnsembleClassifier.DefaultThreshold;
                return report;
            }

            var benignScores = benignFeatures.Select(f => (double)MelixEnsembleClassifier.PredictProbability(f)).ToArray();
            var maliciousScores = maliciousFeatures.Select(f => (double)MelixEnsembleClassifier.PredictProbability(f)).ToArray();

            report.Auc = ComputeAuc(benignScores, maliciousScores);

            // 0.05..0.95 步进 0.005（181 个工作点）
            for (double t = 0.05; t <= 0.9501; t += 0.005)
            {
                int tp = maliciousScores.Count(s => s >= t);
                int fn = maliciousScores.Length - tp;
                int fp = benignScores.Count(s => s >= t);
                int tn = benignScores.Length - fp;

                report.Curve.Add(new CalibrationPoint
                {
                    Threshold = Math.Round(t, 3),
                    Tp = tp,
                    Fp = fp,
                    Tn = tn,
                    Fn = fn,
                    Tpr = (double)tp / maliciousScores.Length,
                    Fpr = (double)fp / benignScores.Length,
                    Precision = tp + fp == 0 ? 1.0 : (double)tp / (tp + fp)
                });
            }

            var feasible = report.Curve.Where(p => p.Fpr <= targetFpr).ToList();
            CalibrationPoint chosen;
            if (feasible.Count > 0)
            {
                double bestTpr = feasible.Max(p => p.Tpr);
                chosen = feasible
                    .Where(p => Math.Abs(p.Tpr - bestTpr) < 1e-9)
                    .OrderByDescending(p => p.Threshold)   // 同等 TPR 取更高阈值（更少误报）
                    .First();
            }
            else
            {
                chosen = report.Curve.OrderBy(p => p.Fpr).ThenByDescending(p => p.Tpr).First();
            }

            report.RecommendedThreshold = chosen.Threshold;
            report.FprAtRecommended = chosen.Fpr;
            report.TprAtRecommended = chosen.Tpr;
            report.PrecisionAtRecommended = chosen.Precision;
            report.Summary = $"推荐阈值 {chosen.Threshold:F3}：FPR {chosen.Fpr:P2} / TPR {chosen.Tpr:P2} / " +
                             $"Precision {chosen.Precision:P2} / AUC {report.Auc:F4}" +
                             (feasible.Count == 0 ? "（目标 FPR 不可达，已取最小误报点）" : "");
            return report;
        }

        /// <summary>直接从样本文件目录校准（自动提取 EMBER 特征）。</summary>
        public static CalibrationReport CalibrateFromDirectories(
            string benignDir, string maliciousDir, double targetFpr = DefaultTargetFpr,
            int maxPerClass = 300, Action<string> log = null)
        {
            var benign = LoadFeatures(benignDir, maxPerClass, log);
            var malicious = LoadFeatures(maliciousDir, maxPerClass, log);
            return Calibrate(benign, malicious, targetFpr);
        }

        /// <summary>把推荐阈值写回模型 JSON（文件不存在时导出内置专家树模型）。</summary>
        public static bool ApplyToModel(string modelPath, double threshold, out string error)
        {
            error = "";
            try
            {
                if (string.IsNullOrWhiteSpace(modelPath))
                {
                    error = "模型路径为空";
                    return false;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(modelPath) ?? ".");

                if (File.Exists(modelPath))
                {
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var model = JsonSerializer.Deserialize<MelixModel>(File.ReadAllText(modelPath), options);
                    if (model == null || model.Trees == null || model.Trees.Count == 0)
                    {
                        error = "模型文件无效，无法更新阈值";
                        return false;
                    }
                    model.Threshold = threshold;
                    File.WriteAllText(modelPath, JsonSerializer.Serialize(model,
                        new JsonSerializerOptions { WriteIndented = true }));
                }
                else
                {
                    if (!MelixEnsembleClassifier.SaveBuiltinModel(modelPath, threshold, out error))
                        return false;
                }

                MelixEnsembleClassifier.Initialize(modelPath);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static List<float[]> LoadFeatures(string dir, int max, Action<string> log)
        {
            var list = new List<float[]>();
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return list;

            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly).Take(max))
            {
                try
                {
                    var f = EmberFeatureExtractor.Extract(file);
                    if (f.Any(v => v != 0f)) list.Add(f);
                }
                catch (Exception ex)
                {
                    log?.Invoke($"特征提取失败 {Path.GetFileName(file)}: {ex.Message}");
                }
            }
            log?.Invoke($"已加载 {list.Count} 个特征（{dir}）");
            return list;
        }

        /// <summary>AUC（Mann-Whitney U，含并列 0.5 权重）。</summary>
        public static double ComputeAuc(IReadOnlyList<double> benignScores, IReadOnlyList<double> maliciousScores)
        {
            if (benignScores.Count == 0 || maliciousScores.Count == 0) return 0.5;
            double wins = 0;
            foreach (var m in maliciousScores)
            {
                foreach (var b in benignScores)
                {
                    if (m > b) wins += 1;
                    else if (Math.Abs(m - b) < 1e-12) wins += 0.5;
                }
            }
            return wins / ((double)benignScores.Count * maliciousScores.Count);
        }
    }
}