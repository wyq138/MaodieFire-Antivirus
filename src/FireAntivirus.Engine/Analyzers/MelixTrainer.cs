// Melix EMBER 样本集训练器（真实 CART 随机森林，不是占位/伪训练）：
//   数据：① index.jsonl（{"label":0/1,"path":"..."} 或 {"label":..,"features":[...]}）
//         ② 目录约定 benign/ 与 malicious/ 下的原始样本文件
//   训练：方差/非零率过滤 → 分层切分 → Bagging + 特征子采样 → CART（基尼不纯度、候选阈值）
//         → 并行建树 → 特征重要性（分裂增益累计）→ 验证集评估 → 阈值校准 → 导出 Melix 模型 JSON
//   部署：写 melix_ember.json（Aggregation=mean），Melix 推理按文件时间戳热加载。
// 数据集自动构建：恶意=隔离区真实样本，良性=System32 已数字签名二进制；零臆造样本。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class TrainingSample
    {
        public int Label { get; set; }              // 1 = 恶意，0 = 良性
        public float[] Features { get; set; }
        public string Source { get; set; }
    }

    public sealed class TrainingOptions
    {
        public int Trees { get; set; } = 40;
        public int MaxDepth { get; set; } = 6;
        public double FeatureFraction { get; set; } = 0.08;   // 过滤后特征池的采样比例
        public int MinLeaf { get; set; } = 4;
        public int MaxCandidates { get; set; } = 12;          // 每个特征的候选阈值数
        public double ValidationRatio { get; set; } = 0.25;
        public int Seed { get; set; } = 1337;
        public double MinFeatureNonZeroRate { get; set; } = 0.01;
        public double TargetFpr { get; set; } = MelixThresholdCalibrator.DefaultTargetFpr;
    }

    public sealed class TrainingReport
    {
        public int TotalSamples { get; set; }
        public int TrainSamples { get; set; }
        public int ValidationSamples { get; set; }
        public int BenignSamples { get; set; }
        public int MaliciousSamples { get; set; }
        public int Trees { get; set; }
        public int FeaturesUsed { get; set; }
        public double Accuracy { get; set; }
        public double Precision { get; set; }
        public double Tpr { get; set; }
        public double Fpr { get; set; }
        public double Auc { get; set; }
        public int Tp { get; set; }
        public int Fp { get; set; }
        public int Tn { get; set; }
        public int Fn { get; set; }
        public double RecommendedThreshold { get; set; }
        public long DurationMs { get; set; }
        public string ModelPath { get; set; }
        public List<(int Feature, double Importance)> TopFeatures { get; set; } = new();
        public string Summary { get; set; }
    }

    public static class MelixTrainer
    {
        private sealed class TreeNode
        {
            public bool IsLeaf;
            public int Feature = -1;
            public float Threshold;
            public TreeNode Left;
            public TreeNode Right;
            public float Value;
        }

        private sealed class IndexRow
        {
            public int Label { get; set; }
            public string Path { get; set; }
            public float[] Features { get; set; }
        }

        // ---------------------------------------------------------------- 数据集构建 / 加载

        /// <summary>
        /// 自动构建数据集索引（index.jsonl）：恶意来自隔离区真实样本，良性来自 System32 已签名二进制。
        /// 只写路径索引，不复制文件，避免占用磁盘。
        /// </summary>
        public static int BuildAutoDataset(string datasetRoot, int maxPerClass, Action<string> log, out string error)
        {
            error = "";
            try
            {
                Directory.CreateDirectory(datasetRoot);
                var rows = new List<IndexRow>();

                // 恶意：隔离区
                string quarantine = FireAntivirus.Common.PathHelper.GetQuarantinePath();
                var maliciousRoots = new List<string>();
                if (!string.IsNullOrEmpty(quarantine) && Directory.Exists(quarantine))
                    maliciousRoots.Add(quarantine);

                // 历史隔离目录（统一存储迁移前的落点）同样含真实恶意样本，一并纳入采集
                var legacyQuarantine = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "FireAntivirus", "Quarantine");
                if (Directory.Exists(legacyQuarantine) &&
                    !maliciousRoots.Any(r => string.Equals(r, legacyQuarantine, StringComparison.OrdinalIgnoreCase)))
                    maliciousRoots.Add(legacyQuarantine);

                int added = 0;
                foreach (var root in maliciousRoots)
                {
                    foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        if (added >= maxPerClass) break;
                        try
                        {
                            var fi = new FileInfo(file);
                            if (fi.Length <= 0 || fi.Length > 16L * 1024 * 1024) continue;
                            // 隔离区索引 JSON 不是样本；非 PE（脚本/文档/加密残留）不进 PE 特征训练集
                            if (string.Equals(fi.Extension, ".json", StringComparison.OrdinalIgnoreCase)) continue;
                            if (!IsPeFile(file)) continue;
                            rows.Add(new IndexRow { Label = 1, Path = file });
                            added++;
                        }
                        catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                    }
                }
                log?.Invoke(maliciousRoots.Count == 0
                    ? "隔离区为空或不存在，恶意样本为 0"
                    : $"恶意样本（隔离区）: {added}");

                // 良性：System32 顶层已签名 exe/dll
                string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                int benign = 0;
                foreach (var file in Directory.EnumerateFiles(system32, "*.exe", SearchOption.TopDirectoryOnly)
                             .Concat(Directory.EnumerateFiles(system32, "*.dll", SearchOption.TopDirectoryOnly)))
                {
                    if (benign >= maxPerClass) break;
                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length <= 0 || fi.Length > 16L * 1024 * 1024) continue;
                        if (!HasEmbeddedSignature(file)) continue;
                        rows.Add(new IndexRow { Label = 0, Path = file });
                        benign++;
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
                log?.Invoke($"良性样本（System32 已签名）: {benign}");

                string indexPath = Path.Combine(datasetRoot, "index.jsonl");
                var sb = new StringBuilder();
                var indexJsonOptions = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                };
                foreach (var row in rows)
                    sb.AppendLine(JsonSerializer.Serialize(row, indexJsonOptions));
                File.WriteAllText(indexPath, sb.ToString(), Encoding.UTF8);

                log?.Invoke($"数据集索引已写入: {indexPath}（共 {rows.Count} 条）");
                return rows.Count;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return 0;
            }
        }

        /// <summary>加载数据集：优先 index.jsonl，其次 benign/ 与 malicious/ 目录。</summary>
        public static List<TrainingSample> LoadDataset(string datasetRoot, int maxPerClass, Action<string> log, out string error)
        {
            error = "";
            var samples = new List<TrainingSample>();
            try
            {
                if (string.IsNullOrWhiteSpace(datasetRoot))
                {
                    error = "数据集路径为空";
                    return samples;
                }

                string indexPath = Path.Combine(datasetRoot, "index.jsonl");
                if (File.Exists(indexPath))
                {
                    int benignCount = 0, maliciousCount = 0;
                    foreach (var line in File.ReadLines(indexPath))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        IndexRow row;
                        try
                        {
                            row = JsonSerializer.Deserialize<IndexRow>(line,
                                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        }
                        catch { continue; }
                        if (row == null) continue;
                        if (row.Label == 1 && maliciousCount >= maxPerClass) continue;
                        if (row.Label == 0 && benignCount >= maxPerClass) continue;

                        float[] features = row.Features;
                        if (features == null || features.Length != EmberFeatureExtractor.FeatureCount)
                        {
                            if (string.IsNullOrWhiteSpace(row.Path) || !File.Exists(row.Path)) continue;
                            features = EmberFeatureExtractor.Extract(row.Path);
                        }
                        if (features.All(v => v == 0f)) continue;

                        samples.Add(new TrainingSample
                        {
                            Label = row.Label,
                            Features = features,
                            Source = row.Path
                        });
                        if (row.Label == 1) maliciousCount++; else benignCount++;
                    }
                    log?.Invoke($"index.jsonl 加载: 良性 {benignCount} / 恶意 {maliciousCount}");
                    return samples;
                }

                // 目录约定
                samples.AddRange(LoadFolderSamples(Path.Combine(datasetRoot, "benign"), 0, maxPerClass, log));
                samples.AddRange(LoadFolderSamples(Path.Combine(datasetRoot, "malicious"), 1, maxPerClass, log));
                log?.Invoke($"目录加载: {samples.Count} 条（良性 {samples.Count(s => s.Label == 0)} / 恶意 {samples.Count(s => s.Label == 1)}）");
                return samples;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return samples;
            }
        }

        private static List<TrainingSample> LoadFolderSamples(string dir, int label, int max, Action<string> log)
        {
            var list = new List<TrainingSample>();
            if (!Directory.Exists(dir)) return list;
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                if (list.Count >= max) break;
                try
                {
                    var features = EmberFeatureExtractor.Extract(file);
                    if (features.All(v => v == 0f)) continue;
                    list.Add(new TrainingSample { Label = label, Features = features, Source = file });
                }
                catch (Exception ex) { log?.Invoke($"跳过 {Path.GetFileName(file)}: {ex.Message}"); }
            }
            return list;
        }

        // ---------------------------------------------------------------- 训练

        /// <summary>训练随机森林、评估、校准阈值并写模型文件。</summary>
        public static TrainingReport TrainAndDeploy(
            List<TrainingSample> samples, TrainingOptions options, string modelPath,
            Action<string> log, out string error)
        {
            error = "";
            var report = new TrainingReport { ModelPath = modelPath };
            var sw = Stopwatch.StartNew();

            try
            {
                if (samples == null || samples.Count < 20)
                {
                    error = "样本太少（至少 20 条）";
                    return report;
                }

                int benignTotal = samples.Count(s => s.Label == 0);
                int maliciousTotal = samples.Count(s => s.Label == 1);
                if (benignTotal < 5 || maliciousTotal < 5)
                {
                    error = $"两类样本都需要至少 5 条（当前良性 {benignTotal} / 恶意 {maliciousTotal}）";
                    return report;
                }

                var usable = samples.Where(s => s.Features != null &&
                                                s.Features.Length == EmberFeatureExtractor.FeatureCount).ToList();
                if (usable.Count < 20) { error = "有效特征样本不足 20 条"; return report; }

                // 特征池：非零率 + 方差过滤（2568 维里大量维度对当前样本恒定，剔除可大幅加速且不降精度）
                var featurePool = SelectFeatures(usable, options.MinFeatureNonZeroRate);
                if (featurePool.Length < 8) { error = "有效特征维度不足（样本过于单一）"; return report; }

                // 分层切分
                var rng = new Random(options.Seed);
                var train = new List<TrainingSample>();
                var valid = new List<TrainingSample>();
                foreach (var group in usable.GroupBy(s => s.Label))
                {
                    var arr = group.OrderBy(_ => rng.Next()).ToList();
                    int validCount = Math.Max(1, (int)(arr.Count * options.ValidationRatio));
                    valid.AddRange(arr.Take(validCount));
                    train.AddRange(arr.Skip(validCount));
                }
                if (train.Count == 0 || valid.Count == 0) { error = "切分后训练/验证集为空"; return report; }

                log?.Invoke($"训练集 {train.Count} / 验证集 {valid.Count} / 特征池 {featurePool.Length}（原始 2568 维）");

                var importance = new double[EmberFeatureExtractor.FeatureCount];
                var forest = new MelixTree[options.Trees];
                object impLock = new object();

                // 每棵树独立随机源；并行训练（训练集只读，importance 用独立数组后合并）
                Parallel.For(0, options.Trees, t =>
                {
                    var treeRng = new Random(options.Seed + t * 7919);
                    var bag = Bootstrap(train, treeRng);
                    var localImportance = new double[EmberFeatureExtractor.FeatureCount];
                    var root = BuildTree(bag, 0, options.MaxDepth, featurePool, options, treeRng, localImportance, 0);
                    forest[t] = ToMelixTree(root);

                    lock (impLock)
                        for (int i = 0; i < importance.Length; i++) importance[i] += localImportance[i];
                });

                log?.Invoke($"{options.Trees} 棵树训练完成，开始验证评估");

                // 用内存模型评估（避免先写盘再读）
                var model = new MelixModel
                {
                    Version = "trained-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"),
                    FeatureCount = EmberFeatureExtractor.FeatureCount,
                    Aggregation = "mean",
                    Sigmoid = false,
                    Threshold = 0.5,
                    Trees = forest.ToList()
                };

                var validBenign = valid.Where(s => s.Label == 0).Select(s => s.Features).ToList();
                var validMalicious = valid.Where(s => s.Label == 1).Select(s => s.Features).ToList();

                var calibration = CalibrateWithModel(model, validBenign, validMalicious, options.TargetFpr);
                model.Threshold = calibration.RecommendedThreshold;

                report.TotalSamples = usable.Count;
                report.TrainSamples = train.Count;
                report.ValidationSamples = valid.Count;
                report.BenignSamples = benignTotal;
                report.MaliciousSamples = maliciousTotal;
                report.Trees = options.Trees;
                report.FeaturesUsed = featurePool.Length;
                report.RecommendedThreshold = calibration.RecommendedThreshold;
                report.Auc = calibration.Auc;

                // 用推荐阈值重新统计验证集混淆矩阵（与线上判定一致）
                int tp = 0, fp = 0, tn = 0, fn = 0;
                foreach (var s in valid)
                {
                    float score = PredictWithModel(model, s.Features);
                    bool predicted = score >= model.Threshold;
                    if (s.Label == 1) { if (predicted) tp++; else fn++; }
                    else { if (predicted) fp++; else tn++; }
                }
                report.Tp = tp; report.Fp = fp; report.Tn = tn; report.Fn = fn;
                report.Tpr = tp + fn == 0 ? 0 : (double)tp / (tp + fn);
                report.Fpr = fp + tn == 0 ? 0 : (double)fp / (fp + tn);
                report.Precision = tp + fp == 0 ? 1 : (double)tp / (tp + fp);
                report.Accuracy = (double)(tp + tn) / Math.Max(1, valid.Count);

                report.TopFeatures = importance
                    .Select((v, i) => (Feature: i, Importance: v))
                    .Where(x => x.Importance > 0)
                    .OrderByDescending(x => x.Importance)
                    .Take(20)
                    .ToList();

                // 写模型（时间戳热更新由 MelixEnsembleClassifier 检测）
                Directory.CreateDirectory(Path.GetDirectoryName(modelPath) ?? ".");
                File.WriteAllText(modelPath, JsonSerializer.Serialize(model,
                    new JsonSerializerOptions { WriteIndented = true }));

                MelixEnsembleClassifier.Initialize(modelPath);

                report.DurationMs = sw.ElapsedMilliseconds;
                report.Summary = $"训练完成：{options.Trees} 棵树 / 特征 {featurePool.Length} 维 / " +
                                 $"验证 TPR {report.Tpr:P2} / FPR {report.Fpr:P2} / Precision {report.Precision:P2} / " +
                                 $"AUC {report.Auc:F4} / 阈值 {model.Threshold:F3} / 耗时 {report.DurationMs / 1000.0:F1}s";
                log?.Invoke(report.Summary);
                return report;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                report.DurationMs = sw.ElapsedMilliseconds;
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error,
                    "Melix 模型训练失败: " + ex.Message);
                return report;
            }
        }

        private static int[] SelectFeatures(List<TrainingSample> samples, double minNonZeroRate)
        {
            int n = samples.Count;
            int minCount = Math.Max(2, (int)(n * minNonZeroRate));
            var selected = new List<int>(512);
            for (int f = 0; f < EmberFeatureExtractor.FeatureCount; f++)
            {
                int nonZero = 0;
                double sum = 0, sumSq = 0;
                foreach (var s in samples)
                {
                    float v = s.Features[f];
                    if (v != 0f) nonZero++;
                    sum += v;
                    sumSq += (double)v * v;
                }
                if (nonZero < minCount) continue;
                double mean = sum / n;
                double variance = sumSq / n - mean * mean;
                if (variance < 1e-9) continue;
                selected.Add(f);
            }
            return selected.ToArray();
        }

        private static TrainingSample[] Bootstrap(List<TrainingSample> train, Random rng)
        {
            var bag = new TrainingSample[train.Count];
            for (int i = 0; i < bag.Length; i++)
                bag[i] = train[rng.Next(train.Count)];
            return bag;
        }

        private static TreeNode BuildTree(TrainingSample[] samples, int depth, int maxDepth,
            int[] featurePool, TrainingOptions options, Random rng, double[] importance, int _)
        {
            int n = samples.Length;
            int malicious = 0;
            for (int i = 0; i < n; i++) if (samples[i].Label == 1) malicious++;

            var leaf = new TreeNode
            {
                IsLeaf = true,
                Value = (float)((malicious + 1.0) / (n + 2.0))   // Laplace 平滑
            };

            if (depth >= maxDepth || n < options.MinLeaf * 2 || malicious == 0 || malicious == n)
                return leaf;

            double parentGini = Gini(malicious, n);
            int featureCount = Math.Max(8, (int)(featurePool.Length * options.FeatureFraction));
            featureCount = Math.Min(featureCount, featurePool.Length);

            // 随机特征子集：有放回采样（不修改共享特征池——多棵树并行训练时原地洗牌是数据竞争）
            var picked = new int[featureCount];
            for (int i = 0; i < featureCount; i++)
                picked[i] = featurePool[rng.Next(featurePool.Length)];

            double bestScore = parentGini;
            int bestFeature = -1;
            float bestThreshold = 0;
            int bestLeftCount = 0, bestLeftMalicious = 0;

            foreach (int f in picked)
            {
                // 候选阈值：从当前样本随机取样值的分位点（真实 CART 的近似加速）
                int candCount = Math.Min(options.MaxCandidates, n);
                var candidates = new float[candCount];
                for (int c = 0; c < candCount; c++)
                    candidates[c] = samples[rng.Next(n)].Features[f];
                Array.Sort(candidates);

                float prev = float.NaN;
                foreach (float threshold in candidates)
                {
                    if (float.IsNaN(threshold) || threshold == prev) continue;
                    prev = threshold;

                    int leftCount = 0, leftMalicious = 0;
                    for (int i = 0; i < n; i++)
                    {
                        if (samples[i].Features[f] >= threshold) continue;
                        leftCount++;
                        if (samples[i].Label == 1) leftMalicious++;
                    }
                    int rightCount = n - leftCount;
                    if (leftCount < options.MinLeaf || rightCount < options.MinLeaf) continue;

                    double weighted = (leftCount * Gini(leftMalicious, leftCount) +
                                       rightCount * Gini(malicious - leftMalicious, rightCount)) / n;
                    if (weighted < bestScore - 1e-12)
                    {
                        bestScore = weighted;
                        bestFeature = f;
                        bestThreshold = threshold;
                        bestLeftCount = leftCount;
                        bestLeftMalicious = leftMalicious;
                    }
                }
            }

            if (bestFeature < 0) return leaf;

            importance[bestFeature] += (parentGini - bestScore) * n;

            var leftSamples = new TrainingSample[bestLeftCount];
            var rightSamples = new TrainingSample[n - bestLeftCount];
            int li = 0, ri = 0;
            foreach (var s in samples)
            {
                if (s.Features[bestFeature] < bestThreshold) leftSamples[li++] = s;
                else rightSamples[ri++] = s;
            }

            return new TreeNode
            {
                IsLeaf = false,
                Feature = bestFeature,
                Threshold = bestThreshold,
                Left = BuildTree(leftSamples, depth + 1, maxDepth, featurePool, options, rng, importance, 0),
                Right = BuildTree(rightSamples, depth + 1, maxDepth, featurePool, options, rng, importance, 0)
            };
        }

        private static double Gini(int malicious, int total)
        {
            if (total <= 0) return 0;
            double p = (double)malicious / total;
            return 1.0 - p * p - (1 - p) * (1 - p);
        }

        /// <summary>树 → Melix 扁平节点数组（BFS，保证子索引大于父索引）。</summary>
        private static MelixTree ToMelixTree(TreeNode root)
        {
            var nodes = new List<MelixNode> { null };
            var queue = new Queue<(TreeNode Node, int Index)>();
            queue.Enqueue((root, 0));

            while (queue.Count > 0)
            {
                var (node, index) = queue.Dequeue();
                if (node == null)
                {
                    nodes[index] = new MelixNode { IsLeaf = true, Leaf = 0f };
                    continue;
                }
                if (node.IsLeaf)
                {
                    nodes[index] = new MelixNode { IsLeaf = true, Leaf = node.Value };
                    continue;
                }

                int leftIndex = nodes.Count; nodes.Add(null);
                int rightIndex = nodes.Count; nodes.Add(null);
                nodes[index] = new MelixNode
                {
                    IsLeaf = false,
                    Feature = node.Feature,
                    Threshold = node.Threshold,
                    Left = leftIndex,
                    Right = rightIndex
                };
                queue.Enqueue((node.Left, leftIndex));
                queue.Enqueue((node.Right, rightIndex));
            }

            return new MelixTree { Nodes = nodes };
        }

        // ---------------------------------------------------------------- 模型内评估（不依赖全局单例）

        private static float PredictWithModel(MelixModel model, float[] features)
        {
            if (model?.Trees == null || model.Trees.Count == 0) return 0f;
            double sum = 0;
            foreach (var tree in model.Trees) sum += Traverse(tree, features);
            return (float)Math.Clamp(sum / model.Trees.Count, 0, 1);
        }

        private static float Traverse(MelixTree tree, float[] features)
        {
            var nodes = tree.Nodes;
            if (nodes == null || nodes.Count == 0) return 0f;
            int idx = 0;
            for (int guard = 0; guard < 64; guard++)
            {
                if (idx < 0 || idx >= nodes.Count) return 0f;
                var node = nodes[idx];
                if (node.IsLeaf) return node.Leaf;
                idx = features[node.Feature] < node.Threshold ? node.Left : node.Right;
            }
            return 0f;
        }

        private static CalibrationReport CalibrateWithModel(MelixModel model,
            IReadOnlyList<float[]> benign, IReadOnlyList<float[]> malicious, double targetFpr)
        {
            var report = new CalibrationReport
            {
                TargetFpr = targetFpr,
                BenignCount = benign.Count,
                MaliciousCount = malicious.Count
            };
            if (benign.Count == 0 || malicious.Count == 0)
            {
                report.RecommendedThreshold = 0.5;
                report.Summary = "验证集缺少某一类，使用默认阈值 0.5";
                return report;
            }

            var benignScores = benign.Select(f => (double)PredictWithModel(model, f)).ToArray();
            var maliciousScores = malicious.Select(f => (double)PredictWithModel(model, f)).ToArray();
            report.Auc = MelixThresholdCalibrator.ComputeAuc(benignScores, maliciousScores);

            CalibrationPoint chosen = null;
            double bestTprUnderConstraint = -1;
            for (double t = 0.05; t <= 0.9501; t += 0.005)
            {
                int tp = maliciousScores.Count(s => s >= t);
                int fp = benignScores.Count(s => s >= t);
                var point = new CalibrationPoint
                {
                    Threshold = Math.Round(t, 3),
                    Tp = tp,
                    Fp = fp,
                    Tn = benignScores.Length - fp,
                    Fn = maliciousScores.Length - tp,
                    Tpr = (double)tp / maliciousScores.Length,
                    Fpr = (double)fp / benignScores.Length,
                    Precision = tp + fp == 0 ? 1 : (double)tp / (tp + fp)
                };
                report.Curve.Add(point);

                if (point.Fpr <= targetFpr && point.Tpr > bestTprUnderConstraint)
                {
                    bestTprUnderConstraint = point.Tpr;
                    chosen = point;
                }
            }

            chosen ??= report.Curve.OrderBy(p => p.Fpr).ThenByDescending(p => p.Tpr).First();
            report.RecommendedThreshold = chosen.Threshold;
            report.FprAtRecommended = chosen.Fpr;
            report.TprAtRecommended = chosen.Tpr;
            report.PrecisionAtRecommended = chosen.Precision;
            report.Summary = $"验证集推荐阈值 {chosen.Threshold:F3}：FPR {chosen.Fpr:P2} / TPR {chosen.Tpr:P2} / AUC {report.Auc:F4}";
            return report;
        }

        // ---------------------------------------------------------------- 工具

        private static bool HasEmbeddedSignature(string filePath)
        {
            try
            {
                using var cert = X509Certificate.CreateFromSignedFile(filePath);
                return cert != null;
            }
            catch { return false; }
        }

        /// <summary>PE 头检查（EMBER 特征只对 PE 有意义；非 PE/加密残留不进训练集）。</summary>
        private static bool IsPeFile(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                return fs.ReadByte() == 'M' && fs.ReadByte() == 'Z';
            }
            catch { return false; }
        }
    }
}