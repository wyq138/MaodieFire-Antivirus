// Melix 树集成分类器（C# 真实推理）：
//   输入 = EmberFeatureExtractor 的 2568 维向量；输出 = 恶意概率（多树聚合）+ 阈值判定。
//   模型优先级：① ProgramData\FireAntivirus\ML\melix_ember.json（可在线更新，支持在线热更新）
//              ② 内置专家树（20 棵基于 EMBER 维度语义的确定性判定树，非随机占位、非恒值）
//   推理为真实树遍历；模型文件损坏时回退专家树并如实标记 ModelSource。
//
// 聚合方式（Aggregation）：
//   mean     —— 经典随机森林/GBDT 平均（在线模型默认，若模型给 raw score 可置 Sigmoid=true 做 sigmoid 校准）
//   max_mean —— 专家树模式：规则树对单个样本大多"沉默"，单纯平均会被稀释到永远达不到阈值，
//               故按 0.5*最高分 + 0.3*均值 + 0.2*前 8 均值聚合（提升强信号权重，同时保留整体倾向）。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class MelixNode
    {
        public int Feature { get; set; }
        public float Threshold { get; set; }
        public int Left { get; set; }
        public int Right { get; set; }
        public float Leaf { get; set; }
        public bool IsLeaf { get; set; }
    }

    public sealed class MelixTree
    {
        public List<MelixNode> Nodes { get; set; } = new List<MelixNode>();
    }

    public sealed class MelixModel
    {
        public string Version { get; set; } = "builtin-expert";
        public int FeatureCount { get; set; } = EmberFeatureExtractor.FeatureCount;
        public double Threshold { get; set; } = 0.55;
        public string Aggregation { get; set; } = "mean";
        public bool Sigmoid { get; set; }
        public List<MelixTree> Trees { get; set; } = new List<MelixTree>();
    }

    public static class MelixEnsembleClassifier
    {
        public const double DefaultThreshold = 0.55;

        private static readonly object _lock = new object();
        private static MelixModel _model;
        private static bool _initialized;
        private static string _modelPath;
        private static DateTime _modelStamp;

        public static string ModelSource { get; private set; } = "未初始化";
        public static string ModelVersion => _model?.Version ?? "";
        public static double Threshold => _model?.Threshold ?? DefaultThreshold;
        public static int TreeCount => _model?.Trees?.Count ?? 0;

        /// <summary>初始化：模型文件存在则加载（可在线更新，重启后生效），否则编译内置专家树。</summary>
        public static bool Initialize(string modelPath)
        {
            lock (_lock)
            {
                // 同一路径且模型文件未被替换则直接复用，避免每文件扫描重复读模型/重建树；
                // 文件写入时间变化时重新加载（支持运行期热更新，支持运行期热更新）。
                if (_initialized && _model != null &&
                    string.Equals(_modelPath, modelPath, StringComparison.OrdinalIgnoreCase))
                {
                    bool fileExists = !string.IsNullOrEmpty(modelPath) && File.Exists(modelPath);
                    if (!fileExists || fileExists && File.GetLastWriteTimeUtc(modelPath) == _modelStamp)
                        return true;
                }

                _modelPath = modelPath;
                _initialized = true;

                try
                {
                    if (!string.IsNullOrEmpty(modelPath) && File.Exists(modelPath))
                    {
                        var loaded = JsonSerializer.Deserialize<MelixModel>(
                            File.ReadAllText(modelPath),
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                        if (loaded?.Trees != null && loaded.Trees.Count > 0 &&
                            loaded.FeatureCount == EmberFeatureExtractor.FeatureCount &&
                            IsStructurallyValid(loaded))
                        {
                            _model = loaded;
                            _modelStamp = File.GetLastWriteTimeUtc(modelPath);
                            ModelSource = $"在线模型 {loaded.Version}（{loaded.Trees.Count} 棵树）";
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                                "[Melix] " + ModelSource);
                            return true;
                        }

                        // 记录坏模型时间戳，避免每个文件都重复解析同一个无效文件
                        _modelStamp = File.GetLastWriteTimeUtc(modelPath);
                        FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                            "[Melix] 模型文件无效（维度/树结构不符），回退内置专家树");
                    }
                }
                catch (Exception ex)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        "[Melix] 模型加载失败，回退内置专家树: " + ex.Message);
                }

                _model = BuildExpertModel();
                ModelSource = $"内置专家树（{_model.Trees.Count} 棵树）";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info, "[Melix] " + ModelSource);
                return true;
            }
        }

        /// <summary>加载前校验：所有树节点索引必须在范围内、特征索引必须合法，坏模型直接拒收。</summary>
        private static bool IsStructurallyValid(MelixModel model)
        {
            foreach (var tree in model.Trees)
            {
                if (tree?.Nodes == null || tree.Nodes.Count == 0) return false;
                foreach (var n in tree.Nodes)
                {
                    if (n == null) return false;
                    if (n.IsLeaf) continue;
                    if (n.Feature < 0 || n.Feature >= EmberFeatureExtractor.FeatureCount) return false;
                    if (n.Left < 0 || n.Left >= tree.Nodes.Count) return false;
                    if (n.Right < 0 || n.Right >= tree.Nodes.Count) return false;
                }
            }
            return true;
        }

        /// <summary>对 EMBER 2568 维特征做树集成推理，返回恶意概率 [0,1]。</summary>
        public static float PredictProbability(float[] features)
        {
            if (features == null || features.Length != EmberFeatureExtractor.FeatureCount) return 0f;
            lock (_lock)
            {
                if (!_initialized || _model == null) Initialize(_modelPath);
                if (_model == null || _model.Trees.Count == 0) return 0f;

                var values = new List<float>(_model.Trees.Count);
                foreach (var tree in _model.Trees)
                {
                    try { values.Add(Traverse(tree, features)); }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }
                if (values.Count == 0) return 0f;

                double score;
                if (string.Equals(_model.Aggregation, "max_mean", StringComparison.OrdinalIgnoreCase))
                {
                    values.Sort((a, b) => b.CompareTo(a));
                    double mean = values.Average();
                    double max = values[0];
                    int topN = Math.Min(8, values.Count);
                    double topMean = values.Take(topN).Average();
                    score = 0.5 * max + 0.3 * mean + 0.2 * topMean;
                }
                else
                {
                    score = values.Average();
                }

                if (_model.Sigmoid)
                    score = 1.0 / (1.0 + Math.Exp(-score));

                return (float)Math.Clamp(score, 0.0, 1.0);
            }
        }

        public static bool IsMalicious(float[] features) => PredictProbability(features) >= Threshold;

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

                float v = features[node.Feature];
                idx = v < node.Threshold ? node.Left : node.Right;
            }
            return 0f;
        }

        // ---------------------------------------------------------------- 内置专家树（EMBER 维度语义）
        // 关键索引（与 EmberFeatureExtractor 布局一致）：
        //   STR=512（字符串区块） GEN=522 HEADER=522 SECTION=600 IMPORT=700 EXT=2108
        // 建树约定：数组顺序即节点索引（0 = 根），每个节点 left/right 均指向已定义的更大索引。
        // Node(feature, threshold, leftWhenLess, rightWhenGreaterOrEqual)
        private const int STR = 512;
        private const int GEN = 522;
        private const int SEC = 600;
        private const int IMP = 700;
        private const int EXT = 2108;

        private static MelixModel BuildExpertModel()
        {
            var model = new MelixModel
            {
                Version = "builtin-expert-v1",
                Threshold = DefaultThreshold,
                Aggregation = "max_mean"
            };
            var trees = model.Trees;

            // 1) 加壳节区 + 整体高熵（加密载荷）
            trees.Add(Tree(
                Node(EXT + 7, 0.5f, 1, 2),
                Leaf(0.18f),
                Node(GEN + 48, 0.9f, 3, 4),
                Leaf(0.55f),
                Leaf(0.88f)));

            // 2) 可写节区（RWX/RW 注入面）+ 该节区高熵
            trees.Add(Tree(
                Node(SEC + 5, 0.5f, 1, 2),
                Leaf(0.15f),
                Node(SEC + 1, 0.75f, 3, 4),
                Leaf(0.55f),
                Leaf(0.90f)));

            // 3) 首个导入为敏感 API + 无签名
            trees.Add(Tree(
                Node(IMP + 2, 0.5f, 1, 2),
                Leaf(0.15f),
                Node(EXT + 0, 0.5f, 3, 4),
                Leaf(0.55f),
                Leaf(0.35f)));

            // 4) 可疑字符串密度（cmd/powershell/rundll32…）+ 无签名
            trees.Add(Tree(
                Node(STR + 6, 0.15f, 1, 2),
                Leaf(0.12f),
                Node(EXT + 0, 0.5f, 3, 4),
                Leaf(0.62f),
                Leaf(0.40f)));

            // 5) 有效签名 → 极低概率（签名仲裁前置，这里仅作模型投票）
            trees.Add(Tree(
                Node(EXT + 0, 0.5f, 1, 2),
                Leaf(0.35f),
                Leaf(0.05f)));

            // 6) 无导入 + PE 有效（手搓/反射加载载荷）
            trees.Add(Tree(
                Node(GEN + 6, 0.01f, 2, 1),
                Leaf(0.12f),
                Node(GEN + 1, 0.5f, 3, 4),
                Leaf(0.30f),
                Leaf(0.60f)));

            // 7) 空节区名（加壳/手工构造）
            trees.Add(Tree(
                Node(EXT + 15, 0.5f, 1, 2),
                Leaf(0.15f),
                Leaf(0.72f)));

            // 8) 大 Overlay（附加数据隐藏载荷）
            trees.Add(Tree(
                Node(EXT + 13, 0.2f, 1, 2),
                Leaf(0.12f),
                Leaf(0.62f)));

            // 9) 节区数量异常多
            trees.Add(Tree(
                Node(GEN + 5, 0.5f, 1, 2),
                Leaf(0.12f),
                Leaf(0.42f)));

            // 10) TLS 回调（反调试/早期执行）
            trees.Add(Tree(
                Node(EXT + 3, 0.5f, 1, 2),
                Leaf(0.12f),
                Leaf(0.60f)));

            // 11) 入口点不在任何节区（异常布局）
            trees.Add(Tree(
                Node(EXT + 10, 0.5f, 1, 2),
                Leaf(0.12f),
                Leaf(0.68f)));

            // 12) 调试目录（正常发布软件大多带 PDB 记录）
            trees.Add(Tree(
                Node(EXT + 2, 0.5f, 1, 2),
                Leaf(0.20f),
                Leaf(0.10f)));

            // 13) 高 URL 字符串密度（下载器）
            trees.Add(Tree(
                Node(STR + 3, 0.02f, 1, 2),
                Leaf(0.12f),
                Leaf(0.55f)));

            // 14) 高注册表字符串密度（持久化/篡改）
            trees.Add(Tree(
                Node(STR + 5, 0.02f, 1, 2),
                Leaf(0.12f),
                Leaf(0.55f)));

            // 15) 导出极少 + 节区可执行（DLL 注入载体）
            trees.Add(Tree(
                Node(GEN + 7, 0.001f, 2, 1),
                Leaf(0.15f),
                Node(SEC + 4, 0.5f, 3, 4),
                Leaf(0.20f),
                Leaf(0.50f)));

            // 16) 64 位 + 大体积（正常大型程序偏多）
            trees.Add(Tree(
                Node(GEN + 9, 0.5f, 1, 2),
                Leaf(0.20f),
                Leaf(0.12f)));

            // 17) 可打印字符串比例低（混淆/加密载荷）
            trees.Add(Tree(
                Node(STR + 2, 0.98f, 1, 2),
                Leaf(0.22f),
                Leaf(0.12f)));

            // 18) 时间戳为零（手工构造/擦除）
            trees.Add(Tree(
                Node(GEN + 11, 0.0001f, 1, 2),
                Leaf(0.50f),
                Leaf(0.12f)));

            // 19) 第 2 节区熵极高（加密/压缩）
            trees.Add(Tree(
                Node(SEC + 11, 0.9f, 1, 2),
                Leaf(0.18f),
                Leaf(0.72f)));

            // 20) 兜底（无信息时输出中性偏低）
            trees.Add(Tree(
                Node(GEN + 0, 0.00001f, 1, 2),
                Leaf(0.30f),
                Leaf(0.20f)));

            return model;
        }

        /// <summary>
        /// 导出内置专家树模型到文件（供阈值校准落盘，或作为在线模型的初始模板）。
        /// 导出后 Melix 会按"在线模型"加载（含校准后的 Threshold）。
        /// </summary>
        public static bool SaveBuiltinModel(string modelPath, double threshold, out string error)
        {
            error = "";
            try
            {
                if (string.IsNullOrWhiteSpace(modelPath)) { error = "模型路径为空"; return false; }
                var model = BuildExpertModel();
                model.Threshold = threshold;
                Directory.CreateDirectory(Path.GetDirectoryName(modelPath) ?? ".");
                File.WriteAllText(modelPath, JsonSerializer.Serialize(model,
                    new JsonSerializerOptions { WriteIndented = true }));
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                    $"[Melix] 内置专家树已导出: {modelPath}（阈值 {threshold:F3}）");
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static MelixNode Node(int feature, float threshold, int left, int right) =>
            new MelixNode { Feature = feature, Threshold = threshold, Left = left, Right = right, IsLeaf = false };

        private static MelixNode Leaf(float value) =>
            new MelixNode { IsLeaf = true, Leaf = value };

        private static MelixTree Tree(params MelixNode[] nodes) => new MelixTree { Nodes = nodes.ToList() };
    }
}