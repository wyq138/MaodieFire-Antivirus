using FireAntivirus.Common;
using FireAntivirus.Data;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace FireAntivirus.Services
{
    public class MachineLearning
    {
        private readonly string _modelDirectory;
        private readonly string _dataDirectory;
        private readonly int _maxFileSize;
        private readonly int _featureVectorSize;

        public MachineLearning(string modelDirectory, string dataDirectory, int maxFileSize = 1048576, int featureVectorSize = 1024)
        {
            _modelDirectory = modelDirectory;
            _dataDirectory = dataDirectory;
            _maxFileSize = maxFileSize;
            _featureVectorSize = featureVectorSize;

            if (!Directory.Exists(modelDirectory))
            {
                Directory.CreateDirectory(modelDirectory);
            }

            if (!Directory.Exists(dataDirectory))
            {
                Directory.CreateDirectory(dataDirectory);
            }
        }

        public async Task<MLDetectionResult> DetectMalwareAsync(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found", filePath);
            }

            try
            {
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > _maxFileSize)
                {
                    return new MLDetectionResult
                    {
                        IsMalicious = false,
                        Confidence = 0.0,
                        DetectionTime = DateTime.UtcNow,
                        Message = "File too large for ML analysis"
                    };
                }

                var features = await ExtractFeaturesAsync(filePath);
                var model = LoadModel();
                var prediction = Predict(model, features);

                return new MLDetectionResult
                {
                    IsMalicious = prediction.IsMalicious,
                    Confidence = prediction.Confidence,
                    DetectionTime = DateTime.UtcNow,
                    Features = features,
                    ModelVersion = model.Version
                };
            }
            catch (Exception ex)
            {
                Logger.Error($"ML detection error: {ex.Message}");
                return new MLDetectionResult
                {
                    IsMalicious = false,
                    Confidence = 0.0,
                    DetectionTime = DateTime.UtcNow,
                    Message = $"Error during ML analysis: {ex.Message}"
                };
            }
        }

        public async Task<MLModel> TrainModelAsync(string trainingDataPath, string modelName)
        {
            try
            {
                var trainingData = await LoadTrainingDataAsync(trainingDataPath);
                var model = await TrainModelInternalAsync(trainingData);
                await SaveModelAsync(model, modelName);
                return model;
            }
            catch (Exception ex)
            {
                Logger.Error($"Model training error: {ex.Message}");
                throw;
            }
        }

        public async Task<MLModel> LoadModelAsync(string modelName)
        {
            try
            {
                var modelPath = Path.Combine(_modelDirectory, $"{modelName}.model");
                if (!File.Exists(modelPath))
                {
                    throw new FileNotFoundException("Model not found", modelPath);
                }

                // 从 JSON 文件真实反序列化完整模型（含训练得到的参数）
                var json = await File.ReadAllTextAsync(modelPath);
                var model = JsonSerializer.Deserialize<MLModel>(json);
                if (model == null)
                {
                    throw new InvalidOperationException($"Model file is corrupted: {modelPath}");
                }

                return model;
            }
            catch (Exception ex)
            {
                Logger.Error($"Model loading error: {ex.Message}");
                throw;
            }
        }

        public async Task UpdateModelAsync(string modelName, string newTrainingDataPath)
        {
            try
            {
                var existingModel = await LoadModelAsync(modelName);
                var newTrainingData = await LoadTrainingDataAsync(newTrainingDataPath);
                var updatedModel = await RetrainModelAsync(existingModel, newTrainingData);
                await SaveModelAsync(updatedModel, modelName);
            }
            catch (Exception ex)
            {
                Logger.Error($"Model update error: {ex.Message}");
                throw;
            }
        }

        public async Task<MLModelEvaluation> EvaluateModelAsync(string modelName, string testDataPath)
        {
            try
            {
                var model = await LoadModelAsync(modelName);
                var testData = await LoadTrainingDataAsync(testDataPath);
                var evaluation = await EvaluateModelInternalAsync(model, testData);
                return evaluation;
            }
            catch (Exception ex)
            {
                Logger.Error($"Model evaluation error: {ex.Message}");
                throw;
            }
        }

        public async Task<List<MLFeature>> ExtractFeaturesAsync(string filePath)
        {
            var features = new List<MLFeature>();

            try
            {
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    // 文件大小特征
                    var fileSize = new FileInfo(filePath).Length;
                    features.Add(new MLFeature { Name = "FileSize", Value = fileSize / (double)1024, Type = FeatureType.Numeric });

                    // 文件头特征
                    var headerBytes = new byte[16];
                    fileStream.ReadExactly(headerBytes, 0, headerBytes.Length);
                    var headerHex = BitConverter.ToString(headerBytes).Replace("-", "").ToLower();
                    features.Add(new MLFeature { Name = "FileHeader", Value = headerHex.GetHashCode() / (double)int.MaxValue, Type = FeatureType.Numeric });

                    // 熵值特征
                    fileStream.Position = 0;
                    var entropy = CalculateEntropy(fileStream);
                    features.Add(new MLFeature { Name = "Entropy", Value = entropy, Type = FeatureType.Numeric });

                    // 字符串特征
                    fileStream.Position = 0;
                    var stringFeatures = ExtractStringFeatures(fileStream);
                    features.AddRange(stringFeatures);

                    // 导入表特征
                    var importFeatures = ExtractImportFeatures(filePath);
                    features.AddRange(importFeatures);

                    // 节表特征
                    var sectionFeatures = ExtractSectionFeatures(filePath);
                    features.AddRange(sectionFeatures);

                    // 补足特征向量大小
                    while (features.Count < _featureVectorSize)
                    {
                        features.Add(new MLFeature { Name = $"Padding{features.Count}", Value = 0, Type = FeatureType.Numeric });
                    }

                    // 截断特征向量
                    if (features.Count > _featureVectorSize)
                    {
                        features = features.Take(_featureVectorSize).ToList();
                    }
                }

                return features;
            }
            catch (Exception ex)
            {
                Logger.Error($"Feature extraction error: {ex.Message}");
                // 返回默认特征
                return Enumerable.Range(0, _featureVectorSize)
                    .Select(i => new MLFeature { Name = $"Default{i}", Value = 0, Type = FeatureType.Numeric })
                    .ToList();
            }
        }

        private MLModel LoadModel()
        {
            try
            {
                var defaultModelPath = Path.Combine(_modelDirectory, "default.model");
                if (File.Exists(defaultModelPath))
                {
                    return LoadModelAsync("default").Result;
                }

                // 创建默认模型
                var defaultModel = new MLModel
                {
                    Name = "default",
                    Version = "1.0.0.0",
                    TrainingDate = DateTime.UtcNow,
                    FeatureCount = _featureVectorSize
                };

                SaveModelAsync(defaultModel, "default").Wait();
                return defaultModel;
            }
            catch (Exception ex)
            {
                Logger.Error($"Default model loading error: {ex.Message}");
                return new MLModel
                {
                    Name = "default",
                    Version = "1.0.0.0",
                    TrainingDate = DateTime.UtcNow,
                    FeatureCount = _featureVectorSize
                };
            }
        }

        private MLPrediction Predict(MLModel model, List<MLFeature> features)
        {
            try
            {
                // 优先使用训练得到的逻辑回归参数进行真实推断
                if (model.Parameters.TryGetValue("weights", out var weightsObj) &&
                    model.Parameters.TryGetValue("bias", out var biasObj) &&
                    model.Parameters.TryGetValue("features", out var featureNamesObj))
                {
                    var weights = ParseDoubleList(weightsObj?.ToString());
                    double.TryParse(biasObj?.ToString(), System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out var bias);
                    var featureNames = featureNamesObj?.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();

                    if (weights.Length > 0 && weights.Length == featureNames.Length)
                    {
                        var featureMap = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
                        foreach (var feature in features)
                            featureMap[feature.Name] = feature.Value;

                        double z = bias;
                        for (int i = 0; i < featureNames.Length; i++)
                        {
                            featureMap.TryGetValue(featureNames[i], out var value);
                            z += weights[i] * value;
                        }

                        // sigmoid(z)，对超大输入做数值稳定处理
                        double probability = 1.0 / (1.0 + Math.Exp(-Math.Max(Math.Min(z, 30), -30)));

                        return new MLPrediction
                        {
                            IsMalicious = probability >= 0.5,
                            Confidence = Math.Abs(probability - 0.5) * 2
                        };
                    }
                }

                // 模型尚未训练时的启发式回退（全部基于真实提取的特征值）
                var maliciousScore = 0.0;

                var entropyFeature = features.FirstOrDefault(f => f.Name == "Entropy");
                if (entropyFeature != null && entropyFeature.Value > 7.0)
                {
                    maliciousScore += 0.3;
                }

                var suspiciousStringsFeature = features.FirstOrDefault(f => f.Name == "SuspiciousStringCount");
                if (suspiciousStringsFeature != null && suspiciousStringsFeature.Value > 0)
                {
                    maliciousScore += Math.Min(suspiciousStringsFeature.Value * 0.1, 0.3);
                }

                var suspiciousImportsFeature = features.FirstOrDefault(f => f.Name == "HasSuspiciousImports");
                if (suspiciousImportsFeature != null && suspiciousImportsFeature.Value > 0.5)
                {
                    maliciousScore += 0.3;
                }

                var fileSizeFeature = features.FirstOrDefault(f => f.Name == "FileSize");
                if (fileSizeFeature != null)
                {
                    if (fileSizeFeature.Value < 10.0)
                    {
                        maliciousScore += 0.2;
                    }
                    else if (fileSizeFeature.Value > 10000.0)
                    {
                        maliciousScore += 0.1;
                    }
                }

                var isMalicious = maliciousScore > 0.5;
                var confidence = Math.Min(maliciousScore, 1.0);

                return new MLPrediction
                {
                    IsMalicious = isMalicious,
                    Confidence = confidence
                };
            }
            catch (Exception ex)
            {
                Logger.Error($"Prediction error: {ex.Message}");
                return new MLPrediction
                {
                    IsMalicious = false,
                    Confidence = 0.0
                };
            }
        }

        private async Task<List<MLTrainingSample>> LoadTrainingDataAsync(string dataPath)
        {
            var samples = new List<MLTrainingSample>();

            try
            {
                if (Directory.Exists(dataPath))
                {
                    var maliciousFiles = Directory.GetFiles(Path.Combine(dataPath, "malicious"), "*.*", SearchOption.AllDirectories);
                    var benignFiles = Directory.GetFiles(Path.Combine(dataPath, "benign"), "*.*", SearchOption.AllDirectories);

                    foreach (var file in maliciousFiles)
                    {
                        var features = await ExtractFeaturesAsync(file);
                        samples.Add(new MLTrainingSample { Features = features, IsMalicious = true });
                    }

                    foreach (var file in benignFiles)
                    {
                        var features = await ExtractFeaturesAsync(file);
                        samples.Add(new MLTrainingSample { Features = features, IsMalicious = false });
                    }
                }
                else if (File.Exists(dataPath))
                {
                    // 真实解析训练数据文件，支持两种行格式：
                    //   格式一（命名特征）: label,name1=v1,name2=v2,...
                    //   格式二（纯数值）  : label,v1,v2,v3,...（特征名自动编号为 f0,f1,...）
                    // 标签取值：1/true/malicious/malware 表示恶意，0/false/benign/clean 表示良性
                    foreach (var line in File.ReadLines(dataPath))
                    {
                        var trimmedLine = line.Trim();
                        if (trimmedLine.Length == 0 || trimmedLine.StartsWith("#")) continue;

                        var tokens = trimmedLine.Split(',');
                        if (tokens.Length < 2) continue;

                        var label = tokens[0].Trim();
                        bool isMalicious;
                        if (label.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                            label.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                            label.Equals("malicious", StringComparison.OrdinalIgnoreCase) ||
                            label.Equals("malware", StringComparison.OrdinalIgnoreCase))
                        {
                            isMalicious = true;
                        }
                        else if (label.Equals("0", StringComparison.OrdinalIgnoreCase) ||
                                 label.Equals("false", StringComparison.OrdinalIgnoreCase) ||
                                 label.Equals("benign", StringComparison.OrdinalIgnoreCase) ||
                                 label.Equals("clean", StringComparison.OrdinalIgnoreCase))
                        {
                            isMalicious = false;
                        }
                        else
                        {
                            continue;
                        }

                        var sampleFeatures = new List<MLFeature>();
                        for (int i = 1; i < tokens.Length; i++)
                        {
                            var token = tokens[i].Trim();
                            if (token.Length == 0) continue;

                            int eqIndex = token.IndexOf('=');
                            if (eqIndex > 0 &&
                                double.TryParse(token.Substring(eqIndex + 1), System.Globalization.NumberStyles.Float,
                                    System.Globalization.CultureInfo.InvariantCulture, out var namedValue))
                            {
                                sampleFeatures.Add(new MLFeature { Name = token.Substring(0, eqIndex).Trim(), Value = namedValue, Type = FeatureType.Numeric });
                            }
                            else if (double.TryParse(token, System.Globalization.NumberStyles.Float,
                                System.Globalization.CultureInfo.InvariantCulture, out var value))
                            {
                                sampleFeatures.Add(new MLFeature { Name = $"f{i - 1}", Value = value, Type = FeatureType.Numeric });
                            }
                        }

                        if (sampleFeatures.Count > 0)
                        {
                            samples.Add(new MLTrainingSample { Features = sampleFeatures, IsMalicious = isMalicious });
                        }
                    }
                }

                return samples;
            }
            catch (Exception ex)
            {
                Logger.Error($"Loading training data error: {ex.Message}");
                return samples;
            }
        }

        private async Task<MLModel> TrainModelInternalAsync(List<MLTrainingSample> trainingData)
        {
            return await Task.Run(() =>
            {
                if (trainingData == null || trainingData.Count == 0)
                    throw new InvalidOperationException("No training data available");

                // 收集特征名空间（排序保证权重顺序稳定可复现）
                var featureNames = trainingData
                    .SelectMany(s => s.Features)
                    .Select(f => f.Name)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                var featureIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < featureNames.Length; i++)
                    featureIndex[featureNames[i]] = i;

                // 构建训练矩阵与标签
                var X = new double[trainingData.Count][];
                var y = new double[trainingData.Count];
                for (int row = 0; row < trainingData.Count; row++)
                {
                    var vector = new double[featureNames.Length];
                    foreach (var feature in trainingData[row].Features)
                    {
                        if (featureIndex.TryGetValue(feature.Name, out var idx))
                            vector[idx] = feature.Value;
                    }
                    X[row] = vector;
                    y[row] = trainingData[row].IsMalicious ? 1.0 : 0.0;
                }

                var (weights, bias) = TrainLogisticRegression(X, y, new double[featureNames.Length], 0.0);

                var model = new MLModel
                {
                    Name = "trained_model",
                    Version = "1.0.0.0",
                    TrainingDate = DateTime.UtcNow,
                    FeatureCount = _featureVectorSize,
                    TrainingSampleCount = trainingData.Count
                };
                model.Parameters["features"] = string.Join(",", featureNames);
                model.Parameters["weights"] = string.Join(",", weights.Select(w => w.ToString("R", System.Globalization.CultureInfo.InvariantCulture)));
                model.Parameters["bias"] = bias.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
                model.Parameters["algorithm"] = "logistic-regression-sgd";

                return model;
            });
        }

        private async Task<MLModel> RetrainModelAsync(MLModel existingModel, List<MLTrainingSample> newTrainingData)
        {
            return await Task.Run(() =>
            {
                if (newTrainingData == null || newTrainingData.Count == 0)
                    throw new InvalidOperationException("No new training data available");

                // 读取现有模型的特征空间与权重作为初始值（warm start），在新数据上继续优化
                string[] featureNames = null;
                double[] initialWeights = null;
                double initialBias = 0.0;

                if (existingModel != null &&
                    existingModel.Parameters.TryGetValue("features", out var featObj) &&
                    existingModel.Parameters.TryGetValue("weights", out var weightObj) &&
                    existingModel.Parameters.TryGetValue("bias", out var biasObj))
                {
                    featureNames = featObj?.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries);
                    initialWeights = ParseDoubleList(weightObj?.ToString());
                    double.TryParse(biasObj?.ToString(), System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out initialBias);
                }

                if (featureNames == null || initialWeights == null || featureNames.Length != initialWeights.Length)
                {
                    featureNames = newTrainingData.SelectMany(s => s.Features).Select(f => f.Name)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                    initialWeights = new double[featureNames.Length];
                }

                var featureIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < featureNames.Length; i++)
                    featureIndex[featureNames[i]] = i;

                var X = new double[newTrainingData.Count][];
                var y = new double[newTrainingData.Count];
                for (int row = 0; row < newTrainingData.Count; row++)
                {
                    var vector = new double[featureNames.Length];
                    foreach (var feature in newTrainingData[row].Features)
                    {
                        if (featureIndex.TryGetValue(feature.Name, out var idx))
                            vector[idx] = feature.Value;
                    }
                    X[row] = vector;
                    y[row] = newTrainingData[row].IsMalicious ? 1.0 : 0.0;
                }

                var (weights, bias) = TrainLogisticRegression(X, y, initialWeights, initialBias);

                var updatedModel = new MLModel
                {
                    Name = existingModel?.Name ?? "trained_model",
                    Version = $"1.0.{DateTime.UtcNow.Ticks % 100000}",
                    TrainingDate = DateTime.UtcNow,
                    FeatureCount = _featureVectorSize,
                    TrainingSampleCount = (existingModel?.TrainingSampleCount ?? 0) + newTrainingData.Count
                };
                updatedModel.Parameters["features"] = string.Join(",", featureNames);
                updatedModel.Parameters["weights"] = string.Join(",", weights.Select(w => w.ToString("R", System.Globalization.CultureInfo.InvariantCulture)));
                updatedModel.Parameters["bias"] = bias.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
                updatedModel.Parameters["algorithm"] = "logistic-regression-sgd";

                return updatedModel;
            });
        }

        private async Task<MLModelEvaluation> EvaluateModelInternalAsync(MLModel model, List<MLTrainingSample> testData)
        {
            try
            {
                int truePositives = 0;
                int falsePositives = 0;
                int trueNegatives = 0;
                int falseNegatives = 0;

                foreach (var sample in testData)
                {
                    var prediction = Predict(model, sample.Features);
                    if (sample.IsMalicious)
                    {
                        if (prediction.IsMalicious)
                        {
                            truePositives++;
                        }
                        else
                        {
                            falseNegatives++;
                        }
                    }
                    else
                    {
                        if (prediction.IsMalicious)
                        {
                            falsePositives++;
                        }
                        else
                        {
                            trueNegatives++;
                        }
                    }
                }

                var accuracy = (double)(truePositives + trueNegatives) / testData.Count;
                var precision = truePositives > 0 ? (double)truePositives / (truePositives + falsePositives) : 0;
                var recall = truePositives > 0 ? (double)truePositives / (truePositives + falseNegatives) : 0;
                var f1Score = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;

                return new MLModelEvaluation
                {
                    ModelName = model.Name,
                    ModelVersion = model.Version,
                    TestSampleCount = testData.Count,
                    TruePositives = truePositives,
                    FalsePositives = falsePositives,
                    TrueNegatives = trueNegatives,
                    FalseNegatives = falseNegatives,
                    Accuracy = accuracy,
                    Precision = precision,
                    Recall = recall,
                    F1Score = f1Score,
                    EvaluationDate = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                Logger.Error($"Evaluation error: {ex.Message}");
                throw;
            }
        }

        private async Task SaveModelAsync(MLModel model, string modelName)
        {
            try
            {
                var modelPath = Path.Combine(_modelDirectory, $"{modelName}.model");

                // 完整序列化模型元数据与训练参数（JSON 格式，LoadModelAsync 可直接反序列化）
                var options = new JsonSerializerOptions { WriteIndented = true };
                var json = JsonSerializer.Serialize(model, options);
                await File.WriteAllTextAsync(modelPath, json);
            }
            catch (Exception ex)
            {
                Logger.Error($"Model saving error: {ex.Message}");
                throw;
            }
        }

        private double CalculateEntropy(Stream stream)
        {
            try
            {
                var buffer = new byte[4096];
                var counts = new long[256];
                int bytesRead;
                long totalBytes = 0;

                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    for (int i = 0; i < bytesRead; i++)
                    {
                        counts[buffer[i]]++;
                    }
                    totalBytes += bytesRead;
                }

                double entropy = 0.0;
                for (int i = 0; i < 256; i++)
                {
                    if (counts[i] > 0)
                    {
                        double probability = (double)counts[i] / totalBytes;
                        entropy -= probability * Math.Log(probability, 2);
                    }
                }

                return entropy;
            }
            catch
            {
                return 0.0;
            }
        }

        private List<MLFeature> ExtractStringFeatures(Stream stream)
        {
            var features = new List<MLFeature>();

            try
            {
                var buffer = new byte[4096];
                var asciiChars = new List<char>();
                var extractedStrings = new List<string>();
                int bytesRead;

                // 真实提取全部可读字符串（长度>=5）
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    for (int i = 0; i < bytesRead; i++)
                    {
                        if (buffer[i] >= 32 && buffer[i] <= 126)
                        {
                            asciiChars.Add((char)buffer[i]);
                        }
                        else
                        {
                            if (asciiChars.Count >= 5)
                            {
                                extractedStrings.Add(new string(asciiChars.ToArray()));
                            }
                            asciiChars.Clear();
                        }
                    }
                }

                if (asciiChars.Count >= 5)
                {
                    extractedStrings.Add(new string(asciiChars.ToArray()));
                }

                features.Add(new MLFeature { Name = "LongString", Value = extractedStrings.Count, Type = FeatureType.Numeric });

                // 在提取的字符串中统计可疑关键字命中数
                var suspiciousKeywords = new List<string> { "malware", "virus", "trojan", "ransom", "encrypt", "steal", "password", "keylog", "backdoor", "rootkit", "botnet", "payload" };
                int suspiciousHits = 0;
                foreach (var text in extractedStrings)
                {
                    var lower = text.ToLowerInvariant();
                    foreach (var keyword in suspiciousKeywords)
                    {
                        if (lower.Contains(keyword))
                        {
                            suspiciousHits++;
                            break;
                        }
                    }
                }

                features.Add(new MLFeature { Name = "SuspiciousStringCount", Value = suspiciousHits, Type = FeatureType.Numeric });
            }
            catch
            {
                return features;
            }

            return features;
        }

        private List<MLFeature> ExtractImportFeatures(string filePath)
        {
            var features = new List<MLFeature>();

            try
            {
                // 真实解析 PE 导入表（DOS头 -> PE头 -> 数据目录 -> 导入目录）
                var peInfo = PeFileParser.Parse(filePath);
                features.Add(new MLFeature { Name = "ImportCount", Value = peInfo.ImportFunctionCount, Type = FeatureType.Numeric });
                features.Add(new MLFeature { Name = "ImportDllCount", Value = peInfo.ImportDllCount, Type = FeatureType.Numeric });
                features.Add(new MLFeature { Name = "HasSuspiciousImports", Value = peInfo.HasSuspiciousImports ? 1.0 : 0.0, Type = FeatureType.Numeric });
            }
            catch
            {
                features.Add(new MLFeature { Name = "ImportCount", Value = 0.0, Type = FeatureType.Numeric });
                features.Add(new MLFeature { Name = "ImportDllCount", Value = 0.0, Type = FeatureType.Numeric });
                features.Add(new MLFeature { Name = "HasSuspiciousImports", Value = 0.0, Type = FeatureType.Numeric });
            }

            return features;
        }

        private List<MLFeature> ExtractSectionFeatures(string filePath)
        {
            var features = new List<MLFeature>();

            try
            {
                // 真实解析 PE 节表（数量、可写可执行节、节熵）
                var peInfo = PeFileParser.Parse(filePath);
                features.Add(new MLFeature { Name = "SectionCount", Value = peInfo.SectionCount, Type = FeatureType.Numeric });
                features.Add(new MLFeature { Name = "HasWritableExecutableSection", Value = peInfo.HasWritableExecutableSection ? 1.0 : 0.0, Type = FeatureType.Numeric });
                features.Add(new MLFeature { Name = "MaxSectionEntropy", Value = peInfo.MaxSectionEntropy, Type = FeatureType.Numeric });
            }
            catch
            {
                features.Add(new MLFeature { Name = "SectionCount", Value = 0.0, Type = FeatureType.Numeric });
                features.Add(new MLFeature { Name = "HasWritableExecutableSection", Value = 0.0, Type = FeatureType.Numeric });
                features.Add(new MLFeature { Name = "MaxSectionEntropy", Value = 0.0, Type = FeatureType.Numeric });
            }

            return features;
        }

        private static double[] ParseDoubleList(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return Array.Empty<double>();

            return text.Split(',')
                .Select(t => double.TryParse(t.Trim(), System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var value) ? value : 0.0)
                .ToArray();
        }

        /// <summary>
        /// 逻辑回归训练（SGD + L2 正则，固定随机种子保证结果可复现）
        /// </summary>
        private static (double[] Weights, double Bias) TrainLogisticRegression(
            double[][] X, double[] y, double[] initialWeights, double initialBias)
        {
            int featureCount = initialWeights.Length;
            var weights = (double[])initialWeights.Clone();
            double bias = initialBias;

            const double learningRate = 0.05;
            const double l2Lambda = 1e-4;
            const int epochs = 200;

            var rng = new Random(42);
            var order = Enumerable.Range(0, X.Length).ToArray();

            for (int epoch = 0; epoch < epochs; epoch++)
            {
                for (int i = order.Length - 1; i > 0; i--)
                {
                    int j = rng.Next(i + 1);
                    (order[i], order[j]) = (order[j], order[i]);
                }

                foreach (var row in order)
                {
                    double z = bias;
                    for (int i = 0; i < featureCount; i++)
                        z += weights[i] * X[row][i];

                    double prediction = 1.0 / (1.0 + Math.Exp(-Math.Max(Math.Min(z, 30), -30)));
                    double error = prediction - y[row];

                    for (int i = 0; i < featureCount; i++)
                        weights[i] -= learningRate * (error * X[row][i] + l2Lambda * weights[i]);
                    bias -= learningRate * error;
                }
            }

            return (weights, bias);
        }
    }

    /// <summary>
    /// 轻量 PE 文件解析器：纯托管实现，解析节表与导入表
    /// </summary>
    internal static class PeFileParser
    {
        public sealed class PeInfo
        {
            public bool IsValidPe;
            public int SectionCount;
            public bool HasWritableExecutableSection;
            public double MaxSectionEntropy;
            public int ImportDllCount;
            public int ImportFunctionCount;
            public bool HasSuspiciousImports;
        }

        private static readonly HashSet<string> SuspiciousImports = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
            "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress",
            "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
            "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
            "CryptEncrypt", "CryptEncryptMessage", "RegSetValueExA", "RegSetValueExW",
            "SetWindowsHookExA", "SetWindowsHookExW", "NtUnmapViewOfSection", "ZwUnmapViewOfSection"
        };

        private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

        public static PeInfo Parse(string filePath)
        {
            var info = new PeInfo();

            try
            {
                byte[] data;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (fs.Length < 0x200) return info;

                    var length = (int)Math.Min(fs.Length, 8L * 1024 * 1024);
                    data = new byte[length];
                    int read = 0;
                    while (read < length)
                    {
                        int n = fs.Read(data, read, length - read);
                        if (n <= 0) break;
                        read += n;
                    }
                    if (read < length) Array.Resize(ref data, read);
                }

                if (data.Length < 0x40) return info;

                int peOffset = BitConverter.ToInt32(data, 0x3C);
                if (peOffset <= 0 || peOffset + 24 > data.Length) return info;
                if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
                    return info;

                info.IsValidPe = true;

                int coffOffset = peOffset + 4;
                ushort sectionCount = BitConverter.ToUInt16(data, coffOffset + 2);
                ushort optionalHeaderSize = BitConverter.ToUInt16(data, coffOffset + 16);
                int optionalOffset = coffOffset + 20;

                if (optionalOffset + 2 > data.Length) return info;

                ushort magic = BitConverter.ToUInt16(data, optionalOffset);
                int dataDirectoryOffset;
                int thunkSize;
                if (magic == 0x20B) { dataDirectoryOffset = optionalOffset + 112; thunkSize = 8; }   // PE32+
                else if (magic == 0x10B) { dataDirectoryOffset = optionalOffset + 96; thunkSize = 4; } // PE32
                else return info;

                if (dataDirectoryOffset + 8 > data.Length) return info;
                uint importRva = BitConverter.ToUInt32(data, dataDirectoryOffset + 8);

                int sectionTableOffset = optionalOffset + optionalHeaderSize;

                // 解析节表
                for (int i = 0; i < sectionCount; i++)
                {
                    int secOffset = sectionTableOffset + i * 40;
                    if (secOffset + 40 > data.Length) break;

                    uint virtualSize = BitConverter.ToUInt32(data, secOffset + 8);
                    uint virtualAddress = BitConverter.ToUInt32(data, secOffset + 12);
                    uint rawSize = BitConverter.ToUInt32(data, secOffset + 16);
                    uint rawPointer = BitConverter.ToUInt32(data, secOffset + 20);
                    uint characteristics = BitConverter.ToUInt32(data, secOffset + 36);

                    info.SectionCount++;

                    if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && (characteristics & IMAGE_SCN_MEM_WRITE) != 0)
                        info.HasWritableExecutableSection = true;

                    // 计算节数据熵（最多取前64KB）
                    if (rawPointer < (ulong)data.Length && rawSize > 256)
                    {
                        int len = (int)Math.Min((long)rawSize, Math.Min(65536L, data.Length - (long)rawPointer));
                        if (len > 256)
                        {
                            double entropy = ComputeEntropy(data, (int)rawPointer, len);
                            if (entropy > info.MaxSectionEntropy) info.MaxSectionEntropy = entropy;
                        }
                    }
                }

                // 解析导入表
                if (importRva != 0)
                {
                    int importOffset = RvaToOffset(data, importRva, sectionTableOffset, sectionCount);
                    int guard = 0;

                    while (importOffset >= 0 && importOffset + 20 <= data.Length && guard++ < 4096)
                    {
                        uint originalFirstThunk = BitConverter.ToUInt32(data, importOffset);
                        uint nameRva = BitConverter.ToUInt32(data, importOffset + 12);
                        uint firstThunk = BitConverter.ToUInt32(data, importOffset + 16);

                        if (nameRva == 0 && firstThunk == 0) break;

                        int nameOffset = RvaToOffset(data, nameRva, sectionTableOffset, sectionCount);
                        var dllName = nameOffset >= 0 ? ReadAsciiName(data, nameOffset) : null;
                        if (!string.IsNullOrEmpty(dllName))
                            info.ImportDllCount++;

                        uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                        int thunkOffset = RvaToOffset(data, thunkRva, sectionTableOffset, sectionCount);
                        int thunkGuard = 0;

                        while (thunkOffset >= 0 && thunkOffset + thunkSize <= data.Length && thunkGuard++ < 65536)
                        {
                            uint thunkValue = thunkSize == 8
                                ? (uint)(BitConverter.ToUInt64(data, thunkOffset) & 0xFFFFFFFF)   // PE32+ 取低32位（RVA）
                                : BitConverter.ToUInt32(data, thunkOffset);

                            if (thunkValue == 0) break;

                            if ((thunkValue & 0x80000000) == 0)
                            {
                                int fnOffset = RvaToOffset(data, thunkValue, sectionTableOffset, sectionCount);
                                if (fnOffset >= 0 && fnOffset + 2 <= data.Length)
                                {
                                    var functionName = ReadAsciiName(data, fnOffset + 2);
                                    if (!string.IsNullOrEmpty(functionName))
                                    {
                                        info.ImportFunctionCount++;
                                        if (SuspiciousImports.Contains(functionName))
                                            info.HasSuspiciousImports = true;
                                    }
                                }
                            }
                            else
                            {
                                info.ImportFunctionCount++;
                            }

                            thunkOffset += thunkSize;
                        }

                        importOffset += 20;
                    }
                }
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }

            return info;
        }

        private static int RvaToOffset(byte[] data, uint rva, int sectionTableOffset, int sectionCount)
        {
            for (int i = 0; i < sectionCount; i++)
            {
                int secOffset = sectionTableOffset + i * 40;
                if (secOffset + 40 > data.Length) break;

                uint virtualSize = BitConverter.ToUInt32(data, secOffset + 8);
                uint virtualAddress = BitConverter.ToUInt32(data, secOffset + 12);
                uint rawSize = BitConverter.ToUInt32(data, secOffset + 16);
                uint rawPointer = BitConverter.ToUInt32(data, secOffset + 20);

                if (rva >= virtualAddress && rva < virtualAddress + Math.Max(virtualSize, rawSize))
                {
                    long delta = rva - virtualAddress;
                    if (delta < rawSize && rawPointer + delta < data.Length)
                        return (int)(rawPointer + delta);
                }
            }

            return -1;
        }

        private static string ReadAsciiName(byte[] data, int offset, int maxLength = 256)
        {
            if (offset < 0 || offset >= data.Length) return null;

            int end = offset;
            while (end < data.Length && end < offset + maxLength && data[end] != 0) end++;

            return end > offset ? Encoding.ASCII.GetString(data, offset, end - offset) : null;
        }

        private static double ComputeEntropy(byte[] data, int offset, int length)
        {
            var counts = new long[256];
            for (int i = 0; i < length; i++)
                counts[data[offset + i]]++;

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double p = (double)counts[i] / length;
                    entropy -= p * Math.Log(p, 2);
                }
            }

            return entropy;
        }
    }

    public class MLModel
    {
        public string Name { get; set; }
        public string Version { get; set; }
        public DateTime TrainingDate { get; set; }
        public int FeatureCount { get; set; }
        public int TrainingSampleCount { get; set; }
        public Dictionary<string, object> Parameters { get; set; } = new Dictionary<string, object>();
    }

    public class MLFeature
    {
        public string Name { get; set; }
        public double Value { get; set; }
        public FeatureType Type { get; set; }
    }

    public class MLTrainingSample
    {
        public List<MLFeature> Features { get; set; } = new List<MLFeature>();
        public bool IsMalicious { get; set; }
    }

    public class MLPrediction
    {
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
    }

    public class MLDetectionResult
    {
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
        public DateTime DetectionTime { get; set; }
        public List<MLFeature> Features { get; set; } = new List<MLFeature>();
        public string ModelVersion { get; set; }
        public string Message { get; set; }
    }

    public class MLModelEvaluation
    {
        public string ModelName { get; set; }
        public string ModelVersion { get; set; }
        public int TestSampleCount { get; set; }
        public int TruePositives { get; set; }
        public int FalsePositives { get; set; }
        public int TrueNegatives { get; set; }
        public int FalseNegatives { get; set; }
        public double Accuracy { get; set; }
        public double Precision { get; set; }
        public double Recall { get; set; }
        public double F1Score { get; set; }
        public DateTime EvaluationDate { get; set; }
    }

    public enum FeatureType
    {
        Numeric,
        Categorical,
        Binary
    }
}
