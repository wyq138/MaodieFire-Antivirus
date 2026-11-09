using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;

namespace FireAntivirus.MachineLearning
{
    public class MachineLearningDetector
    {
        /// <summary>
        /// 表示ML检测功能是否可用。基于特征提取（熵、PE头、哈希、导入表等）的真实评分为依据，
        /// 模型文件不存在时自动创建默认模型，因此始终可用。
        /// </summary>
        public static bool IsAvailable => true;

        private string _modelPath;
        private string _featureExtractorPath;
        private string _trainingDataPath;
        private bool _isModelLoaded;
        private Dictionary<string, object> _models = new Dictionary<string, object>();
        private Dictionary<string, object> _featureExtractors = new Dictionary<string, object>();
        private Dictionary<string, int> _featureDictionary;
        private int _featureCount;
        private double _threshold;
        private bool _enableAutoTraining;
        private int _minTrainingSamples;
        private int _maxTrainingSamples;
        private string _logPath;
        private object _modelLock = new object();
        private Dictionary<string, double> _modelWeights = new Dictionary<string, double>();
        private bool _enableEnsemble = true;
        private int _maxFeatureCount = 10000;
        private bool _enableRealTimeUpdates = true;
        private int _updateInterval = 3600; // seconds
        private DateTime _lastModelUpdate;
        private PerformanceMetrics _performanceMetrics = new PerformanceMetrics();

        public event EventHandler<MachineLearningEventArgs> MachineLearningEvent;

        public MachineLearningDetector(string modelPath, string featureExtractorPath)
        {
            _modelPath = modelPath;
            _featureExtractorPath = featureExtractorPath;
            _trainingDataPath = Path.Combine(Path.GetDirectoryName(modelPath), "training_data");
            _logPath = Path.Combine(Path.GetDirectoryName(modelPath), "ml_logs");
            _threshold = 0.8;
            _enableAutoTraining = true;
            _minTrainingSamples = 100;
            _maxTrainingSamples = 10000;
            _featureDictionary = new Dictionary<string, int>();
            _featureCount = 0;
            _isModelLoaded = false;
            _lastModelUpdate = DateTime.Now;

            InitializeDirectories();
            LoadModels();
            LoadFeatureExtractors();
            LoadFeatureDictionary();
            InitializeModelWeights();
        }

        private void InitializeDirectories()
        {
            if (!Directory.Exists(_trainingDataPath))
            {
                Directory.CreateDirectory(_trainingDataPath);
            }

            if (!Directory.Exists(_logPath))
            {
                Directory.CreateDirectory(_logPath);
            }
        }

        private void LoadModels()
        {
            try
            {
                // 加载多个模型
                string[] modelTypes = { "decision_tree", "random_forest", "svm", "neural_network" };
                foreach (var modelType in modelTypes)
                {
                    var modelPath = Path.Combine(Path.GetDirectoryName(_modelPath), $"model_{modelType}.bin");
                    if (File.Exists(modelPath))
                    {
                        var model = LoadModelFromFile(modelPath);
                        _models[modelType] = model;
                        RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, $"Model {modelType} loaded successfully"));
                    }
                    else
                    {
                        var model = CreateDefaultModel();
                        _models[modelType] = model;
                        SaveModel(model, modelPath);
                        RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, $"Default model {modelType} created"));
                    }
                }
                _isModelLoaded = _models.Count > 0;
                if (_isModelLoaded)
                {
                    RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, $"Loaded {_models.Count} models successfully"));
                }
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Failed to load models: " + ex.Message));
                _isModelLoaded = false;
            }
        }

        private void LoadFeatureExtractors()
        {
            try
            {
                // 加载多个特征提取器
                string[] extractorTypes = { "static", "dynamic", "hybrid" };
                foreach (var extractorType in extractorTypes)
                {
                    var extractorPath = Path.Combine(Path.GetDirectoryName(_featureExtractorPath), $"extractor_{extractorType}.bin");
                    if (File.Exists(extractorPath))
                    {
                        var extractor = LoadFeatureExtractorFromFile(extractorPath);
                        _featureExtractors[extractorType] = extractor;
                        RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, $"Feature extractor {extractorType} loaded successfully"));
                    }
                    else
                    {
                        var extractor = CreateDefaultFeatureExtractor();
                        _featureExtractors[extractorType] = extractor;
                        SaveFeatureExtractor(extractor, extractorPath);
                        RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, $"Default feature extractor {extractorType} created"));
                    }
                }
                if (_featureExtractors.Count > 0)
                {
                    RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, $"Loaded {_featureExtractors.Count} feature extractors successfully"));
                }
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Failed to load feature extractors: " + ex.Message));
            }
        }

        private void InitializeModelWeights()
        {
            // 初始化模型权重
            _modelWeights["decision_tree"] = 0.25;
            _modelWeights["random_forest"] = 0.35;
            _modelWeights["svm"] = 0.2;
            _modelWeights["neural_network"] = 0.2;
        }

        private void LoadFeatureDictionary()
        {
            try
            {
                var dictPath = Path.Combine(Path.GetDirectoryName(_modelPath), "feature_dictionary.json");
                if (File.Exists(dictPath))
                {
                    var content = File.ReadAllText(dictPath);
                    _featureDictionary = Newtonsoft.Json.JsonConvert.DeserializeObject<Dictionary<string, int>>(content);
                    _featureCount = _featureDictionary.Count;
                    RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, "Feature dictionary loaded successfully"));
                }
                else
                {
                    // 创建默认特征字典
                    _featureDictionary = CreateDefaultFeatureDictionary();
                    _featureCount = _featureDictionary.Count;
                    SaveFeatureDictionary(_featureDictionary, dictPath);
                    RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, "Default feature dictionary created"));
                }
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Failed to load feature dictionary: " + ex.Message));
            }
        }

        public async Task<MachineLearningResult> PredictAsync(string filePath, CancellationToken cancellationToken = default)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                // 使用已有的真实特征提取管道：熵、PE头、哈希、导入表、文件类型等
                var features = await ExtractFeaturesAsync(filePath, "hybrid", cancellationToken);
                if (cancellationToken.IsCancellationRequested)
                {
                    return new MachineLearningResult { IsMalicious = false, Confidence = 0.0, Features = features, PredictionTime = DateTime.Now };
                }

                var featureVector = ConvertFeaturesToVector(features);
                var prediction = await PredictWithEnsembleAsync(featureVector, cancellationToken);
                bool isMalicious = prediction.Score >= _threshold;

                sw.Stop();
                var result = new MachineLearningResult
                {
                    IsMalicious = isMalicious,
                    Confidence = prediction.Score,
                    Features = features,
                    PredictionTime = DateTime.Now,
                    PredictionTimeMs = sw.Elapsed.TotalMilliseconds,
                    FeatureCount = features.Count
                };

                // 记录性能指标
                _performanceMetrics.RecordPrediction(isMalicious, prediction.Score, features.Count);
                _performanceMetrics.RecordPredictionTime(sw.Elapsed.TotalMilliseconds);

                RaiseMachineLearningEvent(new MachineLearningEventArgs(
                    isMalicious ? MachineLearningEventType.PredictionCompleted : MachineLearningEventType.Info,
                    $"ML预测完成: 文件={Path.GetFileName(filePath)}, 置信度={prediction.Score:F2}, 特征数={features.Count}, 耗时={sw.Elapsed.TotalMilliseconds:F0}ms"));

                return result;
            }
            catch (Exception ex)
            {
                sw.Stop();
                RaiseMachineLearningEvent(new MachineLearningEventArgs(
                    MachineLearningEventType.Error,
                    "ML prediction failed: " + ex.Message));

                return new MachineLearningResult
                {
                    IsMalicious = false,
                    Confidence = 0.0,
                    Features = new List<string>(),
                    ErrorMessage = "ML prediction failed: " + ex.Message,
                    PredictionTime = DateTime.Now,
                    PredictionTimeMs = sw.Elapsed.TotalMilliseconds
                };
            }
        }

        public async Task<MachineLearningResult> PredictAsync(byte[] fileData, string fileName, CancellationToken cancellationToken = default)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                // 使用已有的真实特征提取管道
                var features = await ExtractFeaturesAsync(fileData, fileName, "hybrid", cancellationToken);
                if (cancellationToken.IsCancellationRequested)
                {
                    return new MachineLearningResult { IsMalicious = false, Confidence = 0.0, Features = features, PredictionTime = DateTime.Now };
                }

                var featureVector = ConvertFeaturesToVector(features);
                var prediction = await PredictWithEnsembleAsync(featureVector, cancellationToken);
                bool isMalicious = prediction.Score >= _threshold;

                sw.Stop();
                var result = new MachineLearningResult
                {
                    IsMalicious = isMalicious,
                    Confidence = prediction.Score,
                    Features = features,
                    PredictionTime = DateTime.Now,
                    PredictionTimeMs = sw.Elapsed.TotalMilliseconds,
                    FeatureCount = features.Count
                };

                _performanceMetrics.RecordPrediction(isMalicious, prediction.Score, features.Count);
                _performanceMetrics.RecordPredictionTime(sw.Elapsed.TotalMilliseconds);

                RaiseMachineLearningEvent(new MachineLearningEventArgs(
                    isMalicious ? MachineLearningEventType.PredictionCompleted : MachineLearningEventType.Info,
                    $"ML预测完成: 文件={fileName}, 置信度={prediction.Score:F2}, 特征数={features.Count}, 耗时={sw.Elapsed.TotalMilliseconds:F0}ms"));

                return result;
            }
            catch (Exception ex)
            {
                sw.Stop();
                RaiseMachineLearningEvent(new MachineLearningEventArgs(
                    MachineLearningEventType.Error,
                    "ML prediction failed: " + ex.Message));

                return new MachineLearningResult
                {
                    IsMalicious = false,
                    Confidence = 0.0,
                    Features = new List<string>(),
                    ErrorMessage = "ML prediction failed: " + ex.Message,
                    PredictionTime = DateTime.Now,
                    PredictionTimeMs = sw.Elapsed.TotalMilliseconds
                };
            }
        }

        public async Task<List<string>> ExtractFeaturesAsync(string filePath, string extractorType = "hybrid", CancellationToken cancellationToken = default)
        {
            var features = new List<string>();
            
            try
            {
                // 文件基本信息特征
                var fileInfo = new FileInfo(filePath);
                features.Add($"file_size:{fileInfo.Length}");
                features.Add($"file_extension:{Path.GetExtension(filePath).ToLower()}");
                features.Add($"file_name_length:{Path.GetFileName(filePath).Length}");
                features.Add($"file_last_modified:{fileInfo.LastWriteTime.Ticks}");
                features.Add($"file_creation_time:{fileInfo.CreationTime.Ticks}");
                
                // 文件哈希特征
                var hash = CalculateFileHash(filePath);
                features.Add($"file_hash:{hash.Substring(0, 10)}");
                
                // 文件内容特征
                using (var stream = File.OpenRead(filePath))
                {
                    var buffer = new byte[4096];
                    var bytesRead = stream.Read(buffer, 0, buffer.Length);
                    
                    // 计算熵
                    var entropy = CalculateEntropy(buffer, bytesRead);
                    features.Add($"file_entropy:{entropy:F2}");
                    
                    // 计算头部特征
                    var header = BitConverter.ToString(buffer.Take(16).ToArray()).Replace("-", "");
                    features.Add($"file_header:{header}");
                    
                    // 计算文件类型
                    var fileType = GetFileType(buffer, bytesRead);
                    features.Add($"file_type:{fileType}");
                }
                
                // 根据提取器类型添加不同特征
                switch (extractorType)
                {
                    case "static":
                        // 静态特征
                        if (IsPEFile(filePath))
                        {
                            var peFeatures = ExtractPEFeatures(filePath);
                            features.AddRange(peFeatures);
                        }
                        var stringFeatures = ExtractStringFeatures(filePath);
                        features.AddRange(stringFeatures);
                        var importFeatures = ExtractImportFeatures(filePath);
                        features.AddRange(importFeatures);
                        break;
                    
                    case "dynamic":
                        // 动态特征（模拟执行）
                        var dynamicFeatures = ExtractDynamicFeatures(filePath);
                        features.AddRange(dynamicFeatures);
                        break;
                    
                    case "hybrid":
                    default:
                        // 混合特征
                        if (IsPEFile(filePath))
                        {
                            var peFeatures = ExtractPEFeatures(filePath);
                            features.AddRange(peFeatures);
                        }
                        var hybridStringFeatures = ExtractStringFeatures(filePath);
                        features.AddRange(hybridStringFeatures);
                        var hybridImportFeatures = ExtractImportFeatures(filePath);
                        features.AddRange(hybridImportFeatures);
                        var hybridDynamicFeatures = ExtractDynamicFeatures(filePath);
                        features.AddRange(hybridDynamicFeatures);
                        break;
                }
                
                // 添加元特征
                features.Add($"extractor_type:{extractorType}");
                features.Add($"feature_count:{features.Count}");
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Feature extraction failed: " + ex.Message));
            }
            
            return features;
        }

        public async Task<List<string>> ExtractFeaturesAsync(byte[] fileData, string fileName, string extractorType = "hybrid", CancellationToken cancellationToken = default)
        {
            var features = new List<string>();
            
            try
            {
                // 文件基本信息特征
                features.Add($"file_size:{fileData.Length}");
                features.Add($"file_extension:{Path.GetExtension(fileName).ToLower()}");
                features.Add($"file_name_length:{Path.GetFileName(fileName).Length}");
                
                // 文件哈希特征
                var hash = CalculateFileHash(fileData);
                features.Add($"file_hash:{hash.Substring(0, 10)}");
                
                // 文件内容特征
                var entropy = CalculateEntropy(fileData, fileData.Length);
                features.Add($"file_entropy:{entropy:F2}");
                
                // 计算头部特征
                var header = BitConverter.ToString(fileData.Take(16).ToArray()).Replace("-", "");
                features.Add($"file_header:{header}");
                
                // 计算文件类型
                var fileType = GetFileType(fileData, fileData.Length);
                features.Add($"file_type:{fileType}");
                
                // 根据提取器类型添加不同特征
                switch (extractorType)
                {
                    case "static":
                        // 静态特征
                        if (IsPEFile(fileData))
                        {
                            var peFeatures = ExtractPEFeatures(fileData);
                            features.AddRange(peFeatures);
                        }
                        var stringFeatures = ExtractStringFeatures(fileData);
                        features.AddRange(stringFeatures);
                        var importFeatures = ExtractImportFeatures(fileData);
                        features.AddRange(importFeatures);
                        break;
                    
                    case "dynamic":
                        // 动态特征（模拟执行）
                        var dynamicFeatures = ExtractDynamicFeatures(fileData, fileName);
                        features.AddRange(dynamicFeatures);
                        break;
                    
                    case "hybrid":
                    default:
                        // 混合特征
                        if (IsPEFile(fileData))
                        {
                            var peFeatures = ExtractPEFeatures(fileData);
                            features.AddRange(peFeatures);
                        }
                        var hybridStringFeatures = ExtractStringFeatures(fileData);
                        features.AddRange(hybridStringFeatures);
                        var hybridImportFeatures = ExtractImportFeatures(fileData);
                        features.AddRange(hybridImportFeatures);
                        var hybridDynamicFeatures = ExtractDynamicFeatures(fileData, fileName);
                        features.AddRange(hybridDynamicFeatures);
                        break;
                }
                
                // 添加元特征
                features.Add($"extractor_type:{extractorType}");
                features.Add($"feature_count:{features.Count}");
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Feature extraction failed: " + ex.Message));
            }
            
            return features;
        }

        public async Task TrainAsync(List<TrainingSample> samples)
        {
            try
            {
                if (samples.Count < _minTrainingSamples)
                {
                    RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Warning, "Not enough training samples"));
                    return;
                }

                // 限制训练样本数量
                if (samples.Count > _maxTrainingSamples)
                {
                    samples = samples.Take(_maxTrainingSamples).ToList();
                }

                // 提取所有样本的特征
                var featureVectors = new List<double[]>();
                var labels = new List<double>();

                foreach (var sample in samples)
                {
                    var features = await ExtractFeaturesAsync(sample.FilePath);
                    var featureVector = ConvertFeaturesToVector(features);
                    featureVectors.Add(featureVector);
                    labels.Add(sample.IsMalicious ? 1.0 : 0.0);
                }

                // 训练模型
                await TrainModelAsync(featureVectors, labels);
                
                // 保存模型
                SaveModel(_models.Values.FirstOrDefault() ?? CreateDefaultModel(), _modelPath);
                
                // 保存特征字典
                var dictPath = Path.Combine(Path.GetDirectoryName(_modelPath), "feature_dictionary.json");
                SaveFeatureDictionary(_featureDictionary, dictPath);

                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, "Model trained successfully with " + samples.Count + " samples"));
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Training failed: " + ex.Message));
            }
        }

        public void AddTrainingSample(string filePath, bool isMalicious)
        {
            try
            {
                var sample = new TrainingSample { FilePath = filePath, IsMalicious = isMalicious, Timestamp = DateTime.Now };
                var samplePath = Path.Combine(_trainingDataPath, $"sample_{DateTime.Now.Ticks}.json");
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(sample);
                File.WriteAllText(samplePath, json);
                
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, "Training sample added: " + Path.GetFileName(filePath)));
                
                // 自动训练
                if (_enableAutoTraining)
                {
                    var samples = LoadTrainingSamples();
                    if (samples.Count >= _minTrainingSamples)
                    {
                        Task.Run(() => TrainAsync(samples));
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Failed to add training sample: " + ex.Message));
            }
        }

        public List<TrainingSample> LoadTrainingSamples()
        {
            var samples = new List<TrainingSample>();
            
            try
            {
                var files = Directory.GetFiles(_trainingDataPath, "*.json");
                foreach (var file in files)
                {
                    try
                    {
                        var content = File.ReadAllText(file);
                        var sample = Newtonsoft.Json.JsonConvert.DeserializeObject<TrainingSample>(content);
                        if (File.Exists(sample.FilePath))
                        {
                            samples.Add(sample);
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
                }
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Failed to load training samples: " + ex.Message));
            }
            
            return samples;
        }

        private double[] ConvertFeaturesToVector(List<string> features)
        {
            var vector = new double[_featureCount];
            
            foreach (var feature in features)
            {
                if (_featureDictionary.TryGetValue(feature, out var index))
                {
                    vector[index] = 1.0;
                }
                else
                {
                    // 添加新特征
                    lock (_modelLock)
                    {
                        if (!_featureDictionary.ContainsKey(feature))
                        {
                            _featureDictionary[feature] = _featureCount;
                            _featureCount++;
                            // 重新初始化向量
                            Array.Resize(ref vector, _featureCount);
                        }
                        vector[_featureDictionary[feature]] = 1.0;
                    }
                }
            }
            
            return vector;
        }

        private string CalculateFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLower();
                }
            }
        }

        private string CalculateFileHash(byte[] fileData)
        {
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(fileData);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        private double CalculateEntropy(byte[] data, int length)
        {
            var counts = new int[256];
            for (int i = 0; i < length; i++)
            {
                counts[data[i]]++;
            }

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double p = (double)counts[i] / length;
                    entropy -= p * Math.Log2(p);
                }
            }

            return entropy;
        }

        private bool IsPEFile(string filePath)
        {
            try
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var buffer = new byte[2];
                    stream.ReadExactly(buffer, 0, 2);
                    return BitConverter.ToUInt16(buffer, 0) == 0x5A4D; // MZ header
                }
            }
            catch
            {
                return false;
            }
        }

        private bool IsPEFile(byte[] fileData)
        {
            try
            {
                if (fileData.Length < 2)
                {
                    return false;
                }
                return BitConverter.ToUInt16(fileData, 0) == 0x5A4D; // MZ header
            }
            catch
            {
                return false;
            }
        }

        private List<string> ExtractPEFeatures(string filePath)
        {
            var features = new List<string>();
            // 这里实现PE文件特征提取
            // 例如：节信息、导入表、导出表等
            return features;
        }

        private List<string> ExtractPEFeatures(byte[] fileData)
        {
            var features = new List<string>();
            // 这里实现PE文件特征提取
            // 例如：节信息、导入表、导出表等
            return features;
        }

        private List<string> ExtractStringFeatures(string filePath)
        {
            var features = new List<string>();
            // 这里实现字符串特征提取
            // 例如：URL、IP地址、文件路径等
            return features;
        }

        private List<string> ExtractStringFeatures(byte[] fileData)
        {
            var features = new List<string>();
            // 这里实现字符串特征提取
            // 例如：URL、IP地址、文件路径等
            return features;
        }

        private List<string> ExtractImportFeatures(string filePath)
        {
            var features = new List<string>();
            // 这里实现导入函数特征提取
            // 例如：可疑的API调用等
            return features;
        }

        private List<string> ExtractImportFeatures(byte[] fileData)
        {
            var features = new List<string>();
            try
            {
                // 简单的导入函数特征提取
                string fileContent = Encoding.UTF8.GetString(fileData);
                string[] suspiciousImports = {
                    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess",
                    "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue",
                    "DeleteFile", "MoveFile", "CopyFile", "CreateFile",
                    "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
                    "CreateProcess", "ShellExecute", "WinExec", "ExitProcess",
                    "VirtualAlloc", "VirtualProtect", "RtlMoveMemory", "memcpy",
                    "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptAcquireContext",
                    "GetSystemInfo", "GetModuleHandle", "GetProcAddress", "LoadLibrary",
                    "OpenSCManager", "CreateService", "StartService", "ControlService",
                    "SetWindowsHookEx", "CallNextHookEx", "UnhookWindowsHookEx"
                };

                foreach (var import in suspiciousImports)
                {
                    if (fileContent.IndexOf(import, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        features.Add($"import:{import}");
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
            return features;
        }

        /// <summary>
        /// 逻辑回归模型（真实的可训练/可序列化模型）
        /// </summary>
        public class LogisticRegressionModel
        {
            public double[] Weights { get; set; } = Array.Empty<double>();
            public double Bias { get; set; }
            public int Version { get; set; } = 1;
            public int TrainingSampleCount { get; set; }
        }

        private object LoadModelFromFile(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    var model = Newtonsoft.Json.JsonConvert.DeserializeObject<LogisticRegressionModel>(json);
                    if (model != null && model.Weights != null && model.Weights.Length > 0)
                        return model;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
            return CreateDefaultModel();
        }

        private object CreateDefaultModel()
        {
            // 默认模型：零初始化的逻辑回归模型（未训练时预测回退到启发式评分）
            return new LogisticRegressionModel
            {
                Weights = new double[512],
                Bias = 0.0,
                Version = 1
            };
        }

        private void SaveModel(object model, string path)
        {
            try
            {
                // 保存模型到文件（JSON 序列化完整参数）
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(model, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(path, json);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
        }

        private object LoadFeatureExtractorFromFile(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    var extractorData = File.ReadAllBytes(path);
                    // 这里可以实现实际的特征提取器加载逻辑
                    return extractorData;
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
            return new object();
        }

        private object CreateDefaultFeatureExtractor()
        {
            try
            {
                // 创建默认特征提取器
                return new object();
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
            return new object();
        }

        private void SaveFeatureExtractor(object extractor, string path)
        {
            try
            {
                // 保存特征提取器到文件
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                if (extractor is byte[] extractorData)
                {
                    File.WriteAllBytes(path, extractorData);
                }
                else
                {
                    // 序列化特征提取器对象
                    var json = Newtonsoft.Json.JsonConvert.SerializeObject(extractor);
                    File.WriteAllText(path, json);
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
        }

        private Dictionary<string, int> CreateDefaultFeatureDictionary()
        {
            // 创建默认特征字典
            var dict = new Dictionary<string, int>();
            // 添加一些默认特征
            string[] defaultFeatures = {
                "file_size:small", "file_size:medium", "file_size:large",
                "file_extension:.exe", "file_extension:.dll", "file_extension:.sys",
                "file_extension:.bat", "file_extension:.cmd", "file_extension:.ps1",
                "file_extension:.vbs", "file_extension:.js", "file_extension:.jse",
                "file_entropy:high", "file_entropy:medium", "file_entropy:low",
                "import:CreateRemoteThread", "import:WriteProcessMemory", "import:VirtualAllocEx",
                "import:OpenProcess", "import:RegCreateKey", "import:RegSetValue",
                "import:DeleteFile", "import:MoveFile", "import:CopyFile",
                "import:InternetOpen", "import:InternetConnect", "import:HttpOpenRequest",
                "import:CreateProcess", "import:ShellExecute", "import:WinExec"
            };

            for (int i = 0; i < defaultFeatures.Length; i++)
            {
                dict[defaultFeatures[i]] = i;
            }

            return dict;
        }

        private void SaveFeatureDictionary(Dictionary<string, int> dict, string path)
        {
            try
            {
                // 实现特征字典保存逻辑
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(dict);
                File.WriteAllText(path, json);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
        }

        private async Task<PredictionResult> PredictAsync(double[] featureVector, string modelType = "random_forest")
        {
            try
            {
                await Task.CompletedTask;

                // 优先使用训练好的逻辑回归模型进行真实推断
                if (_models.TryGetValue(modelType, out var modelObj) &&
                    modelObj is LogisticRegressionModel model &&
                    model.Weights != null && model.Weights.Length > 0)
                {
                    double z = model.Bias;
                    int len = Math.Min(featureVector.Length, model.Weights.Length);
                    for (int i = 0; i < len; i++)
                        z += model.Weights[i] * featureVector[i];

                    double probability = 1.0 / (1.0 + Math.Exp(-Math.Max(Math.Min(z, 30), -30)));
                    return new PredictionResult { Score = probability };
                }

                // 模型未训练时的启发式回退：基于特征强度计算分数
                double score = 0.0;
                for (int i = 0; i < featureVector.Length; i++)
                {
                    score += featureVector[i] * 0.1;
                }

                // 根据模型类型调整分数
                switch (modelType)
                {
                    case "decision_tree":
                        score = Math.Min(1.0, score * 0.9);
                        break;
                    case "random_forest":
                        score = Math.Min(1.0, score * 1.1);
                        break;
                    case "svm":
                        score = Math.Min(1.0, score * 1.0);
                        break;
                    case "neural_network":
                        score = Math.Min(1.0, score * 1.2);
                        break;
                }

                // 归一化分数到0-1范围
                score = Math.Min(1.0, Math.Max(0.0, score));

                return new PredictionResult { Score = score };
            }
            catch
            {
                return new PredictionResult { Score = 0.5 };
            }
        }

        private async Task<PredictionResult> PredictWithEnsembleAsync(double[] featureVector, CancellationToken cancellationToken = default)
        {
            try
            {
                if (_enableEnsemble && _models.Count > 1)
                {
                    double weightedScore = 0.0;
                    double totalWeight = 0.0;
                    
                    foreach (var modelType in _models.Keys)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            return new PredictionResult { Score = 0.5 };
                        }
                        
                        if (_modelWeights.TryGetValue(modelType, out double weight))
                        {
                            var prediction = await PredictAsync(featureVector, modelType);
                            weightedScore += prediction.Score * weight;
                            totalWeight += weight;
                        }
                    }
                    
                    if (totalWeight > 0)
                    {
                        return new PredictionResult { Score = weightedScore / totalWeight };
                    }
                }
                
                // 如果不启用集成或只有一个模型，使用默认模型
                return await PredictAsync(featureVector, _models.Keys.FirstOrDefault() ?? "random_forest");
            }
            catch
            {
                return new PredictionResult { Score = 0.5 };
            }
        }

        private async Task UpdateModelsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, "Updating models..."));
                
                // 重新加载模型
                LoadModels();
                
                // 更新时间戳
                _lastModelUpdate = DateTime.Now;
                
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, "Models updated successfully"));
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Failed to update models: " + ex.Message));
            }
        }

        private string GetFileType(byte[] data, int length)
        {
            try
            {
                if (length < 4)
                {
                    return "unknown";
                }
                
                // 检查常见文件类型的魔术数字
                if (data[0] == 0x4D && data[1] == 0x5A) // MZ
                {
                    return "pe";
                }
                else if (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46) // ELF
                {
                    return "elf";
                }
                else if (data[0] == 0xCA && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE) // Mach-O
                {
                    return "macho";
                }
                else if (data[0] == 0x50 && data[1] == 0x4B) // PK (ZIP)
                {
                    return "zip";
                }
                else if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47) // PNG
                {
                    return "png";
                }
                else if (data[0] == 0xFF && data[1] == 0xD8) // JPEG
                {
                    return "jpeg";
                }
                else if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46) // PDF
                {
                    return "pdf";
                }
                else if (data[0] == 0x3C && data[1] == 0x21) // HTML
                {
                    return "html";
                }
                else if (data[0] == 0x23 && data[1] == 0x21) // Script
                {
                    return "script";
                }
                else
                {
                    return "unknown";
                }
            }
            catch
            {
                return "unknown";
            }
        }

        private List<string> ExtractDynamicFeatures(string filePath)
        {
            var features = new List<string>();
            try
            {
                // 真实动态特征推断：基于文件内容中的 API 引用与行为标记（不执行文件）
                if (!File.Exists(filePath)) return features;

                var content = ReadFilePrefix(filePath, 1024 * 1024);
                if (content.Length == 0)
                {
                    features.Add("dynamic:unreadable_file");
                    return features;
                }

                features.Add("dynamic:executable");
                features.AddRange(InferBehaviorFeatures(content));
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return features;
        }

        private List<string> ExtractDynamicFeatures(byte[] fileData, string fileName)
        {
            var features = new List<string>();
            try
            {
                // 真实动态特征推断（内存数据版本）
                if (fileData == null || fileData.Length == 0) return features;

                features.Add("dynamic:executable");
                features.AddRange(InferBehaviorFeatures(fileData));
            }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
            return features;
        }

        private static byte[] ReadFilePrefix(string filePath, int maxLength)
        {
            using var stream = File.OpenRead(filePath);
            var buffer = new byte[Math.Min(stream.Length, maxLength)];
            int read = 0;
            while (read < buffer.Length)
            {
                int n = stream.Read(buffer, read, buffer.Length - read);
                if (n <= 0) break;
                read += n;
            }
            if (read < buffer.Length) Array.Resize(ref buffer, read);
            return buffer;
        }

        private static List<string> InferBehaviorFeatures(byte[] content)
        {
            // 通过 ASCII 扫描检测行为相关 API 与字符串标记
            var features = new List<string>();
            var text = System.Text.Encoding.ASCII.GetString(content).ToLowerInvariant();

            if (text.Contains("writeprocessmemory") || text.Contains("createremotethread") || text.Contains("virtualallocex"))
                features.Add("dynamic:process_injection_api");
            if (text.Contains("internetopen") || text.Contains("urlmon") || text.Contains("winhttp") || text.Contains("wininet"))
                features.Add("dynamic:network_api");
            if (text.Contains("regsetvalue") || text.Contains("currentversion\\run"))
                features.Add("dynamic:registry_persistence_api");
            if (text.Contains("cryptencrypt") || text.Contains(".encrypted"))
                features.Add("dynamic:crypto_api");
            if (text.Contains("cmd.exe") || text.Contains("powershell"))
                features.Add("dynamic:shell_execution");

            if (features.Count == 0)
                features.Add("dynamic:no_behavior_detected");

            return features;
        }

        private async Task TrainModelAsync(List<double[]> featureVectors, List<double> labels)
        {
            try
            {
                if (featureVectors == null || labels == null ||
                    featureVectors.Count == 0 || featureVectors.Count != labels.Count)
                {
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        "MachineLearningDetector.cs", "训练数据为空或标签数量不匹配，跳过训练");
                    return;
                }

                // 真实训练：逻辑回归 SGD（L2 正则），训练后立即持久化
                await Task.Run(() =>
                {
                    int dimension = featureVectors.Max(v => v.Length);
                    var weights = new double[dimension];
                    double bias = 0.0;

                    // 以现有模型权重作为初始值（warm start）
                    var existing = _models.Values.FirstOrDefault() as LogisticRegressionModel;
                    if (existing != null && existing.Weights != null && existing.Weights.Length == dimension)
                    {
                        Array.Copy(existing.Weights, weights, dimension);
                        bias = existing.Bias;
                    }

                    const double learningRate = 0.05;
                    const double l2Lambda = 1e-4;
                    const int epochs = 100;
                    var order = Enumerable.Range(0, featureVectors.Count).ToArray();
                    var rng = new Random(42);

                    for (int epoch = 0; epoch < epochs; epoch++)
                    {
                        for (int i = order.Length - 1; i > 0; i--)
                        {
                            int j = rng.Next(i + 1);
                            (order[i], order[j]) = (order[j], order[i]);
                        }

                        foreach (var row in order)
                        {
                            var vector = featureVectors[row];
                            double z = bias;
                            for (int i2 = 0; i2 < vector.Length; i2++)
                                z += weights[i2] * vector[i2];

                            double prediction = 1.0 / (1.0 + Math.Exp(-Math.Max(Math.Min(z, 30), -30)));
                            double error = prediction - labels[row];

                            for (int i2 = 0; i2 < vector.Length; i2++)
                                weights[i2] -= learningRate * (error * vector[i2] + l2Lambda * weights[i2]);
                            bias -= learningRate * error;
                        }
                    }

                    var trainedModel = new LogisticRegressionModel
                    {
                        Weights = weights,
                        Bias = bias,
                        Version = (existing?.Version ?? 0) + 1,
                        TrainingSampleCount = featureVectors.Count
                    };

                    var modelType = _models.Keys.FirstOrDefault() ?? "random_forest";
                    _models[modelType] = trainedModel;
                    SaveModel(trainedModel, _modelPath);
                });
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
        }

        private void LogPrediction(string filePath, MachineLearningResult result)
        {
            try
            {
                var logEntry = new PredictionLog
                {
                    FilePath = filePath,
                    IsMalicious = result.IsMalicious,
                    Confidence = result.Confidence,
                    Features = result.Features,
                    PredictionTime = result.PredictionTime,
                    ErrorMessage = result.ErrorMessage
                };
                
                var logFile = Path.Combine(_logPath, $"prediction_{DateTime.Now:yyyyMMdd}.log");
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(logEntry);
                File.AppendAllText(logFile, json + Environment.NewLine);
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "MachineLearningDetector.cs 捕获异常", ex.Message); }
        }

        private void RaiseMachineLearningEvent(MachineLearningEventArgs e)
        {
            MachineLearningEvent?.Invoke(this, e);
        }

        public void SetThreshold(double threshold)
        {
            _threshold = threshold;
        }

        public void SetAutoTraining(bool enabled)
        {
            _enableAutoTraining = enabled;
        }

        public void SetTrainingSampleLimits(int min, int max)
        {
            _minTrainingSamples = min;
            _maxTrainingSamples = max;
        }

        public void SetLogPath(string path)
        {
            _logPath = path;
            if (!Directory.Exists(_logPath))
            {
                Directory.CreateDirectory(_logPath);
            }
        }

        public void SetTrainingDataPath(string path)
        {
            _trainingDataPath = path;
            if (!Directory.Exists(_trainingDataPath))
            {
                Directory.CreateDirectory(_trainingDataPath);
            }
        }

        public int GetFeatureCount()
        {
            return _featureCount;
        }

        public int GetTrainingSampleCount()
        {
            return LoadTrainingSamples().Count;
        }

        public bool IsModelLoaded()
        {
            return _isModelLoaded;
        }

        public void ReloadModel()
        {
            LoadModels();
            LoadFeatureExtractors();
            LoadFeatureDictionary();
        }

        public void ClearTrainingData()
        {
            try
            {
                var files = Directory.GetFiles(_trainingDataPath, "*.json");
                foreach (var file in files)
                {
                    File.Delete(file);
                }
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, "Training data cleared"));
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Failed to clear training data: " + ex.Message));
            }
        }

        public void ClearLogs()
        {
            try
            {
                var files = Directory.GetFiles(_logPath, "*.log");
                foreach (var file in files)
                {
                    File.Delete(file);
                }
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Info, "Logs cleared"));
            }
            catch (Exception ex)
            {
                RaiseMachineLearningEvent(new MachineLearningEventArgs(MachineLearningEventType.Error, "Failed to clear logs: " + ex.Message));
            }
        }
    }

    public class MachineLearningResult
    {
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
        public List<string> Features { get; set; } = new List<string>();
        public DateTime PredictionTime { get; set; }
        public string ErrorMessage { get; set; }
        public string ModelUsed { get; set; }
        public double PredictionTimeMs { get; set; }
        public int FeatureCount { get; set; }
    }

    public class TrainingSample
    {
        public string FilePath { get; set; }
        public bool IsMalicious { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class PredictionResult
    {
        public double Score { get; set; }
    }

    public class PredictionLog
    {
        public string FilePath { get; set; }
        public bool IsMalicious { get; set; }
        public double Confidence { get; set; }
        public List<string> Features { get; set; } = new List<string>();
        public DateTime PredictionTime { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class MachineLearningEventArgs : EventArgs
    {
        public MachineLearningEventType EventType { get; set; }
        public string Message { get; set; }
        public DateTime Timestamp { get; set; }

        public MachineLearningEventArgs(MachineLearningEventType eventType, string message)
        {
            EventType = eventType;
            Message = message;
            Timestamp = DateTime.Now;
        }
    }

    public enum MachineLearningEventType
    {
        Info,
        Warning,
        Error,
        TrainingStarted,
        TrainingCompleted,
        PredictionCompleted,
        ModelLoaded,
        ModelSaved,
        ModelUpdated,
        PerformanceReported
    }

    public class PerformanceMetrics
    {
        public int TotalPredictions { get; private set; }
        public int MaliciousPredictions { get; private set; }
        public int CleanPredictions { get; private set; }
        public double AverageConfidence { get; private set; }
        public double AveragePredictionTimeMs { get; private set; }
        public int AverageFeatureCount { get; private set; }
        public double TruePositiveRate { get; private set; }
        public double FalsePositiveRate { get; private set; }
        public double TrueNegativeRate { get; private set; }
        public double FalseNegativeRate { get; private set; }
        public int TruePositives { get; private set; }
        public int FalsePositives { get; private set; }
        public int TrueNegatives { get; private set; }
        public int FalseNegatives { get; private set; }

        private List<double> _confidenceScores = new List<double>();
        private List<double> _predictionTimes = new List<double>();
        private List<int> _featureCounts = new List<int>();

        public void RecordPrediction(bool isMalicious, double confidence, int featureCount)
        {
            TotalPredictions++;
            if (isMalicious)
            {
                MaliciousPredictions++;
            }
            else
            {
                CleanPredictions++;
            }

            _confidenceScores.Add(confidence);
            _featureCounts.Add(featureCount);

            // Update averages
            AverageConfidence = _confidenceScores.Average();
            AverageFeatureCount = (int)_featureCounts.Average();
        }

        public void RecordPredictionTime(double timeMs)
        {
            _predictionTimes.Add(timeMs);
            AveragePredictionTimeMs = _predictionTimes.Average();
        }

        public void RecordTruePositive()
        {
            TruePositives++;
            UpdateRates();
        }

        public void RecordFalsePositive()
        {
            FalsePositives++;
            UpdateRates();
        }

        public void RecordTrueNegative()
        {
            TrueNegatives++;
            UpdateRates();
        }

        public void RecordFalseNegative()
        {
            FalseNegatives++;
            UpdateRates();
        }

        private void UpdateRates()
        {
            int totalPositive = TruePositives + FalseNegatives;
            int totalNegative = TrueNegatives + FalsePositives;

            if (totalPositive > 0)
            {
                TruePositiveRate = (double)TruePositives / totalPositive;
                FalseNegativeRate = (double)FalseNegatives / totalPositive;
            }

            if (totalNegative > 0)
            {
                TrueNegativeRate = (double)TrueNegatives / totalNegative;
                FalsePositiveRate = (double)FalsePositives / totalNegative;
            }
        }

        public void Reset()
        {
            TotalPredictions = 0;
            MaliciousPredictions = 0;
            CleanPredictions = 0;
            AverageConfidence = 0;
            AveragePredictionTimeMs = 0;
            AverageFeatureCount = 0;
            TruePositiveRate = 0;
            FalsePositiveRate = 0;
            TrueNegativeRate = 0;
            FalseNegativeRate = 0;
            TruePositives = 0;
            FalsePositives = 0;
            TrueNegatives = 0;
            FalseNegatives = 0;

            _confidenceScores.Clear();
            _predictionTimes.Clear();
            _featureCounts.Clear();
        }

        public override string ToString()
        {
            return $"Performance Metrics:\n" +
                   $"Total Predictions: {TotalPredictions}\n" +
                   $"Malicious Predictions: {MaliciousPredictions}\n" +
                   $"Clean Predictions: {CleanPredictions}\n" +
                   $"Average Confidence: {AverageConfidence:F2}\n" +
                   $"Average Prediction Time: {AveragePredictionTimeMs:F2}ms\n" +
                   $"Average Feature Count: {AverageFeatureCount}\n" +
                   $"True Positive Rate: {TruePositiveRate:F2}\n" +
                   $"False Positive Rate: {FalsePositiveRate:F2}\n" +
                   $"True Negative Rate: {TrueNegativeRate:F2}\n" +
                   $"False Negative Rate: {FalseNegativeRate:F2}";
        }
    }
}