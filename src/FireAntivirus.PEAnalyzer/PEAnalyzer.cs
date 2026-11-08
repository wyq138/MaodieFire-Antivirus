using System;
using System.IO;
using System.Text;

namespace FireAntivirus.PEAnalyzer
{
    public class PEAnalyzer
    {
        /// <summary>
        /// 分析PE文件
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>PE分析结果</returns>
        public static PEAnalysisResult AnalyzePEFile(string filePath)
        {
            var result = new PEAnalysisResult { FilePath = filePath };

            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (var br = new BinaryReader(fs))
                {
                    // 检查DOS头部
                    if (!CheckDOSHeader(br, result))
                        return result;

                    // 检查PE头部
                    if (!CheckPEHeader(br, result))
                        return result;

                    // 检查节表
                    CheckSections(br, result);

                    // 检查导入表
                    CheckImportTable(br, result);

                    // 检查导出表
                    CheckExportTable(br, result);

                    // 检查资源表
                    CheckResourceTable(br, result);

                    // 分析可疑特征
                    AnalyzeSuspiciousFeatures(result);
                }
            }
            catch (Exception ex)
            {
                result.IsValidPE = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// 检查DOS头部
        /// </summary>
        private static bool CheckDOSHeader(BinaryReader br, PEAnalysisResult result)
        {
            // 读取DOS签名
            ushort dosSignature = br.ReadUInt16();
            if (dosSignature != 0x5A4D) // "MZ"
            {
                result.IsValidPE = false;
                result.ErrorMessage = "不是有效的PE文件（缺少DOS签名）";
                return false;
            }

            // 读取PE头部偏移
            br.BaseStream.Position = 0x3C;
            uint peHeaderOffset = br.ReadUInt32();
            result.PEHeaderOffset = peHeaderOffset;

            return true;
        }

        /// <summary>
        /// 检查PE头部
        /// </summary>
        private static bool CheckPEHeader(BinaryReader br, PEAnalysisResult result)
        {
            // 移动到PE头部
            br.BaseStream.Position = result.PEHeaderOffset;

            // 读取PE签名
            uint peSignature = br.ReadUInt32();
            if (peSignature != 0x4550) // "PE"
            {
                result.IsValidPE = false;
                result.ErrorMessage = "不是有效的PE文件（缺少PE签名）";
                return false;
            }

            // 读取机器类型
            ushort machine = br.ReadUInt16();
            result.MachineType = machine;

            // 读取节数量
            ushort numberOfSections = br.ReadUInt16();
            result.NumberOfSections = numberOfSections;

            // 读取时间戳
            uint timeDateStamp = br.ReadUInt32();
            result.TimeDateStamp = DateTime.FromFileTime((long)(timeDateStamp * 10000000) + 621355968000000000);

            // 读取可选头部大小
            ushort sizeOfOptionalHeader = br.ReadUInt16();
            result.SizeOfOptionalHeader = sizeOfOptionalHeader;

            // 读取特征标志
            ushort characteristics = br.ReadUInt16();
            result.Characteristics = characteristics;

            // 读取可选头部
            if (sizeOfOptionalHeader > 0)
            {
                CheckOptionalHeader(br, result);
            }

            result.IsValidPE = true;
            return true;
        }

        /// <summary>
        /// 检查可选头部
        /// </summary>
        private static void CheckOptionalHeader(BinaryReader br, PEAnalysisResult result)
        {
            // 读取魔术数字
            ushort magic = br.ReadUInt16();
            result.Magic = magic;

            // 读取链接器版本
            byte majorLinkerVersion = br.ReadByte();
            byte minorLinkerVersion = br.ReadByte();
            result.LinkerVersion = $"{majorLinkerVersion}.{minorLinkerVersion}";

            // 读取代码大小
            uint sizeOfCode = br.ReadUInt32();
            result.SizeOfCode = sizeOfCode;

            // 读取初始化数据大小
            uint sizeOfInitializedData = br.ReadUInt32();
            result.SizeOfInitializedData = sizeOfInitializedData;

            // 读取未初始化数据大小
            uint sizeOfUninitializedData = br.ReadUInt32();
            result.SizeOfUninitializedData = sizeOfUninitializedData;

            // 读取入口点地址
            uint addressOfEntryPoint = br.ReadUInt32();
            result.AddressOfEntryPoint = addressOfEntryPoint;

            // 读取代码基址
            uint baseOfCode = br.ReadUInt32();
            result.BaseOfCode = baseOfCode;

            // 读取数据基址（32位）
            if (result.Magic == 0x10B) // PE32
            {
                uint baseOfData = br.ReadUInt32();
                result.BaseOfData = baseOfData;
            }

            // 读取镜像基址
            if (result.Magic == 0x10B) // PE32
            {
                uint imageBase = br.ReadUInt32();
                result.ImageBase = imageBase;
            }
            else if (result.Magic == 0x20B) // PE32+
            {
                ulong imageBase = br.ReadUInt64();
                result.ImageBase = (uint)imageBase;
            }

            // 读取节对齐
            uint sectionAlignment = br.ReadUInt32();
            result.SectionAlignment = sectionAlignment;

            // 读取文件对齐
            uint fileAlignment = br.ReadUInt32();
            result.FileAlignment = fileAlignment;

            // 读取操作系统版本
            ushort majorOperatingSystemVersion = br.ReadUInt16();
            ushort minorOperatingSystemVersion = br.ReadUInt16();
            result.OperatingSystemVersion = $"{majorOperatingSystemVersion}.{minorOperatingSystemVersion}";

            // 读取镜像版本
            ushort majorImageVersion = br.ReadUInt16();
            ushort minorImageVersion = br.ReadUInt16();
            result.ImageVersion = $"{majorImageVersion}.{minorImageVersion}";

            // 读取子系统版本
            ushort majorSubsystemVersion = br.ReadUInt16();
            ushort minorSubsystemVersion = br.ReadUInt16();
            result.SubsystemVersion = $"{majorSubsystemVersion}.{minorSubsystemVersion}";

            // 跳过保留字段
            br.ReadUInt32();

            // 读取镜像大小
            uint sizeOfImage = br.ReadUInt32();
            result.SizeOfImage = sizeOfImage;

            // 读取头大小
            uint sizeOfHeaders = br.ReadUInt32();
            result.SizeOfHeaders = sizeOfHeaders;

            // 读取校验和
            uint checkSum = br.ReadUInt32();
            result.CheckSum = checkSum;

            // 读取子系统
            ushort subsystem = br.ReadUInt16();
            result.Subsystem = subsystem;

            // 读取DLL特征
            ushort dllCharacteristics = br.ReadUInt16();
            result.DLLCharacteristics = dllCharacteristics;

            // 读取堆栈保留大小
            if (result.Magic == 0x10B) // PE32
            {
                uint sizeOfStackReserve = br.ReadUInt32();
                result.SizeOfStackReserve = sizeOfStackReserve;
            }
            else if (result.Magic == 0x20B) // PE32+
            {
                ulong sizeOfStackReserve = br.ReadUInt64();
                result.SizeOfStackReserve = (uint)sizeOfStackReserve;
            }

            // 读取堆栈提交大小
            if (result.Magic == 0x10B) // PE32
            {
                uint sizeOfStackCommit = br.ReadUInt32();
                result.SizeOfStackCommit = sizeOfStackCommit;
            }
            else if (result.Magic == 0x20B) // PE32+
            {
                ulong sizeOfStackCommit = br.ReadUInt64();
                result.SizeOfStackCommit = (uint)sizeOfStackCommit;
            }

            // 读取堆保留大小
            if (result.Magic == 0x10B) // PE32
            {
                uint sizeOfHeapReserve = br.ReadUInt32();
                result.SizeOfHeapReserve = sizeOfHeapReserve;
            }
            else if (result.Magic == 0x20B) // PE32+
            {
                ulong sizeOfHeapReserve = br.ReadUInt64();
                result.SizeOfHeapReserve = (uint)sizeOfHeapReserve;
            }

            // 读取堆提交大小
            if (result.Magic == 0x10B) // PE32
            {
                uint sizeOfHeapCommit = br.ReadUInt32();
                result.SizeOfHeapCommit = sizeOfHeapCommit;
            }
            else if (result.Magic == 0x20B) // PE32+
            {
                ulong sizeOfHeapCommit = br.ReadUInt64();
                result.SizeOfHeapCommit = (uint)sizeOfHeapCommit;
            }

            // 跳过加载配置目录（如果存在）
            br.BaseStream.Position += 4;

            // 读取导入表地址和大小
            uint importTableRVA = br.ReadUInt32();
            uint importTableSize = br.ReadUInt32();
            result.ImportTableRVA = importTableRVA;
            result.ImportTableSize = importTableSize;

            // 读取导出表地址和大小
            uint exportTableRVA = br.ReadUInt32();
            uint exportTableSize = br.ReadUInt32();
            result.ExportTableRVA = exportTableRVA;
            result.ExportTableSize = exportTableSize;

            // 读取资源表地址和大小
            uint resourceTableRVA = br.ReadUInt32();
            uint resourceTableSize = br.ReadUInt32();
            result.ResourceTableRVA = resourceTableRVA;
            result.ResourceTableSize = resourceTableSize;
        }

        /// <summary>
        /// 检查节表
        /// </summary>
        private static void CheckSections(BinaryReader br, PEAnalysisResult result)
        {
            // 移动到节表
            br.BaseStream.Position = result.PEHeaderOffset + 24 + result.SizeOfOptionalHeader;

            result.Sections = new List<SectionInfo>();

            for (int i = 0; i < result.NumberOfSections; i++)
            {
                var section = new SectionInfo();

                // 读取节名称
                byte[] nameBytes = br.ReadBytes(8);
                section.Name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

                // 读取虚拟大小
                section.VirtualSize = br.ReadUInt32();

                // 读取虚拟地址
                section.VirtualAddress = br.ReadUInt32();

                // 读取大小
                section.SizeOfRawData = br.ReadUInt32();

                // 读取偏移
                section.PointerToRawData = br.ReadUInt32();

                // 跳过其他字段
                br.BaseStream.Position += 16;

                result.Sections.Add(section);
            }
        }

        /// <summary>
        /// 检查导入表
        /// </summary>
        private static void CheckImportTable(BinaryReader br, PEAnalysisResult result)
        {
            if (result.ImportTableRVA == 0 || result.ImportTableSize == 0)
                return;

            // 计算导入表在文件中的位置
            uint importTableOffset = RVAtoFileOffset(br, result, result.ImportTableRVA);
            if (importTableOffset == 0)
                return;

            br.BaseStream.Position = importTableOffset;
            result.Imports = new List<ImportInfo>();

            while (true)
            {
                // 读取导入描述符
                uint originalFirstThunk = br.ReadUInt32();
                if (originalFirstThunk == 0)
                    break;

                br.BaseStream.Position += 12; // 跳过其他字段

                // 读取DLL名称
                uint nameRVA = br.ReadUInt32();
                if (nameRVA != 0)
                {
                    uint nameOffset = RVAtoFileOffset(br, result, nameRVA);
                    if (nameOffset != 0)
                    {
                        long currentPos = br.BaseStream.Position;
                        br.BaseStream.Position = nameOffset;

                        StringBuilder dllName = new StringBuilder();
                        char c;
                        while ((c = br.ReadChar()) != '\0')
                        {
                            dllName.Append(c);
                        }

                        result.Imports.Add(new ImportInfo { DLLName = dllName.ToString() });
                        br.BaseStream.Position = currentPos;
                    }
                }

                br.BaseStream.Position += 4; // 跳过最后一个字段
            }
        }

        /// <summary>
        /// 检查导出表
        /// </summary>
        private static void CheckExportTable(BinaryReader br, PEAnalysisResult result)
        {
            if (result.ExportTableRVA == 0 || result.ExportTableSize == 0)
                return;

            // 计算导出表在文件中的位置
            uint exportTableOffset = RVAtoFileOffset(br, result, result.ExportTableRVA);
            if (exportTableOffset == 0)
                return;

            br.BaseStream.Position = exportTableOffset;

            // 读取导出表头部
            br.BaseStream.Position += 12; // 跳过前三个字段

            // 读取名称
            uint nameRVA = br.ReadUInt32();
            if (nameRVA != 0)
            {
                uint nameOffset = RVAtoFileOffset(br, result, nameRVA);
                if (nameOffset != 0)
                {
                    long currentPos = br.BaseStream.Position;
                    br.BaseStream.Position = nameOffset;

                    StringBuilder exportName = new StringBuilder();
                    char c;
                    while ((c = br.ReadChar()) != '\0')
                    {
                        exportName.Append(c);
                    }

                    result.ExportName = exportName.ToString();
                    br.BaseStream.Position = currentPos;
                }
            }
        }

        /// <summary>
        /// 检查资源表
        /// </summary>
        private static void CheckResourceTable(BinaryReader br, PEAnalysisResult result)
        {
            if (result.ResourceTableRVA == 0 || result.ResourceTableSize == 0)
                return;

            // 计算资源表在文件中的位置
            uint resourceTableOffset = RVAtoFileOffset(br, result, result.ResourceTableRVA);
            if (resourceTableOffset == 0)
                return;

            br.BaseStream.Position = resourceTableOffset;
            result.HasResources = true;
        }

        /// <summary>
        /// RVA转文件偏移
        /// </summary>
        private static uint RVAtoFileOffset(BinaryReader br, PEAnalysisResult result, uint rva)
        {
            foreach (var section in result.Sections)
            {
                if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
                {
                    return section.PointerToRawData + (rva - section.VirtualAddress);
                }
            }
            return 0;
        }

        /// <summary>
        /// 分析可疑特征
        /// </summary>
        private static void AnalyzeSuspiciousFeatures(PEAnalysisResult result)
        {
            // 检查节名称
            foreach (var section in result.Sections)
            {
                if (section.Name.Contains(".text") && section.VirtualSize == 0)
                {
                    result.SuspiciousFeatures.Add("空的.text节");
                }
                else if (section.Name.Contains(".data") && section.VirtualSize > 1024 * 1024)
                {
                    result.SuspiciousFeatures.Add("过大的.data节");
                }
            }

            // 检查入口点
            if (result.AddressOfEntryPoint == 0)
            {
                result.SuspiciousFeatures.Add("入口点为0");
            }

            // 检查文件大小
            FileInfo fileInfo = new FileInfo(result.FilePath);
            if (fileInfo.Length > 50 * 1024 * 1024)
            {
                result.SuspiciousFeatures.Add("文件过大");
            }

            // 检查时间戳
            if (result.TimeDateStamp < new DateTime(2015, 1, 1))
            {
                result.SuspiciousFeatures.Add("时间戳过旧");
            }
            else if (result.TimeDateStamp > DateTime.Now.AddDays(1))
            {
                result.SuspiciousFeatures.Add("时间戳为未来日期");
            }

            // 根据可疑特征判断是否为恶意文件（更严格的组合判断）
            // 结构性严重异常特征列表
            var criticalAnomalies = result.SuspiciousFeatures.Where(f =>
                f == "空的.text节" || f == "入口点为0" || f == "时间戳为未来日期"
                || f == "过大的.data节").ToList();

            if (result.SuspiciousFeatures.Count >= 5 && criticalAnomalies.Count >= 2)
            {
                // 高置信度：5+特征且至少2个严重结构性异常
                result.IsMalicious = true;
                result.ThreatName = "高度可疑PE文件";
                result.Confidence = 0.95;
            }
            else if (result.SuspiciousFeatures.Count >= 3 && criticalAnomalies.Count >= 1)
            {
                // 中置信度：3+特征且至少1个严重结构性异常
                result.IsMalicious = true;
                result.ThreatName = "可疑PE文件";
                result.Confidence = 0.75;
            }
        }
    }

    public class PEAnalysisResult
    {
        public string FilePath { get; set; }
        public bool IsValidPE { get; set; }
        public bool IsMalicious { get; set; }
        public string ThreatName { get; set; }
        public double Confidence { get; set; }
        public string ErrorMessage { get; set; }
        public uint PEHeaderOffset { get; set; }
        public ushort MachineType { get; set; }
        public ushort NumberOfSections { get; set; }
        public DateTime TimeDateStamp { get; set; }
        public ushort SizeOfOptionalHeader { get; set; }
        public ushort Characteristics { get; set; }
        public ushort Magic { get; set; }
        public string LinkerVersion { get; set; }
        public uint SizeOfCode { get; set; }
        public uint SizeOfInitializedData { get; set; }
        public uint SizeOfUninitializedData { get; set; }
        public uint AddressOfEntryPoint { get; set; }
        public uint BaseOfCode { get; set; }
        public uint BaseOfData { get; set; }
        public uint ImageBase { get; set; }
        public uint SectionAlignment { get; set; }
        public uint FileAlignment { get; set; }
        public string OperatingSystemVersion { get; set; }
        public string ImageVersion { get; set; }
        public string SubsystemVersion { get; set; }
        public uint SizeOfImage { get; set; }
        public uint SizeOfHeaders { get; set; }
        public uint CheckSum { get; set; }
        public ushort Subsystem { get; set; }
        public ushort DLLCharacteristics { get; set; }
        public uint SizeOfStackReserve { get; set; }
        public uint SizeOfStackCommit { get; set; }
        public uint SizeOfHeapReserve { get; set; }
        public uint SizeOfHeapCommit { get; set; }
        public uint ImportTableRVA { get; set; }
        public uint ImportTableSize { get; set; }
        public uint ExportTableRVA { get; set; }
        public uint ExportTableSize { get; set; }
        public uint ResourceTableRVA { get; set; }
        public uint ResourceTableSize { get; set; }
        public string ExportName { get; set; }
        public bool HasResources { get; set; }
        public List<SectionInfo> Sections { get; set; }
        public List<ImportInfo> Imports { get; set; }
        public List<string> SuspiciousFeatures { get; set; } = new List<string>();
    }

    public class SectionInfo
    {
        public string Name { get; set; }
        public uint VirtualSize { get; set; }
        public uint VirtualAddress { get; set; }
        public uint SizeOfRawData { get; set; }
        public uint PointerToRawData { get; set; }
    }

    public class ImportInfo
    {
        public string DLLName { get; set; }
    }
}
