# 耄耋安全软件 (MaodieFire Antivirus)

> 🐱 一款以猫为灵感的国产综合性安全防护软件，集病毒扫描、实时防护、网络防火墙、行为分析等多种安全功能于一体。

![License](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Framework](https://img.shields.io/badge/.NET-10.0-purple)
![Lines](https://img.shields.io/badge/代码总量-160%2C647-green)

---

## 项目简介

耄耋安全软件是一款基于 WPF 技术开发的 Windows 平台安全防护软件，采用模块化架构设计，涵盖病毒检测、实时防护、网络安全、隐私保护等多个安全领域。项目包含 **38 个功能模块**，源代码超过 **16 万行**，是目前功能较为全面的国产开源安全软件之一。

### 核心特性

- **双进程架构**：主程序 (FireAntivirus.exe) + 后台防护 (FireAntivirus.ServiceHost.exe)，主程序关闭后防护服务持续运行
- **ClamAV 引擎集成**：基于开源 ClamAV 引擎进行病毒扫描，支持本地特征库更新
- **实时文件监控**：监控文件系统变化，实时检测恶意文件
- **行为分析引擎**：通过行为特征分析识别未知威胁
- **网络防火墙**：控制网络流量，阻止恶意连接
- **勒索软件防护**：监控关键文件变化，防止勒索软件加密
- **家长控制**：限制儿童访问不当内容，管理上网时间
- **密码管理器**：安全存储和管理密码
- **隐私保护**：清理浏览痕迹，保护个人隐私
- **系统优化**：优化系统性能，清理无用文件
- **漏洞扫描**：检测系统安全漏洞，提供修复建议
- **安全评分**：综合评估系统安全状况

---

## 项目架构

项目采用 **.NET 10 / WPF** 技术栈，基于模块化设计，各功能模块独立开发，通过项目引用集成到主程序中。

### 双进程设计

| 进程 | 文件名 | 类型 | 说明 |
|------|--------|------|------|
| 主程序 | `FireAntivirus.exe` | WinExe | WPF 界面程序，用户交互入口 |
| 后台防护 | `FireAntivirus.ServiceHost.exe` | Exe | 后台守护进程，支持 Windows 服务模式、控制台模式、独立运行模式 |

主程序关闭后，ServiceHost 进程继续运行，提供持续的安全防护和进程守护功能（自动重启主程序）。

### 模块结构

| 模块 | 代码行数 | 文件数 | 功能 |
|------|---------|--------|------|
| FireAntivirus.Services | 66,909 | 87 | 核心服务层（防护、通知、命名管道） |
| FireAntivirus.Host | 22,796 | 48 | 旧版主程序（WinForms） |
| FireAntivirus.Engine | 21,827 | 46 | 扫描引擎（文件扫描、特征匹配） |
| FireAntivirus.Host.WPF | 15,812 | 63 | WPF 主界面程序 |
| FireAntivirus.Common | 3,673 | 4 | 公共工具库 |
| FireAntivirus.Data | 3,587 | 2 | 数据访问层 |
| FireAntivirus.RealTimeProtectionPlus | 1,029 | 3 | 实时防护增强 |
| FireAntivirus.ServiceHost | 1,119 | 5 | 后台防护服务 |
| FireAntivirus.MachineLearning | 1,219 | 1 | 机器学习模块 |
| FireAntivirus.Tests | 1,465 | 3 | 单元测试 |
| FireAntivirus.ClamAV | 671 | 2 | ClamAV 集成 |
| FireAntivirus.ParentalControl | 780 | 3 | 家长控制 |
| FireAntivirus.AI | 555 | 1 | AI 分析模块 |
| FireAntivirus.RansomwareProtection | 563 | 3 | 勒索防护 |
| FireAntivirus.StartupManager | 708 | 3 | 启动项管理 |
| FireAntivirus.VulnerabilityScanner | 880 | 3 | 漏洞扫描 |
| FireAntivirus.SecurityReport | 552 | 3 | 安全报告 |
| 其他 20+ 模块 | ~10,000 | ~60 | 各专业安全功能 |

---

## 技术栈

| 技术 | 说明 |
|------|------|
| .NET 10 | 运行时框架 |
| WPF | 主界面框架 |
| C# / XAML | 开发语言 |
| ClamAV | 病毒扫描引擎 |
| Newtonsoft.Json | JSON 处理 |
| EntityFramework | 数据持久化 |
| System.ServiceProcess | Windows 服务支持 |
| Named Pipes | 进程间通信 |
| BouncyCastle | 加密算法 |

---

## 构建说明

### 前置要求

- .NET 10 SDK（net10.0-windows）
- Visual Studio 2022 或更高版本
- Windows 10/11 操作系统

### 构建

```bash
# 还原依赖
dotnet restore FireAntivirus.WPF.sln

# 构建 Release 版本
dotnet build FireAntivirus.WPF.sln -c Release
```

构建完成后，输出目录为：
- 主程序：`FireAntivirus.Host.WPF/bin/Release/net10.0-windows/`
- 后台防护：`FireAntivirus.ServiceHost/bin/Release/net10.0-windows/`

两个 exe 及其依赖文件会自动合并到主程序输出目录中。

### 运行

```bash
# 启动主程序
FireAntivirus.exe

# 启动后台防护（控制台模式，用于调试）
FireAntivirus.ServiceHost.exe -console

# 启动后台防护（独立运行模式）
FireAntivirus.ServiceHost.exe -run
```

---

## 代码统计

| 指标 | 数量 |
|------|------|
| C# 源文件 | 352 |
| XAML 文件 | 37 |
| 项目文件 (.csproj) | 38 |
| C# 代码行数 | 154,879 |
| XAML 代码行数 | 5,768 |
| **总代码行数** | **160,647** |

---

## 许可证

本项目采用 **CC BY-NC-SA 4.0**（知识共享 署名-非商业性使用-相同方式共享 4.0 国际）许可证。

- ✅ 个人学习、研究使用
- ✅ 修改和分发（需署名并保持相同许可证）
- ❌ **任何形式的商业使用**（包括但不限于销售、商业集成、付费服务）
- ❌ 未经授权的商业授权

详见 [LICENSE](LICENSE) 文件。

---

## 致谢

- [ClamAV](https://www.clamav.net/) — 开源病毒扫描引擎
- 所有开源依赖库的贡献者

---

*耄耋安全软件 — 以猫之名，守护安全* 🐱
