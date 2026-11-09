<p align="center">
  <img src="docs/logo.png" alt="MaodieFire Antivirus" width="200"/>
</p>

> 🐱 一款以猫为灵感的 Windows 综合性安全防护软件：病毒扫描、实时防护、内核驱动、网络阻断、行为分析、沙箱验证与系统工具的全栈安全能力。

![License](https://img.shields.io/badge/License-MIT-blue) ![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue) ![Framework](https://img.shields.io/badge/.NET-10.0-purple) ![Kernel](https://img.shields.io/badge/Kernel_Driver-WDM%20%2B%20Minifilter-orange)

## 项目简介

基于 .NET 10 / WinUI 3 的 Windows 安全软件，采用「用户态引擎 + 内核驱动 + 沙箱验证」三层纵深防御。检测链融合病毒签名、ClamAV、YARA、机器学习、模糊哈希、行为分析等多源证据，按强弱证据分级裁决：强证据单票定罪、弱证据须多源共识，未共识的可疑文件送本地沙箱做 60 秒行为验证，兼顾高检出率与低误报。

## 防护手段（检测引擎）

### 多源证据判定链

| 手段 | 说明 |
|------|------|
| 多引擎加权评分 | 强证据（签名/驱动级确认）单票定罪；弱证据须 ≥3 源共识，未共识送沙箱验证 |
| 病毒签名库 | 多数据源聚合哈希签名，支持在线更新与镜像回退 |
| ClamAV 引擎 | 集成 ClamAV（freshclam 特征库更新 / libclamav 扫描核心） |
| YARA 规则引擎 | YARA 规则扫描（YARA-X 扫描器可选接入，二进制运行时自备），叠加 LMD 规则集；社区规则降级为弱证据防误报 |
| PE 结构解析 | 导入表 / 节区 / 熵 / 数字签名证书链完整验证（有效期 + 链 + 吊销） |
| EMBER V3 机器学习 | 2568 维特征 CART 随机森林集成，按目标误报率校准阈值（模型经 MelixTrainer 本地训练生成，支持热更新） |
| 四模型集成推理 | 独立 ML 项目，四模型投票并入扫描主判定链（模型文件就位后生效） |
| 模糊哈希聚类 | ssdeep + TLSH 相似度聚类，识别变种与同族样本 |
| 文件 I/O 熵变时序 | 运行期文件熵变化时序分析，识别加壳/加密行为 |
| 启发式分析 | 可疑结构特征启发式评分 |

### 沙箱行为验证

- 可疑文件在本地沙箱（Sandboxie 组件随程序分发）静默运行 **60 秒**，全程行为跟踪
- **62 条 IOA 行为规则**评分，阈值 100 确认恶意；冷却 4 秒 + TTL 10 秒防重复分析
- **13 项沙箱加固配置**（隐藏痕迹 / 保护沙箱进程 / 独立用户配置单元）
- **反沙箱对抗**：识别虚拟机 / 调试器 / 沙箱痕迹的反检测行为，命中仍强制进沙箱绝不裸机运行

### 内核级防护（FireAntivirusKrn.sys）

- **进程创建回调**（PsSetCreateProcessNotifyRoutineEx）：已确认恶意进程内核级拒绝启动
- **Minifilter 文件遥测**：文件写入 / 删除事件实时上报用户态处置链
- **异步 IOCTL 事件通道**：pending IRP + OVERLAPPED 全异步，事件零延迟送达
- 驱动经 Authenticode 签名 + 证书链部署（inf2cat + pnputil）

### 行为与内存分析

| 手段 | 说明 |
|------|------|
| ETW 行为采集 | 进程 / 磁盘 I/O / 网络 / 注册表四通道实时跟踪 |
| 进程血缘图 | 父子链血缘追踪，kill chain 链级阻断 |
| LOLBins 识别 | 无文件执行链路（certutil/regsvr32/mshta 等滥用）阻断 |
| 敏感数据污点追踪 | 敏感数据流跨进程传播追踪 |
| VAD 隐匿内存剥离 | 虚拟地址描述符树解析，剥离隐匿注入内存 |
| LSASS 句柄审计 | 句柄访问掩码周期审计，可疑持有者经确认处置（系统进程白名单拒杀） |
| AMSI 直调 | AmsiScanBuffer 内存直调，脚本/宏内容实时过检 |

## 实时防护

- **文件实时监控**：文件系统变更实时检测，恶意文件落地即报
- **勒索软件防护**：蜜罐文件 + 加密行为速率监测，异常批量改写即刻拦截
- **进程监控**：WMI 进程启动事件订阅（SeSecurityPrivilege 特权）
- **注册表监控**：关键 Run 键 / 服务键变更实时告警
- **USB 设备控制**：WMI BlockDevice 真实禁用 U 盘等存储设备，含解除入口
- **网页与邮件附件防护**：网页下载与邮件附件落盘即扫（附件落盘检测，不挂接邮件收发通道）
- **WFP 网络阻断**：Windows Filtering Platform 策略层动态规则，按远端 IP 双向阻断，TTL 到期自动撤销
- **看门狗自恢复**：防护进程被病毒杀灭后自动拉起（Windows 计划任务 + Mutex 零常驻），正常退出不误拉

## 处置与运营

- **威胁处置窗口**：隔离 / 忽略 / 打开位置 / 重启清除（MoveFileEx） / Restart Manager 解锁占用
- **加密隔离区**：样本加密隔离，未加密样本回流机器学习训练集
- **威胁时间线**：全量检测事件时间轴回溯
- **病毒库更新**：多源在线更新 + 镜像回退，逐源状态可视
- **安全评分与报告**：综合评估系统安全状况，可导出报告
- **漏洞扫描**：系统补丁 / 弱配置检测，给出修复建议
- **数据备份与恢复**：AES 加密备份 / 校验恢复，支持定时计划
- **启动项管理**：注册表 / 计划任务 / 服务启动项可视化管理
- **家长控制**：允许时段限制 + 应用管控
- **密码管理器**：本地加密存储
- **隐私保护**：浏览痕迹清理
- **系统优化**：垃圾清理与性能优化

## 项目架构

```
├─ FireAntivirus.Host.WinUI      WinUI 3 主程序（32 个功能页面，Windows App SDK 自包含）
├─ FireAntivirus.ServiceHost     后台防护服务（Windows 服务 / 控制台 / 独立运行三模式）
├─ FireAntivirus.Watchman        看门狗（被杀自拉）
├─ FireAntivirus.Engine          扫描引擎（多引擎协调 / YARA / PE / ML / 沙箱判定）
├─ FireAntivirus.Services        核心服务层（防护 / 通知 / 备份 / 命名管道）
├─ FireAntivirus.KernelConnect   内核通信（异步 IOCTL / OVERLAPPED）
├─ FireAntivirus.Sandbox         沙箱行为监视（文件 / 注册表 / 网络 / 进程树）
├─ FireAntivirus.MachineLearning 四模型集成推理
├─ FireAntivirus.Driver          内核驱动 FireAntivirusKrn.sys（WDM + Minifilter）
├─ FireAntivirus.Backup          数据备份
├─ FireAntivirus.Common          公共库（日志 / 通知）
└─ Sandbox\                      Sandboxie 运行组件（随程序分发）
```

**技术栈**：.NET 10 / WinUI 3 / C# / WDM 内核驱动 / Minifilter / WFP / ETW / WMI / ClamAV / YARA-YARA-X / EMBER V3

## 构建说明

### 前置要求

- .NET 10 SDK（net10.0-windows10.0.19041.0）
- Windows App SDK 1.6+（NuGet 自还原，SelfContained）
- EWDK / WDK 10.0.28000.0（仅构建内核驱动时需要）
- Windows 10 19041+ / Windows 11

### 构建主程序

```bash
dotnet build src\FireAntivirus.Host.WinUI\FireAntivirus.Host.WinUI.csproj -c Release -p:Platform=x64 -o <输出目录>
```

### 构建内核驱动

仓库已包含编译产物 `src\FireAntivirus.Driver\dist\FireAntivirusKrn.sys`，可直接部署使用。自行构建需准备 EWDK（或 WDK 10.0.28000.0 + VS BuildTools）环境，然后在 `src\FireAntivirus.Driver\bld\` 下执行：

```
msbuild FireAntivirusKrn.vcxproj /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=Windows10 /p:Inf2Cat=false /p:SignMode=Off
```

### 运行时资产（不入库，运行时生成/自备）

- `Sandbox\`（Sandboxie 组件）：出于许可证原因仓库不含二进制，构建后从本机 Sandboxie-Plus 安装目录拷贝 `Start.exe / SbieIni.exe / SbieDll.dll / SbieSvc.exe` 等核心文件至输出目录 `Sandbox\`，或直接依赖系统安装路径。
- `tools\yara-x.exe`：YARA-X 扫描器二进制，运行时自动下载或自备放入输出目录。
- `ML\model_*.bin / melix_ember.json`：EMBER V3 模型由 `MelixTrainer` 本地训练生成，支持运行期热更新。

### 驱动部署

1. 管理员运行 `fa_sign_admin.ps1`（签名 sys）
2. 管理员运行 `fa_pnp_sign.ps1`（打包含签 cat + pnputil 自动部署）
3. `sc query FireAntivirusKrn` 应显示 `RUNNING`

## 运行

```
FireAntivirus.Host.WinUI.exe    主界面（普通权限即可）
FireAntivirus.ServiceHost.exe   后台防护（服务模式随系统启动）
```

## 许可证

本项目采用 **MIT** 许可证，详见 [LICENSE](LICENSE)。**明确允许随安装包（setup 包）与绿色运行包（zip）自由分发**，无需额外授权。

### 第三方组件声明（随包分发合规说明）

本软件主体以 **MIT** 许可证发布；随包分发的第三方组件遵循各自的开源许可证，均允许再分发：

- **Sandboxie-Plus**（`Sandbox\` 目录随包分发的沙箱运行组件）：遵循 **GPLv3** 许可证（非 MIT），版权归 Sandboxie-Plus 项目原作者所有，源码见 [Sandboxie-Plus 官方仓库](https://github.com/sandboxie-plus/Sandboxie)。随包分发符合 GPLv3 再分发条款（保留版权与许可声明，分发包内已附 `Sandbox\LICENSE-Sandboxie.txt`）。MIT 主程序调用 GPL 组件不影响各自许可证的独立性。
- **ClamAV**（病毒扫描引擎）：遵循 **GPLv2** 许可证，由 Cisco Talos 社区维护。
- **YARA / YARA-X**：BSD-3-Clause / MIT，版权归 VirusTotal 社区。

依据上述第三方许可证条款，本软件的安装包与绿色运行包**均可自由再分发**，前提是保留各组件的许可声明与版权信息（分发包内已包含）。

## 开发者

- **开发者**：耄耋软件工作室
- **电话**：18281970402
- **邮箱**：zjhwyq123456@qq.com

---

*耄耋安全软件 — 以猫之名，守护安全* 🐱
