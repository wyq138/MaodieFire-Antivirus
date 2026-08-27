# 耄耋杀毒软件问题修复任务清单

## 任务总览
- [x] 任务1：修复误报问题（扩展白名单+修复评分逻辑）
- [x] 任务2：修复开机自启动功能（设置页面绑定）
- [x] 任务3：修复风险弹窗位置（右下角显示）

---

## 任务1：修复误报问题

### 1.1 扩展系统进程白名单
**文件**: `FireAntivirus.Services.ApplicationWhitelist.cs`
**修改方法**: `InitializeDefaultWhitelist()` (第100-125行)

- [ ] 1.1.1 添加完整的Windows系统核心进程
  - taskmgr.exe, cmd.exe, powershell.exe, conhost.exe
  - rundll32.exe, svchost.exe (已有), services.exe (已有)
  - lsass.exe (已有), winlogon.exe (已有), csrss.exe (已有)
  - smss.exe (已有), wininit.exe (已有), explorer.exe (已有)
  - dwm.exe, fontdrvhost.exe, RuntimeBroker.exe, SearchIndexer.exe

- [ ] 1.1.2 添加Windows系统工具进程
  - control.exe, mmc.exe, regedit.exe, msiexec.exe
  - taskmgr.exe, diskmgmt.msc, devmgmt.msc

- [ ] 1.1.3 添加杀毒软件自身进程
  - FireAntivirus.Host.exe, FireAntivirus.Services.exe
  - FireAntivirus.Engine.dll相关进程

- [ ] 1.1.4 添加常见可信应用程序
  - notepad.exe, calc.exe, mspaint.exe
  - dllhost.exe, WmiPrvSE.exe, SearchHost.exe

### 1.2 修复temp目录评分逻辑
**文件**: `FireAntivirus.Services.ApplicationWhitelist.cs`
**修改方法**: `GetViolationSeverity()` (第400-426行)

- [ ] 1.2.1 移除对temp路径的额外扣分逻辑
  - 删除或注释第406-408行对temp路径的加分
  - 只对真正可疑的temp文件（如.exe在temp中）报警

### 1.3 添加排除路径
**文件**: `FireAntivirus.Services.ApplicationWhitelist.cs`

- [ ] 1.3.1 添加病毒库临时目录排除
  - 在白名单检查中添加病毒库临时目录检查

---

## 任务2：修复开机自启动功能

### 2.1 实现开机自启动复选框逻辑
**文件**: `FireAntivirus.Host.WPF\Pages\SettingsPage.xaml.cs`

- [ ] 2.1.1 添加开机自启动状态读取方法
  - 创建检查注册表Run项的方法
  - 页面加载时更新复选框状态

- [ ] 2.1.2 添加开机自启动设置/取消方法
  - 实现注册表添加/删除逻辑
  - 处理异常情况

- [ ] 2.1.3 绑定复选框事件
  - 为AutoStartCheckBox添加Checked事件处理
  - 为AutoStartCheckBox添加Unchecked事件处理

### 2.2 修改SettingsPage.xaml
**文件**: `FireAntivirus.Host.WPF\Pages\SettingsPage.xaml`

- [ ] 2.2.1 为AutoStartCheckBox添加事件绑定
  - 添加Checked="AutoStartCheckBox_Changed"
  - 添加Unchecked="AutoStartCheckBox_Changed"

---

## 任务3：修复风险弹窗位置

### 3.1 替换MessageBox为自定义通知窗口
**文件**: `FireAntivirus.Common\Notification\NotificationService.cs`
**修改方法**: `ShowNotificationInternal()` (第100-132行)

- [ ] 3.1.1 移除MessageBox.Show调用
  - 删除或注释第116-124行的MessageBox.Show
  - 改为调用自定义通知窗口显示方法

- [ ] 3.1.2 确保使用统一的自定义通知
  - 所有类型的通知都通过ShowNotificationForm显示
  - 保持右下角位置

### 3.2 优化通知窗口位置设置
**文件**: `FireAntivirus.Common\Notification\NotificationService.cs`

- [ ] 3.2.1 增强位置设置的可靠性
  - 在ShowNotificationForm开始时再次调用UpdateNotificationPosition
  - 添加异常处理确保不因位置设置失败影响显示

- [ ] 3.2.2 测试多显示器场景
  - 确保在主显示器右下角显示
