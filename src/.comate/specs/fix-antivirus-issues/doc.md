# 耄耋杀毒软件问题修复规范

## 需求概述

用户反馈三个问题需要修复：

1. **误报率高**：杀毒软件自己的进程、病毒库temp目录、系统进程都被误报
2. **开机自启缺失**：虽然底层有开机自启功能，但设置界面没有实际生效
3. **风险弹窗位置错误**：弹窗显示在屏幕中央，应该显示在右下角

---

## 问题1：误报率高

### 问题分析

**当前白名单实现分析** (`FireAntivirus.Services.ApplicationWhitelist.cs`):

- 第100-125行：仅初始化了少量系统进程（explorer.exe, svchost.exe, services.exe等9个）
- 第405-408行：`GetViolationSeverity` 方法对包含 "temp" 的路径额外加分，导致temp目录更容易被误报
- 没有包含杀毒软件自身进程
- 没有排除病毒库临时目录
- 系统进程白名单不完整（缺少taskmgr.exe, cmd.exe, powershell.exe等）

**影响范围**:
- 扫描引擎会误报正常系统进程
- 病毒库更新时的临时目录会被扫描
- 自身进程可能被防护模块阻止

### 解决方案

1. **扩展系统进程白名单** (`ApplicationWhitelist.cs`):
   - 添加完整的Windows系统进程列表（taskmgr, cmd, powershell, rundll32等）
   - 添加Windows Defender相关进程
   - 添加杀毒软件自身进程

2. **排除病毒库目录**:
   - 在扫描时排除病毒库临时目录
   - 添加排除路径配置

3. **修复temp目录评分逻辑**:
   - 修改 `GetViolationSeverity` 方法，不要对temp路径额外加分

### 修改文件

- `d:\桌面\All-files\Item file\耄耋安全软件\src\FireAntivirus.Services\ApplicationWhitelist.cs`
  - 修改 `InitializeDefaultWhitelist()` 方法（第100-125行）
  - 修改 `GetViolationSeverity()` 方法（第400-426行）

---

## 问题2：开机自启动设置不生效

### 问题分析

**设置界面分析** (`SettingsPage.xaml.cs` 和 `SettingsPage.xaml`):

- `SettingsPage.xaml` 第286-302行存在"开机自启动"复选框 `AutoStartCheckBox`
- 但代码中只有 `AutoStartLabel.Text` 的国际化设置（第88行）
- **没有任何事件绑定或实际逻辑**来设置开机自启动
- 虽然 `DataManager.cs` 第172行定义了 `StartWithWindows` 配置项，但UI与底层功能没有连接

**StartupManager分析**:
- `StartupManager.cs` 包含完整的开机启动项管理功能
- 但没有被设置页面调用

### 解决方案

1. **在SettingsPage中实现开机自启动逻辑**:
   - 页面加载时读取当前开机自启动状态
   - 复选框状态改变时实际设置/取消开机自启动

2. **利用现有的Windows API实现**:
   - 使用注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 添加启动项
   - 或使用 `StartupManager` 类

### 修改文件

- `d:\桌面\All-files\Item file\耄耋安全软件\src\FireAntivirus.Host.WPF\Pages\SettingsPage.xaml.cs`
  - 添加 `AutoStartCheckBox` 的 `Checked` 和 `Unchecked` 事件处理
  - 添加加载和保存开机自启动状态的逻辑

---

## 问题3：风险弹窗位置错误

### 问题分析

**当前实现** (`NotificationService.cs`):

- 第339-479行：`InitializeNotificationForm()` 方法创建自定义通知窗口
- 第350行：`StartPosition = FormStartPosition.Manual` - 使用手动位置
- 第354行：`UpdateNotificationPosition()` - 确实调用了更新位置方法
- 第481-487行：`UpdateNotificationPosition()` 方法尝试设置右下角位置
  ```csharp
  Screen screen = Screen.PrimaryScreen;
  _notificationForm.Location = new Point(
      screen.WorkingArea.Width - _notificationForm.Width - 10,
      screen.WorkingArea.Height - _notificationForm.Height - 10
  );
  ```

- **问题1**: 第116-124行，当 `type == NotificationType.Error` 时会弹出 `MessageBox.Show`
  - 这个 `MessageBox.Show` 是系统原生窗口，会显示在屏幕中央
  - 这才是用户看到的"弹窗"

- **问题2**: 虽然 `UpdateNotificationPosition` 代码看起来正确，但可能在某些情况下没有正确执行

### 解决方案

1. **将MessageBox替换为自定义通知窗口**:
   - 将第116-124行的 `MessageBox.Show` 改为调用自定义通知窗口
   - 确保所有类型的通知都使用统一的自定义窗口

2. **确保位置设置正确**:
   - 在显示窗口前再次调用 `UpdateNotificationPosition()`
   - 添加异常处理确保位置设置不会失败

### 修改文件

- `d:\桌面\All-files\Item file\耄耋安全软件\src\FireAntivirus.Common\Notification\NotificationService.cs`
  - 修改 `ShowNotificationInternal()` 方法（第100-132行）
  - 确保使用自定义通知窗口而不是 `MessageBox.Show`

---

## 任务执行顺序

1. 修复误报问题（白名单+评分逻辑）
2. 修复开机自启动功能（设置页面）
3. 修复风险弹窗位置（通知服务）
