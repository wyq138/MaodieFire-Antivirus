# 耄耋杀毒软件问题修复总结

## 修复概览

本次修复解决了用户反馈的三个问题：

1. **误报率高** - 杀毒软件自身进程、病毒库temp、系统进程都被误报
2. **开机自启无效** - 设置界面无法实际设置开机自启动
3. **风险弹窗位置错误** - 弹窗显示在屏幕中央而非右下角

---

## 已完成的修改

### 1. 修复误报问题

**修改文件**: `FireAntivirus.Services\ApplicationWhitelist.cs`

#### 1.1 扩展系统进程白名单（第100-170行）
- 添加完整的Windows系统核心进程（dwm.exe, fontdrvhost.exe, RuntimeBroker.exe等）
- 添加Windows系统工具进程（cmd.exe, powershell.exe, taskmgr.exe等）
- 添加常见系统应用进程（notepad.exe, calc.exe, mspaint.exe等）
- 添加杀毒软件自身进程（FireAntivirus.Host.exe等）
- 添加更多浏览器和办公软件
- 添加病毒库临时目录到排除路径

#### 1.2 修复temp目录评分逻辑（第469-512行）
- 移除了对temp路径的额外加分逻辑
- 只对temp/download目录中的`.exe`文件加分（真正可疑的文件）
- 减少了正常文件被误报的情况

### 2. 修复开机自启动功能

**修改文件**:
- `FireAntivirus.Host.WPF\Pages\SettingsPage.xaml`
- `FireAntivirus.Host.WPF\Pages\SettingsPage.xaml.cs`

#### 2.1 XAML修改（第286-302行）
- 为`AutoStartCheckBox`添加了`Checked`和`Unchecked`事件绑定

#### 2.2 代码修改
- 添加了注册表路径常量定义
- 实现了`LoadAutoStartStatus()`方法 - 读取当前开机自启动状态
- 实现了`IsAutoStartEnabled()`方法 - 检查注册表Run项
- 实现了`SetAutoStart(bool enable)`方法 - 设置/取消开机自启动
- 实现了`AutoStartCheckBox_Changed()`事件处理 - 响应用户操作

### 3. 修复风险弹窗位置

**修改文件**: `FireAntivirus.Common\Notification\NotificationService.cs`

#### 3.1 替换MessageBox（第100-128行）
- 移除了`MessageBox.Show()`调用（会显示在屏幕中央）
- 所有通知类型现在都使用自定义通知窗口`ShowNotificationForm()`
- 保持了托盘气泡通知功能

#### 3.2 增强位置设置可靠性（第476-506行）
- 为`UpdateNotificationPosition()`方法添加了异常处理
- 改用`screen.WorkingArea.Right`和`screen.WorkingArea.Bottom`计算位置
- 添加了边界检查确保窗口在屏幕内
- 添加了降级处理，失败时使用默认位置

---

## 技术细节

### 开机自启动实现原理
使用Windows注册表实现开机自启动：
- 注册表路径: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- 键名: `FireAntivirus`
- 值: 程序完整路径

### 误报修复原理
通过扩展白名单和优化评分逻辑：
- 将常见系统进程、可信应用加入白名单
- 只对temp目录中的可执行文件(.exe)提高风险评分
- 排除病毒库临时目录扫描

### 通知窗口定位
使用WinForms的`Screen`类获取工作区域：
- 计算右下角坐标：`WorkingArea.Right - FormWidth - 10`
- 考虑任务栏等系统元素

---

## 修改文件清单

| 文件 | 修改内容 |
|------|----------|
| `FireAntivirus.Services\ApplicationWhitelist.cs` | 扩展白名单、修复评分逻辑 |
| `FireAntivirus.Host.WPF\Pages\SettingsPage.xaml` | 添加事件绑定 |
| `FireAntivirus.Host.WPF\Pages\SettingsPage.xaml.cs` | 实现开机自启动逻辑 |
| `FireAntivirus.Common\Notification\NotificationService.cs` | 修复弹窗位置 |

---

## 修复状态

- [x] 任务1：修复误报问题
- [x] 任务2：修复开机自启动功能
- [x] 任务3：修复风险弹窗位置

所有问题已修复完成。
