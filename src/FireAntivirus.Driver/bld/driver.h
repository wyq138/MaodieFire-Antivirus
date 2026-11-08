/* ============================================================
 * FireAntivirusKrn - 耄耋安全 内核防护驱动 (完整版)
 * 模块: 1) IOCTL 设备接口(\Device\FireAntivirusKernel)
 *       2) 进程创建拦截(PsSetCreateProcessNotifyRoutineEx)
 *       3) 注册表自启动/服务注入防护(CmRegisterCallbackEx)
 *       4) 多进程自保护(ObRegisterCallbacks 防杀 + 注入尝试检测)
 *       5) 分区表/UEFI 防护(磁盘写过滤: MBR + GPT 头/分区表)
 *       6) 内核事件上报管道(环形队列, 用户态 IOCTL 0x805 轮询)
 * 对齐用户态: FireAntivirus.Engine.Kernel.KernelProtectionInterface.cs
 * 构建: EWDK/WDK, 见 build.cmd
 * ============================================================ */
#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>

/* 进程访问权限常量（内核模式头文件不导出，自行定义） */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE       0x0001
#define PROCESS_CREATE_THREAD   0x0002
#define PROCESS_VM_OPERATION    0x0008
#define PROCESS_VM_WRITE        0x0020
#endif

/* 未文档化但已导出（Windows 7+）：取进程 15 字符短名 */
NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

/* ---- 设备与符号链接名(与用户态 CreateFile("\\\\.\\FireAntivirusKernel") 对齐) ---- */
#define FAV_DEVICE_NAME     L"\\Device\\FireAntivirusKernel"
#define FAV_SYMLINK_NAME    L"\\DosDevices\\FireAntivirusKernel"

/* ---- IOCTL 定义(必须与用户态 CTL_CODE(FILE_DEVICE_UNKNOWN, n, METHOD_BUFFERED, FILE_ANY_ACCESS) 一致) ---- */
#define FAV_IOCTL_SET_FILE_FILTER       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x222000 */
#define FAV_IOCTL_SET_PROCESS_FILTER    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x222004 */
#define FAV_IOCTL_SET_REGISTRY_FILTER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x222008 */
#define FAV_IOCTL_SET_PROTECTED_PID     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x22200C 扩展: 输入=ULONG count + ULONG pids[count]（批量受保护进程） */
#define FAV_IOCTL_ENABLE_DISK_GUARD     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x222010 扩展: 输入8字节(LONG mbrGuard, LONG gptGuard) */
#define FAV_IOCTL_GET_EVENTS            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x222014 扩展: 内核事件上报, 输出=[ULONG count][FAV_EVENT×count] */

/* ---- 内核事件类型(与用户态 KernelEvent 对齐) ---- */
#define FAV_EVT_PROCESS_BLOCKED     1   /* 进程创建被拦截 */
#define FAV_EVT_REGISTRY_BLOCKED    2   /* 注册表自启动/服务注入被拦截 */
#define FAV_EVT_INJECTION_ATTEMPT   3   /* 对受保护进程的注入尝试 */
#define FAV_EVT_DISK_WRITE_BLOCKED  4   /* 分区表/UEFI 写被拦截 */
#define FAV_EVT_HANDLE_STRIPPED     5   /* 受保护进程句柄权限被剥离 */
#define FAV_EVT_FILE_WRITE          6   /* minifilter: 文件写入 */
#define FAV_EVT_FILE_DELETE         7   /* minifilter: 文件删除 */

/* ---- 事件队列 ---- */
#define FAV_EVENT_QUEUE_SIZE   64
#define FAV_MAX_PIDS           16
#define FAV_EVENT_TEXT         128

/* 单条内核事件（固定大小, 用户态按同布局解析） */
typedef struct _FAV_EVENT {
    ULONG Type;                     /* FAV_EVT_* */
    ULONG Pid;                      /* 相关进程 PID */
    WCHAR Source[FAV_EVENT_TEXT];   /* 进程镜像路径 / 键路径 / 目标描述 */
    WCHAR Detail[FAV_EVENT_TEXT];   /* 行为详情 */
} FAV_EVENT, *PFAV_EVENT;           /* 4+4+256+256 = 520 字节 */

/* ---- 配置结构(与 C# 结构体布局一致: C# bool 按 4 字节 int 编组) ---- */
typedef struct _FAV_FILE_CONFIG {
    LONG MonitorCreate;                 /* 1 = 开启 */
    LONG MonitorWrite;
    LONG MonitorDelete;
    LONG MonitorExecute;
    LONG BlockSuspiciousExtensions;
} FAV_FILE_CONFIG, *PFAV_FILE_CONFIG;               /* 20 字节 */

typedef struct _FAV_PROCESS_CONFIG {
    LONG MonitorProcessCreation;
    LONG MonitorThreadCreation;
    LONG MonitorRemoteThread;
    LONG BlockCodeInjection;
} FAV_PROCESS_CONFIG, *PFAV_PROCESS_CONFIG;         /* 16 字节 */

typedef struct _FAV_REGISTRY_CONFIG {
    LONG MonitorAutoRun;
    LONG MonitorServices;
    LONG MonitorBrowserExtensions;
    LONG BlockSuspiciousKeys;
} FAV_REGISTRY_CONFIG, *PFAV_REGISTRY_CONFIG;       /* 16 字节 */

/* ---- 全局防护状态 ---- */
typedef struct _FAV_GLOBAL_STATE {
    PDRIVER_OBJECT  DriverObject;

    /* 配置开关(默认关闭=仅记录, 由用户态 IOCTL 打开=真实拦截) */
    LONG FileGuardEnabled;
    LONG ProcessGuardEnabled;
    LONG RegistryGuardEnabled;
    LONG DiskGuardEnabled;      /* 分区表防护: MBR(LBA0) 写拦截 */
    LONG GptGuardEnabled;       /* UEFI 防护: GPT 头/分区表(LBA1..33) 写拦截 */

    /* 多进程自保护（受保护 PID 数组, 用户态批量下发） */
    HANDLE ProtectedPids[FAV_MAX_PIDS];
    ULONG  ProtectedPidCount;
    PVOID  ObCallbackHandle;    /* ObRegisterCallbacks 注册句柄 */

    /* 磁盘过滤设备 */
    PDEVICE_OBJECT  DiskFilterDevice;
    PDEVICE_OBJECT  DiskTargetDevice;
    PFILE_OBJECT    DiskFileObject;

    /* 注册表回调 */
    LARGE_INTEGER   RegistryCookie;
    BOOLEAN         RegistryCallbackRegistered;

    /* 进程回调 */
    BOOLEAN         ProcessCallbackRegistered;

    /* Ob 回调 */
    BOOLEAN         ObCallbackRegistered;

    /* 内核事件队列 */
    FAV_EVENT       EventQueue[FAV_EVENT_QUEUE_SIZE];
    ULONG           EventHead;      /* 写入位置 */
    ULONG           EventTail;      /* 读出位置 */
    KSPIN_LOCK      EventLock;

    /* 异步 GET_EVENTS：挂起的 IRP（事件入队时直接完成，消除轮询延迟） */
    PIRP            PendingEventIrp;
    KSPIN_LOCK      PendingLock;
} FAV_GLOBAL_STATE, *PFAV_GLOBAL_STATE;

/* ---- 磁盘过滤设备扩展 ---- */
typedef struct _FAV_DEVICE_EXTENSION {
    PDEVICE_OBJECT  TargetDevice;   /* 下层磁盘设备 */
    PFILE_OBJECT    DiskFileObject; /* 引用的磁盘文件对象 */
} FAV_DEVICE_EXTENSION, *PFAV_DEVICE_EXTENSION;

/* ---- 受保护路径常量 ---- */
#define FAV_MBR_GPT_PROTECT_BYTES  0x4400   /* 保护 LBA0..33: MBR(512B)+GPT头+GPT分区表(共17KB) */

/* ---- 函数声明 ---- */
DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       FavUnload;

DRIVER_DISPATCH     FavDispatchCreateClose;
DRIVER_DISPATCH     FavDispatchDeviceControl;
DRIVER_DISPATCH     FavDispatchWrite;

/* 进程创建回调 */
VOID FavProcessNotifyCallback(
    _In_ HANDLE  ParentId,
    _In_ HANDLE  ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

/* 注册表回调 */
NTSTATUS FavRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
);

/* Ob 句柄回调 */
OB_PREOP_CALLBACK_STATUS FavObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

/* 磁盘栈附加 */
NTSTATUS FavAttachToDiskStack(VOID);
VOID FavDetachFromDiskStack(VOID);

/* 事件队列 */
VOID FavPushEvent(_In_ ULONG Type, _In_ ULONG Pid, _In_opt_ PCWSTR Source, _In_opt_ PCWSTR Detail);
BOOLEAN FavIsProtectedPid(_In_ HANDLE ProcessId);

/* 事件日志(DebugView 可见) */
VOID FavLog(_In_ PCSTR Format, ...);