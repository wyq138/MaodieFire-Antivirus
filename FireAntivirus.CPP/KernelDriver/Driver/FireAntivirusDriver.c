/*
 * FireAntivirus Kernel Driver (自签名黑签名版)
 * 设备对象名: \Device\FireAntivirusKernel
 * 符号链接:   \DosDevices\FireAntivirusKernel (用户态可见: \\.\FireAntivirusKernel)
 *
 * 编译方式:
 *   1. 安装 WDK (Windows Driver Kit 10.x)
 *   2. 用 VS 2022 + WDK 新建 Kernel Driver 项目,替换 Driver.c
 *   3. 运行 Scripts\install_driver_signed.bat (自动启用测试签名 + 生成自签名证书 + 安装驱动)
 *
 * 由于用户态 AntivirusEngine 在驱动不存在时会自动降级为"用户模式保护",
 * 所以 sys 驱动的存在是"增强拦截",而非硬性依赖。
 */

#include <ntddk.h>

// ==================== 常量 ====================

#define FIREANTIVIRUS_DEVICE_NAME   L"\\Device\\FireAntivirusKernel"
#define FIREANTIVIRUS_DOS_NAME      L"\\DosDevices\\FireAntivirusKernel"

// IOCTL 码 (与用户态 KernelProtection.h 对齐)
#define IOCTL_SET_FILE_FILTER     CTL_CODE(0x00000022, 0x800, 0, 0)
#define IOCTL_SET_PROCESS_FILTER  CTL_CODE(0x00000022, 0x801, 0, 0)
#define IOCTL_SET_REGISTRY_FILTER CTL_CODE(0x00000022, 0x802, 0, 0)
#define IOCTL_QUERY_STATUS        CTL_CODE(0x00000022, 0x803, 0, 0)

// ==================== 全局 ====================

static PDEVICE_OBJECT g_DeviceObject   = nullptr;
static UNICODE_STRING g_DeviceName;
static UNICODE_STRING g_DosName;

static KSPIN_LOCK g_FilterLock;
static BOOLEAN g_FileFilterEnabled    = FALSE;
static BOOLEAN g_ProcessFilterEnabled = FALSE;
static BOOLEAN g_RegFilterEnabled     = FALSE;

// ==================== 转发声明 ====================

DRIVER_INITIALIZE DriverEntry;
NTSTATUS          DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS          DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS          DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// ==================== DriverEntry ====================

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_DeviceName, sizeof(g_DeviceName));
    RtlZeroMemory(&g_DosName,    sizeof(g_DosName));
    RtlInitUnicodeString(&g_DeviceName, FIREANTIVIRUS_DEVICE_NAME);
    RtlInitUnicodeString(&g_DosName,    FIREANTIVIRUS_DOS_NAME);
    KeInitializeSpinLock(&g_FilterLock);

    // 创建设备对象
    NTSTATUS status = IoCreateDevice(
        DriverObject, 0, &g_DeviceName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint("FireAntivirus: IoCreateDevice failed 0x%X\n", status);
        return status;
    }

    // 创建符号链接
    status = IoCreateSymbolicLink(&g_DosName, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("FireAntivirus: IoCreateSymbolicLink failed 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = nullptr;
        return status;
    }

    // 分发函数
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    DbgPrint("FireAntivirus: Kernel driver loaded OK (TEST SIGNED)\n");
    return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_DeviceObject) {
        IoDeleteSymbolicLink(&g_DosName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = nullptr;
    }
    DbgPrint("FireAntivirus: Kernel driver unloaded\n");
    return STATUS_SUCCESS;
}

// ==================== 分发函数 ====================

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT, 0);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG in_size  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_size = stack->Parameters.DeviceIoControl.OutputBufferLength;

    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytes = 0;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_FilterLock, &old_irql);

    switch (code) {
        case IOCTL_SET_FILE_FILTER:
            if (in_size >= sizeof(BOOLEAN)) {
                g_FileFilterEnabled = TRUE;
                status = STATUS_SUCCESS;
            }
            break;
        case IOCTL_SET_PROCESS_FILTER:
            if (in_size >= sizeof(BOOLEAN)) {
                g_ProcessFilterEnabled = TRUE;
                status = STATUS_SUCCESS;
            }
            break;
        case IOCTL_SET_REGISTRY_FILTER:
            if (in_size >= sizeof(BOOLEAN)) {
                g_RegFilterEnabled = TRUE;
                status = STATUS_SUCCESS;
            }
            break;
        case IOCTL_QUERY_STATUS: {
            struct StatusOut { BOOLEAN file_filt; BOOLEAN proc_filt; BOOLEAN reg_filt; ULONG reserved; } out;
            out.file_filt = g_FileFilterEnabled;
            out.proc_filt = g_ProcessFilterEnabled;
            out.reg_filt  = g_RegFilterEnabled;
            out.reserved  = 0;
            bytes = min(out_size, sizeof(out));
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &out, bytes);
            status = STATUS_SUCCESS;
            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    KeReleaseSpinLock(&g_FilterLock, old_irql);

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT, 0);
    return status;
}
