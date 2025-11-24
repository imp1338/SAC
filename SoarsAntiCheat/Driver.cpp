#include "IOCTL.h"
#include "SAC.h"
#include "Utils.h"
#include "Globals.h"

UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
UNICODE_STRING g_SymLink = RTL_CONSTANT_STRING(SYMLINK_NAME);

VOID ScanThreadRoutine(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    LARGE_INTEGER interval;
    interval.QuadPart = -100000LL;

    while (!g_StopScan)
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DetectionLock, &oldIrql);
        g_DetectionCount = 0;
        RtlZeroMemory(g_Detections, sizeof(DETECTION_RESULT) * MAX_DETECTIONS);
        KeReleaseSpinLock(&g_DetectionLock, oldIrql);

        if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        {
            SAC::Detect_SuspiciousDriverNames();
            SAC::Detect_UnsignedDrivers();
            SAC::Detect_HookedDriverObject();
            SAC::Detect_HWID_Spoofing();
            SAC::Detect_SSDT_Changes();
            SAC::Detect_IDT_NMI_Hook(); // somewhat dangerous didnt fully debug this
        }
        else
        {
            DbgPrint("SAC: skipping detection, IRQL too high: %u\n", KeGetCurrentIrql());
        }

        for (int i = 0; i < 5 && !g_StopScan; i++)
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID ImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);
    if (FullImageName && FullImageName->Buffer) {
        PCWSTR pcwstr = FullImageName->Buffer;
        Utils::ReportDetection(0x9202, 0, SevCritical, L"ImageLoad: ", pcwstr);
    }
}

NTSTATUS
DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
DispatchIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {
    case IOCTL_SCAN_DRIVERS:
    {
        size_t outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DetectionLock, &oldIrql);

        size_t needed = sizeof(DETECTION_RESULT) * g_DetectionCount;
        if (outLen >= needed) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_Detections, needed);
            Irp->IoStatus.Information = (ULONG)needed;
            status = STATUS_SUCCESS;
        }
        else {
            Irp->IoStatus.Information = 0;
            status = STATUS_BUFFER_TOO_SMALL;
        }

        KeReleaseSpinLock(&g_DetectionLock, oldIrql);
    }
    break;
    case IOCTL_INJECT_DETECTION:
    {
        size_t inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (inLen >= sizeof(INJECT_DETECTION)) {
            INJECT_DETECTION* p = (INJECT_DETECTION*)Irp->AssociatedIrp.SystemBuffer;
            p->Description[RTL_NUMBER_OF(p->Description) - 1] = L'\0';
            Utils::ReportDetection(p->Code, p->Extra, (DETECTION_SEVERITY)p->Severity, p->Description);
            Irp->IoStatus.Information = 0;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
            Irp->IoStatus.Information = 0;
        }
    }
    break;
    case IOCTL_GET_TELEMETRY:
    {
        size_t outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        size_t needed = sizeof(TELEMETRY_ENTRY) * TELEMETRY_RING_SIZE;
        if (outLen >= needed) {
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_TelemetryLock, &oldIrql);
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_TelemetryRing, needed);
            KeReleaseSpinLock(&g_TelemetryLock, oldIrql);
            Irp->IoStatus.Information = (ULONG)needed;
            status = STATUS_SUCCESS;
        }
        else {
            Irp->IoStatus.Information = 0;
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }
    break;


    case IOCTL_GET_BASELINES:
    {
        size_t outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        size_t needed = sizeof(DRIVER_BASELINE) * g_DriverBaselineCount;
        if (outLen >= needed && g_DriverBaselineCount > 0) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_DriverBaselines, needed);
            Irp->IoStatus.Information = (ULONG)needed;
            status = STATUS_SUCCESS;
        }
        else {
            Irp->IoStatus.Information = 0;
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }
    break;
        

    default:
        DbgPrint("SAC: Unknown IOCTL 0x%X\n", code);
        status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// very unstable and most of the time will never unload, plus i didint care about unloading at the time
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    g_StopScan = TRUE;
    SAC::FreeDetectionBaselines();

    if (g_ScanThreadHandle)
    {
        KeWaitForSingleObject(g_ScanThreadHandle,
            Executive,
            KernelMode,
            FALSE,
            NULL);
        ZwClose(g_ScanThreadHandle);
        g_ScanThreadHandle = NULL;
    }

    SAC::UnregisterObCallbacks();
    NTSTATUS st = PsSetCreateProcessNotifyRoutineEx(SAC::ProcessNotifyCallbackEx, TRUE);
    if (!NT_SUCCESS(st)) DbgPrint("SAC: Failed to unregister process notify routine: 0x%X\n", st);
    PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);

    if (g_TelemetryRing)
    {
        ExFreePoolWithTag(g_TelemetryRing, 'telR');
        g_TelemetryRing = NULL;
    }

    IoDeleteSymbolicLink(&g_SymLink);
    if (g_DeviceObject)
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrint("SAC: Driver unloaded safely.\n");
}

extern "C"
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("SAC: Driver Entry Loaded\n");
    DbgPrint("SAC: Sigma Alpha Wolf Mode Activated\n");
    NTSTATUS status;

    KeInitializeSpinLock(&g_DetectionLock);
    status = IoCreateDevice(DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SAC: IoCreateDevice failed 0x%X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        DbgPrint("SAC: IoCreateSymbolicLink failed 0x%X\n", status);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIOCTL;
    DriverObject->DriverUnload = DriverUnload;

    HANDLE threadHandle = NULL;
    status = PsCreateSystemThread(&threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        ScanThreadRoutine,
        NULL);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&g_SymLink);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        DbgPrint("SAC: PsCreateSystemThread failed 0x%X\n", status);
        return status;
    }

    SAC::BuildHWIDBaseline();
    SAC::BuildSyscallBaseline();

    // ring
    g_TelemetryRing = (TELEMETRY_ENTRY*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(TELEMETRY_ENTRY) * TELEMETRY_RING_SIZE, 'telR');
    if (g_TelemetryRing) RtlZeroMemory(g_TelemetryRing, sizeof(TELEMETRY_ENTRY) * TELEMETRY_RING_SIZE);
    g_TelemetryWriteIndex = 0;
    KeInitializeSpinLock(&g_TelemetryLock);

    // base
    SAC::BuildDriverHashBaseline();

    // ob
    SAC::RegisterObCallbacks();
    NTSTATUS st = PsSetCreateProcessNotifyRoutineEx(SAC::ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(st)) DbgPrint("SAC: PsSetCreateProcessNotifyRoutineEx failed 0x%X\n", st);
    PsSetLoadImageNotifyRoutine(ImageLoadNotify);
    

    g_ScanThreadHandle = threadHandle;
    DbgPrint("SAC: Driver loaded successfully.\n");
    return STATUS_SUCCESS;
}
