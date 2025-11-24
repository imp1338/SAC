#pragma once
#include "IOCTL.h"
#include "Globals.h"
extern "C" {
    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwQuerySystemInformation(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );
    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwWaitForSingleObject(
            _In_ HANDLE Handle,
            _In_ BOOLEAN Alertable,
            _In_opt_ PLARGE_INTEGER Timeout
        );
}

typedef NTSTATUS(*pfnIoGetDriverObjectPointer)(
    PUNICODE_STRING DriverName,
    PDRIVER_OBJECT* DriverObject,
    PUNICODE_STRING* RemainingName
    );

#pragma pack(push, 1)
typedef struct _SYSTEM_MODULE {
    ULONG  Reserved1;
    ULONG  Reserved2;
    PVOID  ImageBaseAddress;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
#pragma pack(pop)