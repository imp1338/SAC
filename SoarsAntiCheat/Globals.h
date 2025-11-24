#pragma once
#include "IOCTL.h"

#define DET_SSDT_CHANGES_CODE 0x1005
#define DET_HWID_SPOOF_CODE   0x2001
#define DET_IDT_NMI_HOOK_CODE 0x1006
#define MAX_DETECTIONS 128
#define SYS_CALL_STUB_BYTES 32
#define SYS_HASH_SEED 5381UL
#define SYSTEM_MODULE_INFO 11
#define IRP_MJ_MAXIMUM 28
#define MAX_DETECTIONS_TRACKED 128

typedef PVOID POB_CALLBACK_HANDLE;

typedef enum _DETECTION_SEVERITY {
    SevInfo = 0,
    SevMedium = 1,
    SevHigh = 2,
    SevCritical = 3
} DETECTION_SEVERITY;

typedef struct _MODULE_RANGE {
    PVOID Base;
    SIZE_T Size;
} MODULE_RANGE, * PMODULE_RANGE;

typedef struct _DETECTION_RESULT {
    UINT32 Code;
    UINT32 Extra;
    DETECTION_SEVERITY  Severity;
    UINT8  Padding[3];
    LARGE_INTEGER Timestamp;
    WCHAR Description[128];
} DETECTION_RESULT;

typedef struct _DRIVER_BASELINE {
    PVOID ImageBase;
    SIZE_T ImageSize;
    CHAR Name[128];
    UINT64 Hash;
} DRIVER_BASELINE;

#pragma pack(push,1)
typedef struct _INJECT_DETECTION {
    UINT32 Code;
    UINT32 Extra;
    UINT8  Severity;
    UINT8  Padding[3];
    WCHAR  Description[128];
} INJECT_DETECTION;
#pragma pack(pop)

typedef struct _SYS_MODULE_ENTRY_LOCAL {
    PVOID Reserved1;
    PVOID ImageBaseAddress;
    ULONG ImageSize;
    ULONG Flags;
    USHORT Id;
    USHORT Rank;
    USHORT NameOffset;
    CHAR Name[256];
} SYS_MODULE_ENTRY_LOCAL, * PSYS_MODULE_ENTRY_LOCAL;

typedef struct _SYS_MODULE_INFO_LOCAL {
    ULONG NumberOfModules;
    SYS_MODULE_ENTRY_LOCAL Modules[1];
} SYS_MODULE_INFO_LOCAL, * PSYS_MODULE_INFO_LOCAL;

extern const char* g_SyscallNames[];
extern const SIZE_T g_SyscallCount;
typedef struct _SYS_FINGERPRINT {
    char Name[64];
    ULONG64 Hash; 
} SYS_FINGERPRINT;
extern SYS_FINGERPRINT* g_SysBaseline;
extern WCHAR* g_BaselineMachineGuid;
extern WCHAR* g_BaselineDiskId; 

extern DRIVER_BASELINE* g_DriverBaselines;
extern SIZE_T g_DriverBaselineCount;

#define TELEMETRY_RING_SIZE 256
typedef struct {
    LARGE_INTEGER Timestamp;
    UINT32 EventCode;
    UINT32 Extra;
    WCHAR Message[128];
} TELEMETRY_ENTRY;

extern TELEMETRY_ENTRY* g_TelemetryRing;
extern volatile LONG g_TelemetryWriteIndex;
extern KSPIN_LOCK g_TelemetryLock;

extern OB_CALLBACK_REGISTRATION gObReg;
extern OB_OPERATION_REGISTRATION gOpReg[1];
extern POB_CALLBACK_HANDLE gObHandle;

extern UINT32 g_PreviouslyReportedCodes[MAX_DETECTIONS_TRACKED];
extern SIZE_T g_PreviouslyReportedCount;
extern DETECTION_RESULT g_Detections[MAX_DETECTIONS];
extern ULONG g_DetectionCount;
extern KSPIN_LOCK g_DetectionLock;
extern HANDLE g_ScanThreadHandle;
extern volatile BOOLEAN g_StopScan;

extern PDEVICE_OBJECT g_DeviceObject;

extern const char* g_BlocklistSubstrings[];
extern const size_t g_BlocklistCount;