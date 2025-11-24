#include "Globals.h"

DETECTION_RESULT g_Detections[MAX_DETECTIONS];
ULONG g_DetectionCount = 0;
KSPIN_LOCK g_DetectionLock;
HANDLE g_ScanThreadHandle = NULL;
volatile BOOLEAN g_StopScan = FALSE;


PDEVICE_OBJECT g_DeviceObject = nullptr;

const char* g_BlocklistSubstrings[] = {
    "cheat", "cheater", "cheats", "aimbot", "aimassist", "inject",
    "trainer", "spoofer", "rootkit", "hax", "spoof", "fortnite","detected","undetected"
};
const size_t g_BlocklistCount = sizeof(g_BlocklistSubstrings) / sizeof(g_BlocklistSubstrings[0]);

const char* g_SyscallNames[] = {
    "NtCreateFile",
    "NtOpenFile",
    "NtReadFile",
    "NtWriteFile",
    "NtClose",
    "NtQueryInformationProcess",
    "NtOpenProcess",
    "NtCreateProcessEx",  
    "NtMapViewOfSection",
    "NtProtectVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtOpenThread",
    "NtQuerySystemInformation"
};
const SIZE_T g_SyscallCount = RTL_NUMBER_OF(g_SyscallNames);
UINT32 g_PreviouslyReportedCodes[MAX_DETECTIONS_TRACKED];
SIZE_T g_PreviouslyReportedCount = 0;
SYS_FINGERPRINT* g_SysBaseline = nullptr;
WCHAR* g_BaselineMachineGuid = nullptr;
 WCHAR* g_BaselineDiskId = nullptr;

DRIVER_BASELINE* g_DriverBaselines = nullptr;
SIZE_T g_DriverBaselineCount = 0;
TELEMETRY_ENTRY* g_TelemetryRing = nullptr;
volatile LONG g_TelemetryWriteIndex = 0;
KSPIN_LOCK g_TelemetryLock;

OB_CALLBACK_REGISTRATION gObReg = { 0 };
OB_OPERATION_REGISTRATION gOpReg[1] = { 0 };
POB_CALLBACK_HANDLE gObHandle = NULL;