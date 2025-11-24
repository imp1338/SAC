#pragma once
#include <ntddk.h>

namespace SAC {
	VOID Detect_SuspiciousDriverNames(void);
	VOID Detect_UnsignedDrivers(void);
	VOID Detect_HookedDriverObject(void);
	VOID BuildSyscallBaseline(void);
	VOID BuildHWIDBaseline(void);
	VOID Detect_SSDT_Changes(void);
	VOID Detect_HWID_Spoofing(void);
	VOID FreeDetectionBaselines(void);
	BOOLEAN ReadIdtr(_Out_ PVOID* idtrBase, _Out_ USHORT* idtrLimit);
	VOID Detect_IDT_NMI_Hook(void);
	VOID BuildDriverHashBaseline(void);
	VOID Detect_DriverHashChanges(void);
	VOID ProcessNotifyCallbackEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
	EXTERN_C
		OB_PREOP_CALLBACK_STATUS NTAPI HandlePreCallback(
			_In_ PVOID RegistrationContext,
			_Inout_ POB_PRE_OPERATION_INFORMATION OpInfo
		);
	VOID RegisterObCallbacks(void);
	VOID UnregisterObCallbacks(void);
}