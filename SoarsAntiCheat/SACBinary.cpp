#include "Utils.h"
#include <ntimage.h>
#include "SAC.h"
#include "Globals.h"
#include <ntddstor.h>

VOID SAC::Detect_SuspiciousDriverNames(void)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG needed = 0;
    PVOID buffer = NULL;
    SIZE_T bufSize = 0;

    for (int attempt = 0; attempt < 6; ++attempt) {
        if (bufSize == 0) bufSize = 4096;
        else bufSize *= 2;

        buffer = ExAllocatePoolWithTag(NonPagedPoolNx, bufSize, 'modT');
        if (!buffer) {
            DbgPrint("SAC: Detect_SuspiciousDriverNames - allocation failed (%llu bytes)\n", (unsigned long long)bufSize);
            return;
        }

        status = ZwQuerySystemInformation(11, buffer, (ULONG)bufSize, &needed);
        if (NT_SUCCESS(status)) {
            break;
        }
        else {
            ExFreePoolWithTag(buffer, 'modT');
            buffer = NULL;
            if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
                if (needed != 0 && needed > bufSize) {
                    bufSize = needed + 4096;
                }
                continue;
            }
            else {
                DbgPrint("SAC: Detect_SuspiciousDriverNames - ZwQuerySystemInformation failed 0x%X\n", status);
                return;
            }
        }
    }

    if (!buffer) {
        DbgPrint("SAC: Detect_SuspiciousDriverNames - final allocation failed\n");
        return;
    }

    PSYSTEM_MODULE_INFORMATION pInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
    ULONG count = 0;

    __try {
        count = pInfo->NumberOfModules;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("SAC: Detect_SuspiciousDriverNames - exception reading module count\n");
        ExFreePoolWithTag(buffer, 'modT');
        return;
    }

    for (ULONG i = 0; i < count; ++i) {
        PSYSTEM_MODULE m = &pInfo->Modules[i];
        const char* basename = Utils::GetModuleBasename(m);
        if (!basename) continue;

        size_t maxNameLen = sizeof(m->FullPathName); 
        size_t nameLen = strnlen_s(basename, maxNameLen);
        if (nameLen == 0 || nameLen >= maxNameLen) continue;

        BOOLEAN flagged = FALSE;
        for (SIZE_T bi = 0; bi < g_BlocklistCount; ++bi) {
            if (Utils::AsciiStrContainsInsensitive(basename, g_BlocklistSubstrings[bi])) {
                flagged = TRUE;
                break;
            }
        }

        if (flagged) {
            ANSI_STRING ansi;
            UNICODE_STRING uni;
            RtlInitAnsiString(&ansi, basename);
            NTSTATUS conv = RtlAnsiStringToUnicodeString(&uni, &ansi, TRUE); 
            if (NT_SUCCESS(conv)) {
                WCHAR descBuffer[128];
                RtlStringCchPrintfW(descBuffer, RTL_NUMBER_OF(descBuffer), L"Suspicious driver filename: %wZ", &uni);
                Utils::ReportDetection(0x1001, 0, SevMedium, descBuffer);
                RtlFreeUnicodeString(&uni);
            }
            else {
                WCHAR fallback[128];
                SIZE_T k;
                for (k = 0; k < nameLen && k < (RTL_NUMBER_OF(fallback) - 1); ++k) {
                    fallback[k] = (WCHAR)basename[k];
                }
                fallback[k] = L'\0';
                WCHAR descBuffer2[160];
                RtlStringCchPrintfW(descBuffer2, RTL_NUMBER_OF(descBuffer2), L"Suspicious driver filename: %s", fallback);
                Utils::ReportDetection(0x1001, 0, SevMedium, descBuffer2);
            }
        }
    }

    ExFreePoolWithTag(buffer, 'modT');
    return;
}


VOID SAC::Detect_UnsignedDrivers(void)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG needed = 0;
    PVOID sysBuffer = NULL;
    SIZE_T bufSize = 0;

    for (int attempt = 0; attempt < 6; ++attempt) {
        if (bufSize == 0) bufSize = 4096;
        else bufSize *= 2;

        sysBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, bufSize, 'modT');
        if (!sysBuffer) {
            DbgPrint("SAC: Detect_UnsignedDrivers - alloc failed %llu\n", (unsigned long long)bufSize);
            return;
        }

        status = ZwQuerySystemInformation(11, sysBuffer, (ULONG)bufSize, &needed);
        if (NT_SUCCESS(status)) break;

        ExFreePoolWithTag(sysBuffer, 'modT');
        sysBuffer = NULL;

        if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
            if (needed != 0 && needed > bufSize) bufSize = needed + 4096;
            continue;
        }
        else {
            DbgPrint("SAC: Detect_UnsignedDrivers - ZwQuerySystemInformation failed 0x%X\n", status);
            return;
        }
    }

    if (!sysBuffer) return;
    PSYSTEM_MODULE_INFORMATION pInfo = (PSYSTEM_MODULE_INFORMATION)sysBuffer;

#define MAX_SEEN 64
    const char* seenNames[MAX_SEEN];
    RtlZeroMemory((PVOID)seenNames, sizeof(seenNames));
    ULONG seenCount = 0;

    ULONG count = 0;
    __try {
        count = pInfo->NumberOfModules;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(sysBuffer, 'modT');
        return;
    }

    for (ULONG i = 0; i < count; ++i) {
        PSYSTEM_MODULE m = &pInfo->Modules[i];
        const char* basename = Utils::GetModuleBasename(m);
        const char* fullPath = (const char*)m->FullPathName;
        if (!basename || !fullPath) continue;

        // de-dup: skip if we've reported this basename already this scan
        BOOLEAN already = FALSE;
        for (ULONG s = 0; s < seenCount; ++s) {
            if (Utils::Utils_AsciiStricmp(seenNames[s], basename) == 0) { already = TRUE; break; }
        }
        if (already) continue;
        if (seenCount < MAX_SEEN) seenNames[seenCount++] = basename;

        BOOLEAN isSysDriver = Utils::IsLikelyWindowsDriverPath(fullPath);
        PVOID fileBuf = NULL;
        SIZE_T fileRead = 0;
        SIZE_T readSize = 64 * 1024;
        status = Utils::ReadFileBytes(fullPath, &fileBuf, &fileRead, readSize);
        if (!NT_SUCCESS(status) || !fileBuf || fileRead < sizeof(IMAGE_DOS_HEADER)) {
            if (fileBuf) ExFreePoolWithTag(fileBuf, 'sigR');
            // cannot read file -> skip to avoid false positives
            continue;
        }

        // Parse PE headers safely (file buffer contains disk image bytes)
        BOOLEAN hasEmbeddedCert = FALSE;
        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBuf;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                // e_lfanew should be within fileRead
                if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) <= fileRead) {
                    PIMAGE_NT_HEADERS64 nth = (PIMAGE_NT_HEADERS64)((PUCHAR)fileBuf + dos->e_lfanew);
                    if (nth->Signature == IMAGE_NT_SIGNATURE) {
                        // Check if the optional header has DataDirectory
                        if (nth->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
                            IMAGE_DATA_DIRECTORY secDir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
                            // The Security Directory for IMAGE is a file offset and size. If size > 0 => embedded signature exists.
                            if (secDir.Size != 0) {
                                hasEmbeddedCert = TRUE;
                            }
                        }
                    }
                    else {
                        // It's possible the image is 32-bit. Try 32-bit header
                        PIMAGE_NT_HEADERS32 nth32 = (PIMAGE_NT_HEADERS32)((PUCHAR)fileBuf + dos->e_lfanew);
                        if (nth32->Signature == IMAGE_NT_SIGNATURE) {
                            if (nth32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
                                IMAGE_DATA_DIRECTORY secDir = nth32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
                                if (secDir.Size != 0) hasEmbeddedCert = TRUE;
                            }
                        }
                    }
                }
                else {
                    // e_lfanew beyond read region; 
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

        }


        ExFreePoolWithTag(fileBuf, 'sigR');
        BOOLEAN basenameSuspicious = FALSE;
        for (SIZE_T bi = 0; bi < g_BlocklistCount; ++bi) {
            if (Utils::AsciiStrContainsInsensitive(basename, g_BlocklistSubstrings[bi])) { basenameSuspicious = TRUE; break; }
        }

        if (!hasEmbeddedCert && (!isSysDriver || basenameSuspicious)) {
            ANSI_STRING aName;
            RtlInitAnsiString(&aName, basename);
            UNICODE_STRING uName;
            if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uName, &aName, TRUE))) {
                WCHAR desc[192];
                RtlStringCchPrintfW(desc, RTL_NUMBER_OF(desc), L"Unsigned or non-embedded-signed driver: %wZ", &uName);
                Utils::ReportDetection(0x1002, 0, SevHigh, desc);
                RtlFreeUnicodeString(&uName);
            }
            else {
                WCHAR desc2[192];
                SIZE_T k;
                size_t nameLen = strlen(basename);
                for (k = 0; k < nameLen && k < (RTL_NUMBER_OF(desc2) - 1); ++k) desc2[k] = (WCHAR)basename[k];
                desc2[k] = L'\0';
                WCHAR final[256];
                RtlStringCchPrintfW(final, RTL_NUMBER_OF(final), L"Unsigned or non-embedded-signed driver: %s", desc2);
                Utils::ReportDetection(0x1002, 0, SevHigh, final);
            }
        }

    } 

    ExFreePoolWithTag(sysBuffer, 'modT');
    return;
}

void SAC::Detect_HookedDriverObject(void)
{
    NTSTATUS status;
    ULONG needed = 0;
    PVOID sysBuffer = NULL;
    SIZE_T bufSize = 0;

    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"IoGetDriverObjectPointer");
    pfnIoGetDriverObjectPointer IoGetDriverObjectPointerPtr =
        (pfnIoGetDriverObjectPointer)MmGetSystemRoutineAddress(&routineName);

    for (int attempt = 0; attempt < 6; ++attempt) {
        bufSize = (bufSize == 0) ? 4096 : bufSize * 2;
        sysBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, bufSize, 'modT');
        if (!sysBuffer) {
            DbgPrint("SAC: Detect_HookedDriverObject - alloc failed %llu\n", (unsigned long long)bufSize);
            return;
        }

        status = ZwQuerySystemInformation(SYSTEM_MODULE_INFO, sysBuffer, (ULONG)bufSize, &needed);
        if (NT_SUCCESS(status)) break;

        ExFreePoolWithTag(sysBuffer, 'modT');
        sysBuffer = NULL;

        if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
            if (needed != 0 && needed > bufSize) bufSize = needed + 4096;
            continue;
        }
        else {
            DbgPrint("SAC: Detect_HookedDriverObject - ZwQuerySystemInformation failed 0x%X\n", status);
            return;
        }
    }

    if (!sysBuffer) return;
    PSYSTEM_MODULE_INFORMATION pInfo = (PSYSTEM_MODULE_INFORMATION)sysBuffer;

    ULONG moduleCount = 0;
    __try {
        moduleCount = pInfo->NumberOfModules;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(sysBuffer, 'modT');
        return;
    }

    typedef struct { char name[64]; unsigned long bitmaskLo; } SEEN;
    SEEN seen[256];
    RtlZeroMemory(seen, sizeof(seen));
    ULONG seenCount = 0;

    for (ULONG i = 0; i < moduleCount; ++i) {
        PSYSTEM_MODULE m = &pInfo->Modules[i];
        const char* basename = Utils::GetModuleBasename(m);
        if (!basename) continue;
        char basebuf[64];
        RtlZeroMemory(basebuf, sizeof(basebuf));
        size_t bLen = strnlen(basename, sizeof(basebuf) - 1);
        if (bLen == 0 || bLen >= sizeof(basebuf)) continue;
        RtlCopyMemory(basebuf, basename, bLen);
        Utils::RemoveDotSysInPlace(basebuf);
        WCHAR driverNameBuf[128];
        UNICODE_STRING driverName;
        RtlZeroMemory(driverNameBuf, sizeof(driverNameBuf));
        if (!Utils::BuildDriverNameUnicodeLocal(basebuf, &driverName, driverNameBuf, RTL_NUMBER_OF(driverNameBuf))) {
            continue;
        }

        PDRIVER_OBJECT targetDrv = NULL;
        NTSTATUS callSt = STATUS_NOT_FOUND;
        if (IoGetDriverObjectPointerPtr) {
            PUNICODE_STRING rem = NULL;
            callSt = IoGetDriverObjectPointerPtr(&driverName, &targetDrv, &rem);
            if (!NT_SUCCESS(callSt) || !targetDrv) {
                continue;
            }
        }
        else {
            continue;
        }

        ULONG_PTR imgStart = 0;
        ULONG_PTR imgEnd = 0;
        if (targetDrv->DriverStart != NULL && targetDrv->DriverSize != 0) {
            imgStart = (ULONG_PTR)targetDrv->DriverStart;
            imgEnd = imgStart + (ULONG_PTR)targetDrv->DriverSize;
        }
        else {
            imgStart = (ULONG_PTR)m->ImageBaseAddress;
            imgEnd = imgStart + (ULONG_PTR)m->ImageSize;
        }

        for (ULONG mj = 0; mj < IRP_MJ_MAXIMUM; ++mj) {
            PVOID func = (PVOID)targetDrv->MajorFunction[mj];
            if (func == NULL) continue;
            ULONG_PTR fAddr = (ULONG_PTR)func;
            BOOLEAN inImgRange = (fAddr >= imgStart && fAddr < imgEnd);

            if (!inImgRange) {
                BOOLEAN already = FALSE;
                for (ULONG s = 0; s < seenCount; ++s) {
                    if (Utils::Utils_AsciiStricmp(seen[s].name, basebuf) == 0) {
                        ULONG idx = mj % 32;
                        if (seen[s].bitmaskLo & (1u << idx)) { already = TRUE; break; }
                        seen[s].bitmaskLo |= (1u << idx);
                        already = FALSE;
                        break;
                    }
                }
                if (!already) {
                    if (seenCount < RTL_NUMBER_OF(seen)) {
                        RtlStringCchCopyA(seen[seenCount].name, RTL_NUMBER_OF(seen[seenCount].name), basebuf);
                        seen[seenCount].bitmaskLo = (1u << (mj % 32));
                        seenCount++;
                    }
                    WCHAR desc[256];
                    RtlStringCchPrintfW(desc, RTL_NUMBER_OF(desc),
                        L"Suspicious DriverObject: %hs MajorFunction[%u] -> 0x%p outside image [0x%p-0x%p]",
                        basebuf, (unsigned)mj, func, (PVOID)imgStart, (PVOID)imgEnd);
                    Utils::ReportDetection(0x1004, mj, SevHigh, desc);
                }
            }
        }
        ObDereferenceObject(targetDrv);
    }

    ExFreePoolWithTag(sysBuffer, 'modT');
}

VOID SAC::BuildSyscallBaseline(void)
{
    if (g_SysBaseline) return;

    SIZE_T allocBytes = sizeof(SYS_FINGERPRINT) * g_SyscallCount;
    g_SysBaseline = (SYS_FINGERPRINT*)ExAllocatePoolWithTag(NonPagedPoolNx, allocBytes, 'sbAS');
    if (!g_SysBaseline) return;
    RtlZeroMemory(g_SysBaseline, allocBytes);

    for (SIZE_T i = 0; i < g_SyscallCount; ++i) {
        RtlStringCchCopyA(g_SysBaseline[i].Name, RTL_NUMBER_OF(g_SysBaseline[i].Name), g_SyscallNames[i]);
        ANSI_STRING a;
        RtlInitAnsiString(&a, g_SyscallNames[i]);
        UNICODE_STRING uni;
        if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uni, &a, TRUE))) {
            g_SysBaseline[i].Hash = 0;
            continue;
        }

        PVOID addr = MmGetSystemRoutineAddress(&uni);
        RtlFreeUnicodeString(&uni);
        if (!addr) {
            g_SysBaseline[i].Hash = 0;
            continue;
        }
        ULONG64 h = 0;
        __try {
            h = Utils::FastHashBytes(addr, SYS_CALL_STUB_BYTES);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            h = 0;
        }
        g_SysBaseline[i].Hash = h;
    }
}

VOID SAC::BuildHWIDBaseline(void)
{
    UNICODE_STRING keyPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS st = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (NT_SUCCESS(st)) {
        UNICODE_STRING val = RTL_CONSTANT_STRING(L"MachineGuid");
        ULONG needed = 0;
        ULONG alloc = 512;
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, alloc, 'rgMD');
        if (info) {
            st = ZwQueryValueKey(hKey, &val, KeyValuePartialInformation, info, alloc, &needed);
            if (NT_SUCCESS(st) && info->Type == REG_SZ && info->DataLength) {
                PWCHAR tmp = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, info->DataLength, 'mgMD');
                if (tmp) {
                    RtlCopyMemory(tmp, info->Data, info->DataLength);
                    tmp[(info->DataLength / sizeof(WCHAR)) - 1] = L'\0';
                    g_BaselineMachineGuid = tmp;
                }
            }
            ExFreePoolWithTag(info, 'rgMD');
        }
        ZwClose(hKey);
    }

    UNICODE_STRING diskName = RTL_CONSTANT_STRING(L"\\Device\\Harddisk0\\DR0");
    OBJECT_ATTRIBUTES diskAttr;
    InitializeObjectAttributes(&diskAttr, &diskName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDisk = NULL;
    IO_STATUS_BLOCK iosb;
    st = ZwCreateFile(&hDisk,
        FILE_READ_DATA | SYNCHRONIZE,
        &diskAttr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (NT_SUCCESS(st)) {
        STORAGE_PROPERTY_QUERY query;
        RtlZeroMemory(&query, sizeof(query));
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        ULONG outSize = 2048;
        PVOID outBuf = ExAllocatePoolWithTag(NonPagedPoolNx, outSize, 'sdMD');
        if (outBuf) {
            RtlZeroMemory(outBuf, outSize);
            st = ZwDeviceIoControlFile(hDisk, NULL, NULL, NULL, &iosb,
                IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), outBuf, outSize);
            if (NT_SUCCESS(st)) {
                STORAGE_DEVICE_DESCRIPTOR* desc = (STORAGE_DEVICE_DESCRIPTOR*)outBuf;
                if (desc->SerialNumberOffset && desc->SerialNumberOffset < outSize) {
                    CHAR* serial = (CHAR*)outBuf + desc->SerialNumberOffset;
                    WCHAR conv[256]; RtlZeroMemory(conv, sizeof(conv));
                    size_t i;
                    for (i = 0; i < RTL_NUMBER_OF(conv) - 1 && serial[i]; ++i) conv[i] = (WCHAR)serial[i];
                    conv[i] = L'\0';
                    Utils::AllocCopyUnicodeNonPaged(conv, &g_BaselineDiskId);
                }
            }
            ExFreePoolWithTag(outBuf, 'sdMD');
        }
        ZwClose(hDisk);
    }
}

VOID SAC::Detect_SSDT_Changes(void)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    if (!g_SysBaseline) return;

    for (SIZE_T i = 0; i < g_SyscallCount; ++i) {
        ANSI_STRING a;
        RtlInitAnsiString(&a, g_SyscallNames[i]);
        UNICODE_STRING uni;
        if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uni, &a, TRUE))) continue;

        PVOID addr = MmGetSystemRoutineAddress(&uni);
        RtlFreeUnicodeString(&uni);
        if (!addr) continue;

        ULONG64 curHash = 0;
        __try {
            curHash = Utils::FastHashBytes(addr, SYS_CALL_STUB_BYTES);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            curHash = 0;
        }

        ULONG64 baseHash = g_SysBaseline[i].Hash;
        if (baseHash == 0) continue;

        if (curHash != baseHash) {
            WCHAR desc[256];
            RtlStringCchPrintfW(desc, RTL_NUMBER_OF(desc),
                L"Syscall stub modified: %hs baseline=0x%llx current=0x%llx",
                g_SyscallNames[i], baseHash, curHash);
            Utils::ReportDetection(DET_SSDT_CHANGES_CODE, (ULONG)i, SevHigh, desc);
        }
    }
}

VOID SAC::Detect_HWID_Spoofing(void)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    UNICODE_STRING keyPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE keyHandle = NULL;
    NTSTATUS st = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    if (NT_SUCCESS(st)) {
        UNICODE_STRING valName = RTL_CONSTANT_STRING(L"MachineGuid");
        ULONG needed = 0;
        ULONG alloc = 512;
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, alloc, 'rgMD');
        if (info) {
            RtlZeroMemory(info, alloc);
            st = ZwQueryValueKey(keyHandle, &valName, KeyValuePartialInformation, info, alloc, &needed);
            if (NT_SUCCESS(st) && info->Type == REG_SZ && info->DataLength) {
                PWCHAR guidStr = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, info->DataLength, 'gmMD');
                if (guidStr) {
                    RtlCopyMemory(guidStr, info->Data, info->DataLength);
                    guidStr[(info->DataLength / sizeof(WCHAR)) - 1] = L'\0';
                    if (g_BaselineMachineGuid) {
                        if (wcscmp(g_BaselineMachineGuid, guidStr) != 0) {
                            WCHAR desc[256];
                            RtlStringCchPrintfW(desc, RTL_NUMBER_OF(desc),
                                L"MachineGuid changed. baseline='%ws' current='%ws'", g_BaselineMachineGuid, guidStr);
                            Utils::ReportDetection(DET_HWID_SPOOF_CODE, 1, SevCritical, desc);
                        }
                    }
                    ExFreePoolWithTag(guidStr, 'gmMD');
                }
            }
            ExFreePoolWithTag(info, 'rgMD');
        }
        ZwClose(keyHandle);
    }
    UNICODE_STRING diskName = RTL_CONSTANT_STRING(L"\\Device\\Harddisk0\\DR0");
    OBJECT_ATTRIBUTES diskAttr;
    InitializeObjectAttributes(&diskAttr, &diskName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDisk = NULL;
    IO_STATUS_BLOCK iosb;
    st = ZwCreateFile(&hDisk,
        FILE_READ_DATA | SYNCHRONIZE,
        &diskAttr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (NT_SUCCESS(st)) {
        STORAGE_PROPERTY_QUERY query;
        RtlZeroMemory(&query, sizeof(query));
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        ULONG outSize = 2048;
        PVOID outBuf = ExAllocatePoolWithTag(NonPagedPoolNx, outSize, 'sdMD');
        if (outBuf) {
            RtlZeroMemory(outBuf, outSize);
            st = ZwDeviceIoControlFile(hDisk, NULL, NULL, NULL, &iosb,
                IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), outBuf, outSize);
            if (NT_SUCCESS(st)) {
                STORAGE_DEVICE_DESCRIPTOR* desc = (STORAGE_DEVICE_DESCRIPTOR*)outBuf;
                if (desc->SerialNumberOffset && desc->SerialNumberOffset < outSize) {
                    CHAR* serial = (CHAR*)outBuf + desc->SerialNumberOffset;
                    WCHAR conv[256]; RtlZeroMemory(conv, sizeof(conv));
                    size_t i;
                    for (i = 0; i < RTL_NUMBER_OF(conv) - 1 && serial[i]; ++i) conv[i] = (WCHAR)serial[i];
                    conv[i] = L'\0';
                    // compare to baseline
                    if (g_BaselineDiskId) {
                        if (wcscmp(g_BaselineDiskId, conv) != 0) {
                            WCHAR dd[256];
                            RtlStringCchPrintfW(dd, RTL_NUMBER_OF(dd),
                                L"Disk serial changed. baseline='%ws' current='%ws'", g_BaselineDiskId, conv);
                            Utils::ReportDetection(DET_HWID_SPOOF_CODE, 2, SevHigh, dd);
                        }
                    }
                }
            }
            ExFreePoolWithTag(outBuf, 'sdMD');
        }
        ZwClose(hDisk);
    }
}

VOID SAC::FreeDetectionBaselines(void)
{
    if (g_SysBaseline) {
        ExFreePoolWithTag(g_SysBaseline, 'sbAS');
        g_SysBaseline = nullptr;
    }
    if (g_BaselineMachineGuid) {
        ExFreePoolWithTag(g_BaselineMachineGuid, 'mgMD');
        g_BaselineMachineGuid = nullptr;
    }
    if (g_BaselineDiskId) {
        ExFreePoolWithTag(g_BaselineDiskId, 'bGNW');
        g_BaselineDiskId = nullptr;
    }
}

extern "C" BOOLEAN SACReadIdtrAsm(PVOID* idtrBaseOut, USHORT* idtrLimitOut);

BOOLEAN SAC::ReadIdtr(_Out_ PVOID* idtrBase, _Out_ USHORT* idtrLimit) {
    if (!idtrBase || !idtrLimit) return FALSE;
#if defined(_M_IX86)
    unsigned char buffer[6];
    __asm {
        sidt buffer
    }
    *idtrLimit = *(USHORT*)&buffer[0];
    *idtrBase = (PVOID) * (ULONG*)(*(ULONG_PTR)((ULONG_PTR)buffer + 2));
    return TRUE;
#elif defined(_M_X64) || defined(_M_AMD64)
    return SACReadIdtrAsm(idtrBase, idtrLimit) ? TRUE : FALSE;
#else
    return FALSE;
#endif
}



VOID SAC::Detect_IDT_NMI_Hook(void) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;

    PVOID idtBase = NULL;
    USHORT idtLimit = 0;
    if (!SAC::ReadIdtr(&idtBase, &idtLimit)) {
        return;
    }

    PMODULE_RANGE ranges = NULL;
    SIZE_T rangeCount = Utils::QueryLoadedModuleRanges(&ranges);
    if (rangeCount == 0 || !ranges) {
        if (ranges) ExFreePoolWithTag(ranges, 'mrg2');
        return;
    }

    const UINT NMI_VECTOR = 2;
    PVOID handler = NULL;
    if (!Utils::GetIdtHandlerForVector(idtBase, idtLimit, NMI_VECTOR, &handler)) {
        ExFreePoolWithTag(ranges, 'mrg2');
        return;
    }

    if (!handler) {
        Utils::ReportDetection(DET_IDT_NMI_HOOK_CODE, NMI_VECTOR, SevCritical, L"NMI IDT entry empty or invalid");
        ExFreePoolWithTag(ranges, 'mrg2');
        return;
    }

    if (!Utils::AddressInLoadedModule(ranges, rangeCount, handler)) {
        WCHAR desc[256];
        RtlStringCchPrintfW(desc, RTL_NUMBER_OF(desc),
            L"NMI handler at 0x%p not inside any loaded module (possible IDT hook)", handler);
        Utils::ReportDetection(DET_IDT_NMI_HOOK_CODE, NMI_VECTOR, SevCritical, desc);
    }

    ExFreePoolWithTag(ranges, 'mrg2');
}

VOID SAC::BuildDriverHashBaseline(void)
{
    if (g_DriverBaselines) return;

    ULONG needed = 0;
    ULONG bufSize = 0x10000;
    PVOID buffer = NULL;
    NTSTATUS st;

    for (int attempt = 0; attempt < 6; ++attempt) {
        buffer = ExAllocatePoolWithTag(NonPagedPoolNx, bufSize, 'bmdr');
        if (!buffer) return;
        RtlZeroMemory(buffer, bufSize);

        st = ZwQuerySystemInformation(11, buffer, bufSize, &needed);
        if (NT_SUCCESS(st)) break;
        ExFreePoolWithTag(buffer, 'bmdr');
        buffer = NULL;
        if (st == STATUS_INFO_LENGTH_MISMATCH && needed > bufSize) {
            bufSize = needed + 4096;
            continue;
        }
        return;
    }
    if (!buffer) return;;

    PSYS_MODULE_INFO_LOCAL info = (PSYS_MODULE_INFO_LOCAL)buffer;
    ULONG n = 0;
    __try { n = info->NumberOfModules; }
    __except (EXCEPTION_EXECUTE_HANDLER) { ExFreePoolWithTag(buffer, 'bmdr'); return; }
    if (n == 0) { ExFreePoolWithTag(buffer, 'bmdr'); return; }

    g_DriverBaselines = (DRIVER_BASELINE*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(DRIVER_BASELINE) * n, 'bmdr');
    if (!g_DriverBaselines) { ExFreePoolWithTag(buffer, 'bmdr'); return; }
    RtlZeroMemory(g_DriverBaselines, sizeof(DRIVER_BASELINE) * n);
    g_DriverBaselineCount = n;

    for (ULONG i = 0; i < n; ++i) {
        PVOID base = info->Modules[i].ImageBaseAddress;
        SIZE_T size = (SIZE_T)info->Modules[i].ImageSize;
        const char* name = info->Modules[i].Name + info->Modules[i].NameOffset;

        g_DriverBaselines[i].ImageBase = base;
        g_DriverBaselines[i].ImageSize = size;
        //RtlStringCchCopyA(g_DriverBaselines[i].Name, RTL_NUMBER_OF(g_DriverBaselines[i].Name), name);

        UINT64 h = 0;
        __try {
            SIZE_T bytesToHash = min((SIZE_T)256, size);
            h = Utils::FastHashBytes(base, bytesToHash);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            h = 0;
        }
        g_DriverBaselines[i].Hash = h;
    }

    ExFreePoolWithTag(buffer, 'bmdr');
    Utils::ReportDetection(0x9001, 0, SevInfo, L"Driver baseline built: %u entries", (PCWSTR)g_DriverBaselineCount);
}

VOID SAC::Detect_DriverHashChanges(void)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    if (!g_DriverBaselines) return;

    for (SIZE_T i = 0; i < g_DriverBaselineCount; ++i) {
        DRIVER_BASELINE* b = &g_DriverBaselines[i];
        if (!b->ImageBase || b->ImageSize == 0) continue;
        UINT64 cur = 0;
        __try {
            SIZE_T bytesToHash = min((SIZE_T)256, b->ImageSize);
            cur = Utils::FastHashBytes(b->ImageBase, bytesToHash);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            cur = 0;
        }
        if (cur == 0) continue;
        if (cur != b->Hash) {
            WCHAR desc[256];
            RtlStringCchPrintfW(desc, RTL_NUMBER_OF(desc), L"Driver image changed: %a baseline=0x%llx current=0x%llx", b->Name, b->Hash, cur);
            Utils::ReportDetection(0x1011, 0, SevHigh, desc);
            Utils::ReportDetection(0x9101, 0, SevInfo, L"Driver change: %S", b->Name);
        }
    }
}

VOID SAC::ProcessNotifyCallbackEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo) {
        PCUNICODE_STRING image = CreateInfo->ImageFileName;
        if (image && image->Buffer) {
            Utils::ReportDetection(0x9201, 0, SevInfo, L"ProcCreate: %wZ", image);
        }
    }
    else {
    }
}

EXTERN_C
OB_PREOP_CALLBACK_STATUS NTAPI SAC::HandlePreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!OpInfo) return OB_PREOP_SUCCESS;

    __try {
        if (OpInfo->Operation != OB_OPERATION_HANDLE_CREATE &&
            OpInfo->Operation != OB_OPERATION_HANDLE_DUPLICATE) {
            return OB_PREOP_SUCCESS;
        }

        if (!OpInfo->Parameters->CreateHandleInformation.DesiredAccess) {}
        ACCESS_MASK desired = OpInfo->Parameters->CreateHandleInformation.DesiredAccess;

        PVOID obj = OpInfo->Object;
        if (!obj) {
            Utils::ReportDetection(0x9304, 0, SevInfo, L"SAC: ObPre, NULL object on handle op");
            return OB_PREOP_SUCCESS;
        }

        HANDLE targetPidHandle = NULL;
        ULONG pidVal = 0;
        __try {
            PEPROCESS targetProc = (PEPROCESS)obj;
            PVOID pidPtr = PsGetProcessId(targetProc);
            pidVal = (ULONG)(ULONG_PTR)pidPtr;
            targetPidHandle = pidPtr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Utils::ReportDetection(0x9305, 0, SevInfo, L"SAC: ObPre, failed to read target PID");
            return OB_PREOP_SUCCESS;
        }

        Utils::ReportDetection(0x9306, 0, SevInfo,
            L"ObPre: Op=%u DesiredAccess=0x%08x PID=%u",
            (UINT)OpInfo->Operation,
            (UINT)desired,
            pidVal);

        //   PROCESS_TERMINATE       0x0001
        //   PROCESS_CREATE_THREAD   0x0002
        //   PROCESS_VM_OPERATION    0x0008
        //   PROCESS_VM_WRITE        0x0020
        //   PROCESS_SET_INFORMATION 0x0200
        //   PROCESS_ALL_ACCESS      0x1FFFFF

        const ACCESS_MASK suspiciousMask =
            (ACCESS_MASK)0x00000001UL |
            (ACCESS_MASK)0x00000002UL |
            (ACCESS_MASK)0x00000008UL |
            (ACCESS_MASK)0x00000020UL |
            (ACCESS_MASK)0x00000200UL ;

        BOOLEAN suspicious = FALSE;
        if ((desired & suspiciousMask) != 0) suspicious = TRUE;
        if (!suspicious) {
            if ((desired & 0x00FF0000UL) != 0 || (desired & 0x1FFFFFUL) == 0x1FFFFFUL) {
                suspicious = TRUE;
            }
        }

        if (suspicious) {
            WCHAR desc[192];
            RtlStringCchPrintfW(desc, RTL_NUMBER_OF(desc),
                L"Suspicious handle to PID %u requested access=0x%08x (pre-op)", pidVal, (UINT)desired);
            Utils::ReportDetection(0x1013, pidVal, SevHigh, desc);
            Utils::ReportDetection(0x9307, 0, SevInfo, L"Suspicious handle op PID=%u access=0x%08x", pidVal, (UINT)desired);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Utils::ReportDetection(0x9309, 0, SevInfo, L"ObPre: exception in callback");
    }
    return OB_PREOP_SUCCESS;
}

VOID SAC::RegisterObCallbacks(void)
{
    RtlZeroMemory(&gObReg, sizeof(gObReg));
    RtlZeroMemory(&gOpReg, sizeof(gOpReg));
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"360800");
    gOpReg[0].ObjectType = PsProcessType;
    gOpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    gOpReg[0].PreOperation = SAC::HandlePreCallback;
    gOpReg[0].PostOperation = NULL;
    gObReg.Version = OB_FLT_REGISTRATION_VERSION;
    gObReg.OperationRegistrationCount = 1;
    gObReg.RegistrationContext = NULL;
    gObReg.OperationRegistration = gOpReg;
    gObReg.Altitude = altitude;

    NTSTATUS st = ObRegisterCallbacks(&gObReg, &gObHandle);
    if (!NT_SUCCESS(st))
    {
        DbgPrint("SAC: ObRegisterCallbacks failed 0x%X\n", st);
        gObHandle = NULL;
    }
    else
    {
        Utils::ReportDetection(0x9302, 0, SevInfo, L"ObRegisterCallbacks registered");
    }
}

VOID SAC::UnregisterObCallbacks(void)
{
    if (gObHandle) {
        ObUnRegisterCallbacks(gObHandle);
        gObHandle = NULL;
    }
}

// to be added, possibly...
VOID Detect_KernelTextChanges(void) {}
VOID Detect_CallbackTampering(void) {}
VOID Detect_HiddenProcesses(void) {}
VOID Detect_UsermodeInjectionPatterns(void) {}
VOID Detect_SuspiciousIOCTLAccess(void) {}
VOID Detect_MemoryPatternScans(void) {}
VOID Detect_RegistryMismatch(void) {}
VOID Detect_KernelVarTamper(void) {}