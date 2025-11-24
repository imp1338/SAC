#include "Utils.h"
#include <ntstrsafe.h>
#include "SAC.h"
#include "Globals.h"

int Utils::Utils_AsciiStricmp(const char* a, const char* b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return ca - cb;
        ++a; ++b;
    }
    return *a - *b;
}

BOOLEAN
Utils::AsciiStrContainsInsensitive(_In_z_ const char* haystack, _In_z_ const char* needle)
{
    if (!haystack || !needle) return FALSE;
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen == 0 || hlen < nlen) return FALSE;

    for (size_t i = 0; i + nlen <= hlen; ++i) {
        BOOLEAN match = TRUE;
        for (size_t j = 0; j < nlen; ++j) {
            char a = haystack[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

 void Utils::RemoveDotSysInPlace(char* s) {
    if (!s) return;
    size_t len = strlen(s);
    if (len > 4) {
        const char* end = s + len - 4;
        if (Utils::Utils_AsciiStricmp(end, ".sys") == 0) {
            *(char*)end = '\0';
        }
    }
}

 ULONG64 Utils::FastHashBytes(_In_reads_bytes_(len) const void* ptr, SIZE_T len) {
     const unsigned char* p = (const unsigned char*)ptr;
     unsigned long long h = SYS_HASH_SEED;
     for (SIZE_T i = 0; i < len; ++i) {
         h = ((h << 5) + h) + p[i];
     }
     return h;
 }

 BOOLEAN Utils::HasReported(UINT32 code)
 {
     for (SIZE_T i = 0; i < g_PreviouslyReportedCount; ++i)
     {
         if (g_PreviouslyReportedCodes[i] == code)
             return TRUE;
     }
     return FALSE;
 }

 VOID Utils::MarkReported(UINT32 code)
 {
     if (g_PreviouslyReportedCount < RTL_NUMBER_OF(g_PreviouslyReportedCodes))
         g_PreviouslyReportedCodes[g_PreviouslyReportedCount++] = code;
 }

 VOID Utils::ReportDetection(UINT32 code, UINT32 extra, DETECTION_SEVERITY sev, PCWSTR desc, ...)
 {
     KIRQL oldIrql;
     KeAcquireSpinLock(&g_DetectionLock, &oldIrql);

     if (Utils::HasReported(code))
     {
         KeReleaseSpinLock(&g_DetectionLock, oldIrql);
         return;
     }

     if (g_DetectionCount >= MAX_DETECTIONS)
     {
         KeReleaseSpinLock(&g_DetectionLock, oldIrql);
         return;
     }

     g_Detections[g_DetectionCount].Code = code;
     g_Detections[g_DetectionCount].Extra = extra;
     g_Detections[g_DetectionCount].Severity = sev;
     RtlStringCchCopyW(g_Detections[g_DetectionCount].Description,
         RTL_NUMBER_OF(g_Detections[g_DetectionCount].Description),
         desc);

     g_DetectionCount++;
     Utils::MarkReported(code);
     KeReleaseSpinLock(&g_DetectionLock, oldIrql);
 }

NTSTATUS
Utils::ReadFileBytes(
    _In_z_ const char* ansiPath,
    _Out_ PVOID* outBuffer,
    _Out_ SIZE_T* outSize,
    _In_ SIZE_T readSize
)
{
    if (!ansiPath || !outBuffer || !outSize) return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uPath;
    IO_STATUS_BLOCK iosb;
    HANDLE fileHandle = NULL;
    PVOID buffer = NULL;
    SIZE_T bufSz = readSize;

    RtlZeroMemory(&iosb, sizeof(iosb));
    *outBuffer = NULL;
    *outSize = 0;

    ANSI_STRING a;
    RtlInitAnsiString(&a, ansiPath);
    if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uPath, &a, TRUE))) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    InitializeObjectAttributes(&objAttr, &uPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&fileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    RtlFreeUnicodeString(&uPath);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    buffer = ExAllocatePoolWithTag(NonPagedPoolNx, bufSz, 'sigR');
    if (!buffer) {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    status = ZwReadFile(fileHandle,
        NULL,
        NULL,
        NULL,
        &iosb,
        buffer,
        (ULONG)bufSz,
        &offset,
        NULL);

    if (NT_SUCCESS(status)) {
        *outSize = (SIZE_T)iosb.Information;
        *outBuffer = buffer;
    }
    else {
        ExFreePoolWithTag(buffer, 'sigR');
    }

    ZwClose(fileHandle);
    return status;
}

BOOLEAN Utils::BuildDriverNameUnicodeLocal(
    const char* ansiBasenameNoExt,
    UNICODE_STRING* outName,
    PWCH buffer,
    SIZE_T bufferChars
) {
    if (!ansiBasenameNoExt || !outName || !buffer) return FALSE;
    RtlZeroMemory(buffer, bufferChars * sizeof(WCHAR));
    CHAR tmp[128];
    RtlStringCchPrintfA(tmp, RTL_NUMBER_OF(tmp), "\\Driver\\%s", ansiBasenameNoExt);
    ANSI_STRING a;
    RtlInitAnsiString(&a, tmp);
    UNICODE_STRING u;
    if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&u, &a, TRUE))) {
        size_t i;
        for (i = 0; i < strlen(tmp) && i < (bufferChars - 1); ++i)
            buffer[i] = (WCHAR)tmp[i];
        buffer[i] = L'\0';
        RtlInitUnicodeString(outName, buffer);
        return TRUE;
    }
    SIZE_T copyChars = min((SIZE_T)u.Length / sizeof(WCHAR), bufferChars - 1);
    RtlCopyMemory(buffer, u.Buffer, copyChars * sizeof(WCHAR));
    buffer[copyChars] = L'\0';
    RtlFreeUnicodeString(&u);
    RtlInitUnicodeString(outName, buffer);
    return TRUE;
}


const char*
Utils::GetModuleBasename(_In_ PSYSTEM_MODULE m)
{
    if (!m) return NULL;
    if (m->OffsetToFileName >= sizeof(m->FullPathName))
        return (const char*)m->FullPathName; // fallback
    return (const char*)(m->FullPathName + m->OffsetToFileName);
}

BOOLEAN Utils::IsLikelyWindowsDriverPath(_In_z_ const char* fullPath)
{
    if (!fullPath) return FALSE;
    const char* p = fullPath;
    BOOLEAN hasSystemRoot = AsciiStrContainsInsensitive(fullPath, "systemroot");
    BOOLEAN hasWindows = AsciiStrContainsInsensitive(fullPath, "\\windows\\");
    BOOLEAN hasSystem32 = AsciiStrContainsInsensitive(fullPath, "system32");
    BOOLEAN hasDrivers = AsciiStrContainsInsensitive(fullPath, "drivers");

    return (hasSystemRoot || hasWindows) && hasSystem32 && hasDrivers;
}

BOOLEAN Utils::AllocCopyUnicodeNonPaged(_In_z_ PCWSTR src, _Out_ PWCHAR* out) {
    if (!src || !out) return FALSE;
    SIZE_T chars = wcslen(src);
    SIZE_T bytes = (chars + 1) * sizeof(WCHAR);
    PWCHAR buf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, bytes, 'bGNW');
    if (!buf) return FALSE;
    RtlCopyMemory(buf, src, bytes);
    *out = buf;
    return TRUE;
}



BOOLEAN Utils::GetIdtHandlerForVector(_In_ PVOID idtBase, _In_ USHORT idtLimit, _In_ UINT vector, _Out_ PVOID* outHandler) {
    if (!idtBase || !outHandler) return FALSE;
#if defined(_M_IX86)
    const SIZE_T entrySize = 8;
#elif defined(_M_X64) || defined(_M_AMD64)
    const SIZE_T entrySize = 16;
#else
    const SIZE_T entrySize = 16;
#endif

    SIZE_T count = (idtLimit + 1) / entrySize;
    if (vector >= count) return FALSE;

    ULONG_PTR entryAddr = (ULONG_PTR)idtBase + (vector * entrySize);

    __try {
#if defined(_M_IX86)
        // read 8 bytes
        USHORT offset_low = *(USHORT*)(entryAddr + 0);
        USHORT offset_high = *(USHORT*)(entryAddr + 6);
        ULONG handler = ((ULONG)offset_high << 16) | offset_low;
        *outHandler = (PVOID)(ULONG_PTR)handler;
        return TRUE;
#elif defined(_M_X64) || defined(_M_AMD64)
        // x64 gate layout
        USHORT offset_low = *(USHORT*)(entryAddr + 0);
        USHORT selector = *(USHORT*)(entryAddr + 2);
        UCHAR ist = *(UCHAR*)(entryAddr + 4);
        UCHAR typeAttr = *(UCHAR*)(entryAddr + 5);
        USHORT offset_mid = *(USHORT*)(entryAddr + 6);
        ULONG offset_high = *(ULONG*)(entryAddr + 8);
        ULONGLONG handler = ((ULONGLONG)offset_high << 32) | ((ULONGLONG)offset_mid << 16) | (ULONGLONG)offset_low;
        *outHandler = (PVOID)(ULONG_PTR)handler;
        return TRUE;
#else
        return FALSE;
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

BOOLEAN Utils::AddressInLoadedModule(_In_ PMODULE_RANGE ranges, SIZE_T count, _In_ PVOID addr) {
    if (!ranges || count == 0 || !addr) return FALSE;
    ULONG_PTR a = (ULONG_PTR)addr;
    for (SIZE_T i = 0; i < count; ++i) {
        ULONG_PTR b = (ULONG_PTR)ranges[i].Base;
        ULONG_PTR e = b + ranges[i].Size;
        if (a >= b && a < e) return TRUE;
    }
    return FALSE;
}
SIZE_T Utils::QueryLoadedModuleRanges(_Outptr_result_maybenull_ PMODULE_RANGE* outRanges) {
    if (!outRanges) return 0;
    *outRanges = NULL;
    SIZE_T count = 0;
    NTSTATUS st;
    ULONG needed = 0;
    ULONG bufSize = 0x10000; 
    PVOID buffer = NULL;

    for (int attempt = 0; attempt < 6; ++attempt) {
        buffer = ExAllocatePoolWithTag(NonPagedPoolNx, bufSize, 'mrgQ');
        if (!buffer) return 0;
        RtlZeroMemory(buffer, bufSize);

        st = ZwQuerySystemInformation(11, buffer, bufSize, &needed);
        if (NT_SUCCESS(st)) break;

        ExFreePoolWithTag(buffer, 'mrgQ');
        buffer = NULL;

        if (st == STATUS_INFO_LENGTH_MISMATCH && needed > bufSize) {
            bufSize = needed + 4096;
            continue;
        }
        return 0;
    }

    if (!buffer) return 0;
    __try {
        ULONG_PTR basePtr = (ULONG_PTR)buffer;
        ULONG num = *(ULONG_PTR*)basePtr;
        ULONG moduleCount = *(ULONG*)basePtr;
        ULONG_PTR modulesPtr = basePtr + sizeof(ULONG);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(buffer, 'mrgQ');
        return 0;
    }

#if defined(_SYSTEM_MODULE_INFORMATION_DEFINED) || 1
    typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
        PVOID Unknown1;
        PVOID ImageBaseAddress;
        ULONG ImageSize;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown2;
        USHORT LoadCount;
        USHORT NameOffset;
        CHAR ImageName[256];
    } SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

    typedef struct _SYSTEM_MODULE_INFORMATION_EX {
        ULONG NumberOfModules;
        SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
    } SYSTEM_MODULE_INFORMATION_EX, * PSYSTEM_MODULE_INFORMATION_EX;

    PSYSTEM_MODULE_INFORMATION_EX pInfo = (PSYSTEM_MODULE_INFORMATION_EX)buffer;
    SIZE_T n = pInfo->NumberOfModules;
    if (n == 0) { ExFreePoolWithTag(buffer, 'mrgQ'); return 0; }

    PMODULE_RANGE ranges = (PMODULE_RANGE)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(MODULE_RANGE) * n, 'mrg2');
    if (!ranges) { ExFreePoolWithTag(buffer, 'mrgQ'); return 0; }

    for (SIZE_T i = 0; i < n; ++i) {
        ranges[i].Base = pInfo->Modules[i].ImageBaseAddress;
        ranges[i].Size = (SIZE_T)pInfo->Modules[i].ImageSize;
    }

    *outRanges = ranges;
    count = n;
    ExFreePoolWithTag(buffer, 'mrgQ');
    return count;
#else
    ExFreePoolWithTag(buffer, 'mrgQ');
    return 0;
#endif
}