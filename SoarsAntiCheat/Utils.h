#include <ntddk.h>
#include "Driver.h"
#include <minwindef.h>

namespace Utils {
    BOOLEAN AsciiStrContainsInsensitive(_In_z_ const char* haystack, _In_z_ const char* needle);
    const char* GetModuleBasename(_In_ PSYSTEM_MODULE m);
    BOOLEAN IsLikelyWindowsDriverPath(_In_z_ const char* fullPath);
    NTSTATUS ReadFileBytes(_In_z_ const char* ansiPath, _Out_ PVOID* outBuffer, _Out_ SIZE_T* outSize, _In_ SIZE_T readSize);
    void RemoveDotSysInPlace(char* s);
    void ReportDetection(UINT32 code, UINT32 extra, DETECTION_SEVERITY sev, PCWSTR desc, ...);
    int Utils_AsciiStricmp(const char* a, const char* b);
    BOOLEAN BuildDriverNameUnicodeLocal(const char* ansiBasenameNoExt, UNICODE_STRING* outName, PWCH buffer, SIZE_T bufferChars);
    ULONG64 FastHashBytes(_In_reads_bytes_(len) const void* ptr, SIZE_T len);
    BOOLEAN AllocCopyUnicodeNonPaged(_In_z_ PCWSTR src, _Out_ PWCHAR* out);
    BOOLEAN HasReported(UINT32 code);
    VOID MarkReported(UINT32 code);
    BOOLEAN AddressInLoadedModule(_In_ PMODULE_RANGE ranges, SIZE_T count, _In_ PVOID addr);
    SIZE_T QueryLoadedModuleRanges(_Outptr_result_maybenull_ PMODULE_RANGE* outRanges);
    BOOLEAN GetIdtHandlerForVector(_In_ PVOID idtBase, _In_ USHORT idtLimit, _In_ UINT vector, _Out_ PVOID* outHandler);
}