// SACClient.cpp
// Build: Visual Studio console app. No special libs required.
// Purpose: Open \\.\SAC and poll IOCTL_SCAN_DRIVERS for detection results.

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <codecvt>
#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED 0
#define FILE_READ_DATA  (0x0001) 
#define FILE_WRITE_DATA (0x0002)
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

constexpr DWORD IOCTL_SCAN_DRIVERS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);

#define IOCTL_GET_TELEMETRY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_GET_BASELINES   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

enum DETECTION_SEVERITY {
    SevInfo = 0,
    SevMedium = 1,
    SevHigh = 2,
    SevCritical = 3
};
typedef struct _DETECTION_RESULT {
    UINT32 Code;
    UINT32 Extra;
    DETECTION_SEVERITY  Severity; // keep sizes explicit
    UINT8  Padding[3];
    LARGE_INTEGER Timestamp;
    WCHAR Description[128];
} DETECTION_RESULT;

#pragma pack(push,1)
typedef struct _TELEMETRY_ENTRY {
    LARGE_INTEGER Timestamp;
    UINT32 EventCode;
    UINT32 Extra;
    WCHAR Message[128];
} TELEMETRY_ENTRY;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct _DRIVER_BASELINE {
    PVOID ImageBase;
    SIZE_T ImageSize;
    CHAR Name[128];
    UINT64 Hash;
} DRIVER_BASELINE;
#pragma pack(pop)

typedef struct _BASELINE_ENTRY {
    WCHAR Name[260];
    ULONG Hash;
} BASELINE_ENTRY, * PBASELINE_ENTRY;

typedef struct _BASELINE_COLLECTION {
    ULONG Count;
    BASELINE_ENTRY Entries[1];
} BASELINE_COLLECTION, * PBASELINE_COLLECTION;

#define MAX_DETECTIONS 128
#define DET_DESC_LEN 128

#define COL_RESET   7
#define COL_RED     12
#define COL_GREEN   10
#define COL_YELLOW  14
#define COL_CYAN    11
#define COL_WHITE   15
#define COL_GRAY    8

void SetColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void PrintBanner() {
    SetColor(COL_CYAN);
    std::wcout << L"============================================================\n";
    std::wcout << L"   SOARS ANTI-CHEAT | USERMODE CLIENT | v1.0\n";
    std::wcout << L"   https://feds.lol/soarcheats\n";
    std::wcout << L"============================================================\n";
    SetColor(COL_RESET);
}

std::wstring MapCodeToMessage(UINT32 code) {
    switch (code) {
    case 0x0000: return L"DET_NONE";
    case 0x1001: return L"DET_SUSP_DRIVER_NAME";
    case 0x1002: return L"DET_UNSIGNED_DRIVER";
    case 0x1003: return L"DET_DRIVER_WHITELIST_MISS";
    case 0x1004: return L"DET_HOOKED_DRIVER_OBJECT";
    case 0x1005: return L"DET_SSDT_CHANGES";
    case 0x1006: return L"DET_IDT_NMI_HOOK";
    case 0x1007: return L"DET_CRITICAL_SECTION_HOOK";
    case 0x1008: return L"DET_HIDDEN_PROCESS";
    case 0x1009: return L"DET_USERMODE_INJECTION";
    case 0x100A: return L"DET_SUSPICIOUS_IOCTL_ACCESS";
    case 0x100B: return L"DET_MEMORY_PATCH";
    case 0x100C: return L"DET_UNKNOWN_SIGNATURE";
    case 0x2001: return L"DET_HARDWARE_ID_CHANGE";
    case 0xFFFF: return L"DET_UNKNOWN";
    case 0x1011: return L"DET_DRIVER_IMAGE_CHANGED";
    case 0x1013: return L"DET_SUSPICIOUS_HANDLE_OP";
    case 0x9101: return L"TEL_DRIVER_CHANGE";
    default: {
        std::wstringstream ss;
        ss << L"CODE_0x" << std::hex << code;
        return ss.str();
    }
    }
}

std::wstring SeverityToString(DETECTION_SEVERITY s) {
    switch (s) {
    case SevInfo: return L"Info";
    case SevMedium: return L"Medium";
    case SevHigh: return L"High";
    case SevCritical: return L"Critical";
    default: return L"Unknown";
    }
}

SYSTEMTIME FileTimeToSystemTimeLocal(const LARGE_INTEGER& ft) {
    FILETIME f;
    f.dwLowDateTime = (DWORD)ft.LowPart;
    f.dwHighDateTime = (DWORD)ft.HighPart;
    SYSTEMTIME stUTC{}, stLocal{};
    if (FileTimeToSystemTime(&f, &stUTC)) {
        FileTimeToSystemTime(&f, &stUTC);
        FileTimeToSystemTime(&f, &stUTC);
    }
    if (FileTimeToSystemTime(&f, &stUTC)) {
        if (SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal)) {
            return stLocal;
        }
        return stUTC;
    }
    SYSTEMTIME zero{}; return zero;
}

void PrintDetection(const DETECTION_RESULT& d) {
    int color = COL_WHITE;
    switch (d.Severity) {
    case SevCritical: color = COL_RED; break;
    case SevHigh:     color = COL_RED; break;
    case SevMedium:   color = COL_YELLOW; break;
    case SevInfo:     color = COL_GREEN; break;
    }

    SetColor(COL_GRAY);
    std::wcout << L"------------------------------------------------------------\n";
    
    SetColor(color);
    std::wcout << L"[!] DETECTION TRIGGERED\n";
    std::wcout << L"    Code:     " << MapCodeToMessage(d.Code) << L" (0x" << std::hex << d.Code << std::dec << L")\n";
    std::wcout << L"    Severity: " << SeverityToString(d.Severity) << L"\n";
    
    SetColor(COL_WHITE);
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)d.Timestamp.LowPart;
    ft.dwHighDateTime = (DWORD)d.Timestamp.HighPart;
    SYSTEMTIME st;
    if (FileTimeToSystemTime(&ft, &st)) {
        SYSTEMTIME local;
        if (SystemTimeToTzSpecificLocalTime(nullptr, &st, &local)) st = local;
        wchar_t buf[64];
        swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        std::wcout << L"    Time:     " << buf << L"\n";
    }
    std::wcout << L"    Extra:    " << d.Extra << L"\n";
    std::wcout << L"    Details:  " << d.Description << L"\n";
    SetColor(COL_RESET);
}

void PrintTelemetry(const TELEMETRY_ENTRY& t) {
    FILETIME ft; ft.dwLowDateTime = (DWORD)t.Timestamp.LowPart; ft.dwHighDateTime = (DWORD)t.Timestamp.HighPart;
    SYSTEMTIME stUTC, stLocal;
    wchar_t buf[64] = {};
    if (FileTimeToSystemTime(&ft, &stUTC)) {
        if (SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) {
            swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
                stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
        }
    }
    SetColor(COL_CYAN);
    std::wcout << L"[TEL] ";
    SetColor(COL_GRAY);
    std::wcout << L"[" << buf << L"] ";
    SetColor(COL_WHITE);
    std::wcout << L"Code=0x" << std::hex << t.EventCode << std::dec << L" Extra=" << t.Extra
        << L" Msg=\"" << t.Message << L"\"\n";
    SetColor(COL_RESET);
}

void PrintBaseline(const DRIVER_BASELINE& b) {
    std::wcout << L"Name: " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(b.Name)
        << L" Base=" << b.ImageBase << L" Size=0x" << std::hex << b.ImageSize << std::dec
        << L" Hash=0x" << std::hex << b.Hash << std::dec << L"\n";
}

void FetchTelemetry(HANDLE hDevice) {
    const size_t outBufBytes = sizeof(TELEMETRY_ENTRY) * 256;
    std::vector<BYTE> outBuf(outBufBytes);
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDevice, IOCTL_GET_TELEMETRY, nullptr, 0, outBuf.data(), (DWORD)outBuf.size(), &bytesReturned, nullptr);
    if (!ok) {
        // DWORD err = GetLastError();
        // std::wcout << L"[ERROR] IOCTL_GET_TELEMETRY failed: " << err << L"\n";
        return;
    }
    size_t count = bytesReturned / sizeof(TELEMETRY_ENTRY);
    if (count > 0) {
        std::wcout << L"\n[TELEMETRY] Entries: " << count << L"\n";
        TELEMETRY_ENTRY* arr = (TELEMETRY_ENTRY*)outBuf.data();
        for (size_t i = 0; i < count; ++i) PrintTelemetry(arr[i]);
    }
}

bool FetchBaselines(HANDLE hDevice)
{
    DWORD bytesReturned = 0;
    ULONG bufferSize = sizeof(BASELINE_COLLECTION) + (sizeof(BASELINE_ENTRY) * 128);
    auto buffer = std::make_unique<BYTE[]>(bufferSize);

    BOOL ok = DeviceIoControl(
        hDevice,
        IOCTL_GET_BASELINES,
        nullptr, 0,
        buffer.get(),
        bufferSize,
        &bytesReturned,
        nullptr
    );

    if (!ok) {
        // printf("DeviceIoControl failed %lu\n", GetLastError());
        return false;
    }

    auto base = reinterpret_cast<PBASELINE_COLLECTION>(buffer.get());
    SetColor(COL_GREEN);
    printf("[+] Received %lu baselines\n", base->Count);
    SetColor(COL_RESET);
    // for (ULONG i = 0; i < base->Count; ++i)
    //     wprintf(L"[%lu] %s (0x%08X)\n", i, base->Entries[i].Name, base->Entries[i].Hash);

    return true;
}

void PollLoop(HANDLE hDevice, DWORD pollSeconds) {
    const size_t outBufBytes = sizeof(DETECTION_RESULT) * MAX_DETECTIONS;
    std::vector<BYTE> outBuf(outBufBytes);
    DWORD bytesReturned = 0;

    while (true) {
        BOOL ok = DeviceIoControl(hDevice,
            IOCTL_SCAN_DRIVERS,
            nullptr, 0,
            outBuf.data(), (DWORD)outBuf.size(),
            &bytesReturned,
            nullptr);

        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_MORE_DATA) {
                std::wcout << L"[WARN] Buffer too small; increase MAX_DETECTIONS or try again.\n";
            }
            else {
                // std::wcout << L"[ERROR] DeviceIoControl failed: " << err << L"\n";
            }
        }
        else {
            size_t count = bytesReturned / sizeof(DETECTION_RESULT);
            if (count == 0) {
                //std::wcout << L"[OK] No detections.\n";
            }
            else {
                // std::wcout << L"[DETECTIONS] Count: " << count << L"\n";
                DETECTION_RESULT* arr = (DETECTION_RESULT*)outBuf.data();
                for (size_t i = 0; i < count; ++i) {
                    PrintDetection(arr[i]);
                }
                count = 0;
            }
        }
        Sleep(pollSeconds * 1000);
    }
}

int main() {
    SetConsoleTitle(L"SAC Build");
    
    PrintBanner();

    std::wcout << L"[*] Connecting to SAC Driver...\n";
    HANDLE h = CreateFileW(L"\\\\.\\SAC",
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        SetColor(COL_RED);
        std::wcout << L"[!] Failed to open device. Is the driver loaded? Error: " << GetLastError() << L"\n";
        SetColor(COL_RESET);
        Sleep(-1);
        return 1;
    }

    SetColor(COL_GREEN);
    std::wcout << L"[+] Connected successfully.\n";
    SetColor(COL_RESET);
    std::wcout << L"[*] Polling every 5 seconds. Press Ctrl-C to quit.\n";

    FetchBaselines(h);
    FetchTelemetry(h);
    PollLoop(h, 5);
    CloseHandle(h);
    Sleep(-1);
    return 0;
}
