#include <windows.h>
#include <iostream>
#include <string>

#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED 0
#define FILE_READ_DATA  (0x0001)
#define FILE_WRITE_DATA (0x0002)
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
constexpr DWORD IOCTL_INJECT_DETECTION = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);

#pragma pack(push,1)
typedef struct _INJECT_DETECTION {
    UINT32 Code;
    UINT32 Extra;
    UINT8  Severity;
    UINT8  Padding[3];
    WCHAR  Description[128];
} INJECT_DETECTION;
#pragma pack(pop)

void TestOpenProcess(DWORD pid) {
    DWORD desired = PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;
    HANDLE h = OpenProcess(desired, FALSE, pid);
    if (!h) {
        std::wcout << L"[TEST] OpenProcess(" << pid << L") failed: " << GetLastError() << L"\n";
    }
    else {
        std::wcout << L"[TEST] OpenProcess(" << pid << L") succeeded. Closing handle.\n";
        CloseHandle(h);
    }
}

int main() {
    SetConsoleTitle(L"SAC Build 1.0 | Detection Trigger | feds.lol/soarcheats");
    HANDLE h = CreateFileW(L"\\\\.\\SAC", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) { std::wcout << L"Open failed: " << GetLastError() << L"\n"; return 1; }

    Sleep(2000);
    std::cout << "SAC Driver Successfully Connected" << std::endl;
    std::cout << "press f1 to test basic ioctl communication and callback (again)" << std::endl;
    std::cout << "press f2 to test telementry and nmi callbacks" << std::endl;

    while (true)
    {
        if (GetAsyncKeyState(VK_F1))
        {
            INJECT_DETECTION data{};
            data.Code = 0x1004;
            data.Extra = 3;
            data.Severity = 2;
            wcscpy_s(data.Description, L"Test injection: simulated hooked driver MajorFunction[3] | soarwazhere");

            DWORD ret = 0;
            BOOL ok = DeviceIoControl(h, IOCTL_INJECT_DETECTION, &data, sizeof(data), nullptr, 0, &ret, nullptr);
            if (!ok) std::wcout << L"IOCTL failed: " << GetLastError() << L"\n";
            else std::wcout << L"Injected.\n";
        }
        if (GetAsyncKeyState(VK_F2))
        {
            std::cout << "enter pid : ";
            std::string input;
            std::cin >> input;
            unsigned long v = std::stoul(input, nullptr, 0);
            DWORD dw = static_cast<DWORD>(v);
            TestOpenProcess(dw);
        }
    }
    CloseHandle(h);
    Sleep(-1);
    return 0;
}
