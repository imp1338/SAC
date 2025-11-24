# SAC — Soars Anti Cheat

> **SAC** (Soars Anti Cheat) is a lightweight, research-oriented anti-cheat split across three projects:
>
> 1. **kernelmode** — the kernel driver that performs OS-level integrity checks and telemetry.
> 2. **usermode** — a console client that talks to the driver, polls detections and telemetry, and prints friendly output.
> 3. **injection-tester** — a small usermode test app that exercises IOCTLs and simulates injection detections.

This README documents architecture, build & run instructions, IOCTLs and data structures, usage examples, troubleshooting, and developer notes.

---

# Table of contents

1. [Quick summary](#quick-summary)
2. [Features](#features)
3. [Repo layout](#repo-layout)
4. [Important safety & legal notes](#important-safety--legal-notes)
5. [Build instructions](#build-instructions)
6. [Install / run instructions](#install--run-instructions)
7. [IOCTLs & data structures (canonical)](#ioctls--data-structures-canonical)
8. [Examples: usermode client & injection tester](#examples-usermode-client--injection-tester)
9. [Troubleshooting](#troubleshooting)
10. [Extending SAC (developer notes)](#extending-sac-developer-notes)
11. [Credits](#credits)

---

# Quick summary

SAC is an educational/research anti-cheat that demonstrates kernel- and user-mode cooperation:

* Kernel driver periodically scans for suspicious drivers, unsigned drivers, hooked driver objects, SSDT changes, IDT/NMI hooks, HWID spoofing, etc.
* The driver exposes a device `\\.\SAC` and a set of IOCTLs to retrieve detections, telemetry, and baseline info, and to inject synthetic detections for testing.
* The usermode client polls the driver and nicely prints detections and telemetry.
* The injection-test app can simulate detections (via IOCTL_INJECT_DETECTION) and test process-open behavior for demonstration.

> NOTE: This project contains kernel code that can crash a system if used incorrectly. Read the safety section before running.

---

# Features

* Kernel-mode periodic scanning thread (ScanThreadRoutine) with multiple detectors:

  * suspicious driver names
  * unsigned driver detection
  * hooked DriverObject MajorFunction detection
  * hardware ID baseline comparison (HWID spoofing)
  * SSDT changes detection
  * IDT / NMI hook detection (marked as "somewhat dangerous" in code)
* Image load notification (PsSetLoadImageNotifyRoutine) to report events
* Process create notification via PsSetCreateProcessNotifyRoutineEx
* OB callbacks registration for handle/file operations (RegisterObCallbacks)
* Telemetry ring buffer exposed to usermode
* Driver baselines exposed to usermode
* IOCTL to read detection results (IOCTL_SCAN_DRIVERS), telemetry, baselines, and to inject test detections

---

# Repo layout (recommended)

```
/SAC
  /kernelmode
  /usermode
  /injection-tester
  README.md    <- (this file)
  LICENSE
```

---

# Important safety & legal notes

* **Kernel drivers are powerful** and can crash your machine. Do not run on production machines. Use a disposable VM or a test machine.
* If you modify the driver, **always** test in a controlled environment with kernel debugging enabled where possible.
* To load unsigned drivers on modern Windows, you need to enable **test signing** or use an appropriately signed driver. This README includes test-signing notes below.
* Use SAC for defensive research, testing, and development only. Do **not** use it to create or aid cheating software.

---

# Build instructions

## Requirements

* Windows SDK + Visual Studio (2019/2022 recommended)
* Windows Driver Kit (WDK) matching your target OS
* Administrator privileges to install/run driver
* Optional: kernel debugger (WinDbg / virtual machine snapshot) for safety

## Kernel driver (kernelmode)

1. Open the kernel driver Visual Studio solution (provided under `/kernelmode`) that targets the WDK.
2. Configure platform: `x64` (recommended) and `Debug` or `Release` as needed.
3. Build the driver project — this produces `SAC.sys`.

Notes:

* The driver code uses kernel APIs (PsSetLoadImageNotifyRoutine, PsCreateSystemThread, ObRegisterCallbacks, ExAllocatePoolWithTag, etc.) — build with the WDK.
* If you see link errors related to kernel exports, ensure that the WDK headers/libs match your OS target.

## User-mode apps (usermode / injection-tester)

* `SACClient.cpp` and `injection-tester` are plain Visual Studio console apps. No special external libs required.
* Build as `x64` to match kernel driver architecture.

---

# Install / run instructions

> All commands assume you are Administrator.

## Driver install (development / test signing)

**Test signing** (temporary): On the test machine (or VM), enable test signing so Windows will load an unsigned driver:

```powershell
bcdedit /set testsigning on
bcdedit /debug on
shutdown /r /t 0
```

Then copy `SAC.sys` to `C:\Windows\System32\drivers\` and create a service:

```powershell
sc create SAC type=kernel binPath="C:\Windows\System32\drivers\SAC.sys"
sc start SAC
```

To remove:

```powershell
sc stop SAC
sc delete SAC
```

Alternatively, use an installer or driver management tool (DPInst, devcon) and a properly signed driver for production.

## Run the usermode client

1. Build `SACClient.exe` (x64).
2. Run as Administrator. It tries to open `\\.\SAC` and then polls IOCTL_SCAN_DRIVERS every 5 seconds.

Expected console behavior:

* Connects successfully to `\\.\SAC` (if driver loaded).
* Prints baselines and any telemetry.
* Every poll prints detected results (if any).

## Run the injection tester

1. Build `SACTester` (x64).
2. Run as Administrator.
3. Press `F1` to inject a synthetic detection (sends IOCTL_INJECT_DETECTION).
4. Press `F2` to type a PID to test `OpenProcess` behavior.

---

# IOCTLs & data structures (canonical)

The driver exposes a device `\\.\SAC` and these IOCTLs (defined in the code):

```c
#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED 0
#define FILE_READ_DATA  (0x0001)
#define FILE_WRITE_DATA (0x0002)
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
```

### IOCTLs (from repo)

* `IOCTL_SCAN_DRIVERS` — function `0x800` — returns an array of `DETECTION_RESULT`.
  **Value**: `CTL_CODE(0x22, 0x800, 0, 0x0003) = 0x0022E000`

* `IOCTL_INJECT_DETECTION` — function `0x801` — takes `INJECT_DETECTION` input to simulate/report a detection.
  **Value**: `0x0022E004`

* `IOCTL_GET_TELEMETRY` — function `0x802` — returns `TELEMETRY_ENTRY` ring.
  **Value**: `0x0022E008`

* `IOCTL_GET_BASELINES` — function `0x803` — returns baseline collection.
  **Value**: `0x0022E00C`

> The exact numeric values are computed by the `CTL_CODE` macro and are included above to make interop simple for usermode clients.

---

## Data structures

Canonical definitions used by the usermode clients (C/C++):

```c
enum DETECTION_SEVERITY {
    SevInfo = 0,
    SevMedium = 1,
    SevHigh = 2,
    SevCritical = 3
};

typedef struct _DETECTION_RESULT {
    UINT32 Code;
    UINT32 Extra;
    DETECTION_SEVERITY Severity;
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
    CHAR Name[128];   // ANSI name as stored by kernel baseline builder
    UINT64 Hash;
} DRIVER_BASELINE;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct _INJECT_DETECTION {
    UINT32 Code;
    UINT32 Extra;
    UINT8  Severity;
    UINT8  Padding[3];
    WCHAR  Description[128];
} INJECT_DETECTION;
#pragma pack(pop)
```

`BASELINE_COLLECTION` returned by `IOCTL_GET_BASELINES` follows this pattern:

```c
typedef struct _BASELINE_ENTRY {
    WCHAR Name[260];
    ULONG Hash;
} BASELINE_ENTRY;

typedef struct _BASELINE_COLLECTION {
    ULONG Count;
    BASELINE_ENTRY Entries[1]; // variable-sized
} BASELINE_COLLECTION;
```

> Ensure client-side packing/size matches kernel-side structures (use `#pragma pack` and exact field sizes).

---

# Examples: usermode client & injection tester

### SACClient (usermode)

* Connect: `CreateFileW(L"\\\\.\\SAC", GENERIC_READ|GENERIC_WRITE, ...)`
* To poll detections:

```c
DeviceIoControl(hDevice, IOCTL_SCAN_DRIVERS, NULL, 0, outBuf, sizeof(outBuf), &bytesReturned, NULL);
```

* `bytesReturned / sizeof(DETECTION_RESULT)` gives the number of entries. Print each entry using `MapCodeToMessage()` and severity mapping.

* Fetch telemetry:

```c
DeviceIoControl(hDevice, IOCTL_GET_TELEMETRY, NULL, 0, outTelemetryBuf, telemetryByteSize, &bytesReturned, NULL);
```

### Injection tester

* Connect to `\\.\SAC`, then fill `INJECT_DETECTION` and send it via `IOCTL_INJECT_DETECTION`. This causes the driver to call `Utils::ReportDetection(...)` with the supplied code/severity/description so you can exercise client display.

---

# Troubleshooting

* **Driver open fails (`CreateFile` returns INVALID_HANDLE_VALUE)**

  * Are you running as Administrator?
  * Is the driver service started? (`sc query SAC`)
  * Is test signing enabled or is the driver properly signed?

* **DeviceIoControl returns error or zero bytes**

  * Check `GetLastError()` in usermode.
  * Some IOCTLs return `STATUS_BUFFER_TOO_SMALL` if your output buffer is too small — increase buffer sizes or inspect required size.

* **No detections appearing**

  * The scan thread only runs if `KeGetCurrentIrql() == PASSIVE_LEVEL`; if your system is in a state where this cannot be true, scans are skipped and a DbgPrint warning appears.
  * There simply may be no suspicious items on the system — use injection tester to verify the whole pipeline.

* **Driver crashes / BSOD**

  * Check kernel debug message (WinDbg / VM snapshot).
  * The code contains detection that touches low-level structures (SSDT, IDT); these are delicate and may trigger hard faults on unexpected platforms. Use a snapshot and testing environment.

* **`PsCreateSystemThread` failed**

  * The driver couldn't create its scan thread. Check return status printed by `DbgPrint` on DriverEntry.

* **Telemetry empty**

  * The ring is allocated in DriverEntry. If allocation fails, telemetry is not available.

---

# Extending SAC (developer notes)

* The kernel exposes `SAC::Detect_*` functions. Add new detectors inside `ScanThreadRoutine` with appropriate IRQL/locking considerations.
* When adding IOCTLs:

  * Update `IOCTL.h` consistently on both kernel and usermode sides.
  * Keep `METHOD_BUFFERED` and ensure buffer sizes are verified in kernel driver before copying memory.
* Telemetry ring uses a simple spinlock and write index — if you add heavy telemetry, consider per-CPU structures to reduce contention.
* **IRQL safety**: many Windows kernel APIs are IRQL-sensitive. The scan thread checks for `PASSIVE_LEVEL` where appropriate — preserve that behavior for operations that call pageable code.

---

 # Credits

 Big Inspiration from : https://github.com/lauralex/OAC
 Other Inspiration:
 https://tomchothia.gitlab.io/Papers/AntiCheat2024.pdf
 https://arxiv.org/pdf/2408.00500

# Final notes & disclaimers

* SAC demonstrates kernel-level detection techniques and a usermode user interface for telemetry and testing. The kernel code uses powerful OS facilities; misuse can cause system instability.
