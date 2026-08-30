/*
 * AngeronaSensor.h — Shared definitions between the kernel driver and the
 *                    Python user-mode bridge (kernel_bridge.py).
 *
 * IOCTL codes and data structures used by DeviceIoControl must match exactly
 * between this header and kernel_bridge.py.  Struct layout: packed, no padding.
 *
 * Build requirements:
 *   Windows Driver Kit (WDK) 11 + Visual Studio 2022
 *   Compile target: x64 Release (WDK build system)
 *   SDK: Windows 10 SDK 22H2 or later
 *
 * IMPORTANT: Load only in a VM with kernel debugging enabled before production.
 *   A kernel driver bug causes an immediate Blue Screen of Death (BSOD).
 *   Test with a snapshot so you can roll back instantly.
 *
 *   Deployment requires an EV code-signing certificate (test signing only
 *   works on machines where Secure Boot is disabled).
 */

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <wdm.h>
#else
/* User-mode include (Python bridge) */
#include <windows.h>
#endif

/* Device name visible to user-mode via \\.\AngeronaSensor */
#define ANGERONA_DEVICE_NAME    L"\\Device\\AngeronaSensor"
#define ANGERONA_SYMLINK_NAME   L"\\DosDevices\\AngeronaSensor"
#define ANGERONA_USER_PATH      L"\\\\.\\AngeronaSensor"

/* IOCTL codes — CTL_CODE(DeviceType, Function, Method, Access) */
#define ANGERONA_DEVICE_TYPE    0x8000  /* FILE_DEVICE_UNKNOWN range */

#define IOCTL_ANGERONA_GET_VERSION  \
    CTL_CODE(ANGERONA_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ANGERONA_GET_EVENTS   \
    CTL_CODE(ANGERONA_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ANGERONA_CLEAR_EVENTS \
    CTL_CODE(ANGERONA_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ── Kernel event record ──────────────────────────────────────────────────── */
/* Max path length in a kernel event (chars, UTF-16LE) */
#define ANGERONA_MAX_PATH   260

#pragma pack(push, 1)

typedef enum _ANGERONA_EVENT_TYPE {
    ANG_EVT_PROCESS_CREATE  = 1,
    ANG_EVT_PROCESS_EXIT    = 2,
    ANG_EVT_IMAGE_LOAD      = 3,
} ANGERONA_EVENT_TYPE;

typedef struct _ANGERONA_EVENT {
    ULONG               EventType;          /* ANGERONA_EVENT_TYPE */
    ULONGLONG           Sequence;           /* monotonic delivery identity */
    ULONG               ProcessId;
    ULONG               ParentProcessId;
    ULONG               ThreadId;
    LONGLONG            Timestamp;          /* FILETIME 100-ns intervals since 1601 */
    ULONG               ImagePathLen;       /* chars in ImagePath (not bytes) */
    WCHAR               ImagePath[ANGERONA_MAX_PATH];
    ULONG               CommandLineLen;
    WCHAR               CommandLine[ANGERONA_MAX_PATH];
} ANGERONA_EVENT, *PANGERONA_EVENT;

/* Header for IOCTL_ANGERONA_GET_EVENTS output buffer */
typedef struct _ANGERONA_EVENTS_BUFFER {
    ULONG           EventCount;
    ULONG           ProtocolVersion;
    ULONGLONG       InstanceId;     /* changes on every driver load */
    ULONGLONG       DroppedEvents;  /* cumulative overwritten ring entries */
    ULONGLONG       WriteSequence;  /* newest sequence assigned by producer */
    ANGERONA_EVENT  Events[1];   /* variable-length array */
} ANGERONA_EVENTS_BUFFER, *PANGERONA_EVENTS_BUFFER;

/* Version info returned by IOCTL_ANGERONA_GET_VERSION */
#define ANGERONA_PROTOCOL_VERSION  2
#define ANGERONA_CAP_PROCESS       0x00000001
#define ANGERONA_CAP_IMAGE         0x00000002
#define ANGERONA_CAP_SEQUENCE      0x00000004
#define ANGERONA_CAP_LOSS_COUNTER  0x00000008
#define ANGERONA_CAP_HEARTBEAT     0x00000010
#define ANGERONA_REQUIRED_CAPS     (ANGERONA_CAP_PROCESS | ANGERONA_CAP_IMAGE | \
                                    ANGERONA_CAP_SEQUENCE | ANGERONA_CAP_LOSS_COUNTER | \
                                    ANGERONA_CAP_HEARTBEAT)

typedef struct _ANGERONA_VERSION {
    ULONG   Major;
    ULONG   Minor;
    ULONG   Build;
    CHAR    Tag[8];   /* "ANGRSENS" */
    ULONG   ProtocolVersion;
    ULONG   Capabilities;
    ULONGLONG InstanceId;
    ULONGLONG WriteSequence;
    ULONGLONG DroppedEvents;
    ULONGLONG Heartbeat100ns;
} ANGERONA_VERSION, *PANGERONA_VERSION;

#pragma pack(pop)

/* Ring buffer capacity — number of events buffered in kernel before oldest
   is overwritten.  Keep a power of two for fast modular indexing. */
#define ANGERONA_RING_SIZE  256
