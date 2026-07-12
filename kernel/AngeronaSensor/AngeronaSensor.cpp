/*
 * AngeronaSensor.cpp — Angerona Kernel Sensor Driver (WDM)
 *
 * Registers kernel callbacks for:
 *   PsSetCreateProcessNotifyRoutineEx — process create/exit
 *   PsSetLoadImageNotifyRoutine       — DLL/driver image load
 *
 * Events are stored in a fixed-size ring buffer (ANGERONA_RING_SIZE entries).
 * User-mode reads them via IOCTL_ANGERONA_GET_EVENTS through the device
 *   \\.\AngeronaSensor  (opened by kernel_bridge.py).
 *
 * BUILD (WDK 11, Visual Studio 2022):
 *   1. Open "Developer Command Prompt for VS 2022 with WDK"
 *   2. cd AngeronaSuite\kernel\AngeronaSensor
 *   3. msbuild AngeronaSensor.vcxproj /p:Configuration=Release /p:Platform=x64
 *   or use the provided build.bat (see kernel\AngeronaSensor\build.bat)
 *
 * LOAD (test machine with test signing enabled OR EV-signed):
 *   sc create AngeronaSensor type= kernel binPath= C:\path\to\AngeronaSensor.sys
 *   sc start  AngeronaSensor
 *
 * SAFETY NOTES:
 *   - NEVER load on your primary machine without a snapshot/restore point.
 *   - NEVER use IRQL > DISPATCH_LEVEL in callbacks (causes BSOD immediately).
 *   - All memory allocations use NonPagedPoolNx (no executable pool).
 *   - The ring buffer uses a spinlock (KSPIN_LOCK) for thread safety.
 *   - Unload is always supported (no DriverUnload = NULL tricks).
 */

#include "AngeronaSensor.h"

/* ── Pool tag ───────────────────────────────────────────────────────────────── */
#define ANGERONA_POOL_TAG 'RNGA'

/* ── Ring buffer (shared between callbacks and IRP handler) ─────────────────── */
static ANGERONA_EVENT  g_Ring[ANGERONA_RING_SIZE]  = {};
static volatile LONG   g_WriteIndex                 = 0;
static volatile LONG   g_ReadIndex                  = 0;
static KSPIN_LOCK      g_RingLock;

/* ── Device / symlink objects ───────────────────────────────────────────────── */
static PDEVICE_OBJECT  g_DeviceObject               = NULL;

/* ── Forward declarations ───────────────────────────────────────────────────── */
DRIVER_UNLOAD AngeronaSensorUnload;
DRIVER_DISPATCH AngeronaSensorCreate;
DRIVER_DISPATCH AngeronaSensorClose;
DRIVER_DISPATCH AngeronaSensorDeviceControl;

static VOID AngeronaSensorProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_    HANDLE    ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

static VOID AngeronaSensorImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
);

static VOID RingPush(PANGERONA_EVENT pEvent);
static ULONG RingDrain(PANGERONA_EVENT pOut, ULONG MaxEvents);

/* ── DriverEntry ────────────────────────────────────────────────────────────── */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS          status;
    UNICODE_STRING    devName  = RTL_CONSTANT_STRING(ANGERONA_DEVICE_NAME);
    UNICODE_STRING    symLink  = RTL_CONSTANT_STRING(ANGERONA_SYMLINK_NAME);
    BOOLEAN           symCreated = FALSE;
    BOOLEAN           procCbSet  = FALSE;
    BOOLEAN           imgCbSet   = FALSE;

    KeInitializeSpinLock(&g_RingLock);

    /* Create device object */
    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status)) goto cleanup;

    /* Symbolic link for user-mode access */
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) goto cleanup;
    symCreated = TRUE;

    /* Register process-creation callback */
    status = PsSetCreateProcessNotifyRoutineEx(AngeronaSensorProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) goto cleanup;
    procCbSet = TRUE;

    /* Register image-load callback */
    status = PsSetLoadImageNotifyRoutine(AngeronaSensorImageNotify);
    if (!NT_SUCCESS(status)) goto cleanup;
    imgCbSet = TRUE;

    /* Wire IRP dispatch routines */
    DriverObject->DriverUnload                         = AngeronaSensorUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AngeronaSensorCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AngeronaSensorClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AngeronaSensorDeviceControl;

    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrint("AngeronaSensor: loaded successfully.\n");
    return STATUS_SUCCESS;

cleanup:
    if (imgCbSet)    PsRemoveLoadImageNotifyRoutine(AngeronaSensorImageNotify);
    if (procCbSet)   PsSetCreateProcessNotifyRoutineEx(AngeronaSensorProcessNotify, TRUE);
    if (symCreated)  IoDeleteSymbolicLink(&symLink);
    if (g_DeviceObject) IoDeleteDevice(g_DeviceObject);
    DbgPrint("AngeronaSensor: load FAILED status=0x%08X.\n", status);
    return status;
}

/* ── Unload ─────────────────────────────────────────────────────────────────── */
VOID AngeronaSensorUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(ANGERONA_SYMLINK_NAME);
    PsSetCreateProcessNotifyRoutineEx(AngeronaSensorProcessNotify, TRUE);
    PsRemoveLoadImageNotifyRoutine(AngeronaSensorImageNotify);
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("AngeronaSensor: unloaded.\n");
}

/* ── IRP_MJ_CREATE / IRP_MJ_CLOSE ──────────────────────────────────────────── */
NTSTATUS AngeronaSensorCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS AngeronaSensorClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return AngeronaSensorCreate(DeviceObject, Irp);
}

/* ── IRP_MJ_DEVICE_CONTROL ──────────────────────────────────────────────────── */
NTSTATUS AngeronaSensorDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION  stack  = IoGetCurrentIrpStackLocation(Irp);
    ULONG               code   = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG               outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS            status = STATUS_SUCCESS;
    ULONG               info   = 0;

    switch (code) {

    case IOCTL_ANGERONA_GET_VERSION: {
        if (outLen < sizeof(ANGERONA_VERSION)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        PANGERONA_VERSION ver = (PANGERONA_VERSION)Irp->AssociatedIrp.SystemBuffer;
        ver->Major = 1; ver->Minor = 0; ver->Build = 0;
        RtlCopyMemory(ver->Tag, "ANGRSENS", 8);
        info = sizeof(ANGERONA_VERSION);
        break;
    }

    case IOCTL_ANGERONA_GET_EVENTS: {
        /* Caller allocates buffer for N events; we drain as many as fit. */
        ULONG maxEvents = (outLen - FIELD_OFFSET(ANGERONA_EVENTS_BUFFER, Events))
                          / sizeof(ANGERONA_EVENT);
        if (maxEvents == 0) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PANGERONA_EVENTS_BUFFER buf = (PANGERONA_EVENTS_BUFFER)Irp->AssociatedIrp.SystemBuffer;
        ULONG count = RingDrain(buf->Events, maxEvents);
        buf->EventCount = count;
        info = FIELD_OFFSET(ANGERONA_EVENTS_BUFFER, Events)
               + count * sizeof(ANGERONA_EVENT);
        break;
    }

    case IOCTL_ANGERONA_CLEAR_EVENTS:
        InterlockedExchange(&g_ReadIndex, g_WriteIndex);
        info = 0;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ── Process-creation callback ──────────────────────────────────────────────── */
VOID AngeronaSensorProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_    HANDLE    ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    ANGERONA_EVENT evt = {};
    LARGE_INTEGER  now;
    KeQuerySystemTime(&now);
    evt.Timestamp = now.QuadPart;
    evt.ProcessId = HandleToUlong(ProcessId);

    if (CreateInfo) {
        /* Process creation */
        evt.EventType       = ANG_EVT_PROCESS_CREATE;
        evt.ParentProcessId = HandleToUlong(CreateInfo->ParentProcessId);

        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            ULONG chars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
            if (chars > ANGERONA_MAX_PATH - 1) chars = ANGERONA_MAX_PATH - 1;
            RtlCopyMemory(evt.ImagePath, CreateInfo->ImageFileName->Buffer,
                          chars * sizeof(WCHAR));
            evt.ImagePathLen = chars;
        }
        if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer) {
            ULONG chars = CreateInfo->CommandLine->Length / sizeof(WCHAR);
            if (chars > ANGERONA_MAX_PATH - 1) chars = ANGERONA_MAX_PATH - 1;
            RtlCopyMemory(evt.CommandLine, CreateInfo->CommandLine->Buffer,
                          chars * sizeof(WCHAR));
            evt.CommandLineLen = chars;
        }
    } else {
        /* Process exit */
        evt.EventType = ANG_EVT_PROCESS_EXIT;
    }

    RingPush(&evt);
}

/* ── Image-load callback ────────────────────────────────────────────────────── */
VOID AngeronaSensorImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
)
{
    UNREFERENCED_PARAMETER(ImageInfo);
    ANGERONA_EVENT evt = {};
    LARGE_INTEGER  now;
    KeQuerySystemTime(&now);
    evt.EventType = ANG_EVT_IMAGE_LOAD;
    evt.Timestamp  = now.QuadPart;
    evt.ProcessId  = HandleToUlong(ProcessId);

    if (FullImageName && FullImageName->Buffer) {
        ULONG chars = FullImageName->Length / sizeof(WCHAR);
        if (chars > ANGERONA_MAX_PATH - 1) chars = ANGERONA_MAX_PATH - 1;
        RtlCopyMemory(evt.ImagePath, FullImageName->Buffer, chars * sizeof(WCHAR));
        evt.ImagePathLen = chars;
    }
    RingPush(&evt);
}

/* ── Ring buffer helpers ────────────────────────────────────────────────────── */
static VOID RingPush(PANGERONA_EVENT pEvent)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    LONG wi = g_WriteIndex % ANGERONA_RING_SIZE;
    RtlCopyMemory(&g_Ring[wi], pEvent, sizeof(ANGERONA_EVENT));
    g_WriteIndex++;
    /* If ring is full, advance read index (oldest overwritten) */
    if ((g_WriteIndex - g_ReadIndex) > ANGERONA_RING_SIZE)
        g_ReadIndex = g_WriteIndex - ANGERONA_RING_SIZE;
    KeReleaseSpinLock(&g_RingLock, oldIrql);
}

static ULONG RingDrain(PANGERONA_EVENT pOut, ULONG MaxEvents)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    ULONG available = (ULONG)(g_WriteIndex - g_ReadIndex);
    ULONG count     = (available < MaxEvents) ? available : MaxEvents;
    for (ULONG i = 0; i < count; i++) {
        LONG ri = (g_ReadIndex + (LONG)i) % ANGERONA_RING_SIZE;
        RtlCopyMemory(&pOut[i], &g_Ring[ri], sizeof(ANGERONA_EVENT));
    }
    g_ReadIndex += (LONG)count;
    KeReleaseSpinLock(&g_RingLock, oldIrql);
    return count;
}
