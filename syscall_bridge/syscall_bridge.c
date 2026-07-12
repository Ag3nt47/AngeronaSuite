/*
 * syscall_bridge.c — Indirect Syscall Bridge for Angerona SYS module.
 *
 * Python extension (CPython ≥ 3.10, x86-64 Windows).
 * Build:
 *     cd AngeronaSuite/syscall_bridge
 *     python setup.py build_ext --inplace
 *     copy syscall_bridge*.pyd ..\src\angerona\modules\
 *
 * Purpose
 * ───────
 * Standard SOAR containment (process-kill / suspend) calls kernel32.dll
 * functions that route through ntdll.dll in user-mode.  An adversary that
 * hooks NtTerminateProcess / NtSuspendProcess inside the Python process's
 * loaded ntdll will silently no-op those calls, letting a malicious process
 * survive even after Angerona issues a kill.
 *
 * This module bypasses hooked user-mode DLLs using **indirect syscalls**:
 *   1. Open a pristine copy of ntdll.dll from C:\Windows\System32\ on disk
 *      (not the in-memory, potentially-hooked copy).
 *   2. Locate the target export (e.g. NtTerminateProcess) and read its first
 *      5 bytes to extract the System Service Number (SSN):
 *         mov eax, <SSN>   →  B8 xx xx xx xx
 *   3. Find the `syscall; ret` gadget inside the CLEAN in-memory ntdll
 *      (not the start of the function — the gadget itself is never hooked).
 *   4. Build a minimal stub at runtime that:
 *         mov eax, <SSN>
 *         jmp <gadget>        ; syscall; ret
 *      Allocate it as RWX, call it.
 *
 * Security notes
 * ──────────────
 * • Reading SSN from disk avoids trusting the in-memory export table.
 * • Jumping to the syscall gadget inside ntdll means the CPU transitions
 *   directly to kernel mode via a real ntdll instruction pointer — satisfying
 *   Call Stack Spoofing mitigations (CET shadow stack, KernelCet).
 * • This module only calls NT process management functions.  It does NOT
 *   implement shellcode, injection, or memory write primitives.
 * • All allocations are freed after the call; no persistent RWX regions.
 * • Build with /GS (stack canaries) and /DYNAMICBASE /NXCOMPAT.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <Windows.h>
#include <winternl.h>  /* NtCurrentProcess, PROCESS_BASIC_INFORMATION */
#include <stdint.h>
#include <stdio.h>

/* ── NT status ──────────────────────────────────────────────────────────────*/
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

/* ── PE helpers (stdlib only, same approach as APID) ───────────────────────*/
typedef struct {
    PBYTE base;
    SIZE_T size;
    DWORD export_rva;
} PeView;

static DWORD rva_to_off(PBYTE base, DWORD rva) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD nsec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nsec; i++) {
        DWORD va  = sec[i].VirtualAddress;
        DWORD raw = sec[i].PointerToRawData;
        DWORD sz  = sec[i].SizeOfRawData;
        if (rva >= va && rva < va + sz)
            return raw + (rva - va);
    }
    return 0;
}

/* Extract SSN from disk copy of ntdll for a named export. */
static int get_ssn_from_disk(const char *func_name, WORD *out_ssn) {
    char path[MAX_PATH];
    if (!GetSystemDirectoryA(path, sizeof(path))) return 0;
    strncat_s(path, sizeof(path), "\\ntdll.dll", _TRUNCATE);

    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return 0;

    DWORD sz = GetFileSize(fh, NULL);
    PBYTE buf = (PBYTE)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    if (!buf) { CloseHandle(fh); return 0; }

    DWORD read = 0;
    if (!ReadFile(fh, buf, sz, &read, NULL) || read != sz) {
        VirtualFree(buf, 0, MEM_RELEASE); CloseHandle(fh); return 0;
    }
    CloseHandle(fh);

    /* Parse export directory */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(buf + dos->e_lfanew);
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_off = rva_to_off(buf, export_rva);
    if (!export_off) { VirtualFree(buf, 0, MEM_RELEASE); return 0; }

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(buf + export_off);
    DWORD  n   = exp->NumberOfNames;
    PDWORD names = (PDWORD)(buf + rva_to_off(buf, exp->AddressOfNames));
    PWORD  ords  = (PWORD )(buf + rva_to_off(buf, exp->AddressOfNameOrdinals));
    PDWORD funcs = (PDWORD)(buf + rva_to_off(buf, exp->AddressOfFunctions));

    for (DWORD i = 0; i < n; i++) {
        const char *name = (const char *)(buf + rva_to_off(buf, names[i]));
        if (!name) continue;
        if (strcmp(name, func_name) == 0) {
            DWORD fn_off = rva_to_off(buf, funcs[ords[i]]);
            if (!fn_off) break;
            PBYTE fn = buf + fn_off;
            /* First instruction must be:  mov eax, <ssn>  (B8 xx xx xx xx) */
            if (fn[0] == 0xB8) {
                *out_ssn = *(WORD *)(fn + 1);
                VirtualFree(buf, 0, MEM_RELEASE);
                return 1;
            }
            break;
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}

/* Find `syscall; ret` gadget inside the LIVE (potentially-hooked) ntdll.
 * We only use this address as the jump target — never as a function ptr
 * for the hooked function itself, so it's safe even if the function stub
 * is patched.  The gadget bytes (0F 05 C3) are scattered throughout ntdll
 * and are never individually hooked. */
static PBYTE find_syscall_ret(void) {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return NULL;
    PBYTE base = (PBYTE)h;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    /* Search .text section */
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD nsec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nsec; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            PBYTE start = base + sec[i].VirtualAddress;
            DWORD size  = sec[i].Misc.VirtualSize;
            for (DWORD off = 0; off + 2 < size; off++) {
                if (start[off] == 0x0F && start[off+1] == 0x05 && start[off+2] == 0xC3) {
                    return start + off;
                }
            }
        }
    }
    return NULL;
}

/* ── stub builder ───────────────────────────────────────────────────────────
 * x86-64 calling convention: RCX = 1st arg, RDX = 2nd, R8 = 3rd, R9 = 4th.
 * NT syscalls receive the same args in the same registers.
 *
 * Stub layout (12 bytes):
 *   48 C7 C0 xx xx xx xx   mov rax, <SSN (zero-extended)>
 *   FF 25 00 00 00 00       jmp [rip+0]   ; 6 bytes, followed by 8-byte abs addr
 *   <8-byte gadget addr>
 * Total: 20 bytes.
 */
#pragma pack(push, 1)
typedef struct {
    BYTE  mov_rax[3];    /* 48 B8 (REX.W + MOV RAX, imm64) — alternate encoding */
    DWORD ssn;           /* we zero-extend so upper 4 bytes are 0 */
    BYTE  pad[4];        /* zero pad for upper DWORD */
    BYTE  jmp_rip[6];   /* FF 25 00 00 00 00 */
    PVOID gadget;        /* absolute 64-bit gadget address */
} Stub20;
#pragma pack(pop)

/* Simpler encoding: mov eax, <ssn32>  (B8 xx xx xx xx — zero-extends on x64)
 *                   jmp [rip+0]       (FF 25 00 00 00 00)
 *                   <gadget addr>     (8 bytes)
 * Total: 18 bytes.  Use a 32-byte allocation. */
typedef NTSTATUS (NTAPI *SyscallFn)(...);

static SyscallFn build_stub(WORD ssn, PBYTE gadget, PVOID *out_alloc) {
    PBYTE mem = (PBYTE)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!mem) return NULL;
    BYTE stub[] = {
        0xB8, 0,0,0,0,            /* mov eax, <ssn32> */
        0xFF, 0x25, 0,0,0,0,      /* jmp [rip+0] */
        0,0,0,0,0,0,0,0           /* 8-byte gadget ptr */
    };
    *(DWORD *)(stub + 1)  = (DWORD)ssn;
    *(PVOID *)(stub + 10) = gadget;
    memcpy(mem, stub, sizeof(stub));
    DWORD old;
    VirtualProtect(mem, 32, PAGE_EXECUTE_READ, &old);
    *out_alloc = mem;
    return (SyscallFn)mem;
}

static void free_stub(PVOID alloc) {
    if (alloc) VirtualFree(alloc, 0, MEM_RELEASE);
}

/* ── Python-exposed functions ───────────────────────────────────────────────*/

/*
 * syscall_bridge.terminate_process(pid, exit_code=1) -> bool
 *
 * Opens the target process, then calls NtTerminateProcess via indirect syscall
 * so hooked ntdll exports cannot intercept the call.
 */
static PyObject *py_terminate_process(PyObject *self, PyObject *args) {
    DWORD pid;
    int   exit_code = 1;
    if (!PyArg_ParseTuple(args, "k|i", &pid, &exit_code)) return NULL;

    WORD ssn = 0;
    if (!get_ssn_from_disk("NtTerminateProcess", &ssn)) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to resolve NtTerminateProcess SSN");
        return NULL;
    }
    PBYTE gadget = find_syscall_ret();
    if (!gadget) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to find syscall;ret gadget in ntdll");
        return NULL;
    }

    HANDLE ph = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!ph || ph == INVALID_HANDLE_VALUE) {
        PyErr_Format(PyExc_OSError, "OpenProcess(%lu) failed: %lu", pid, GetLastError());
        return NULL;
    }

    PVOID alloc = NULL;
    SyscallFn fn = build_stub(ssn, gadget, &alloc);
    NTSTATUS status = fn(ph, (NTSTATUS)exit_code);
    free_stub(alloc);
    CloseHandle(ph);

    if (!NT_SUCCESS(status)) {
        PyErr_Format(PyExc_OSError, "NtTerminateProcess NTSTATUS 0x%08X", (unsigned)status);
        return NULL;
    }
    Py_RETURN_TRUE;
}

/*
 * syscall_bridge.suspend_process(pid) -> bool
 *
 * Suspends ALL threads of the target process via NtSuspendProcess.
 */
static PyObject *py_suspend_process(PyObject *self, PyObject *args) {
    DWORD pid;
    if (!PyArg_ParseTuple(args, "k", &pid)) return NULL;

    WORD ssn = 0;
    if (!get_ssn_from_disk("NtSuspendProcess", &ssn)) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to resolve NtSuspendProcess SSN");
        return NULL;
    }
    PBYTE gadget = find_syscall_ret();
    if (!gadget) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to find syscall;ret gadget in ntdll");
        return NULL;
    }

    HANDLE ph = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!ph || ph == INVALID_HANDLE_VALUE) {
        PyErr_Format(PyExc_OSError, "OpenProcess(%lu) failed: %lu", pid, GetLastError());
        return NULL;
    }

    PVOID alloc = NULL;
    SyscallFn fn = build_stub(ssn, gadget, &alloc);
    NTSTATUS status = fn(ph);
    free_stub(alloc);
    CloseHandle(ph);

    if (!NT_SUCCESS(status)) {
        PyErr_Format(PyExc_OSError, "NtSuspendProcess NTSTATUS 0x%08X", (unsigned)status);
        return NULL;
    }
    Py_RETURN_TRUE;
}

/*
 * syscall_bridge.resume_process(pid) -> bool
 */
static PyObject *py_resume_process(PyObject *self, PyObject *args) {
    DWORD pid;
    if (!PyArg_ParseTuple(args, "k", &pid)) return NULL;

    WORD ssn = 0;
    if (!get_ssn_from_disk("NtResumeProcess", &ssn)) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to resolve NtResumeProcess SSN");
        return NULL;
    }
    PBYTE gadget = find_syscall_ret();
    if (!gadget) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to find syscall;ret gadget in ntdll");
        return NULL;
    }

    HANDLE ph = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!ph || ph == INVALID_HANDLE_VALUE) {
        PyErr_Format(PyExc_OSError, "OpenProcess(%lu) failed: %lu", pid, GetLastError());
        return NULL;
    }

    PVOID alloc = NULL;
    SyscallFn fn = build_stub(ssn, gadget, &alloc);
    NTSTATUS status = fn(ph);
    free_stub(alloc);
    CloseHandle(ph);

    if (!NT_SUCCESS(status)) {
        PyErr_Format(PyExc_OSError, "NtResumeProcess NTSTATUS 0x%08X", (unsigned)status);
        return NULL;
    }
    Py_RETURN_TRUE;
}

/*
 * syscall_bridge.get_ssn(func_name) -> int
 *
 * Utility: return the SSN for any Nt* export read from the disk ntdll.
 * Useful for debugging or extending the bridge without recompiling.
 */
static PyObject *py_get_ssn(PyObject *self, PyObject *args) {
    const char *name;
    if (!PyArg_ParseTuple(args, "s", &name)) return NULL;
    WORD ssn = 0;
    if (!get_ssn_from_disk(name, &ssn)) {
        PyErr_Format(PyExc_ValueError, "Could not resolve SSN for '%s'", name);
        return NULL;
    }
    return PyLong_FromLong((long)ssn);
}

/* ── module definition ───────────────────────────────────────────────────────*/
static PyMethodDef SysMethods[] = {
    {"terminate_process", py_terminate_process, METH_VARARGS,
     "terminate_process(pid, exit_code=1) -> bool\n"
     "Terminate process via NtTerminateProcess indirect syscall."},
    {"suspend_process",   py_suspend_process,   METH_VARARGS,
     "suspend_process(pid) -> bool\n"
     "Suspend all threads via NtSuspendProcess indirect syscall."},
    {"resume_process",    py_resume_process,    METH_VARARGS,
     "resume_process(pid) -> bool\n"
     "Resume all threads via NtResumeProcess indirect syscall."},
    {"get_ssn",           py_get_ssn,           METH_VARARGS,
     "get_ssn(func_name) -> int\n"
     "Return the SSN for any Nt* export in the on-disk ntdll."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef syscall_module = {
    PyModuleDef_HEAD_INIT, "syscall_bridge",
    "Indirect syscall bridge for Angerona SYS module (Windows x64 only).",
    -1, SysMethods
};

PyMODINIT_FUNC PyInit_syscall_bridge(void) {
    return PyModule_Create(&syscall_module);
}
