#include "memory.h"

// Undocumented NT functions required for memory operations
extern "C" NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
extern "C" NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

NTSTATUS ReadVirtualMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size) {
    PEPROCESS process = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) return STATUS_INVALID_PARAMETER;

    SIZE_T bytes = 0;
    // We are reading from the target game/app, into our System process MDL buffer
    NTSTATUS status = MmCopyVirtualMemory(process, address, PsGetCurrentProcess(), buffer, size, KernelMode, &bytes);

    ObDereferenceObject(process);
    return status;
}

NTSTATUS WriteVirtualMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size) {
    PEPROCESS process = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) return STATUS_INVALID_PARAMETER;

    SIZE_T bytes = 0;
    // We are writing from our System process MDL buffer, into the target game/app
    NTSTATUS status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer, process, address, size, KernelMode, &bytes);

    ObDereferenceObject(process);
    return status;
}

ULONG64 GetProcessBase(HANDLE pid) {
    PEPROCESS process = nullptr;
    ULONG64 base = 0;
    if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) {
        base = (ULONG64)PsGetProcessSectionBaseAddress(process);
        ObDereferenceObject(process);
    }
    return base;
}