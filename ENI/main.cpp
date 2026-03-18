#include <ntifs.h>
#include "memory.h"
#include "shared.h"

// Global handles so the thread can clean up properly
PVOID g_SharedMemoryKernel = nullptr;
PMDL  g_Mdl = nullptr;

/**
 * @brief Performs the critical cleanup of the MDL.
 * This "unstaples" the usermode memory from physical RAM.
 */
VOID CleanupMDL() {
    if (g_Mdl) {
        MmUnlockPages(g_Mdl);
        IoFreeMdl(g_Mdl);
        g_Mdl = nullptr;
        g_SharedMemoryKernel = nullptr;
    }
}

VOID WriteRegistryError(ULONG errorCode) {
    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SOFTWARE\\Eni");
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey;
    if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_WRITE, &objAttr))) {
        UNICODE_STRING valName;
        RtlInitUnicodeString(&valName, L"Error");
        ZwSetValueKey(hKey, &valName, 0, REG_DWORD, &errorCode, sizeof(ULONG));
        ZwClose(hKey);
    }
}

VOID PollingThread(PVOID StartContext) {
    UNREFERENCED_PARAMETER(StartContext);
    _COMM_BUFFER* comm = (_COMM_BUFFER*)g_SharedMemoryKernel;

    LARGE_INTEGER timeout;
    timeout.QuadPart = -100LL; // Faster polling (0.1ms) for a snappy shutdown response

    while (true) {
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);

        // Check if Usermode is requesting a safe shutdown
        if (comm->shutdown_state == SHUTDOWN_REQUESTED) {
            break;
        }

        if (comm->lock == 0) continue;

        if (comm->magic != SHARED_MAGIC) {
            comm->lock = 0;
            continue;
        }

        switch (comm->operation) {
        case CMD_READ:
            if (comm->size <= sizeof(comm->data)) {
                comm->status = ReadVirtualMemory((HANDLE)comm->target_pid, (PVOID)comm->address, (PVOID)comm->data, (SIZE_T)comm->size);
            }
            break;
        case CMD_WRITE:
            if (comm->size <= sizeof(comm->data)) {
                comm->status = WriteVirtualMemory((HANDLE)comm->target_pid, (PVOID)comm->address, (PVOID)comm->data, (SIZE_T)comm->size);
            }
            break;
        case CMD_BASE:
            comm->base_out = GetProcessBase((HANDLE)comm->target_pid);
            comm->status = (comm->base_out != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
            break;
        default:
            comm->status = STATUS_INVALID_PARAMETER;
            break;
        }

        comm->lock = 0;
    }

    // --- CRITICAL HANDSHAKE SECTION ---
    // At this point, the loop has broken because Usermode requested shutdown.

    // 1. Release the physical lock on the process memory
    CleanupMDL();

    // 2. Tell the Usermode app that the "staple" is removed and it is safe to exit
    comm->shutdown_state = SHUTDOWN_CONFIRMED;

    // 3. Terminate the system thread
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS ReadRegistryHandoff(PULONG pPid, PULONG64 pPtr) {
    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SOFTWARE\\Eni");
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey;
    if (!NT_SUCCESS(ZwOpenKey(&hKey, KEY_READ, &objAttr))) return STATUS_UNSUCCESSFUL;

    UNICODE_STRING valPid, valPtr;
    RtlInitUnicodeString(&valPid, L"Pid");
    RtlInitUnicodeString(&valPtr, L"Ptr");

    PKEY_VALUE_PARTIAL_INFORMATION pInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, 256, 'ineE');
    if (!pInfo) {
        ZwClose(hKey);
        return STATUS_UNSUCCESSFUL;
    }

    ULONG resultLen;
    NTSTATUS status1 = ZwQueryValueKey(hKey, &valPid, KeyValuePartialInformation, pInfo, 256, &resultLen);
    if (NT_SUCCESS(status1)) memcpy(pPid, pInfo->Data, sizeof(ULONG));

    NTSTATUS status2 = ZwQueryValueKey(hKey, &valPtr, KeyValuePartialInformation, pInfo, 256, &resultLen);
    if (NT_SUCCESS(status2)) memcpy(pPtr, pInfo->Data, sizeof(ULONG64));

    ExFreePoolWithTag(pInfo, 'ineE');
    ZwClose(hKey);
    return (NT_SUCCESS(status1) && NT_SUCCESS(status2)) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    ULONG pid = 0;
    ULONG64 ptr = 0;

    if (!NT_SUCCESS(ReadRegistryHandoff(&pid, &ptr)) || pid == 0 || ptr == 0) {
        WriteRegistryError(1);
        return STATUS_SUCCESS;
    }

    PEPROCESS targetProcess;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &targetProcess))) {
        WriteRegistryError(2);
        return STATUS_SUCCESS;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(targetProcess, &apc);

    g_Mdl = IoAllocateMdl((PVOID)ptr, sizeof(_COMM_BUFFER), FALSE, FALSE, NULL);
    if (!g_Mdl) {
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(targetProcess);
        WriteRegistryError(3);
        return STATUS_SUCCESS;
    }

    __try {
        MmProbeAndLockPages(g_Mdl, UserMode, IoModifyAccess);
        g_SharedMemoryKernel = MmGetSystemAddressForMdlSafe(g_Mdl, NormalPagePriority);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(g_Mdl);
        g_Mdl = nullptr;
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(targetProcess);

    if (!g_SharedMemoryKernel) {
        WriteRegistryError(4);
        return STATUS_SUCCESS;
    }

    _COMM_BUFFER* comm = (_COMM_BUFFER*)g_SharedMemoryKernel;
    comm->magic = SHARED_MAGIC;
    comm->shutdown_state = SHUTDOWN_NONE;

    HANDLE threadHandle;
    if (NT_SUCCESS(PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)PollingThread, NULL))) {
        ZwClose(threadHandle);
    }

    return STATUS_SUCCESS;
}