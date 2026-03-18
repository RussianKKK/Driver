#pragma once
#include <ntifs.h>
#include <ntddk.h>

/**
 * @brief Reads virtual memory from a target process.
 * * @param pid The Process ID of the target.
 * @param address The virtual address to read from.
 * @param buffer The local kernel buffer to store the data.
 * @param size The number of bytes to read.
 * @return NTSTATUS result of the operation.
 */
NTSTATUS ReadVirtualMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size);

/**
 * @brief Writes virtual memory to a target process.
 * * @param pid The Process ID of the target.
 * @param address The virtual address to write to.
 * @param buffer The local kernel buffer containing the source data.
 * @param size The number of bytes to write.
 * @return NTSTATUS result of the operation.
 */
NTSTATUS WriteVirtualMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size);

/**
 * @brief Retrieves the base image address of a target process.
 * * @param pid The Process ID of the target.
 * @return ULONG64 The base address, or 0 if lookup fails.
 */
ULONG64 GetProcessBase(HANDLE pid);