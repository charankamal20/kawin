#pragma once
#include "FastMutex.h"

//============================================
// ProcessContext - Cached process information
//============================================

struct ProcessEntry {
    LIST_ENTRY ListEntry;
    // Reference counting
    volatile LONG referenceCount;

    // Process identification
    HANDLE processId;
    HANDLE parentProcessId;
    HANDLE createrProcessId;
    LARGE_INTEGER createTime;
    LARGE_INTEGER exitTime;      // Set on exit
    BOOLEAN hasExited;

    // Process image
    UNICODE_STRING imagePath;
    WCHAR imagePathBuffer[260];

};

//==========================================
// ProcessCache - Hash table for fast lookup
//==========================================

class ProcessCache {
private:
    static const ULONG HASH_TABLE_SIZE = 4096;  // Power of 2 for fast modulo

    // Hash table (array of list heads)
    LIST_ENTRY hashTable_[HASH_TABLE_SIZE];

    // Lock for thread safety
    PushLock tableLock_;

    // Statistics
    volatile LONGLONG totalProcesses_;
    volatile LONGLONG activeProcesses_;
    volatile LONGLONG cacheHits_;
    volatile LONGLONG cacheMisses_;

    ProcessCache()
        : totalProcesses_(0), activeProcesses_(0),
        cacheHits_(0), cacheMisses_(0) {

        // Initialize hash table
        for (ULONG i = 0; i < HASH_TABLE_SIZE; i++) {
            InitializeListHead(&hashTable_[i]);
        }

        // Initialize lock
        tableLock_.Init();
    }

public:
    static ProcessCache& GetInstance() {
        static ProcessCache instance;
        return instance;
    }

    ProcessCache(const ProcessCache&) = delete;
    ProcessCache& operator=(const ProcessCache&) = delete;
    ProcessCache(ProcessCache&& Other) = delete;
    ProcessCache& operator=(ProcessCache&& Other) = delete;

    NTSTATUS Initialize();
    void Cleanup();

    // Add process to cache
    NTSTATUS AddProcess(
        _In_ HANDLE processId,
        _In_ HANDLE parentProcessId,
        _In_ HANDLE creatorProcessId,
        _In_opt_ PCUNICODE_STRING imagePath);

    // Remove process from cache
    NTSTATUS RemoveProcess(_In_ HANDLE processId);

    // Get process context (increments reference count)
    NTSTATUS GetProcessContext(
        _In_ HANDLE processId,
        _Out_ ProcessEntry** context);

    // Lookup without adding reference (for quick checks)
    BOOLEAN IsProcessCached(_In_ HANDLE processId);

    // Get statistics
    void GetStatistics(
        _Out_ PLONGLONG total,
        _Out_ PLONGLONG active,
        _Out_ PLONGLONG hits,
        _Out_ PLONGLONG misses);

private:
    // Hash function
    ULONG ComputeHash(_In_ HANDLE processId) const {
        return (HandleToULong(processId) * 2654435761UL) % HASH_TABLE_SIZE;
    }

    // Allocate process context
    ProcessEntry* AllocateProcessContext() {
        ProcessEntry* ctx = static_cast<ProcessEntry*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ProcessEntry), 'corP')
            );

        if (!ctx) {
            return nullptr;
        }

        RtlZeroMemory(ctx, sizeof(ProcessEntry));

        RtlInitEmptyUnicodeString(&ctx->imagePath,
            ctx->imagePathBuffer,
            sizeof(ctx->imagePathBuffer));

        return ctx;
    }

    // Free process context
    void FreeProcessContext(_In_ ProcessEntry* context) {
        if (!context) return;

        ExFreePoolWithTag(context, 'corP');
    }

    // Find in hash table (lock must be held)
    ProcessEntry* FindProcessContextLocked(_In_ HANDLE processId) {
        ULONG hash = ComputeHash(processId);

        PLIST_ENTRY head = &hashTable_[hash];
        PLIST_ENTRY current = head->Flink;

        while (current != head) {
            ProcessEntry* ctx = CONTAINING_RECORD(
                current,
                ProcessEntry,
                ListEntry
            );

            if (ctx->processId == processId) {
                return ctx;
            }

            current = current->Flink;
        }

        return nullptr;
    }
};