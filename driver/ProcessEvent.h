#pragma once

#include "Buffer.h"
#include "Serializer.h"
#include "EventHeader.h"
#include "Protocol.h"
#include "Context.h"
#include "ProcessNode.h"

struct ProcessContext {

    // Process identification
    HANDLE processId;
    LARGE_INTEGER createTime;
    LARGE_INTEGER exitTime;      // Set on exit
    
    BOOLEAN hasExited;
    ULONG exitCode;

    // Process image
    UNICODE_STRING imagePath;
    WCHAR imagePathBuffer[260];

    // Command line
    UNICODE_STRING commandLine;
    WCHAR commandLineBuffer[32767];

    // Parent process information
    HANDLE parentProcessId;
    UNICODE_STRING parentImagePath;
    WCHAR parentImagePathBuffer[260];

    // Creator process information (could differ from parent)
    HANDLE creatorProcessId;
    UNICODE_STRING creatorImagePath;
    WCHAR creatorImagePathBuffer[260];

    // Security context
    PSID userSid;
    ULONG sidLength;
    BOOLEAN isElevated;
};

class ProcessEventSerializer {
public:
    // Serialize process create event
    static NTSTATUS SerializeProcessEvent(
        _Inout_ Buffer& buffer,
        _In_ protocol::EVENT_TYPE eventType,
        _In_ PEPROCESS Process,
        _In_ HANDLE ProcessId,
        _In_ PPS_CREATE_NOTIFY_INFO CreateInfo)
    {
        Serializer serializer(buffer);

        LARGE_INTEGER timestamp;
        KeQuerySystemTime(&timestamp);

        // write event type
        if (!serializer.WriteFieldULong(FIELD_EVENT_TYPE, static_cast<ULONG>(eventType))) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // write timestamp
        if (!serializer.WriteFieldULongLong(FIELD_TIMESTAMP, timestamp.QuadPart)) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // write process id
        if (!serializer.WriteFieldULong(FIELD_PROCESS_ID, HandleToULong(ProcessId))) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (CreateInfo) { // process create event
            // write parent process id
            if (!serializer.WriteFieldULong(FIELD_PARENT_PROCESS_ID, HandleToULong(CreateInfo->ParentProcessId))) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            // write creater process id
            if (!serializer.WriteFieldULong(FIELD_CREATOR_PROCESS_ID, HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess))) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            // write process image file
            if (CreateInfo->FileOpenNameAvailable && CreateInfo->ImageFileName) {
                if (!serializer.WriteFieldUnicodeString(FIELD_IMAGE_PATH, CreateInfo->ImageFileName)) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }
            else {
                DbgPrint("process %lu has no imageName", HandleToULong(ProcessId));
            }

            NTSTATUS status = ProcessCache::GetInstance().AddProcess(
                ProcessId,
                CreateInfo->ParentProcessId,
                CreateInfo->CreatingThreadId.UniqueProcess,
                CreateInfo->ImageFileName
            );

            if (!NT_SUCCESS(status))
                return status;

            LONGLONG total, active, hit, miss;
            ProcessCache::GetInstance().GetStatistics(&total, &active, &hit, &miss);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                "statisctics::total: %I64d active : %I64d hit : %I64d miss : %I64d", total, active, hit, miss);

            // write command line
            if (CreateInfo->CommandLine) {
                if (!serializer.WriteFieldUnicodeString(FIELD_COMMAND_LINE, CreateInfo->CommandLine)) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }

            if (ProcessCache::GetInstance().IsProcessCached(CreateInfo->ParentProcessId)) {
                ProcessEntry* p_parentProcessCtx = nullptr;
                status = ProcessCache::GetInstance().GetProcessContext(
                    CreateInfo->ParentProcessId,
                    &p_parentProcessCtx
                );

                if (!NT_SUCCESS(status)) {
                    DbgPrint("parent process %lu context failed", CreateInfo->ParentProcessId);
                    return status;
                }

                if (!serializer.WriteFieldUnicodeString(FIELD_PARENT_PROCESS_IMAGE_PATH, &p_parentProcessCtx->imagePath)) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                
            }
            else {
                DbgPrint("parent process %lu was not cached", CreateInfo->ParentProcessId);
            }

            if (CreateInfo->ParentProcessId != CreateInfo->CreatingThreadId.UniqueProcess){
                if (ProcessCache::GetInstance().IsProcessCached(CreateInfo->CreatingThreadId.UniqueProcess)) {
                    ProcessEntry* p_creatorProcessCtx = nullptr;
                    status = ProcessCache::GetInstance().GetProcessContext(
                        CreateInfo->CreatingThreadId.UniqueProcess,
                        &p_creatorProcessCtx
                    );

                    if (!NT_SUCCESS(status)) {
                        DbgPrint("creator process %lu context failed", CreateInfo->CreatingThreadId.UniqueProcess);
                        return status;
                    }

                    if (!serializer.WriteFieldUnicodeString(FIELD_PARENT_PROCESS_IMAGE_PATH, &p_creatorProcessCtx->imagePath)) {
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                }
            }
            else {
                DbgPrint("creator process %lu was not cached", CreateInfo->CreatingThreadId.UniqueProcess);
            }

            // get process token info
            PACCESS_TOKEN token = PsReferencePrimaryToken(Process);
            if (token)
            {
                UNICODE_STRING sidString = {};
                PTOKEN_USER tokenUser = nullptr;
                status = SeQueryInformationToken(token, TokenUser,
                    reinterpret_cast<PVOID*>(&tokenUser));
                if (NT_SUCCESS(status) && tokenUser)
                {
                    status = RtlConvertSidToUnicodeString(&sidString,
                        tokenUser->User.Sid,
                        TRUE /*allocate*/);
                    if (NT_SUCCESS(status))
                    {
                        if (!serializer.WriteFieldUnicodeString(FIELD_PROCESS_USER_SID, &sidString)) {
                            RtlFreeUnicodeString(&sidString);
                            ExFreePool(tokenUser);
                            PsDereferencePrimaryToken(token);
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }
                        // Free the buffer allocated by RtlConvertSidToUnicodeString.
                        RtlFreeUnicodeString(&sidString);
                    }
                    ExFreePool(tokenUser);
                }
                else {
                    DbgPrint("failed to get process token user info");
                }
 
                TOKEN_ELEVATION* elevation = nullptr;
                NTSTATUS elevStatus = SeQueryInformationToken(token, TokenElevation,
                    reinterpret_cast<PVOID*>(&elevation));
                if (NT_SUCCESS(elevStatus) && elevation) {
                    DbgPrint("[TokenInfo] isElevated: %lu\n", elevation->TokenIsElevated);
                    if (!serializer.WriteFieldBoolean(FIELD_PROCESS_TOKEN_ELEVATION,
                        (elevation->TokenIsElevated != 0))) {
                        PsDereferencePrimaryToken(token);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                }

                TOKEN_ELEVATION_TYPE* elevationType = nullptr;
                NTSTATUS elevTypeStatus = SeQueryInformationToken(token, TokenElevationType,
                    reinterpret_cast<PVOID*>(&elevationType));
                if (NT_SUCCESS(elevTypeStatus) && elevationType) {
                    DbgPrint("[TokenInfo] elevationType: %lu\n",
                        static_cast<ULONG>(*elevationType));
                    if (!serializer.WriteFieldULong(FIELD_PROCESS_TOKEN_ELEVATION_TYPE,
                        static_cast<ULONG>(*elevationType))) {
                        PsDereferencePrimaryToken(token);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                }
                else {
                    DbgPrint("failed to get elevation type info");
                }
                PsDereferencePrimaryToken(token);
            }
            else {
                DbgPrint("failed to get process token info");
            }
        }
        else { // process delete event
            if (!serializer.WriteFieldULong(FIELD_EXIT_CODE, (ULONG)PsGetProcessExitStatus(Process))) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ProcessEntry* p_ctx = nullptr;
            ProcessCache::GetInstance().GetProcessContext(ProcessId, &p_ctx);

            if (!p_ctx) {
                DbgPrint("process %lu delted and and has no cache", ProcessId);
                return STATUS_NOT_FOUND;
            }

            if (!serializer.WriteFieldULong(FIELD_PARENT_PROCESS_ID, HandleToULong(p_ctx->parentProcessId))) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            if (!serializer.WriteFieldULong(FIELD_CREATOR_PROCESS_ID, HandleToULong(p_ctx->createrProcessId))) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            if (!serializer.WriteFieldUnicodeString(FIELD_IMAGE_PATH, &p_ctx->imagePath)) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ProcessCache::GetInstance().RemoveProcess(ProcessId);
        }

        if (buffer.HasOverflow()) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return STATUS_SUCCESS;
    }
private:
    // Get process information helpers
    NTSTATUS GetProcessImagePath(
        _In_ HANDLE processId,
        _Out_ PUNICODE_STRING imagePath);

};
