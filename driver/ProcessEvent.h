#pragma once

#include "Buffer.h"
#include "Serializer.h"
#include "EventHeader.h"
#include "Protocol.h"
#include "Context.h"


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

            // write command line
            if (CreateInfo->CommandLine) {
                if (!serializer.WriteFieldUnicodeString(FIELD_COMMAND_LINE, CreateInfo->CommandLine)) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }
        }
        else { // process delete event
            if (!serializer.WriteFieldULong(FIELD_EXIT_CODE, (ULONG)PsGetProcessExitStatus(Process))) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        if (buffer.HasOverflow()) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return STATUS_SUCCESS;
    }
};
