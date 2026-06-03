#pragma once

#include "Buffer.h"
#include "Serializer.h"
#include "Protocol.h"
#include "Context.h"
#include "ProcessNode.h"

class FileEventSerializer {
public:
    // Serialize file create event
    static NTSTATUS SerializeFileEvent(
        _Inout_ Buffer& buffer,
        _In_ protocol::EVENT_TYPE eventType,
        _In_ StreamHandleContext* ptrStrHandleCtx,
        _In_ InstanceContext* pInstCtx)
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
        if (!serializer.WriteFieldULong(FIELD_PROCESS_ID, HandleToULong(ptrStrHandleCtx->processId))) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // write process path
        if (ptrStrHandleCtx->processPath.Length) {
            //DbgPrint("processPath has non zero length: %wZ\n", ptrStrHandleCtx->processPath);
        }
        else {
            //DbgPrint("processPath has zero length");
        }
        if (ptrStrHandleCtx->processPath.Length && !serializer.WriteFieldUnicodeString(FIELD_IMAGE_PATH, &ptrStrHandleCtx->processPath)) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Enrich with process context from the cache (PPID, creator, etc.)
        ProcessEntry* procEntry = nullptr;
        NTSTATUS procStatus = ProcessCache::GetInstance().GetOrPopulateProcessContext(
            ptrStrHandleCtx->processId, &procEntry);

        if (NT_SUCCESS(procStatus) && procEntry)
        {
            // Write parent process ID
            if (!serializer.WriteFieldULong(FIELD_PARENT_PROCESS_ID,
                HandleToULong(procEntry->parentProcessId))) {
                ProcessCache::GetInstance().ReleaseProcessContext(procEntry);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            // Write creator process ID (may differ from parent)
            if (!serializer.WriteFieldULong(FIELD_CREATOR_PROCESS_ID,
                HandleToULong(procEntry->createrProcessId))) {
                ProcessCache::GetInstance().ReleaseProcessContext(procEntry);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            // Write parent process image path if available
            ProcessEntry* parentEntry = nullptr;
            NTSTATUS parentStatus = ProcessCache::GetInstance().GetOrPopulateProcessContext(
                procEntry->parentProcessId, &parentEntry);
            if (NT_SUCCESS(parentStatus) && parentEntry)
            {
                if (parentEntry->imagePath.Length > 0) {
                    serializer.WriteFieldUnicodeString(FIELD_PARENT_PROCESS_IMAGE_PATH,
                        &parentEntry->imagePath);
                }
                ProcessCache::GetInstance().ReleaseProcessContext(parentEntry);
            }

            ProcessCache::GetInstance().ReleaseProcessContext(procEntry);
        }

        // write file path
        if (!serializer.WriteFieldUnicodeString(FIELD_FILE_PATH, &ptrStrHandleCtx->filePath)) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // write file volume details

        // write volume guid
        if (!serializer.WriteFieldBinary(FIELD_VOLUME_GUID, (PVOID)&pInstCtx->volumeGuid, sizeof(GUID))) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // write volume type
        if (!serializer.WriteFieldULong(FIELD_VOLUME_TYPE, static_cast<ULONG>(pInstCtx->volumeType))) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (pInstCtx->isUsbDevice && pInstCtx->volumeName.Length != 0) {
            if (!serializer.WriteFieldUnicodeString(FIELD_VOLUME_NAME, &pInstCtx->volumeName)) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        if (buffer.HasOverflow()) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return STATUS_SUCCESS;
    }
};