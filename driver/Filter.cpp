#include "Filter.h"
#include "Context.h"
#include "Buffer.h"
#include "Protocol.h"
#include "FileEvent.h"
#include "FilenameInformationGuard.h"

constexpr auto EVENT_TAG = 'evnt';

static const HANDLE g_systemProcessId = reinterpret_cast<HANDLE>(4);

// print hex for testing and debugging

VOID
DbgPrintHex(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ SIZE_T Length
)
{
    SIZE_T i;
    for (i = 0; i < Length; i++)
    {
        DbgPrint("%02X ", Buffer[i]);

        // New line every 16 bytes (optional)
        if ((i + 1) % 16 == 0)
        {
            DbgPrint(" ");
        }
    }
    DbgPrint("\n");
}

// ==========================
// ==== Filter Callbacks ====
// ==========================

BOOLEAN SkipEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL ||
        IoGetTopLevelIrp() ||
        FLT_IS_FASTIO_OPERATION(Data) ||
        !FLT_IS_IRP_OPERATION(Data)) {
        return TRUE;
    }

    //
    // Skip if this PreCreate call was performed from the System process.
    //
    if (PsGetCurrentProcessId() == g_systemProcessId)
    {
        return TRUE;
    }

    //
    // Check if the FileObject being processed represents: Named pipe, Mailslot, or Volume. Skip this call if it returns true.
    // 
    if (FltObjects->FileObject->Flags & (FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))
    {
        return TRUE;
    }

    return FALSE;
}

// create

FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PEVENT event = NULL;
    ULONG eventLength = sizeof(EVENT);
    PEVENT_REPLY eventReply = NULL;
    ULONG replyLength;
    LARGE_INTEGER timeOut = { 0 };
    timeOut.QuadPart = -10 * 1000 * 1000; // 1 sec
    PEPROCESS process = NULL;
    PUNICODE_STRING imagePath = NULL;

    //
    // Pre-create callback to get file info during creation or opening
    //

    if (!Data || !FltObjects)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() > PASSIVE_LEVEL || 
        IoGetTopLevelIrp() || 
        FLT_IS_FASTIO_OPERATION(Data) ||
        !FLT_IS_IRP_OPERATION(Data) ) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Skip if this PreCreate call was performed from the System process.
    //
    if (PsGetCurrentProcessId() == g_systemProcessId)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check if the FileObject being processed represents: Named pipe, Mailslot, or Volume. Skip this call if it returns true.
    // 
    if (FltObjects->FileObject->Flags & (FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {

        replyLength = sizeof(EVENT_REPLY);

        if (g_ScannerData.ClientPort != NULL && g_ScannerData.Filter != NULL) {

            process = FltGetRequestorProcess(Data);

            if (process == NULL) {
                DbgPrint("!!! unable to get requestor process");
            }
            else {
                const NTSTATUS status = SeLocateProcessImageName(process, &imagePath);
                if (status == STATUS_SUCCESS) {
                    if (imagePath != NULL) {
                        //DbgPrint("requestor process image path: %wZ of length %d\n", imagePath, imagePath->Length);
                        eventLength += imagePath->Length;
                    }
                }
                else {
                    DbgPrint("SeLocateProcessImageName failed 0x%x\n", status);
                }
            }

            if (FltObjects->FileObject->FileName.Length > 0) {
                eventLength += FltObjects->FileObject->FileName.Length;
            }

            //DbgPrint("event size %llu with process path %lu\n", sizeof(EVENT), eventLength);

            if (eventLength > MAX_FILTER_EVENT_SIZE) {
                returnStatus = FLT_PREOP_COMPLETE;
                __leave;
            }

            event = (PEVENT)ExAllocatePoolZero(NonPagedPool,
                eventLength,
                'nacS');

            eventReply = (PEVENT_REPLY)ExAllocatePoolZero(NonPagedPool,
                sizeof(EVENT_REPLY),
                'nacS');

            if (event == NULL || eventReply == NULL) {
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                returnStatus = FLT_PREOP_COMPLETE;
                __leave;
            }
            ULONG currentOffset = sizeof(EVENT);
            PUCHAR basePtr = (PUCHAR)event;

            event->type = EventType_HostLog;
            event->operation = EventOperation_File;
            KeQuerySystemTime((LARGE_INTEGER*)&event->timestamp);
            event->blocked = false;
            event->data.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            event->data.Operation = 0;

            if (imagePath != NULL) {
                RtlCopyMemory(basePtr + currentOffset, imagePath->Buffer, imagePath->Length);
                event->data.ProcessPathOffset = currentOffset;
                event->data.ProcessPathLength = imagePath->Length;
                currentOffset += imagePath->Length;
            }
            else {
                event->data.ProcessPathOffset = 0;
                event->data.ProcessPathLength = 0;
                DbgPrint("!!! imagePath is NULL");
            }

            if (FltObjects->FileObject->FileName.Length > 0) {
                RtlCopyMemory(basePtr + currentOffset, FltObjects->FileObject->FileName.Buffer, FltObjects->FileObject->FileName.Length);
                event->data.FilePathLength = FltObjects->FileObject->FileName.Length;
                event->data.FilePathOffset = currentOffset;
                currentOffset += FltObjects->FileObject->FileName.Length;
            }
            else {
                event->data.FilePathLength = 0;
                event->data.FilePathOffset = 0;
            }

            returnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

           /* NTSTATUS status = FltSendMessage(g_ScannerData.Filter,
                &g_ScannerData.ClientPort,
                event,
                eventLength,
                (PVOID)eventReply,
                &replyLength,
                &timeOut);

            if (status == STATUS_SUCCESS) {
                if (eventReply->ack) {
                    DbgPrint("!!! successfully sent event to user-mode and ack");
                }
                else {
                    DbgPrint("!!! successfully sent event to user-mode but not ack");
                }
            }
            else {
                DbgPrint("!!! couldn't send event to user-mode, status 0x%X\n", status);

            }*/
        }


    }
    __finally {

        if (event != NULL) {
            ExFreePoolWithTag(event, 'nacS');
        }

        if (eventReply != NULL) {
            ExFreePoolWithTag(eventReply, 'nacS');
        }

        if (imagePath != NULL) {
            ExFreePool(imagePath);
        }
    }

    return returnStatus;
}

FLT_POSTOP_CALLBACK_STATUS PostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags) {

    UNREFERENCED_PARAMETER(completionContext);
    UNREFERENCED_PARAMETER(fltObjects);

    //DbgPrint("postcreate called!!!");

    if (flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(data->IoStatus.Status) || data->IoStatus.Status == STATUS_REPARSE) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    StreamHandleContext* pStrHandleCtx = nullptr;

    __try {
        if (SkipEvent(data, fltObjects)) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
        NTSTATUS status = FltAllocateContext(
            fltObjects->Filter,
            FLT_STREAMHANDLE_CONTEXT,
            sizeof(StreamHandleContext),
            NonPagedPool,
            (PFLT_CONTEXT*)&pStrHandleCtx);

        if (!NT_SUCCESS(status)) {
            DbgPrint("FltAllocateContext failed !!!");
            __leave;
        }
        
        status = Context::InitializeStreamHandleContext(data, fltObjects, pStrHandleCtx);

        if (!NT_SUCCESS(status)) {
            DbgPrint("InitializeStreamHandleContext failed !!!");
            __leave;
        }

        status = FltSetStreamHandleContext(
            fltObjects->Instance,
            fltObjects->FileObject,
            FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
            pStrHandleCtx,
            nullptr);

        if (!NT_SUCCESS(status)) {
            DbgPrint("FltSetStreamHandleContext failed !!!");
            __leave;
        }

        DbgPrint("postCreate StreamHandleContext created !!!");
    }
    __finally {
        if (pStrHandleCtx) {
            //PrintStreamHandleContext(pStrHandleCtx);
            FltReleaseContext((PFLT_CONTEXT)pStrHandleCtx);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// write

FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(completionContext);

    DbgPrint("prewrite called!!!");

    if (SkipEvent(data, fltObjects)) {
        DbgPrint("prewrite skip event!!!");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    StreamHandleContext* pStrHandleCtx = nullptr;
    NTSTATUS status = FltGetStreamHandleContext(
        fltObjects->Instance,
        fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx);

    if (!NT_SUCCESS(status)) {
        DbgPrint("prewrite FltGetStreamHandleContext failed!!!");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!pStrHandleCtx->readOnly || data->Iopb->Parameters.Write.Length == 0) {
        DbgPrint("not readonly or requested 0 byte write");
        FltReleaseContext(pStrHandleCtx);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;

}

FLT_POSTOP_CALLBACK_STATUS PostWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags)
{ 
    UNREFERENCED_PARAMETER(completionContext);

    DbgPrint("postwrite called!!!");

    if (SkipEvent(data, fltObjects) || flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    StreamHandleContext* pStrHandleCtx = nullptr;
    NTSTATUS status = FltGetStreamHandleContext(
        fltObjects->Instance,
        fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx);

    if (NT_SUCCESS(status) && pStrHandleCtx) {
        pStrHandleCtx->wasChanged = TRUE;
        DbgPrint("file changed!!!");
        FltReleaseContext(pStrHandleCtx);
    }

    DbgPrint("file unchanged!!!");

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// setfileinformation
FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipEvent(data, fltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FILE_INFORMATION_CLASS infoClass = data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // if no delete or no rename skip
    BOOLEAN isDelete = 
        (infoClass == FileDispositionInformation || 
        infoClass == FileDispositionInformationEx);
    BOOLEAN isRename = 
        (infoClass == FileRenameInformation || 
        infoClass == FileRenameInformationEx);

    if (!isDelete && !isRename) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    StreamHandleContext* pStrHandleCtx = nullptr;
    NTSTATUS status = FltGetStreamHandleContext(
        fltObjects->Instance,
        fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx);

    if (NT_SUCCESS(status)) {
        DbgPrint("preSetFileInfo file deleted or renamed!!!");
        FltReleaseContext(pStrHandleCtx);
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(completionContext);

    if (SkipEvent(data, fltObjects) || flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(data->IoStatus.Status))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    StreamHandleContext* pStrHandleCtx = nullptr;

    __try {
        NTSTATUS status = FltGetStreamHandleContext(
            fltObjects->Instance,
            fltObjects->FileObject,
            (PFLT_CONTEXT*)&pStrHandleCtx);
        if (!NT_SUCCESS(status)) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        FILE_INFORMATION_CLASS infoClass = data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        // if no delete or no rename skip
        BOOLEAN isDelete =
            (infoClass == FileDispositionInformation ||
                infoClass == FileDispositionInformationEx);
        BOOLEAN isRename =
            (infoClass == FileRenameInformation ||
                infoClass == FileRenameInformationEx);

        if (!isDelete && !isRename) {
            __leave;
        }

        pStrHandleCtx->dispositionDelete = isDelete;
        DbgPrint("postSetFileInfo file deleted or renamed!!!");
    }
    __finally {
        if (pStrHandleCtx) {
            FltReleaseContext(pStrHandleCtx);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// cleanup

FLT_PREOP_CALLBACK_STATUS PreCleanupCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext) {

    UNREFERENCED_PARAMETER(completionContext);

    if (SkipEvent(data, fltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    DbgPrint("precleanup called!!");

    StreamHandleContext* pStrHandleCtx = nullptr;
    NTSTATUS status = FltGetStreamHandleContext(
        fltObjects->Instance,
        fltObjects->FileObject,
        (PFLT_CONTEXT*)&pStrHandleCtx);

    if (!NT_SUCCESS(status)) {
        DbgPrint("precleanup no streamhandlecontext");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltReleaseContext(pStrHandleCtx);
    return FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS PostCleanupCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags) {

    UNREFERENCED_PARAMETER(completionContext);

    DbgPrint("postcleanup called!!");

    if (SkipEvent(data, fltObjects) || flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(data->IoStatus.Status))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    StreamHandleContext* pStrHandleCtx = nullptr;
    InstanceContext* pInstCtx = nullptr;

    __try {
        NTSTATUS status = FltGetStreamHandleContext(
            fltObjects->Instance,
            fltObjects->FileObject,
            (PFLT_CONTEXT*)&pStrHandleCtx);
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        status = FltGetInstanceContext(
            fltObjects->Instance,
            (PFLT_CONTEXT*)&pInstCtx);

        if (!NT_SUCCESS(status)) {
            __leave;
        }

        Buffer event;

        if (!event.IsValid()) {
            DbgPrint("unable to initialize buffer!!");
            __leave;
        }

        protocol::EVENT_TYPE eType;

        BOOLEAN deleted = pStrHandleCtx->deleteOnClose || pStrHandleCtx->dispositionDelete;

        // delete event
        if (deleted && pStrHandleCtx->fileIoStatus != FILE_CREATED) {
            eType = protocol::EVENT_TYPE::EVENT_TYPE_FILE_DELETE;
        }

        // updation event
        if (pStrHandleCtx->wasChanged && !deleted) {
            eType = protocol::EVENT_TYPE::EVENT_TYPE_FILE_WRITE;
        }

        // close event
        eType = protocol::EVENT_TYPE::EVENT_TYPE_FILE_CLOSE;

        status = FileEventSerializer::SerializeFileEvent(event, eType, pStrHandleCtx, pInstCtx);
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        DbgPrint("file event serialized!!");

        LARGE_INTEGER timeOut = { 0 };
        timeOut.QuadPart = 0;

       /*status = FltSendMessage(g_ScannerData.Filter,
            &g_ScannerData.ClientPort,
            (PVOID)event.GetBuffer(),
            event.GetCurrentSize(),
            NULL,
            NULL,
            &timeOut);

       DbgPrint("sending %lu bytes data to user-end", event.GetCurrentSize());
       //DbgPrintHex(event.GetBuffer(), event.GetCurrentSize());
        if (status == STATUS_SUCCESS) {
            DbgPrint("!!! successfully sent event to user-mode");
        }
        else {
            DbgPrint("!!! couldn't send event to user-mode, status 0x%X\n", status);

        }*/

    }
    __finally {
        if (pStrHandleCtx) {
            FltReleaseContext(pStrHandleCtx);
        }
        if (pInstCtx) {
            FltReleaseContext(pInstCtx);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;


}

// ==== // Filter Callbacks

NTSTATUS
ScannerPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie
)
/*++

Routine Description

    This is called when user-mode connects to the server port - to establish a
    connection

Arguments

    ClientPort - This is the client connection port that will be used to
        send messages from the filter

    ServerPortCookie - The context associated with this port when the
        minifilter created this port.

    ConnectionContext - Context from entity connecting to this port (most likely
        your user mode service)

    SizeofContext - Size of ConnectionContext in bytes

    ConnectionCookie - Context to be passed to the port disconnect routine.

Return Value

    STATUS_SUCCESS - to accept the connection

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

    FLT_ASSERT(g_ScannerData.ClientPort == NULL);
    FLT_ASSERT(g_ScannerData.UserProcess == NULL);

    //
    //  Set the user process and port. In a production filter it may
    //  be necessary to synchronize access to such fields with port
    //  lifetime. For instance, while filter manager will synchronize
    //  FltCloseClientPort with FltSendMessage's reading of the port
    //  handle, synchronizing access to the UserProcess would be up to
    //  the filter.
    //

    g_ScannerData.UserProcess = PsGetCurrentProcess();
    g_ScannerData.ClientPort = ClientPort;

    DbgPrint("!!! scanner.sys --- connected, port=0x%p\n", ClientPort);

    return STATUS_SUCCESS;
}

VOID
ScannerPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
/*++

Routine Description

    This is called when the connection is torn-down. We use it to close our
    handle to the connection

Arguments

    ConnectionCookie - Context from the port connect routine

Return value

    None

--*/
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    PAGED_CODE();

    DbgPrint("!!! scanner.sys --- disconnected, port=0x%p\n", g_ScannerData.ClientPort);

    //
    //  Close our handle to the connection: note, since we limited max connections to 1,
    //  another connect will not be allowed until we return from the disconnect routine.
    //

    FltCloseClientPort(g_ScannerData.Filter, &g_ScannerData.ClientPort);

    //
    //  Reset the user-process field.
    //

    g_ScannerData.UserProcess = NULL;
}

NTSTATUS FLTAPI InstanceFilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(Flags);

    //
    // This is called before a filter is unloaded.
    // If NULL is specified for this routine, then the filter can never be unloaded.
    //
    if (g_ScannerData.ClientPort) {
        FltCloseClientPort(g_ScannerData.Filter, &g_ScannerData.ClientPort);
    }

    if (g_ScannerData.ServerPort) {
        FltCloseCommunicationPort(g_ScannerData.ServerPort);
    }

    if (g_ScannerData.Filter)
    {
        FltUnregisterFilter(g_ScannerData.Filter);
    }

    return STATUS_SUCCESS;
}

// ==================================== //
// ===== InstanceContext Callbacks ==== //
// ==================================== //

NTSTATUS InstanceSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS flags,
    _In_ DEVICE_TYPE volumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE volumeFilesystemType) {

    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(volumeDeviceType);
    UNREFERENCED_PARAMETER(volumeFilesystemType);

    DbgPrint("InstanceSetupCallback called!!");

    // Allocate instance context
    InstanceContext* pCtx = nullptr;
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        PFLT_CONTEXT pFltCtx = NULL;
        status = FltAllocateContext(
            fltObjects->Filter,
            FLT_INSTANCE_CONTEXT,
            sizeof(InstanceContext),
            NonPagedPool,
            &pFltCtx);

        if (!NT_SUCCESS(status)) {
            DbgPrint("InstanceSetupCallback:FltAllocateContext failed!! 0x%X\n", status);
            return status;
        }
        pCtx = (InstanceContext*)pFltCtx;

        status = Context::InitializeInstanceContext(fltObjects, pCtx);
        if (!NT_SUCCESS(status)) {
            DbgPrint("InstanceSetupCallback:InitializeInstanceContext failed!!");
            FltReleaseContext(pCtx);
            return status;
        }

        PrintInstanceContext(pCtx);

        status = FltSetInstanceContext(
            fltObjects->Instance,
            FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
            pCtx,
            nullptr);
        if (!NT_SUCCESS(status)) {
            DbgPrint("InstanceSetupCallback:FltSetInstanceContext failed!!");
            FltReleaseContext(pCtx);
            return status;
        }
    }
    __finally {
        if (pCtx != nullptr) {
            FltReleaseContext(pCtx);
        }
    }
    return status;
}

NTSTATUS InstanceQueryTeardownCallback(_In_ PCFLT_RELATED_OBJECTS,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS)
{
    return STATUS_SUCCESS;
}

VOID InstanceStartTeardownCallback(_In_ PCFLT_RELATED_OBJECTS,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS)
{
}

VOID InstanceCompleteTeardownCallback(_In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS)
{
    InstanceContext* pCtx = NULL;
    __try
    {
        FltGetInstanceContext(pFltObjects->Instance, (PFLT_CONTEXT*)&pCtx);
    }
    __finally
    {
        if (pCtx != NULL)
            FltReleaseContext(pCtx);
    }
}

VOID InstanceContextCleanup(_In_ PFLT_CONTEXT pContext, _In_ FLT_CONTEXT_TYPE)
{
    if (pContext == nullptr) {
        return;
    }
    InstanceContext* pCtx = (InstanceContext*)pContext;
    Context::CleanupInstanceContext(pCtx);
}

// ==================================== //

// ============================= //
// ==== StreamHandleContext ==== //
// ============================= //

VOID StreamHandleContextCleanup(_In_ PFLT_CONTEXT pContext, _In_ FLT_CONTEXT_TYPE contextType) {
    UNREFERENCED_PARAMETER(contextType);
    if (pContext == nullptr) {
        return;
    }
    StreamHandleContext* pHndlCtx = (StreamHandleContext*)pContext;
    Context::CleanupStreamHandleContext(pHndlCtx);
}

// ============================= //

NTSTATUS RegisterFilter(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    NTSTATUS status;

    RtlInitUnicodeString(&uniString, L"\\ScannerPort");

    //
    // register minifilter driver
    //
    status = FltRegisterFilter(DriverObject, &g_filterRegistration, &g_ScannerData.Filter);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    KdPrint(("KdPrint:fsminifilter driver loaded"));


    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {

        InitializeObjectAttributes(&oa,
            &uniString,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            sd);

        status = FltCreateCommunicationPort(
            g_ScannerData.Filter,
            &g_ScannerData.ServerPort,
            &oa,
            NULL,
            ScannerPortConnect,
            ScannerPortDisconnect,
            NULL,
            1);

        FltFreeSecurityDescriptor(sd);

        if (NT_SUCCESS(status)) {
            //
            // start minifilter driver
            //
            status = FltStartFiltering(g_ScannerData.Filter);
            if (NT_SUCCESS(status))
            {
                return STATUS_SUCCESS;
            }

            FltCloseCommunicationPort(g_ScannerData.ServerPort);
        }
    }
    FltUnregisterFilter(g_ScannerData.Filter);

    return status;

}