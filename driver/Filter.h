#pragma once
#include "pch.h"
#include "Context.h"

#ifndef __FILTER_H__
#define __FILTER_H__

EXTERN_C_START

// ==========================
// ==== Filter Callbacks ====
// ==========================

// create
FLT_PREOP_CALLBACK_STATUS FLTAPI PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS PostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// write
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext);

FLT_POSTOP_CALLBACK_STATUS PostWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// read
FLT_PREOP_CALLBACK_STATUS PreReadCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext);

FLT_POSTOP_CALLBACK_STATUS PostReadCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// set information
FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext);

FLT_POSTOP_CALLBACK_STATUS PostSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// cleanup
FLT_PREOP_CALLBACK_STATUS PreCleanupCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* completionContext);

FLT_POSTOP_CALLBACK_STATUS PostCleanupCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags);

// ==== // Filter Callbacks

NTSTATUS FLTAPI InstanceFilterUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS FLTAPI InstanceSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType
);

NTSTATUS FLTAPI InstanceQueryTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

VOID InstanceStartTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS);

VOID InstanceCompleteTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS pFltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS);

VOID InstanceContextCleanup(
    _In_ PFLT_CONTEXT pContext, 
    _In_ FLT_CONTEXT_TYPE);

VOID StreamHandleContextCleanup(
    _In_ PFLT_CONTEXT pContext,
    _In_ FLT_CONTEXT_TYPE contextType);

NTSTATUS
ScannerPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie
);

VOID
ScannerPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS RegisterFilter(
    _In_ PDRIVER_OBJECT DriverObject
);

EXTERN_C_END

#ifdef ALLOC_PRAGMA
    #pragma alloc_text (PAGE, InstanceFilterUnloadCallback)
    #pragma alloc_text (PAGE, InstanceSetupCallback)
    #pragma alloc_text (PAGE, InstanceQueryTeardownCallback)
#endif

CONST FLT_OPERATION_REGISTRATION g_callbacks[] =
{
    {
        IRP_MJ_CREATE,
        0,
        PreCreateCallback,
        PostCreateCallback
    },
    {
        IRP_MJ_WRITE,
        0,
        PreWriteCallback,
        PostWriteCallback
    },
    { 
        IRP_MJ_SET_INFORMATION, 
        FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, 
        PreSetInformationCallback, 
        PostSetInformationCallback 
    },
    {
        IRP_MJ_CLEANUP,
        0,
        PreCleanupCallback,
        PostCleanupCallback
    },

    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION g_ContextCallbacks[] = {

    { FLT_INSTANCE_CONTEXT, 0, InstanceContextCleanup,
    sizeof(InstanceContext), c_CtxAllocTag },

    { FLT_STREAMHANDLE_CONTEXT, 0, StreamHandleContextCleanup,
    sizeof(StreamHandleContext), c_CtxAllocTag },

    { FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION g_filterRegistration =
{
    sizeof(FLT_REGISTRATION),      //  Size
    FLT_REGISTRATION_VERSION,      //  Version
    0,                             //  Flags
    g_ContextCallbacks,            //  Context registration
    g_callbacks,                   //  Operation callbacks
    InstanceFilterUnloadCallback,  //  FilterUnload
    InstanceSetupCallback,         //  InstanceSetup
    InstanceQueryTeardownCallback, //  InstanceQueryTeardown
    InstanceStartTeardownCallback,         //  InstanceTeardownStart
    InstanceCompleteTeardownCallback,      //  InstanceTeardownComplete
    NULL,                          //  GenerateFileName
    NULL,                          //  GenerateDestinationFileName
    NULL                           //  NormalizeNameComponent
};

typedef struct _SCANNER_DATA {

    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PEPROCESS UserProcess;
    PFLT_PORT ClientPort;

} SCANNER_DATA, * PSCANNER_DATA;

extern SCANNER_DATA g_ScannerData;

#define MAX_FILTER_EVENT_SIZE (64 * 1024)

#pragma pack(push, 1)
typedef enum _FS_EVENT_TYPE
{
    EventType_HostLog = 1,
    EventType_MatchHostPolicy = 2,
} FS_EVENT_TYPE;

typedef enum _FS_EVENT_OPERATION {
    EventOperation_Invalid = 0,
    EventOperation_Process = 1,
    EventOperation_File = 2,
    EventOperation_Network = 3
} FS_EVENT_OPERATION;


typedef struct _FILE_EVENT {
    ULONG Operation;
    ULONG ProcessId;
    ULONG ProcessPathOffset;
    ULONG ProcessPathLength;
    ULONG FilePathOffset;
    ULONG FilePathLength;
} FILE_EVENT, * PFILE_EVENT;

typedef struct _PROCESS_EVENT {
    ULONG operation;
    ULONG process_id;
    ULONG parent_process_id;
    ULONG process_path_offset;
    ULONG process_path_length;
    ULONG command_line_offset;
    ULONG command_line_length;
    ULONG parent_process_path_offset;
    ULONG parent_process_path_length;
} PROCESS_EVENT, * PPROCESS_EVENT;

typedef struct _NETWORK_EVENT {
    ULONG operation;
    ULONG protocol;
    USHORT local_port;
    USHORT remote_port;
    UCHAR local_address[16];
    UCHAR remote_address[16];
    ULONG data_length;
    UCHAR address_family;
} NETWORK_EVENT, * PNETWORK_EVENT;

typedef struct _EVENT {
    ULONGLONG timestamp;
    FS_EVENT_TYPE type;
    FS_EVENT_OPERATION operation;
    BOOLEAN blocked;
    FILE_EVENT data;
    /*union {
        FILE_EVENT File;
        PROCESS_EVENT Process;
        NETWORK_EVENT Network;
    } data;*/
} EVENT, * PEVENT;

typedef struct _REPLY {
    BOOLEAN ack;
} EVENT_REPLY, * PEVENT_REPLY;

#pragma pack(pop)
#endif // !__FILTER_H__
