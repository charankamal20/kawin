#include "Filter.h"
#include "ETW.h"
#include "DeviceIOCTL.h"
#include "Globals.h"
#include "Buffer.h"
#include "Protocol.h"
#include "ProcessEvent.h"

Globals g_State;
SCANNER_DATA g_ScannerData;
BOOLEAN g_ProcessNotifyRegistered = FALSE, g_SymLinkCreated = FALSE;

void OnProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID LogProcessEvent(RuleAction action, PPROCESS_EVENT_DATA EventData);
DRIVER_DISPATCH KarmorDeviceControl, KarmorCreateClose;

void KarmorUnload(PDRIVER_OBJECT DriverObject) {
    if (g_ProcessNotifyRegistered)
        PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
    g_State.DestroyRuleHashTable();
    if (g_SymLinkCreated)
    {
        UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Karmor");
        IoDeleteSymbolicLink(&symLink);
    }
    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);
    CleanupETW();

    ProcessCache::GetInstance().Cleanup();
    KdPrint(("karmor driver Unload called\n"));
}

VOID TestRuleApi() {
    UNICODE_STRING testPath;
    RtlInitUnicodeString(&testPath, L"\\??\\C:\\Test\\Binary.exe");

    KdPrint(("Inserting rule...\n"));
    if (g_State.InsertRule(&testPath, RuleAction::Audit)) {
        KdPrint(("Rule inserted successfully\n"));
    }
    else {
        KdPrint(("Failed to insert rule\n"));
    }

    KdPrint(("Looking up rule...\n"));
    PRULE_ENTRY found = g_State.LookupRule(&testPath);
    if (found) {
        KdPrint(("Rule found: Path = %wZ, Action = %s\n",
            &found->Path,
            found->Action == RuleAction::Block ? "Block" : "Audit"));
    }
    else {
        KdPrint(("Rule not found\n"));
    }

    /*KdPrint(("Removing rule...\n"));
    if (g_State.RemoveRule(&testPath)) {
        KdPrint(("Rule removed successfully\n"));
    }
    else {
        KdPrint(("Failed to remove rule\n"));
    }*/

   /* KdPrint(("Destroying Rule Hash Table...\n"));
    g_State.DestroyRuleHashTable();*/
}

#ifdef __cplusplus
extern "C"
#endif
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = KarmorUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = KarmorCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KarmorDeviceControl;

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Karmor");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Karmor");
    UNICODE_STRING fltPort = RTL_CONSTANT_STRING(L"\\ScannerPort");
    PDEVICE_OBJECT DeviceObject = nullptr;
    auto status = STATUS_SUCCESS;

    do {
        status = RegisterFilter(DriverObject);
        if (!NT_SUCCESS(status)) {
            KdPrint(("Failed to register Filter: (0x%x)\n", status));
            return status;
        }

        status = InitializeETW();
        if (!NT_SUCCESS(status)) {
            KdPrint(("Failed to initialize ETW: (0x%x)\n", status));
            CleanupETW();
            return status;
        }

        status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
        if (!NT_SUCCESS(status)) {
            KdPrint(("failed to create device (0x%08X)\n", status));
            break;
        }
        DeviceObject->Flags |= DO_DIRECT_IO;

        status = IoCreateSymbolicLink(&symLink, &devName);
        if (!NT_SUCCESS(status)) {
            KdPrint(("failed to create symbolic link (0x%08X)\n", status));
            break;
        }
        g_SymLinkCreated = TRUE;

        status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
        if (!NT_SUCCESS(status)) {
            KdPrint(("failed to register process callback (0x%08X)\n", status));
            break;
        }
        g_ProcessNotifyRegistered = TRUE;

    } while (false);

    if (!NT_SUCCESS(status)) {
        if (g_ProcessNotifyRegistered)
        {
            PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);
            g_ProcessNotifyRegistered = FALSE;
        }
        if (g_SymLinkCreated)
        {
            IoDeleteSymbolicLink(&symLink);
            g_SymLinkCreated = FALSE;
        }
        if (DeviceObject)
            IoDeleteDevice(DeviceObject);
    }

    status = g_State.Init();
    if (!NT_SUCCESS(status)) {
        KdPrint(("Karmor driver initialized failed\n"));
        return status;
    }

    KdPrint(("Karmor driver initialized successfully\n"));
    //TestRuleApi();

    return STATUS_SUCCESS;
}

/*
================================
    ETW Functions
================================
*/
NTSTATUS InitializeETW()
{
    NTSTATUS status;

    // Register ETW provider
    status = EtwRegister(
        &KarmorProvider,  // From generated header
        NULL,                         // Enable callback (optional)
        NULL,                         // Enable callback context
        &g_EtwRegHandle
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("EventRegister failed: 0x%x\n", status));
        return status;
    }

    KdPrint(("ETW provider registered successfully\n"));
    return STATUS_SUCCESS;
}

VOID CleanupETW()
{
    if (g_EtwRegHandle != 0) {
        EtwUnregister(g_EtwRegHandle);
        g_EtwRegHandle = 0;
    }
}

VOID LogProcessEvent(RuleAction action, PPROCESS_EVENT_DATA EventData)
{
    EVENT_DATA_DESCRIPTOR eventDataDescriptor[6];
    const EVENT_DESCRIPTOR* eventDescriptor;
    NTSTATUS status;

    // Select the appropriate event descriptor from generated header
    eventDescriptor = action == RuleAction::Block ? &ProcessBlocked : &ProcessAudited;

    // Prepare event data descriptors
    EventDataDescCreate(&eventDataDescriptor[0], &EventData->ProcessId, sizeof(ULONG));
    EventDataDescCreate(&eventDataDescriptor[1], &EventData->ParentProcessId, sizeof(ULONG));
    EventDataDescCreate(&eventDataDescriptor[2], EventData->ImagePath.Buffer, EventData->ImagePath.Length);
    EventDataDescCreate(&eventDataDescriptor[3], EventData->CommandLine.Buffer, EventData->CommandLine.Length);
    EventDataDescCreate(&eventDataDescriptor[4], EventData->UserSid.Buffer, EventData->UserSid.Length);
    EventDataDescCreate(&eventDataDescriptor[5], EventData->RuleName.Buffer, EventData->RuleName.Length);

    // Write ETW event with correct parameter order
    status = EtwWrite(
        g_EtwRegHandle,         // [in] REGHANDLE RegHandle
        eventDescriptor,        // [in] PCEVENT_DESCRIPTOR EventDescriptor  
        NULL,                   // [in, optional] LPCGUID ActivityId
        6,                      // [in] ULONG UserDataCount
        eventDataDescriptor     // [in, optional] PEVENT_DATA_DESCRIPTOR UserData
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("EtwWrite failed: 0x%x\n", status));
    }
}

/*
================================
    Device Dispatch Functions
================================
*/

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0) {
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, 0);
    return status;
}

NTSTATUS KarmorCreateClose(PDEVICE_OBJECT, PIRP Irp) {
    return CompleteIrp(Irp);
}

NTSTATUS KarmorDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_ADD_RULE: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(USER_RULE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PUSER_RULE_REQUEST request = (PUSER_RULE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        UNICODE_STRING path;
        RtlInitUnicodeString(&path, request->Path);

        if (g_State.InsertRule(&path, (RuleAction)request->Action))
        {
            status = STATUS_SUCCESS;
            KdPrint(("Looking up rule after insertion...\n"));
            PRULE_ENTRY found = g_State.LookupRule(&path);
            if (found) {
                KdPrint(("Rule found: Path = %wZ, Action = %s\n",
                    &found->Path,
                    found->Action == RuleAction::Block ? "Block" : "Audit"));
            }
            else {
                KdPrint(("Inserted rule not found\n"));
            }
        }
        else
        {
            status = STATUS_UNSUCCESSFUL;
        }
        break;
    }

    case IOCTL_REMOVE_RULE: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(USER_RULE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PUSER_RULE_REQUEST request = (PUSER_RULE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        UNICODE_STRING path;
        RtlInitUnicodeString(&path, request->Path);

        if (g_State.RemoveRule(&path))
        {
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_NOT_FOUND;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return CompleteIrp(Irp, status, info);
}

/*
================================
   Process Notify Routine
================================
*/


void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    Buffer event;

    if (!event.IsValid()) {
        DbgPrint("unable to initialize buffer!!");
        return;
    }

    protocol::EVENT_TYPE eType;

    if (CreateInfo != nullptr) {
        eType = EVENT_TYPE_PROCESS_CREATE;
    }
    else {
        eType = EVENT_TYPE_PROCESS_TERMINATE;
    }

    NTSTATUS status = ProcessEventSerializer::SerializeProcessEvent(event, eType, Process, ProcessId, CreateInfo);
    if (!NT_SUCCESS(status)) {
        return;
    }

    DbgPrint("process event serialized!!");

    // Guard: skip sending if no user-mode client is connected
    if (g_ScannerData.ClientPort == nullptr) {
        DbgPrint("!!! no user-mode client connected, skipping process event send");
        return;
    }

    LARGE_INTEGER timeOut = { 0 };
    timeOut.QuadPart = 0;

    DbgPrint("sending %lu bytes data to user-end", event.GetCurrentSize());

    status = FltSendMessage(g_ScannerData.Filter,
        &g_ScannerData.ClientPort,
        (PVOID)event.GetBuffer(),
        event.GetCurrentSize(),
        NULL,
        NULL,
        &timeOut);

    //DbgPrintHex(event.GetBuffer(), event.GetCurrentSize());
    if (status == STATUS_SUCCESS) {
        DbgPrint("!!! successfully process sent event to user-mode");
    }
    else {
        DbgPrint("!!! couldn't send process event to user-mode, status 0x%X\n", status);

    }
    /*UNREFERENCED_PARAMETER(Process);
    if (CreateInfo) {
        KdPrint(("Process Create (%u)\n", HandleToUlong(ProcessId)));
        //
        // process created
        //
        auto imagePath = CreateInfo->ImageFileName;
        if (!imagePath)
            return;

        PROCESS_EVENT_DATA eventData = { 0 };
        eventData.ProcessId = HandleToULong(ProcessId);
        eventData.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
        eventData.ImagePath = *CreateInfo->ImageFileName;
        if (CreateInfo->CommandLine) {
            eventData.CommandLine = *CreateInfo->CommandLine;
        }
        else {
            RtlInitUnicodeString(&eventData.CommandLine, L"");
        }
        RtlInitUnicodeString(&eventData.UserSid, L"Unknown");

        // Set rule name based on your rule evaluation
        UNICODE_STRING ruleName;
        RtlInitUnicodeString(&ruleName, L"DefaultRule");
        eventData.RuleName = ruleName;

        PRULE_ENTRY matched = g_State.LookupRule((PUNICODE_STRING)CreateInfo->ImageFileName);
        if (matched) {
            if (matched->Action == RuleAction::Block) {
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                LogProcessEvent(RuleAction::Block, &eventData);
                KdPrint(("Blocked execution of %wZ\n", imagePath));
                
            }
            else {
                LogProcessEvent(RuleAction::Audit, &eventData);
                KdPrint(("Audited execution of %wZ\n", imagePath));
            }
        }
        else if (g_State.IsProcessWhitelist()) {
            auto defautlProcessPosture = g_State.GetDefaultProcessPosture();
            if (defautlProcessPosture == RuleAction::Audit) {
                LogProcessEvent(RuleAction::Audit, &eventData);
                KdPrint(("Audited execution of not allowed process %wZ\n", imagePath));
            }
            else if (defautlProcessPosture == RuleAction::Block) {
                KdPrint(("Blocking execution of not allowed process is not supported"));
            }
        }
    }
    else {
        KdPrint(("Process Exit (%u)\n", HandleToUlong(ProcessId)));
    }*/
}

