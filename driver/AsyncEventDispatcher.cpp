extern "C" {
#include <fltKernel.h>
}

#include "AsyncEventDispatcher.h"

AsyncEventDispatcher g_AsyncDispatcher;

_Use_decl_annotations_
NTSTATUS AsyncEventDispatcher::Initialize(PFLT_FILTER filter)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    NT_ASSERT(!m_initialized);
    NT_ASSERT(filter != nullptr);

    m_filter = filter;
    KeInitializeSpinLock(&m_portLock);
    KeInitializeEvent(&m_dataReady, SynchronizationEvent, FALSE);
    KeInitializeEvent(&m_stopEvent, NotificationEvent, FALSE);

    LARGE_INTEGER freqHz = {};
    KeQueryPerformanceCounter(&freqHz);
    m_qpcFreqMs = (freqHz.QuadPart > 0)
        ? static_cast<UINT64>(freqHz.QuadPart) / 1000ULL
        : 1000000ULL;

    m_ring = static_cast<UINT8*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, ASYNC_RING_BYTES, ASYNC_RING_TAG));
    if (!m_ring)
    {
        KdPrint(("[AsyncDisp] ring alloc failed\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    m_sendBuf = static_cast<UINT8*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, ASYNC_SEND_BUFFER_BYTES, ASYNC_SEND_TAG));
    if (!m_sendBuf)
    {
        KdPrint(("[AsyncDisp] send-buf alloc failed\n"));
        ExFreePoolWithTag(m_ring, ASYNC_RING_TAG);
        m_ring = nullptr;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    HANDLE hThread;
    NTSTATUS status = PsCreateSystemThread(
        &hThread, THREAD_ALL_ACCESS,
        nullptr, nullptr, nullptr,
        WorkerEntry, this);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("[AsyncDisp] PsCreateSystemThread: %08X\n", status));
        ExFreePoolWithTag(m_sendBuf, ASYNC_SEND_TAG);
        ExFreePoolWithTag(m_ring, ASYNC_RING_TAG);
        m_sendBuf = nullptr;
        m_ring = nullptr;
        return status;
    }

    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, reinterpret_cast<PVOID*>(&m_thread), nullptr);
    ZwClose(hThread);

    InterlockedExchange(&m_active, 1);
    m_initialized = true;

    KdPrint(("[AsyncDisp] init ok ring=%lu sendBuf=%lu qpcFreqMs=%I64u\n",
        ASYNC_RING_BYTES, ASYNC_SEND_BUFFER_BYTES, m_qpcFreqMs));
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void AsyncEventDispatcher::Uninitialize()
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (!m_initialized) return;

    InterlockedExchange(&m_active, 0);
    KeSetEvent(&m_stopEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&m_dataReady, IO_NO_INCREMENT, FALSE);

    KeWaitForSingleObject(m_thread, Executive, KernelMode, FALSE, nullptr);
    ObDereferenceObject(m_thread);
    m_thread = nullptr;

    ExFreePoolWithTag(m_sendBuf, ASYNC_SEND_TAG);
    ExFreePoolWithTag(m_ring, ASYNC_RING_TAG);
    m_sendBuf = nullptr;
    m_ring = nullptr;
    m_initialized = false;

    KdPrint(("[AsyncDisp] uninit enqueued=%I64d dropped=%I64d poisoned=%I64d\n",
        m_enqueued, m_dropped, m_poisoned));
}

_Use_decl_annotations_
void AsyncEventDispatcher::OnClientConnected(PFLT_PORT clientPort)
{
    KIRQL irql;
    KeAcquireSpinLock(&m_portLock, &irql);
    m_clientPort = clientPort;
    m_sendTimeouts = 0;
    KeReleaseSpinLock(&m_portLock, irql);

    KeSetEvent(&m_dataReady, IO_NO_INCREMENT, FALSE);
    KdPrint(("[AsyncDisp] client connected port=%p\n", clientPort));
}

_Use_decl_annotations_
void AsyncEventDispatcher::OnClientDisconnected()
{
    KIRQL irql;
    KeAcquireSpinLock(&m_portLock, &irql);
    m_clientPort = nullptr;
    m_sendTimeouts = 0;
    KeReleaseSpinLock(&m_portLock, irql);

    KdPrint(("[AsyncDisp] client disconnected\n"));
}

_Use_decl_annotations_
NTSTATUS AsyncEventDispatcher::Enqueue(
    protocol::EVENT_TYPE  eventType,
    StreamHandleContext* pStrHandleCtx,
    InstanceContext* pInstCtx)
{
    if (InterlockedCompareExchange(&m_active, 1, 1) == 0)
        return STATUS_UNSUCCESSFUL;

    Buffer event;
    if (!event.IsValid())
    {
        InterlockedAdd64(&m_dropped, 1);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = FileEventSerializer::SerializeFileEvent(
        event, eventType, pStrHandleCtx, pInstCtx);

    if (!NT_SUCCESS(status))
    {
        InterlockedAdd64(&m_dropped, 1);
        return status;
    }

    return ProduceSlot(
        static_cast<const UINT8*>(event.GetBuffer()),
        event.GetCurrentSize());
}

_Use_decl_annotations_
NTSTATUS AsyncEventDispatcher::ProduceSlot(const UINT8* bytes, UINT32 size)
{
    const UINT32 maxPayload =
        static_cast<UINT32>(ASYNC_RING_BYTES / 4u)
        - static_cast<UINT32>(sizeof(SlotHeader));

    if (size > maxPayload)
    {
        KdPrint(("[AsyncDisp] event too large (%u B)\n", size));
        InterlockedAdd64(&m_dropped, 1);
        // BUG A fix: wake worker even on error so it can drain and free space.
        KeSetEvent(&m_dataReady, IO_NO_INCREMENT, FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    const UINT32 stride = Stride(size);
    LONG claimed = 0;

    for (;;)
    {
        const LONG cur = m_writeHead;

        const UINT32 used =
            (static_cast<UINT32>(cur) - static_cast<UINT32>(m_readHead))
            & RingMask();
        const UINT32 freeBytes = static_cast<UINT32>(ASYNC_RING_BYTES) - used;

        if (stride > freeBytes)
        {
            InterlockedAdd64(&m_dropped, 1);
            // BUG A fix: wake the worker so it drains and frees space.
            KeSetEvent(&m_dataReady, IO_NO_INCREMENT, FALSE);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const UINT32 physOff = static_cast<UINT32>(cur) & RingMask();
        const UINT32 spaceToEnd = static_cast<UINT32>(ASYNC_RING_BYTES) - physOff;

        if (stride > spaceToEnd)
        {
            const LONG wrapped = cur + static_cast<LONG>(spaceToEnd);
            if (InterlockedCompareExchange(&m_writeHead, wrapped, cur) == cur)
            {
                if (spaceToEnd >= static_cast<UINT32>(sizeof(SlotHeader)))
                {
                    SlotHeader* pad = SlotAt(static_cast<UINT32>(cur));
                    InterlockedExchange(&pad->state,
                        static_cast<LONG>(SlotState::Claimed));
                    pad->flags = PAD_FLAG;
                    pad->reserved = 0;
                    pad->payloadBytes = spaceToEnd
                        - static_cast<UINT32>(sizeof(SlotHeader));
                    pad->strideBytes = spaceToEnd;
                    pad->seqNum = 0;
                    pad->claimedTick = 0; // padding slots don't time out
                    KeMemoryBarrier();
                    InterlockedExchange(&pad->state,
                        static_cast<LONG>(SlotState::Committed));
                }
            }
            continue;
        }

        const LONG next = cur + static_cast<LONG>(stride);
        if (InterlockedCompareExchange(&m_writeHead, next, cur) == cur)
        {
            claimed = cur;
            break;
        }
    }

    SlotHeader* hdr = SlotAt(static_cast<UINT32>(claimed));
    InterlockedExchange(&hdr->state, static_cast<LONG>(SlotState::Claimed));

    LARGE_INTEGER now;
    KeQueryPerformanceCounter(&now);
    hdr->claimedTick = static_cast<UINT64>(now.QuadPart);

    hdr->flags = 0;
    hdr->reserved = 0;
    hdr->payloadBytes = size;
    hdr->strideBytes = stride;
    hdr->seqNum = static_cast<UINT32>(InterlockedIncrement(&m_seqCounter));

    if (size > 0)
        RtlCopyMemory(PayloadOf(hdr), bytes, size);

    KeMemoryBarrier();
    InterlockedExchange(&hdr->state, static_cast<LONG>(SlotState::Committed));

    InterlockedAdd64(&m_enqueued, 1);
    KeSetEvent(&m_dataReady, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
UINT32 AsyncEventDispatcher::ConsumeOne()
{
    for (;;)
    {
        const UINT32 pending =
            (static_cast<UINT32>(m_writeHead) - static_cast<UINT32>(m_readHead))
            & RingMask();

        if (pending == 0)
            return 0;

        SlotHeader* hdr = SlotAt(static_cast<UINT32>(m_readHead));

        const LONG state = InterlockedCompareExchange(
            &hdr->state,
            static_cast<LONG>(SlotState::Committed),
            static_cast<LONG>(SlotState::Committed));

        if (state == static_cast<LONG>(SlotState::Committed))
        {
            // Normal path - slot is ready.
            const UINT32 payload = hdr->payloadBytes;
            const UINT32 stride = Stride(payload);

            if (hdr->flags == PAD_FLAG)
            {
                InterlockedExchange(&hdr->state, static_cast<LONG>(SlotState::Free));
                m_readHead += static_cast<LONG>(stride);
                continue;
            }

            NT_ASSERT(payload <= ASYNC_SEND_BUFFER_BYTES);
            if (payload > 0)
                RtlCopyMemory(m_sendBuf, PayloadOf(hdr), payload);

            InterlockedExchange(&hdr->state, static_cast<LONG>(SlotState::Free));
            m_readHead += static_cast<LONG>(stride);
            return payload;
        }

        if (state == static_cast<LONG>(SlotState::Claimed))
        {
            const UINT64 claimedTick = hdr->claimedTick;
            if (claimedTick != 0)
            {
                LARGE_INTEGER now;
                KeQueryPerformanceCounter(&now);
                const UINT64 elapsedMs =
                    TicksToMs(static_cast<UINT64>(now.QuadPart) - claimedTick);

                if (elapsedMs >= ASYNC_CLAIM_TIMEOUT_MS)
                {
                    // Producer is dead or stuck - skip this slot.
                    KdPrint(("[AsyncDisp] poisoned slot at readHead=%ld "
                        "elapsed=%I64u ms\n",
                        m_readHead, elapsedMs));

                    // Use the stride written at claim-time; fall back to
                    // minimum aligned skip if it looks corrupt.
                    const UINT32 storedStride = hdr->strideBytes;
                    const UINT32 poisonStride =
                        (storedStride >= static_cast<UINT32>(sizeof(SlotHeader)) &&
                         storedStride <= static_cast<UINT32>(ASYNC_RING_BYTES / 4u))
                        ? AlignUp(storedStride)
                        : AlignUp(static_cast<UINT32>(sizeof(SlotHeader)));

                    RtlZeroMemory(hdr, min(poisonStride,
                        static_cast<UINT32>(ASYNC_RING_BYTES) -
                        (static_cast<UINT32>(m_readHead) & RingMask())));
                    InterlockedExchange(&hdr->state,
                        static_cast<LONG>(SlotState::Free));
                    m_readHead += static_cast<LONG>(poisonStride);

                    InterlockedAdd64(&m_poisoned, 1);
                    continue;
                }
            }
            return 0;
        }

        // Unexpected Free slot - advance by minimum aligned amount.
        KdPrint(("[AsyncDisp] unexpected Free slot at readHead=%ld\n", m_readHead));
        m_readHead += static_cast<LONG>(AlignUp(static_cast<UINT32>(sizeof(SlotHeader))));
        return 0;
    }
}

_Use_decl_annotations_
NTSTATUS AsyncEventDispatcher::SendOne(UINT32 bytes)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    NT_ASSERT(bytes > 0);

    KIRQL irql;
    KeAcquireSpinLock(&m_portLock, &irql);
    PFLT_PORT port = m_clientPort;
    KeReleaseSpinLock(&m_portLock, irql);

    if (!port)
        return STATUS_PORT_DISCONNECTED;

    LARGE_INTEGER timeout;
    timeout.QuadPart = ASYNC_SEND_TIMEOUT_100NS;

    NTSTATUS status = FltSendMessage(
        m_filter, &port,
        m_sendBuf, bytes,
        nullptr, nullptr,
        &timeout);

    if (NT_SUCCESS(status))
    {

        KIRQL irql2;
        KeAcquireSpinLock(&m_portLock, &irql2);
        m_sendTimeouts = 0;
        KeReleaseSpinLock(&m_portLock, irql2);
        return status;
    }

    if (status == STATUS_TIMEOUT)
    {
        KIRQL irql2;
        KeAcquireSpinLock(&m_portLock, &irql2);
        m_sendTimeouts++;
        if (m_sendTimeouts >= ASYNC_MAX_SEND_TIMEOUTS)
        {
            KdPrint(("[AsyncDisp] %lu consecutive timeouts - userspace may be "
                "slow, dropping event\n", m_sendTimeouts));
            // Don't null the port - userspace may recover.  Just reset
            // the counter so we retry sending future events normally.
            m_sendTimeouts = 0;
        }
        KeReleaseSpinLock(&m_portLock, irql2);
    }

    return status;
}

VOID AsyncEventDispatcher::WorkerEntry(PVOID ctx)
{
    static_cast<AsyncEventDispatcher*>(ctx)->WorkerLoop();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

void AsyncEventDispatcher::WorkerLoop()
{
    KdPrint(("[AsyncDisp] worker started\n"));

    PVOID waitObjects[2] = { &m_stopEvent, &m_dataReady };

    LARGE_INTEGER idleTimeout;
    idleTimeout.QuadPart =
        -static_cast<LONGLONG>(ASYNC_IDLE_TIMEOUT_MS) * 10'000LL;

    bool stopping = false;

    for (;;)
    {
        NTSTATUS ws = KeWaitForMultipleObjects(
            2, waitObjects, WaitAny,
            Executive, KernelMode, FALSE,
            &idleTimeout, nullptr);

        if (ws == STATUS_WAIT_0)
            stopping = true;

        // m_dataReady is a SynchronizationEvent (auto-reset).
        // KeWait atomically clears it - no manual KeClearEvent needed.

        for (;;)
        {
            const UINT32 bytes = ConsumeOne();
            if (bytes == 0)
                break;

            KIRQL irql;
            KeAcquireSpinLock(&m_portLock, &irql);
            const bool hasPort = (m_clientPort != nullptr);
            KeReleaseSpinLock(&m_portLock, irql);

            if (!hasPort)
            {
                // No client connected - drain the slot to prevent the ring
                // from filling up, but count the event as dropped.
                InterlockedAdd64(&m_dropped, 1);
                continue;
            }

            const NTSTATUS s = SendOne(bytes);
            if (NT_SUCCESS(s))
                continue;

            if (s == STATUS_TIMEOUT)
            {
                // Userspace was slow but may recover; drop this one event
                // and keep draining.
                InterlockedAdd64(&m_dropped, 1);
                continue;
            }

            KdPrint(("[AsyncDisp] SendOne %08X - stopping drain cycle\n", s));
            break;
        }

        if (stopping)
            break;
    }

    KdPrint(("[AsyncDisp] worker exiting\n"));
}