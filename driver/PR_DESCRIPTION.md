# fix: AsyncEventDispatcher stall bugs, event enrichment, and reference leaks

## Summary

Fixes a critical set of bugs in the async event dispatcher that caused event delivery to silently stop after running for some time, and enriches file events with missing process context (PPID, creator PID, parent image path).

---

## Changes

### 1. AsyncEventDispatcher: `NotificationEvent` → `SynchronizationEvent` (P0)

**Files:** `AsyncEventDispatcher.h`, `AsyncEventDispatcher.cpp`

**Problem:** `m_dataReady` was a `NotificationEvent` (manual-reset). The worker thread called `KeClearEvent(&m_dataReady)` after `KeWaitForMultipleObjects` returned. Between the wait returning and the clear, producers could call `KeSetEvent` — those signals were then wiped by `KeClearEvent`. After the drain loop finished, the worker blocked forever even with data in the ring.

**Fix:** Changed to `SynchronizationEvent` (auto-reset), which atomically resets on wait satisfaction. Removed the manual `KeClearEvent` call entirely.

---

### 2. AsyncEventDispatcher: Don't null port on send timeouts (P0)

**Files:** `AsyncEventDispatcher.cpp`

**Problem:** After `ASYNC_MAX_SEND_TIMEOUTS` (3) consecutive `STATUS_TIMEOUT` returns from `FltSendMessage`, the code set `m_clientPort = nullptr`. This permanently disabled event delivery — the worker's drain loop would break immediately on every cycle, the ring would fill up, and all events would be dropped. If userspace was just temporarily slow, the port was still valid but the driver had already dropped its reference.

**Fix:** On consecutive timeouts, log the condition and reset the counter, but keep the port reference alive. Userspace can recover naturally on the next drain cycle.

---

### 3. AsyncEventDispatcher: Drain ring even without connected client (P1)

**Files:** `AsyncEventDispatcher.cpp`

**Problem:** The worker loop checked for a connected port *before* consuming from the ring. When no port was connected (e.g., client not yet attached, or briefly disconnected), the drain loop broke immediately. Events accumulated in the ring until it was full, after which all `Enqueue` calls dropped events even after the client reconnected.

**Fix:** The drain loop now always consumes from the ring. If no port is connected, the consumed event is counted as dropped (via `m_dropped`) instead of being sent. This prevents backpressure buildup and ensures the ring is always available for new events.

---

### 4. AsyncEventDispatcher: Send timeout resilience in drain loop (P1)

**Files:** `AsyncEventDispatcher.cpp`

**Problem:** Any `SendOne` failure (including `STATUS_TIMEOUT`) caused the drain loop to break entirely, stopping event processing until the next wake-up. Under temporary userspace slowness, this could leave many events unprocessed.

**Fix:** `STATUS_TIMEOUT` from `SendOne` is now handled by dropping the single event and continuing to drain. Only hard errors (e.g., `STATUS_PORT_DISCONNECTED`) break the drain loop.

---

### 5. AsyncEventDispatcher: Safe poison recovery via `strideBytes` (P1)

**Files:** `AsyncEventDispatcher.h`, `AsyncEventDispatcher.cpp`

**Problem:** When a producer slot was detected as "stuck" (claimed for > 500ms), the consumer tried to guess the stride from `hdr->payloadBytes`. If the producer crashed mid-write, `payloadBytes` could contain garbage. A plausible-looking garbage value would cause the consumer to skip the wrong number of bytes, misaligning it permanently. All subsequent events would appear corrupt.

**Fix:** Added `strideBytes` field to `SlotHeader`. The producer now writes the stride at claim-time (before payload copy), so the consumer always has a reliable stride even if the payload was never written. The poison recovery code uses `strideBytes` with bounds checking and falls back to the minimum aligned skip if it looks corrupt.

---

### 6. AsyncEventDispatcher: Aligned advance on unexpected Free slot (P2)

**Files:** `AsyncEventDispatcher.cpp`

**Problem:** When the consumer encountered an unexpected `Free` slot, it advanced by `sizeof(SlotHeader)` (24 bytes). Since `ASYNC_SLOT_ALIGN` is 8 and the header is now 28 bytes (padded to 32), an unaligned advance could misalign the consumer permanently.

**Fix:** Changed to use `AlignUp(sizeof(SlotHeader))` for the advance, ensuring proper alignment is always maintained.

---

### 7. Context: Fix `switch` fall-through in `fileIoStatus` (P0)

**Files:** `Context.cpp`

**Problem:** The `switch` statement for `data->IoStatus.Information` was missing `break` statements. All cases fell through to `default`, so `fileIoStatus` was *always* `FILE_OPENED`. This meant:
- `FILE_CREATED` events were never emitted (the `PostCreateCallback` check `if (fileIoStatus == FILE_CREATED)` always failed)
- Delete event guards based on `fileIoStatus != FILE_CREATED` were incorrect

**Fix:** Added `break` statements to each case.

---

### 8. File events: Enrich with process context from `ProcessCache` (P1)

**Files:** `FileEvent.h`

**Problem:** File events (create/read/write/delete/close/rename) only contained `FIELD_PROCESS_ID` and `FIELD_IMAGE_PATH` from `StreamHandleContext`. No parent process ID, creator process ID, or parent image path was included, making the events incomplete for security analysis.

**Fix:** `SerializeFileEvent` now looks up the acting process in `ProcessCache` and writes:
- `FIELD_PARENT_PROCESS_ID` — the parent PID
- `FIELD_CREATOR_PROCESS_ID` — the creator PID (may differ from parent in cross-process creation)
- `FIELD_PARENT_PROCESS_IMAGE_PATH` — the parent process's image path

References are properly acquired and released.

---

### 9. ProcessCache: Add `ReleaseProcessContext` method (P1)

**Files:** `ProcessNode.h`

**Problem:** `GetProcessContext` incremented the reference count on `ProcessEntry`, but there was no method to decrement it. Every `GetProcessContext` call was a reference leak. `RemoveProcess` freed entries unconditionally without checking the reference count, creating a potential use-after-free.

**Fix:** Added `ReleaseProcessContext()` that decrements `referenceCount` via `InterlockedDecrement`. All call sites in `ProcessEvent.h` and `FileEvent.h` now call `ReleaseProcessContext` when done.

---

### 10. ProcessEvent: Fix reference leaks and wrong field ID (P1)

**Files:** `ProcessEvent.h`

**Problem:**
- Parent and creator `ProcessEntry` references obtained via `GetProcessContext` were never released
- Creator process image path was incorrectly written using `FIELD_PARENT_PROCESS_IMAGE_PATH` instead of `FIELD_CREATOR_PROCESS_IMAGE_PATH`
- Process termination event path leaked the `ProcessEntry` reference on early-return error paths

**Fix:** Added `ReleaseProcessContext` calls on all paths (success and error). Changed creator image path to use the correct field ID `FIELD_CREATOR_PROCESS_IMAGE_PATH`.

---

## Files Changed

| File | Changes |
|------|---------|
| `AsyncEventDispatcher.h` | Added `strideBytes` to `SlotHeader`, updated event type comment |
| `AsyncEventDispatcher.cpp` | 6 fixes: event type, KeClearEvent removal, stride storage, poison recovery, port-null removal, drain-without-port |
| `Context.cpp` | Added `break` statements to `fileIoStatus` switch |
| `FileEvent.h` | Added `ProcessCache` lookup for PPID, creator PID, parent image path |
| `ProcessNode.h` | Added `ReleaseProcessContext()` method |
| `ProcessEvent.h` | Fixed reference leaks, wrong field ID, typo |

## Testing Notes

- The `NotificationEvent` race requires moderate event throughput (100+ events/sec) to reproduce reliably. Under low load it may take hours to manifest.
- The `fileIoStatus` switch bug means all `FILE_CREATE` events were previously suppressed. After this fix, expect to see new create events in the event stream.
- The `SlotHeader` size changed from 24 to 28 bytes (padded to 32 by `ASYNC_SLOT_ALIGN`). This is a wire-format change at the ring buffer level only — it does not affect the FltSendMessage payload format.
