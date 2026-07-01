#pragma once

#include <Windows.h>
#include <cstdint>
#include <fltUser.h>

namespace kubearmor::comm {

    enum class KernelEventType : uint32_t {
        HOST_LOG = 1,
        MATCH_HOST_POLICY = 2
    };

    enum class KernelEventOperation : uint32_t {
        PROCESS_EVENT = 1,
        FILE_EVENT = 2,
        NETWORK_EVENT = 3
    };

#pragma pack(push, 1)

    struct KernelFileEvent {
        uint32_t operation;
        uint32_t process_id;
        uint32_t process_path_offset;
        uint32_t process_path_length;
        uint32_t file_path_offset;
        uint32_t file_path_length;
    };

    struct KernelProcessEvent {
        uint32_t operation;
        uint32_t process_id;
        uint32_t parent_process_id;
        uint32_t process_path_offset;
        uint32_t process_path_length;
        uint32_t command_line_offset;
        uint32_t command_line_length;
        uint32_t parent_process_path_offset;
        uint32_t parent_process_path_length;
    };

    struct KernelNetworkEvent {
        uint32_t operation;
        uint32_t protocol;
        uint16_t local_port;
        uint16_t remote_port;
        uint8_t local_address[16];
        uint8_t remote_address[16];
        uint32_t data_length;
        uint8_t address_family;
    };

    struct KernelEventPayload {
        uint64_t timestamp;
        KernelEventType event_type;
        KernelEventOperation event_operation;
        uint8_t blocked;
        union {
            KernelFileEvent file;
            KernelProcessEvent process;
            KernelNetworkEvent network;
        } data;
    };

#pragma pack(pop)

    struct KernelMessage {
        FILTER_MESSAGE_HEADER header;
        KernelEventPayload payload;

        const wchar_t* get_string_at_offset(size_t offset, size_t buffer_size) const {
            const uint8_t* buffer_start = reinterpret_cast<const uint8_t*>(this);
            // Payload follows header, but the offset is calculated from the start of the EVENT struct (payload).
            const uint8_t* payload_start = reinterpret_cast<const uint8_t*>(&this->payload);
            const uint8_t* target = payload_start + offset;

            if (target >= buffer_start + buffer_size) {
                return nullptr;
            }

            return reinterpret_cast<const wchar_t*>(target);
        }
    };

    // compile-time size checks 
    // we need this to match the user and kernel structs for compatibility
    static_assert(sizeof(KernelFileEvent) == 24,
        "KernelFileEvent size mismatch!");
    static_assert(sizeof(uint32_t) == sizeof(ULONG),
        "uint32_t != ULONG size!");
    static_assert(sizeof(uint64_t) == sizeof(ULONGLONG),
        "uint64_t != ULONGLONG size!");

} // namespace kubearmor::comm