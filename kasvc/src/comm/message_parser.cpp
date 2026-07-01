#include "comm/message_parser.h"
#include "common/logger.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

namespace kubearmor::comm {

    common::Result<data::Event> MessageParser::Parse(const KernelMessage* kernel_msg, size_t buffer_size) {
        if (!kernel_msg) {
            return common::Result<data::Event>::Error("Null kernel message");
        }

        data::Event event;
        event.event_id = 1;
        event.timestamp = std::chrono::system_clock::time_point(
            std::chrono::microseconds(kernel_msg->payload.timestamp / 10));
        event.blocked = kernel_msg->payload.blocked;

        LOG_DEBUG("parsing event operation data");

        switch (kernel_msg->payload.event_operation) {
        case KernelEventOperation::FILE_EVENT:
            event.operation_type = data::EventOperationType::FILE_EVENT;
            event.data = ParseFileEvent(kernel_msg, buffer_size);
            break;
        case KernelEventOperation::PROCESS_EVENT:
            event.operation_type = data::EventOperationType::PROCESS_EVENT;
            event.data = ParseProcessEvent(kernel_msg, buffer_size);
            break;
        case KernelEventOperation::NETWORK_EVENT:
            event.operation_type = data::EventOperationType::NETWORK_EVENT;
            event.data = ParseNetworkEvent(kernel_msg, buffer_size);
            break;
        default:
            return common::Result<data::Event>::Error("Unknown event type");
        }

        return common::Result<data::Event>::Success(event);
    }

    data::FileEventData MessageParser::ParseFileEvent(const KernelMessage* km, size_t buffer_size) {
        const auto& file_data = km->payload.data.file;

        data::FileEventData fd;

        fd.operation = static_cast<data::FileOperation>(file_data.operation);
        fd.process_id = file_data.process_id;

        LOG_DEBUG("parsing file event wstring data");

        if (file_data.process_path_length > 0) {
            const wchar_t* process_path = km->get_string_at_offset(
                file_data.process_path_offset,
                buffer_size
            );
            
            if (process_path){
                size_t char_count = file_data.process_path_length / sizeof(wchar_t);
                std::string path_str = WStringToString(process_path, char_count);
                fd.process_path = path_str;
                LOG_DEBUG("Process path: " + path_str);
            }
        }
        LOG_DEBUG("parsed event operation process path data");
        
        if (file_data.file_path_length > 0) {
            
            const wchar_t* file_path = km->get_string_at_offset(
                file_data.file_path_offset,
                buffer_size
            );

            if (file_path) {
                size_t char_count = file_data.file_path_length / sizeof(wchar_t);
                std::string path_str = WStringToString(file_path, char_count);
                fd.file_path = path_str;
                LOG_DEBUG("file path: " + path_str);
            }
        }
        LOG_DEBUG("returned event operation data");
        return fd;
    }

    data::ProcessEventData MessageParser::ParseProcessEvent(const KernelMessage* km, size_t buffer_size) {
        LOG_DEBUG("parsing process event operation data");
        const auto& process_data = km->payload.data.process;

        data::ProcessEventData pd;

        pd.operation = static_cast<data::ProcessOperation>(process_data.operation);
        pd.process_id = process_data.process_id;
        pd.parent_process_id = process_data.parent_process_id;

        if (process_data.process_path_length > 0) {
            const wchar_t* process_path = km->get_string_at_offset(
                process_data.process_path_offset,
                buffer_size
            );
            if (process_path){
                size_t char_count = process_data.process_path_length / sizeof(wchar_t);
                pd.process_path = WStringToString(process_path, char_count);
            }
        }
        
        if (process_data.command_line_length > 0) {
            const wchar_t* cmdline = km->get_string_at_offset(
                process_data.command_line_offset,
                buffer_size
            );
            if (cmdline){
                size_t char_count = process_data.command_line_length / sizeof(wchar_t);
                pd.command_line = WStringToString(cmdline, char_count);
            }
        }
        
        if (process_data.parent_process_path_length > 0) {
            const wchar_t* parent_path = km->get_string_at_offset(
                process_data.parent_process_path_offset,
                buffer_size
            );
            if (parent_path){
                size_t char_count = process_data.parent_process_path_length / sizeof(wchar_t);
                pd.parent_process_path = WStringToString(parent_path, char_count);
            }
        }

        LOG_DEBUG("returned process event operation data");
        return pd;
    }

    data::NetworkEventData MessageParser::ParseNetworkEvent(const KernelMessage* km, size_t buffer_size) {
        LOG_DEBUG("parsing network operation data");
        const auto& network_data = km->payload.data.network;

        data::NetworkEventData nd;
        nd.operation = static_cast<data::NetworkOperation>(network_data.operation);
        nd.protocol = network_data.protocol;
        nd.local_port = ntohs(network_data.local_port);
        nd.remote_port = ntohs(network_data.remote_port);
        nd.local_address = FormatIPAddress(network_data.local_address, network_data.address_family);
        nd.remote_address = FormatIPAddress(network_data.remote_address, network_data.address_family);
        nd.data_length = network_data.data_length;
        LOG_DEBUG("returned network event operation data");
        return nd;
    }

    std::string MessageParser::WStringToString(const wchar_t* wstr, size_t length) {
        if (!wstr || length == 0) {
            return std::string();
        }

        int size_needed = WideCharToMultiByte(
            CP_UTF8,
            0,
            wstr,
            static_cast<int>(length),
            nullptr,
            0,
            nullptr,
            nullptr
        );

        if (size_needed <= 0) {
            return std::string();
        }

        std::string result(size_needed, 0);
        WideCharToMultiByte(
            CP_UTF8,
            0,
            wstr,
            static_cast<int>(length),
            &result[0],
            size_needed,
            nullptr,
            nullptr
        );

        return result;
    }



    std::string MessageParser::FormatIPAddress(const uint8_t* addr, uint8_t family) {
        char buffer[INET6_ADDRSTRLEN] = { 0 };

        if (family == AF_INET) {
            struct in_addr addr4;
            memcpy(&addr4, addr, sizeof(addr4));
            inet_ntop(AF_INET, &addr4, buffer, sizeof(buffer));
        }
        else if (family == AF_INET6) {
            struct in6_addr addr6;
            memcpy(&addr6, addr, sizeof(addr6));
            inet_ntop(AF_INET6, &addr6, buffer, sizeof(buffer));
        }

        return std::string(buffer);
    }

} // namespace kubearmor::comm