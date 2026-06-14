#include "rpc/feeder_event_publisher.h"
#include "common/logger.h"
#include <sstream>
#include <iomanip>

namespace kubearmor::rpc {

    FeederEventPublisher::FeederEventPublisher(
        const std::string& cluster_name,
        const std::string& host_name)
        : cluster_name_(cluster_name)
        , host_name_(host_name) {
    }

    void FeederEventPublisher::Publish(const data::Event& event) {
        // Publish to appropriate streams based on whether it's an alert or log
        if (event.IsAlert()) {
            // Publish as Alert (matched a rule)
            std::shared_lock lock(alert_subscribers_mutex_);

            feeder::Alert alert = ConvertToAlert(event);

            for (auto& [id, subscriber] : alert_subscribers_) {
                if (!subscriber->active) continue;

                if (!ShouldSendToSubscriber(event, subscriber->filter)) continue;

                std::lock_guard<std::mutex> write_lock(subscriber->write_mutex);

                try {
                    if (subscriber->writer->Write(alert)) {
                        subscriber->last_activity = std::chrono::steady_clock::now();
                        alerts_published_++;
                    }
                    else {
                        subscriber->active = false;
                        events_dropped_++;
                    }
                }
                catch (const std::exception& e) {
                    LOG_ERR("Error writing to alert stream: " + std::string(e.what()));
                    subscriber->active = false;
                    events_dropped_++;
                }
            }
        } 
        else {
            std::shared_lock lock(log_subscribers_mutex_);

            feeder::Log log = ConvertToLog(event);

            for (auto& [id, subscriber] : log_subscribers_) {
                if (!subscriber->active) continue;

                if (!ShouldSendToSubscriber(event, subscriber->filter)) continue;

                std::lock_guard<std::mutex> write_lock(subscriber->write_mutex);

                try {
                    if (subscriber->writer->Write(log)) {
                        subscriber->last_activity = std::chrono::steady_clock::now();
                        logs_published_++;
                    }
                    else {
                        subscriber->active = false;
                        events_dropped_++;
                    }
                }
                catch (const std::exception& e) {
                    LOG_ERR("Error writing to log stream: " + std::string(e.what()));
                    subscriber->active = false;
                    events_dropped_++;
                }
            }
        }
    }

    void FeederEventPublisher::PublishBatch(
        const std::vector<data::Event>& events) {
        for (const auto& event : events) {
            Publish(event);
        }
    }

    size_t FeederEventPublisher::GetSubscriberCount() const {
        size_t count = 0;

        {
            std::shared_lock lock(alert_subscribers_mutex_);
            for (const auto& [id, sub] : alert_subscribers_) {
                if (sub->active) count++;
            }
        }

        {
            std::shared_lock lock(log_subscribers_mutex_);
            for (const auto& [id, sub] : log_subscribers_) {
                if (sub->active) count++;
            }
        }

        return count;
    }

    FeederEventPublisher::PublisherStatistics
        FeederEventPublisher::GetStatistics() const {
        return PublisherStatistics{
            alerts_published_.load() + logs_published_.load(),
            events_dropped_.load(),
            GetSubscriberCount(),
            0
        };
    }

    FeederEventPublisher::AlertStreamId FeederEventPublisher::SubscribeAlerts(
        grpc::ServerWriter<feeder::Alert>* writer,
        const StreamFilter& filter) {

        std::unique_lock lock(alert_subscribers_mutex_);

        AlertStreamId id = next_alert_id_++;
        auto subscriber = std::make_unique<AlertSubscriber>();
        subscriber->writer = writer;
        subscriber->filter = filter;
        subscriber->active = true;
        subscriber->last_activity = std::chrono::steady_clock::now();

        alert_subscribers_[id] = std::move(subscriber);
        LOG_INFO("New alert subscriber registered: " + std::to_string(id));

        return id;
    }

    void FeederEventPublisher::UnsubscribeAlerts(AlertStreamId id) {
        std::unique_lock lock(alert_subscribers_mutex_);

        auto it = alert_subscribers_.find(id);
        if (it != alert_subscribers_.end()) {
            it->second->active = false;
            alert_subscribers_.erase(it);
            LOG_INFO("Alert subscriber unregistered: " + std::to_string(id));
        }
    }

    FeederEventPublisher::LogStreamId FeederEventPublisher::SubscribeLogs(
        grpc::ServerWriter<feeder::Log>* writer,
        const StreamFilter& filter) {

        std::unique_lock lock(log_subscribers_mutex_);

        LogStreamId id = next_log_id_++;
        auto subscriber = std::make_unique<LogSubscriber>();
        subscriber->writer = writer;
        subscriber->filter = filter;
        subscriber->active = true;
        subscriber->last_activity = std::chrono::steady_clock::now();

        log_subscribers_[id] = std::move(subscriber);
        LOG_INFO("New log subscriber registered: " + std::to_string(id));

        return id;
    }

    void FeederEventPublisher::UnsubscribeLogs(LogStreamId id) {
        std::unique_lock lock(log_subscribers_mutex_);

        auto it = log_subscribers_.find(id);
        if (it != log_subscribers_.end()) {
            it->second->active = false;
            log_subscribers_.erase(it);
            LOG_INFO("Log subscriber unregistered: " + std::to_string(id));
        }
    }

    feeder::Alert FeederEventPublisher::ConvertToAlert(
        const data::Event& event) {

        feeder::Alert alert;

        // Timestamps
        alert.set_timestamp(ToUnixTimestamp(event.timestamp));
        alert.set_updatedtime(ToFormattedTime(event.timestamp));

        // Cluster/Host info
        alert.set_clustername(cluster_name_);
        alert.set_hostname(host_name_);

        // For Windows, we don't have namespace/pod concepts
        // Using process as the "container"
        alert.set_namespacename("");
        alert.set_podname("");
        alert.set_containerid("");
        alert.set_containername("");
        alert.set_containerimage("");

        if (event.IsFileEvent()) {
            auto fe = event.GetFileData();
            alert.set_operation("File");
            alert.set_hostpid(fe->process_id);
            alert.set_pid(fe->process_id);
            alert.set_processname(fe->process_path);
            alert.set_parentprocessname("");
            alert.set_resource(fe->file_path);
            alert.set_source(fe->process_path);
            
            std::string opStr;
            switch(fe->operation) {
                case data::FileOperation::F_CREATE: opStr = "Create"; break;
                case data::FileOperation::F_READ: opStr = "Read"; break;
                case data::FileOperation::F_WRITE: opStr = "Write"; break;
                case data::FileOperation::F_DELETE: opStr = "Delete"; break;
                case data::FileOperation::F_RENAME: opStr = "Rename"; break;
                case data::FileOperation::F_SETINFO: opStr = "SetInfo"; break;
                case data::FileOperation::F_CLEANUP: opStr = "Cleanup"; break;
                case data::FileOperation::F_CLOSE: opStr = "Close"; break;
                default: opStr = "Unknown";
            }
            alert.set_data("Event=" + opStr);
        }
        else if (event.IsProcessEvent()) {
            auto pe = event.GetProcessData();
            alert.set_operation("Process");
            alert.set_hostpid(pe->process_id);
            alert.set_pid(pe->process_id);
            alert.set_ppid(pe->parent_process_id);
            alert.set_hostppid(pe->parent_process_id);
            alert.set_processname(pe->process_path);
            alert.set_parentprocessname(pe->parent_process_path);
            alert.set_resource(pe->process_path);
            alert.set_source(pe->command_line);

            std::string opStr;
            switch(pe->operation) {
                case data::ProcessOperation::P_CREATE: opStr = "Create"; break;
                case data::ProcessOperation::P_TERMINATE: opStr = "Terminate"; break;
                case data::ProcessOperation::P_OPEN_HANDLE: opStr = "OpenHandle"; break;
                case data::ProcessOperation::P_DUPLICATE_HANDLE: opStr = "DuplicateHandle"; break;
                default: opStr = "Unknown";
            }
            alert.set_data("Event=" + opStr);
        }
        else if (event.IsNetworkEvent()) {
            alert.set_operation("Network");
        }
        alert.set_policyname("");
        alert.set_severity("");
        alert.set_action(event.blocked ? "Block" : "Audit");
        alert.set_result(event.blocked ? "Permission denied" : "Passed");
        alert.set_type("MatchedPolicy");
        alert.set_message("");

        return alert;
    }

    feeder::Log FeederEventPublisher::ConvertToLog(
        const data::Event& event) {

        feeder::Log log;

        // Timestamps
        log.set_timestamp(ToUnixTimestamp(event.timestamp));
        log.set_updatedtime(ToFormattedTime(event.timestamp));

        // Cluster/Host info
        log.set_clustername(cluster_name_);
        log.set_hostname(host_name_);

        // Container info (using process as container)
        log.set_namespacename("");
        log.set_podname("");
        log.set_containerid("");
        log.set_containername("");
        log.set_containerimage("");

        if (event.IsFileEvent()) {
            auto fe = event.GetFileData();
            log.set_operation("File");
            log.set_hostpid(fe->process_id);
            log.set_pid(fe->process_id);
            log.set_processname(fe->process_path);
            log.set_parentprocessname("");
            log.set_resource(fe->file_path);
            log.set_source(fe->process_path);
            
            std::string opStr;
            switch(fe->operation) {
                case data::FileOperation::F_CREATE: opStr = "Create"; break;
                case data::FileOperation::F_READ: opStr = "Read"; break;
                case data::FileOperation::F_WRITE: opStr = "Write"; break;
                case data::FileOperation::F_DELETE: opStr = "Delete"; break;
                case data::FileOperation::F_RENAME: opStr = "Rename"; break;
                case data::FileOperation::F_SETINFO: opStr = "SetInfo"; break;
                case data::FileOperation::F_CLEANUP: opStr = "Cleanup"; break;
                case data::FileOperation::F_CLOSE: opStr = "Close"; break;
                default: opStr = "Unknown";
            }
            log.set_data("Event=" + opStr);
        }
        else if (event.IsProcessEvent()) {
            auto pe = event.GetProcessData();
            log.set_operation("Process");
            log.set_hostpid(pe->process_id);
            log.set_pid(pe->process_id);
            log.set_ppid(pe->parent_process_id);
            log.set_hostppid(pe->parent_process_id);
            log.set_processname(pe->process_path);
            log.set_parentprocessname(pe->parent_process_path);
            log.set_resource(pe->process_path);
            log.set_source(pe->command_line);

            std::string opStr;
            switch(pe->operation) {
                case data::ProcessOperation::P_CREATE: opStr = "Create"; break;
                case data::ProcessOperation::P_TERMINATE: opStr = "Terminate"; break;
                case data::ProcessOperation::P_OPEN_HANDLE: opStr = "OpenHandle"; break;
                case data::ProcessOperation::P_DUPLICATE_HANDLE: opStr = "DuplicateHandle"; break;
                default: opStr = "Unknown";
            }
            log.set_data("Event=" + opStr);
        }
        else if (event.IsNetworkEvent()) {
            log.set_operation("Network");
        }
        log.set_type("HostLog");
        log.set_result(event.blocked ? "Blocked" : "Passed");

        return log;
    }

    bool FeederEventPublisher::ShouldSendToSubscriber(
        const data::Event& event,
        const StreamFilter& filter) {

        return true;
    }

    int64_t FeederEventPublisher::ToUnixTimestamp(
        std::chrono::system_clock::time_point tp) {

        return std::chrono::duration_cast<std::chrono::seconds>(
            tp.time_since_epoch()).count();
    }

    std::string FeederEventPublisher::ToFormattedTime(
        std::chrono::system_clock::time_point tp) {

        auto time = std::chrono::system_clock::to_time_t(tp);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

} // namespace kubearmor::rpc