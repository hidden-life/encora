#ifndef CORE_UTILS_LOGGER_H
#define CORE_UTILS_LOGGER_H

#include <memory>
#include <string>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

namespace EncoraLogger {
    enum class Level {
        Trace,
        Debug,
        Info,
        Warn,
        Error,
        Critical,
    };

    class Logger final {
    public:
        static void init(const std::string &logDir = "logs");
        static void shutdown();

        static std::shared_ptr<spdlog::logger> &get();
        static void log(Level level, const std::string &msg);

    private:
        static inline std::shared_ptr<spdlog::logger> m_logger;
        static inline bool m_isInitialized;
    };
}

#endif //CORE_UTILS_LOGGER_H
