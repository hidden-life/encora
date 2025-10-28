#include <filesystem>

#include "Logger.h"

namespace fs = std::filesystem;

namespace EncoraLogger {
    std::shared_ptr<spdlog::logger> Logger::m_logger = nullptr;
    bool Logger::m_isInitialized = false;

    void Logger::init(const std::string &logDir) {
        if (m_isInitialized) return;

        try {
            if (!fs::exists(logDir)) {
                fs::create_directory(logDir);
            }

            // 5MB x 5 files
            auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logDir + "/encora.log", 1024 * 1024 * 5, 5);
            // Colored console sink
            auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            std::vector<spdlog::sink_ptr> sinks { consoleSink, fileSink };

            m_logger = std::make_shared<spdlog::logger>("Encora", sinks.begin(), sinks.end());
            spdlog::register_logger(m_logger);

            m_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e][%l][%n] %v");
            m_logger->set_level(spdlog::level::debug);

            m_isInitialized = true;
            m_logger->info("Encora logger initialized.");
        } catch (const spdlog::spdlog_ex &e) {
            printf("Logger init failed: %s\n", e.what());
        }
    }

    void Logger::shutdown() {
        if (m_logger) {
            m_logger->info("Encora logger shutting down.");
            spdlog::drop_all();
            m_logger.reset();

            m_isInitialized = false;
        }
    }

    std::shared_ptr<spdlog::logger> &Logger::get() {
        if (!m_isInitialized) init();

        return m_logger;
    }

    void Logger::log(const Level level, const std::string &msg) {
        if (!m_isInitialized) init();

        switch (level) {
            case Level::Trace: m_logger->trace(msg); break;
            case Level::Debug: m_logger->debug(msg); break;
            case Level::Info: m_logger->info(msg); break;
            case Level::Warn: m_logger->warn(msg); break;
            case Level::Error: m_logger->error(msg); break;
            case Level::Critical: m_logger->critical(msg); break;
        }
    }


}