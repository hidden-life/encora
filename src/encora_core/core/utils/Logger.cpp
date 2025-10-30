#include <filesystem>
#include  <iostream>

#include "Logger.h"

#include "spdlog/sinks/ostream_sink.h"

namespace fs = std::filesystem;

namespace EncoraLogger {
    void Logger::init(const std::string &logDir) {
        if (m_isInitialized) return;

        try {
            if (!fs::exists(logDir)) {
                fs::create_directories(logDir);
            }

            // 5MB x 5 files
            const auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logDir + "/encora.log", 1024 * 1024 * 5, 5);
            // Colored console sink
            const auto consoleSink = std::make_shared<spdlog::sinks::ostream_sink_mt>(std::cout);
            std::vector<spdlog::sink_ptr> sinks { consoleSink, fileSink };

            m_logger = std::make_shared<spdlog::logger>("Encora", sinks.begin(), sinks.end());
            spdlog::register_logger(m_logger);

            m_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e][%n][%l] %v");
            m_logger->set_level(spdlog::level::debug);
            m_logger->flush_on(spdlog::level::info);

            m_isInitialized = true;
            m_logger->info("Encora logger initialized.");
        } catch (const spdlog::spdlog_ex &e) {
            printf("Logger init failed: %s\n", e.what());
        }
    }

    void Logger::shutdown() {
        if (!m_isInitialized) return;

        if (m_logger) {
            m_logger->info("Encora logger shutting down.");
            spdlog::drop_all();
            m_logger.reset();

            m_isInitialized = false;
        }
    }

    std::shared_ptr<spdlog::logger> &Logger::get() {
        return m_logger;
    }

    void Logger::log(const Level level, const std::string &msg) {
        if (!m_isInitialized || !m_logger) return;

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