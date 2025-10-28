#include "ApplicationController.h"

ApplicationController::ApplicationController(QObject *parent) : QObject(parent) {
    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Application initialized and started.");
}

ApplicationController::~ApplicationController() {
    m_vault.lock();
}

bool ApplicationController::tryUnlock(const QString &password) {
    bool isOk = m_vault.unlock(password.toStdString());
    if (isOk) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault unlocked from GUI.");
    } else {
        EncoraLogger::Logger::log(EncoraLogger::Level::Warn, "Failed unlock attempt (GUI).");
    }

    return isOk;
}
