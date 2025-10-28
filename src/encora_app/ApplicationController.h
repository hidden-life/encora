#ifndef APPLICATION_APPLICATION_CONTROLLER_H
#define APPLICATION_APPLICATION_CONTROLLER_H

#include <QObject>

#include "VaultManager.h"
#include "core/utils/Logger.h"

class ApplicationController : public QObject {
    Q_OBJECT
public:
    explicit ApplicationController(QObject *parent = nullptr);
    ~ApplicationController();

    bool tryUnlock(const QString &password);

private:
    VaultManager m_vault;
};

#endif //APPLICATION_APPLICATION_CONTROLLER_H
