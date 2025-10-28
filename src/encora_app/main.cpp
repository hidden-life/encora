#include <QApplication>

#include "ui/MainWindow.h"
#include "core/utils/Logger.h"

/**
 * GUI entry-point
 */
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    EncoraLogger::Logger::init();
    MainWindow w;
    w.show();

    const int rc = app.exec();
    EncoraLogger::Logger::shutdown();

    return rc;
}