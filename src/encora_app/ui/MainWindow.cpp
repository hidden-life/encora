#include <QMessageBox>

#include "MainWindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    connect(ui->unlockButton, &QPushButton::clicked, this, &MainWindow::onUnlockButtonClicked);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::onUnlockButtonClicked() {
    const QString password = ui->passwordLineEdit->text();

    if (m_controller.tryUnlock(password)) {
        QMessageBox::information(this, "Encora", "Vault unlocked!");
    } else {
        QMessageBox::warning(this, "Encora", "Invalid password!");
    }
}
