#include <iostream>

#include "CLIOptions.h"
#include "VaultManager.h"
#include "utils/Logger.h"

int main(int argc, char *argv[]) {
    EncoraLogger::Logger::init();
    CLIOptions opts(argc, argv);

    VaultManager vault;

    if (opts.command == "unlock") {
        bool isOk = vault.unlock(opts.argument);
        if (isOk) {
            std::cout << "Vault unlocked!" << std::endl;
            EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault unlocked via CLI.");
        } else {
            std::cout << "Unlock failed!" << std::endl;
            EncoraLogger::Logger::log(EncoraLogger::Level::Warn, "CLI unlock failed.");
        }
    } else if (opts.command == "status") {
        if (vault.isUnlocked()) {
            std::cout << "Vault unlocked!" << std::endl;
        } else {
            std::cout << "Vault is locked!" << std::endl;
        }
    } else {
        std::cout << "Usage:\n"
                     "  encora_cli unlock <password>\n"
                     "  encora_cli status\n";
    }

    EncoraLogger::Logger::shutdown();

    return 0;
}
