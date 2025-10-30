#include <iostream>

#include "CLIOptions.h"
#include "VaultManager.h"
#include "utils/Logger.h"

/**
 * Entry point for Encora CLI
 *
 * Commands:
 *      encora_cli init <password>
 *          - initializes a brand new vault (generates salt, VMK, etc.)
 *
 *      encora_cli unlock <password>
 *          - attempts to unlock existing vault using the given password
 *
 * Note:
 *      The vault metadata us currently stored at "data/vault.meta"
 *      (this path is defined in VaultManager::metaPath()).
 */
int main(int argc, char *argv[]) {
    EncoraLogger::Logger::init();
    CLIOptions opts(argc, argv);

    {
        VaultManager vault;
        if (opts.command == "init") {
            if (opts.password.empty()) {
                std::cout << "Error: password is required" << std::endl;
            } else if (vault.init(opts.password)) {
                std::cout << "Vault created successfully." << std::endl;
            } else {
                std::cout << "Failed to create vault." << std::endl;
            }
        } else if (opts.command == "unlock") {
            if (opts.password.empty()) {
                std::cout << "Error: password is required" << std::endl;
            } else if (vault.unlock(opts.password)) {
                std::cout << "Vault unlocked successfully." << std::endl;
            } else {
                std::cout << "Failed to unlock vault (wrong password or corrupted vault)." << std::endl;
            }
        } else {
            std::cout << "Usage:\n"
                         "  - encora_cli init <password>\n"
                         "  - encora_cli unlock <password>\n";
        }
    }

    EncoraLogger::Logger::shutdown();

    return 0;
}
