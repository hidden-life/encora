#include <iostream>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#include <filesystem>
#include <fstream>

#include "CLIOptions.h"
#include "VaultManager.h"
#include "storage/EncryptedVaultStorage.h"
#include "utils/Logger.h"

/**
 * Prints CLI usage
 */
static void usage();

/**
 * Reads binary file
 */
static std::vector<unsigned char> readBinary(const std::string &file);

/**
 * Reads binary from stdin
 */
static std::vector<unsigned char> readStdinBinary();

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

    if (opts.command.empty()) {
        usage();
        EncoraLogger::Logger::shutdown();

        return EXIT_SUCCESS;
    }

    int exitCode = 0;

    try {
        VaultManager vault;
        if (opts.command == "init") {
            if (opts.password.empty()) {
                std::cout << "Error: password is required.\n";
                usage();
            } else if (vault.init(opts.password)) {
                std::cout << "Vault created successfully.\n";
            } else {
                std::cout << "Failed to create vault.\n";
                exitCode = EXIT_FAILURE;
            }
        } else if (opts.command == "unlock") {
            if (opts.password.empty()) {
                std::cout << "Error: password is required.\n";
                usage();
            } else if (vault.unlock(opts.password)) {
                std::cout << "Vault unlocked successfully.\n";
            } else {
                std::cout << "Failed to unlock vault (wrong password or corrupted vault).\n";
                exitCode = EXIT_FAILURE;
            }
        } else if (opts.command == "list") {
            if (opts.password.empty()) {
                std::cout << "Error: password is required.\n";
                usage();
            } else if (!vault.unlock(opts.password)) {
                std::cout << "Unlock failed.\n";
                exitCode = EXIT_FAILURE;
            } else {
                EncryptedVaultStorage storage(vault.sessionVMK());
                auto bytes = storage.loadRecord(opts.name);
                // For text notes it's fine to print; for binary, redirect output to file
                const std::string out(bytes.begin(), bytes.end());
                std::cout << out << "\n";
            }
        } else if (opts.command == "add") {
            if (opts.password.empty() || opts.name.empty() || opts.type.empty()) {
                std::cout << "Error: password, name and type are required.\n";
                usage();
            } else if (!vault.unlock(opts.password)) {
                std::cout << "Unlock failed.\n";
                exitCode = EXIT_FAILURE;
            } else {
                std::vector<unsigned char> payload;

                try {
                    if (opts.m_useStdin) {
                        payload = readStdinBinary();
                    } else if (!opts.dataFIle.empty()) {
                        payload = readBinary(opts.dataFIle);
                    } else {
                        payload.assign(opts.dataInline.begin(), opts.dataInline.end());
                    }
                } catch (const std::exception &e) {
                    std::cout << "Read data failed: " << e.what() << "\n";
                    EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("add: ") + e.what());
                    EncoraLogger::Logger::shutdown();

                    return EXIT_FAILURE;
                }

                if (payload.empty()) {
                    std::cout << "No data provided (stdin/file/inline is empty).\n";
                } else {
                    EncryptedVaultStorage storage(vault.sessionVMK());
                    if (storage.addRecord(opts.name, opts.type, payload)) {
                        std::cout << "Added: " << opts.name << "\n";
                    } else {
                        std::cout << "Add failed.\n";
                        exitCode = EXIT_FAILURE;
                    }
                }
            }
        } else if (opts.command == "remove") {
            // Stub: keeping UX + usage consistent; we'll wire once storage exposes remove API.
            if (opts.password.empty() || opts.name.empty()) {
                std::cout << "Error: password and name are required.\n";
                usage();
            } else if (!vault.unlock(opts.password)) {
                std::cout << "Unlock failed.\n";
                exitCode = EXIT_FAILURE;
            } else {
                std::cout << "Remove is not implemented yet.\n";
            }
        } else {
            usage();
        }
    } catch (const std::exception &e) {
        std::cout << "Fatal error: " << e.what() << "\n";
        exitCode = EXIT_FAILURE;
    }

    EncoraLogger::Logger::shutdown();

    return exitCode;
}

static void usage() {
    std::cout << "Usage:\n"
                 "  - encora_cli init <password>\n"
                 "  - encora_cli unlock <password>\n"
                 "  - encora_cli add <password> <name> <type> [--data-file <path> | - | <inline data...>]\n"
                 "  - encora_cli list <password>\n"
                 "  - encora_cli get <password> <name>\n"
                 "  - encora_cli remove <password> <name>\n";
}

static std::vector<unsigned char> readBinary(const std::string &file) {
    std::ifstream ifs(file, std::ios::binary);
    if (!ifs.is_open()) {
        throw std::runtime_error("Failed to open data file: " + file);
    }

    return std::vector<unsigned char>(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
}

static std::vector<unsigned char> readStdinBinary() {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
#endif
    std::istreambuf_iterator<char> begin(std::cin), end;

    return std::vector<unsigned char>(begin, end);
}