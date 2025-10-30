#ifndef CLI_CLI_OPTIONS_H
#define CLI_CLI_OPTIONS_H

#include <string>

/**
 * CLIOptions
 *
 * Minimal command-line parser for Encora CLI.
 *
 * Supported forms:
 *      encora_cli init <password>
 *      encora_cli unlock <password>
 *
 * After parsing:
 *      command -> "init" or "unlock" (or empty if unknown)
 *      password -> the provided password (or empty)
 */
class CLIOptions {
public:
    std::string command;
    std::string password;

    CLIOptions(int argc, char *argv[]);
};

#endif //CLI_CLI_OPTIONS_H
