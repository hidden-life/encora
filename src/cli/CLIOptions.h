#ifndef CLI_CLI_OPTIONS_H
#define CLI_CLI_OPTIONS_H

#include <string>
#include <vector>

/**
 * CLIOptions
 *
 * Unified, minimal, robust parsing for Encora CLI.
 * Keeps backward compatibility via 'args', but also exposes explicit fields for common commands
 * to avoid re-parsing in main.
 *
 * Commands:
 *      init <password>
 *      unlock <password>
 *      add <password> <name> <type> [--data-file <path> | - | <inline data...>]
 *      list <password>
 *      get <password> <name>
 *      remove <password> <name>
 */
class CLIOptions {
public:
    // init, unlock, add, list, get, remove etc.
    std::string command;
    std::vector<std::string> args;

    std::string password;
    std::string name;
    std::string type;

    bool m_useStdin = false;
    std::string dataFIle;
    std::string dataInline;

    CLIOptions(int argc, char *argv[]);
};

#endif //CLI_CLI_OPTIONS_H
