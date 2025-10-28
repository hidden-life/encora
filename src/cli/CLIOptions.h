#ifndef CLI_CLI_OPTIONS_H
#define CLI_CLI_OPTIONS_H

#include <string>

class CLIOptions {
public:
    std::string command;
    std::string argument;

    CLIOptions(int argc, char *argv[]) {
        if (argc > 1) command = argv[1];
        if (argc > 2) argument = argv[2];
    }
};

#endif //CLI_CLI_OPTIONS_H
