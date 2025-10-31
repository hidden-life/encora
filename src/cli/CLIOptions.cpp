#include <sstream>

#include "CLIOptions.h"

#include <iostream>

static std::string join(const std::vector<std::string> &v, size_t start) {
    if (start >= v.size()) {
        return {};
    }

    std::ostringstream oss;
    for (size_t i = start; i < v.size(); ++i) {
        if (i > start) {
            oss << ' ';
        }
        oss << v[i];
    }

    return oss.str();
}

CLIOptions::CLIOptions(int argc, char *argv[]) {
    if (argc > 1) {
        command = argv[1];
        for (int i = 2; i < argc; ++i) {
            args.emplace_back(argv[i]);
        }

        if (command == "add") {
            // minimum: add <password> <name> <type> [<data...> | --data-file <path> | -]
            if (args.size() >= 3) {
                password = args[0];
                name = args[1];
                type = args[2];

                bool isDataFile = false;
                for (size_t i = 3; i < args.size(); ++i) {
                    const std::string &token = args[i];
                    if (token == "-") {
                        m_useStdin = true;
                        // All other is ignored
                        dataFIle.clear();
                        dataInline.clear();
                        break;
                    } else if (token == "--data-file") {
                        if (i + 1 < args.size()) {
                            dataFIle = args[i + 1];
                            isDataFile = true;
                            ++i; // skip
                            dataInline.clear();
                        }
                    }
                }

                if (!m_useStdin && dataFIle.empty()) {
                    dataInline = join(args, 3);
                }
            }
        } else if (command == "list") {
            // list <password>
            if (args.size() >= 1) {
                password = args[0];
            }
        } else if (command == "get" || command == "remove") {
            // get <password> <name>
            // remove <password> <name>
            if (args.size() >= 2) {
                password = args[0];
                name = args[1];
            }
        } else if (command == "init" || command == "unlock") {
            // init <password>
            // unlock <password>
            if (args.size() >= 1) {
                password = args[0];
            }
        } else {
            std::cout << "Usage:\n"
                         "  - encora_cli init <password>\n"
                         "  - encora_cli unlock <password>\n"
                         "  - encora_cli add <password> <name> <type> [<data...> | --data-file <path> | -]\n"
                         "  - encora_cli list <password>\n"
                         "  - encora_cli get <password> <name>\n"
                         "  - encora_cli remove <password> <name>\n";
        }
    }
}
