#include "CLIOptions.h"

CLIOptions::CLIOptions(int argc, char *argv[]) {
    if (argc > 1) command = argv[1];
    if (argc > 2) password = argv[2];
}
