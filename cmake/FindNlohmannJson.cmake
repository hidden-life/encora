include(FetchContent)
set(NLOHMANN_JSON_VERSION "v3.12.0")
# JSON library
FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/${NLOHMANN_JSON_VERSION}/json.tar.xz
)

FetchContent_MakeAvailable(nlohmann_json)