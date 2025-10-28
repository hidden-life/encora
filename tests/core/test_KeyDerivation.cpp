#include <catch2/catch_all.hpp>

#include "core/secrets/KeyDerivation.h"

TEST_CASE("KeyDerivation returns 32-byte key") {
    auto key = KeyDerivation::derive("password", { 1, 2, 3, 4 });
    REQUIRE(key.size() == 32);
    REQUIRE(key[0] == 'p'); // 'p' from "password"
}