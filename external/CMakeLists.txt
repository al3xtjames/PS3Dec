# mbedTLS
set(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs.")
set(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests.")
set(INSTALL_MBEDTLS_HEADERS OFF CACHE BOOL "Install mbed TLS headers.")
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/mbedtls)
target_compile_definitions(mbedcrypto PRIVATE
    MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/mbedtls-config.h"
)
target_include_directories(mbedcrypto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include>
)
add_library(MbedTLS::Crypto ALIAS mbedcrypto)
