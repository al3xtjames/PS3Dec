# mbedTLS
if (NOT TARGET MbedTLS::Crypto)
    find_package(MbedTLS REQUIRED)
endif()

# OpenMP
find_package(OpenMP REQUIRED)

add_executable(PS3Dec PS3Dec.c)

set_target_properties(PS3Dec PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}"
)

target_link_libraries(PS3Dec PRIVATE
    MbedTLS::Crypto
    OpenMP::OpenMP_C
)
