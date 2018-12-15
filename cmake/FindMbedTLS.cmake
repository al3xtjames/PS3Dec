# Portions taken from Dolphin (thanks lioncash!):
# https://github.com/dolphin-emu/dolphin/pull/6664
#
# This module defines the following IMPORTED targets:
# MbedTLS::Crypto
# MbedTLS::X509
# MbedTLS::MbedTLS
#
# This module will set the following variables:
# MBEDTLS_FOUND
# MBEDTLS_INCLUDE_DIRS
# MBEDTLS_LIBRARY
# MBEDX509_LIBRARY
# MBEDCRYPTO_LIBRARY
# MBEDTLS_LIBRARIES
# MBEDTLS_VERSION

find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h)

find_library(MBEDTLS_LIBRARY mbedtls)
find_library(MBEDX509_LIBRARY mbedx509)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto)

if (MBEDTLS_INCLUDE_DIR AND EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")
    # Taken from https://github.com/ARMmbed/mbedtls/issues/298
    file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" VERSION_STRING_LINE REGEX "^#define MBEDTLS_VERSION_STRING[ \\t\\n\\r]+\"[^\"]*\"$")
    file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" VERSION_MAJOR_LINE REGEX "^#define MBEDTLS_VERSION_MAJOR[ \\t\\n\\r]+[0-9]+$")
    file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" VERSION_MINOR_LINE REGEX "^#define MBEDTLS_VERSION_MINOR[ \\t\\n\\r]+[0-9]+$")
    file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" VERSION_PATCH_LINE REGEX "^#define MBEDTLS_VERSION_PATCH[ \\t\\n\\r]+[0-9]+$")

    string(REGEX REPLACE "^#define MBEDTLS_VERSION_STRING[ \\t\\n\\r]+\"([^\"]*)\"$" "\\1" MBEDTLS_VERSION "${VERSION_STRING_LINE}")
    string(REGEX REPLACE "^#define MBEDTLS_VERSION_MAJOR[ \\t\\n\\r]+([0-9]+)$" "\\1" MBEDTLS_VERSION_MAJOR "${VERSION_MAJOR_LINE}")
    string(REGEX REPLACE "^#define MBEDTLS_VERSION_MINOR[ \\t\\n\\r]+([0-9]+)$" "\\1" MBEDTLS_VERSION_MINOR "${VERSION_MINOR_LINE}")
    string(REGEX REPLACE "^#define MBEDTLS_VERSION_PATCH[ \\t\\n\\r]+([0-9]+)$" "\\1" MBEDTLS_VERSION_PATCH "${VERSION_PATCH_LINE}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
    REQUIRED_VARS
        MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY
    VERSION_VAR
        MBEDTLS_VERSION
)

if (MbedTLS_FOUND)
    set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
    set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})

    if (NOT TARGET MbedTLS::Crypto)
        add_library(MbedTLS::Crypto UNKNOWN IMPORTED)
        set_target_properties(MbedTLS::Crypto PROPERTIES
            IMPORTED_LOCATION ${MBEDCRYPTO_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${MBEDTLS_INCLUDE_DIRS}
        )
    endif()

    if (NOT TARGET MbedTLS::X509)
        add_library(MbedTLS::X509 UNKNOWN IMPORTED)
        set_target_properties(MbedTLS::X509 PROPERTIES
            IMPORTED_LOCATION ${MBEDX509_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${MBEDTLS_INCLUDE_DIRS}
            INTERFACE_LINK_LIBRARIES MbedTLS::Crypto
        )
    endif()

    if (NOT TARGET MbedTLS::MbedTLS)
        add_library(MbedTLS::MbedTLS UNKNOWN IMPORTED)
        set_target_properties(MbedTLS::MbedTLS PROPERTIES
            IMPORTED_LOCATION ${MBEDTLS_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${MBEDTLS_INCLUDE_DIRS}
            INTERFACE_LINK_LIBRARIES MbedTLS::X509
        )
  endif()
endif()

mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
