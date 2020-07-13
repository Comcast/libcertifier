#Allow VERSION in project()
cmake_policy(SET CMP0048 NEW)

# This project is semantically versioned.
# For simplicity, the ABI version (soname) is tied to MAJOR.MINOR. When any binary incompatible changes are made,
# MAJOR MUST be incremented.
# Increment MAJOR when introducing API/ABI breaking changes (i.e., not compatible with previous version)
# Increment MINOR when API/ABI is backward compatible but different (e.g., new features added)
# Increment PATCH when API is unchanged (bug/internal fixes)
set(MAJOR 2)
set(MINOR 1)
set(PATCH 1)
set(VERSION ${MAJOR}.${MINOR}.${PATCH})

project("libcertifier" VERSION ${VERSION})
cmake_minimum_required(VERSION 3.11)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

option(ENABLE_SSP "Build with stack smashing protection" ON)
option(ENABLE_ASAN "Build debug executables with AddressSanitizer support" ON)
option(ENABLE_TESTS "Build unit tests (requires cmocka to be enabled or defaults to unity )" OFF)
option(ENABLE_CMOCKA "Enables CMOCKA for unit tests (requires cmocka)" OFF)
option(ENABLE_COVERAGE "Collect code coverage report with unit tests" OFF)
option(ENABLE_MBEDTLS "Build with mBedTLS support instead of OpenSSL" OFF)

option(ENABLE_CMAKE_VERBOSE_MAKEFILE OFF)

if (${ENABLE_CMAKE_VERBOSE_MAKEFILE})
    message(STATUS "Building with ENABLE_CMAKE_VERBOSE_MAKEFILE support")
    set(CMAKE_VERBOSE_MAKEFILE ON)
endif ()

if (${ENABLE_MBEDTLS})
    message(STATUS "ENABLE_MBEDTLS flag was set!")
    find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)

    find_library(MBEDTLS_LIBRARY mbedtls)
    find_library(MBEDX509_LIBRARY mbedx509)
    find_library(MBEDCRYPTO_LIBRARY mbedcrypto)

    set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")

    add_definitions(-DUSE_MBEDTLS)

else ()
    find_package(OpenSSL "1.1.1" REQUIRED)
endif ()

# See cmake-modules(7) for information about the Find<package> modules used here
find_package(ZLIB "1.2.11" REQUIRED)
find_package(CURL "7.60" REQUIRED)

if (${ENABLE_MBEDTLS})
    set(CERTIFIER_LIBS ${ZLIB_LIBRARIES} ${CURL_LIBRARIES} ${MBEDTLS_LIBRARIES})
    set(CERTIFIER_INCLUDE_DIRS ${ZLIB_INCLUDE_DIR} ${MBEDTLS_INCLUDE_DIRS} ${CURL_INCLUDE_DIR})
else ()
    set(CERTIFIER_LIBS ${ZLIB_LIBRARIES} ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} )
    set(CERTIFIER_INCLUDE_DIRS ${ZLIB_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${CURL_INCLUDE_DIR})
    include(CheckLibraryExists)
endif ()
list(REMOVE_DUPLICATES CERTIFIER_INCLUDE_DIRS)
set(CERTIFIER_UTIL_LIBS certifier)

file(GLOB SOURCES "src/*.c")
list(FILTER SOURCES EXCLUDE REGEX "src/main.c|src/test.c")

configure_file(certifier.ver.in certifier.ver @ONLY)
add_library(certifier SHARED ${SOURCES})

set_property(TARGET certifier PROPERTY VERSION ${MAJOR}.${MINOR})

target_include_directories(certifier PUBLIC include PRIVATE internal_headers ${CERTIFIER_INCLUDE_DIRS} ${MBED_TLS_INCLUDE_DIR})
target_link_libraries(certifier ${CERTIFIER_LIBS})

add_executable(certifierUtil "src/main.c")
target_link_libraries(certifierUtil ${CERTIFIER_UTIL_LIBS})

target_include_directories(certifier PUBLIC include PRIVATE internal_headers ${CERTIFIER_INCLUDES})
target_link_libraries(certifier ${CERTIFIER_LIBS})

add_definitions(-D_GNU_SOURCE -DCERTIFIER_VERSION="${VERSION}")

set(DISABLE_WARNINGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall ${DISABLE_WARNINGS} -std=c99")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
#set(CMAKE_EXE_LINKER_FLAGS "-s")  ## Strip binary
#set(CMAKE_SHARED_LINKER_FLAGS "-s")  ## Strip binary

if (${ENABLE_SSP})
    include(CheckCCompilerFlag)
    check_c_compiler_flag("-fstack-protector-strong" HAS_SSP)
    if (${HAS_SSP})
        message(STATUS "Stack smashing protection enabled")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong --param=ssp-buffer-size=4")
    else ()
        message(WARNING "Compiler does not support -fstack-protector-strong")
    endif ()
endif ()

if (${ENABLE_ASAN})
    message(STATUS "AddressSanitizer enabled (debug builds)")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address,undefined")
endif ()

if (NOT GENERATOR_IS_MULTI_CONFIG)
    message(STATUS "buildType: ${CMAKE_BUILD_TYPE}")
endif ()

message(STATUS "extra cflags: ${CMAKE_C_FLAGS}")

if (${ENABLE_TESTS})
    enable_testing()
    message(STATUS "Tests enabled")

    file(GLOB TEST_SOURCES "tests/*.c")
    list(APPEND TEST_SOURCES ${SOURCES})
    list(FILTER TEST_SOURCES EXCLUDE REGEX "src/http.c")

    if (ENABLE_CMOCKA)
        add_definitions(-DCMOCKA_ENABLED)
        find_library(LIB_CMOCKA cmocka)
        find_path(INC_CMOCKA cmocka.h)
    else ()
        list(APPEND TEST_SOURCES "tests/Unity/src/unity.c")
    endif ()

    add_executable(certifierTests ${TEST_SOURCES})

    if (ENABLE_CMOCKA)
        message(STATUS "Building with CMocka support for unit tests")
        target_link_libraries(certifierTests ${LIB_CMOCKA} ${CERTIFIER_LIBS})
        target_include_directories(certifierTests PUBLIC include PRIVATE internal_headers ${INC_CMOCKA})
    else ()
        message(STATUS "Building with Unity support for unit tests")
        target_include_directories(certifierTests PUBLIC include "tests/Unity/include" ${CERTIFIER_INCLUDE_DIRS} PRIVATE internal_headers)
        target_link_libraries(certifierTests ${CERTIFIER_LIBS})
    endif ()

    add_test(NAME certifier-tests COMMAND certifierTests)

    if (${ENABLE_COVERAGE})
        include(CodeCoverage)
        APPEND_COVERAGE_COMPILER_FLAGS()
        SETUP_TARGET_FOR_COVERAGE_LCOV(NAME certifierTests_coverage EXECUTABLE ctest DEPENDENCIES certifierTests)
    endif ()
endif ()

install(TARGETS certifier LIBRARY DESTINATION lib)
install(DIRECTORY include/certifier DESTINATION include)
install(TARGETS certifierUtil RUNTIME DESTINATION bin)

if (ENABLE_TESTS)
    install(TARGETS certifierTests RUNTIME DESTINATION bin)
endif ()
