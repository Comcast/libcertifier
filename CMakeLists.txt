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
set(CMAKE_XCODE_GENERATE_SCHEME ON)
set(CMAKE_XCODE_SCHEME_ADDRESS_SANITIZER ON)
set(CMAKE_XCODE_SCHEME_ADDRESS_SANITIZER_USE_AFTER_RETURN ON)

project("libcertifier" VERSION ${VERSION})
cmake_minimum_required(VERSION 3.10)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

option(ENABLE_SSP "Build with stack smashing protection" ON)
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

if ("${ENABLE_PRINTING}" STREQUAL "0")
    message(STATUS "DEFAULT_LOG_LEVEL set to 6")
    add_definitions(-DDEFAULT_LOG_LEVEL=6)
else()
    message(STATUS "DEFAULT_LOG_LEVEL not set, ENABLE_PRINTING==${ENABLE_PRINTING}==")
endif()

# See cmake-modules(7) for information about the Find<package> modules used here
find_package(ZLIB "1.2.11" REQUIRED)
find_package(CURL "7.60" REQUIRED)
if (NOT CURL_LIBRARIES)
    find_library(CURL_LIBRARIES curl)
endif()

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

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(DoxygenDoc)
include(CheckCCompilerFlag)

file(GLOB SOURCES "src/*.c")
list(FILTER SOURCES EXCLUDE REGEX "src/main.c|src/test.c")

configure_file(certifier.ver.in certifier.ver @ONLY)
add_library(certifier SHARED ${SOURCES})
add_library(certifier_ STATIC ${SOURCES})
message(STATUS "SOURCES = ${SOURCES}")

set_property(TARGET certifier PROPERTY VERSION ${MAJOR}.${MINOR})
set_property(TARGET certifier_ PROPERTY VERSION ${MAJOR}.${MINOR})

target_include_directories(certifier PUBLIC include PRIVATE internal_headers ${CERTIFIER_INCLUDE_DIRS} ${MBED_TLS_INCLUDE_DIR})
target_link_libraries(certifier ${CERTIFIER_LIBS})

target_include_directories(certifier_ PUBLIC include PRIVATE internal_headers ${CERTIFIER_INCLUDE_DIRS} ${MBED_TLS_INCLUDE_DIR} ${CERTIFIER_INCLUDES})
target_link_libraries(certifier_ ${CERTIFIER_LIBS})
SET_TARGET_PROPERTIES(certifier_ PROPERTIES
   OUTPUT_NAME certifier CLEAN_DIRECT_OUTPUT 1)

add_executable(certifierUtil "src/error.c" "src/main.c" )
target_link_libraries(certifierUtil ${CERTIFIER_UTIL_LIBS})
target_include_directories(certifierUtil PUBLIC include PRIVATE internal_headers ${CERTIFIER_INCLUDE_DIRS} ${MBED_TLS_INCLUDE_DIR})

target_include_directories(certifier PUBLIC include PRIVATE internal_headers ${CERTIFIER_INCLUDES})
target_link_libraries(certifier ${CERTIFIER_LIBS})

add_definitions(-D_GNU_SOURCE -DCERTIFIER_VERSION="${VERSION}")

set(DISABLE_WARNINGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall ${DISABLE_WARNINGS} -std=c99")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
#set(CMAKE_EXE_LINKER_FLAGS "-s")  ## Strip binary
#set(CMAKE_SHARED_LINKER_FLAGS "-s")  ## Strip binary

if (${ENABLE_SSP})
    check_c_compiler_flag("-fstack-protector-strong" HAS_SSP)
    if (${HAS_SSP})
        message(STATUS "Stack smashing protection enabled")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong --param=ssp-buffer-size=4")
    else ()
        message(WARNING "Compiler does not support -fstack-protector-strong")
    endif ()
endif ()

#add_compile_options(-Wall -Wextra -Werror)

include(CTest)

# Build Types
# - Debug
# - Release
# - asan
# - lsan
# - ubsan
set(build_types_list Release Debug asan lsan msan ubsan)
IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Debug )
ENDIF()

set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
    CACHE STRING "Choose the type of build, options are: Debug Release asan lsan ubsan"
    FORCE)

if(NOT (${CMAKE_BUILD_TYPE} IN_LIST build_types_list))
  message(FATAL_ERROR "Unsupported CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}." )
endif()


if (NOT GENERATOR_IS_MULTI_CONFIG)
    message(STATUS "buildType: ${CMAKE_BUILD_TYPE}")
endif ()

        message(STATUS "C compiler version " ${CMAKE_C_COMPILER_VERSION})

SET(C_COMPILER_ASAN_OPTION "-fsanitize=address")
SET(C_COMPILER_LSAN_OPTION "-fsanitize=leak")
SET(C_COMPILER_MSAN_OPTION "-fsanitize=memory")
SET(C_COMPILER_UBSAN_OPTION "-fsanitize=undefined")
SET(C_COMPILER_ASAN_USE_AFTER_SCOPE_OPTION "-fsanitize-address-use-after-scope")
SET(C_COMPILER_MSAN_TRACK_ORIGINS "-fsanitize-memory-track-origins=2")
check_c_compiler_flag("${C_COMPILER_ASAN_OPTION}" HAS_ASAN)
check_c_compiler_flag("-fsanitize=leak" HAS_LSAN)
check_c_compiler_flag("${C_COMPILER_MSAN_OPTION}" HAS_MSAN)
check_c_compiler_flag("${C_COMPILER_UBSAN_OPTION}" HAS_UBSAN)
check_c_compiler_flag("${C_COMPILER_ASAN_USE_AFTER_SCOPE_OPTION}" HAS_ASAN_USE_AFTER_SCOPE)
check_c_compiler_flag("${C_COMPILER_MSAN_TRACK_ORIGINS}" HAS_MSAN_TRACK_ORIGINS)

if (${HAS_ASAN_USE_AFTER_SCOPE})
else()
    SET(C_COMPILER_ASAN_USE_AFTER_SCOPE_OPTION "")
endif()

if (${C_COMPILER_MSAN_TRACK_ORIGINS})
else()
    SET(C_COMPILER_MSAN_TRACK_ORIGINS "")
endif()
    
# AddressSanitize
# Sanitizer usage: cmake -DCMAKE_BUILD_TYPE=asan
if (${CMAKE_C_COMPILER_VERSION} VERSION_GREATER_EQUAL "4.8.0")
    message(STATUS "Address sanitizer enabled")
    set(CMAKE_C_FLAGS_ASAN
        "${C_COMPILER_ASAN_OPTION} -fno-optimize-sibling-calls ${C_COMPILER_ASAN_USE_AFTER_SCOPE_OPTION} -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
        FORCE)
    set(CMAKE_CXX_FLAGS_ASAN
        "${C_COMPILER_ASAN_OPTION} -fno-optimize-sibling-calls ${C_COMPILER_ASAN_USE_AFTER_SCOPE_OPTION} -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C++ compiler during AddressSanitizer builds."
        FORCE)
endif()

# LeakSanitizer
if (${HAS_LSAN})
    message(STATUS "Leak sanitizer enabled")
    set(CMAKE_C_FLAGS_LSAN
        "${C_COMPILER_LSAN_OPTION} -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C compiler during LeakSanitizer builds."
        FORCE)
    set(CMAKE_CXX_FLAGS_LSAN
        "${C_COMPILER_LSAN_OPTION} -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C++ compiler during LeakSanitizer builds."
        FORCE)
elseif (${CMAKE_BUILD_TYPE} STREQUAL "lsan")
    message(FATAL_ERROR "Compiler does not support Leakage sanitizer ${C_COMPILER_LSAN_OPTION}")
endif ()

# MemorySanitizer
if (${HAS_MSAN})
    message(STATUS "Memory sanitizer enabled")
    set(CMAKE_C_FLAGS_MSAN
        "${C_COMPILER_MSAN_OPTION} -fno-optimize-sibling-calls ${C_COMPILER_MSAN_TRACK_ORIGINS} -fno-omit-frame-pointer -g -O2"
        CACHE STRING "Flags used by the C compiler during MemorySanitizer builds."
        FORCE)
    set(CMAKE_CXX_FLAGS_MSAN
        "${C_COMPILER_MSAN_OPTION} -fno-optimize-sibling-calls ${C_COMPILER_MSAN_TRACK_ORIGINS} -fno-omit-frame-pointer -g -O2"
        CACHE STRING "Flags used by the C++ compiler during MemorySanitizer builds."
        FORCE)
elseif (${CMAKE_BUILD_TYPE} STREQUAL "msan")
    message(FATAL_ERROR "Compiler does not support Memory sanitizer ${C_COMPILER_MSAN_OPTION}")
endif ()

# UndefinedBehaviour
if (${HAS_UBSAN})
    message(STATUS "Undefined behavior sanitizer enabled")
    set(CMAKE_C_FLAGS_UBSAN
        "${C_COMPILER_UBSAN_OPTION}"
        CACHE STRING "Flags used by the C compiler during UndefinedBehaviourSanitizer builds."
        FORCE)
    set(CMAKE_CXX_FLAGS_UBSAN
        "${C_COMPILER_UBSAN_OPTION}"
        CACHE STRING "Flags used by the C++ compiler during UndefinedBehaviourSanitizer builds."
        FORCE)
elseif (${CMAKE_BUILD_TYPE} STREQUAL "ubsan")
    message(FATAL_ERROR "Compiler does not support Undefined behavior sanitizer ${C_COMPILER_UBSAN_OPTION}")
endif ()

# Valgrind usage: ctest -T memcheck
find_program(MEMORYCHECK_COMMAND NAMES valgrind)
if(MEMORYCHECK_COMMAND STREQUAL "MEMORYCHECK_COMMAND-NOTFOUND")
    message(WARNING "Valgrind not found, corresponding checks won't be available.")
endif()
set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full")

message(STATUS "extra cflags: ${CMAKE_C_FLAGS}")

if (${ENABLE_TESTS})
    project(certifierTests)
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

    add_executable(${PROJECT_NAME} ${TEST_SOURCES})

    if (ENABLE_CMOCKA)
        message(STATUS "Building with CMocka support for unit tests")
        target_link_libraries(${PROJECT_NAME} ${LIB_CMOCKA} ${CERTIFIER_LIBS})
        target_include_directories(${PROJECT_NAME} PUBLIC include PRIVATE internal_headers ${INC_CMOCKA})
    else ()
        message(STATUS "Building with Unity support for unit tests")
        target_include_directories(${PROJECT_NAME} PUBLIC include "tests/Unity/include" ${CERTIFIER_INCLUDE_DIRS} PRIVATE internal_headers)
        target_link_libraries(${PROJECT_NAME} ${CERTIFIER_LIBS})
    endif ()

    add_test(NAME certifier-tests COMMAND ${PROJECT_NAME})
    
    add_custom_command(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/libcertifier.cfg.sample ${CMAKE_CURRENT_BINARY_DIR}/libcertifier.cfg
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/libcertifier-cert.crt ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/resources/device-attestation-certificate.p12 ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/resources/seed.p12 ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/test-app-reg.sh ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/test-create-crt.sh ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/test-create-node-address.sh ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/test-create-x509-crt.sh ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/test-device-reg.sh ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/test-fetch-cert-e2e.sh ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT
            "Copy libcertifier.cfg to the build directory."
        VERBATIM
    )
    add_test(NAME test-fetch-cert-e2e 
        COMMAND ./test-fetch-cert-e2e.sh device-attestation-certificate.p12 changeit &&
         ./test-device-reg.sh `cat x509_crt.tmp` X509 && 
         ./test-app-reg.sh lrg
    )
    
    add_test(NAME test-create-x509-crt 
        COMMAND ./test-create-x509-crt.sh device-attestation-certificate.p12 changeit
    )
    
    add_test(NAME test-create-node-address
        COMMAND ./test-create-node-address.sh
    )

    add_test(NAME test-create-crt 
        COMMAND ./test-create-crt.sh 1MGhJ6LAFFWngqaj1dKLPQGsDP1KNVLwhK X509
    )

    if (${ENABLE_COVERAGE})
        include(CodeCoverage)
        APPEND_COVERAGE_COMPILER_FLAGS()
        SETUP_TARGET_FOR_COVERAGE_LCOV(NAME ${PROJECT_NAME}_coverage EXECUTABLE ctest DEPENDENCIES ${PROJECT_NAME})
    endif ()
endif ()

install(TARGETS certifier LIBRARY DESTINATION lib)
install(DIRECTORY include/certifier DESTINATION include)
install(TARGETS certifierUtil RUNTIME DESTINATION bin)

if (ENABLE_TESTS)
    install(TARGETS certifierTests RUNTIME DESTINATION bin)
endif ()

add_doxygen_doc(
  BUILD_DIR
    ${CMAKE_CURRENT_BINARY_DIR}/_build
  DOXY_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxygen/Doxyfile.in
  TARGET_NAME
    docs
  COMMENT
    "HTML documentation"
  )
