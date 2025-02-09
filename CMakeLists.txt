cmake_minimum_required(VERSION 3.0)
project(EncryptedBackuper)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/AES)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/AES/aes/)

set(CMAKE_CXX_STANDARD 17 REQUIRED)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "-Wall -O3")

file(GLOB SOURCES "src/*.cxx")
file(GLOB SOURCES_AES "AES/src/*.cxx")

add_library(EncryptedBackuperLib ${SOURCES} ${SOURCES_AES})

file(GLOB CI_TESTS_SOURCES "CI_tests/src/*.cxx")


# Find all .cxx files in the utils folder
file(GLOB UTILS_SOURCES "utils/*.cxx")


# Iterate over each .cxx file
foreach(SOURCE_FILE ${UTILS_SOURCES})
    # skip the tests file
    if(${SOURCE_FILE} MATCHES "utils/tests.cxx")
        continue()
    endif()

    # Get the filename without the extension
    get_filename_component(EXECUTABLE_NAME ${SOURCE_FILE} NAME_WE)

    # Add executable
    add_executable(${EXECUTABLE_NAME} ${SOURCE_FILE})

    # Add dependencies
    add_dependencies(${EXECUTABLE_NAME}  EncryptedBackuperLib)

    # Link libraries
    target_link_libraries(${EXECUTABLE_NAME}  EncryptedBackuperLib)
endforeach()

add_executable(tests ${CI_TESTS_SOURCES} "utils/tests.cxx")

add_dependencies(tests EncryptedBackuperLib )

target_link_libraries(tests EncryptedBackuperLib)
