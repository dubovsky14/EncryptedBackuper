cmake_minimum_required(VERSION 2.8.13)
project(EncryptedBackuper)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/AES)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/AES/aes/)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "-Wall -O3")

file(GLOB SOURCES "src/*.cxx")
file(GLOB SOURCES_AES "AES/src/*.cxx")

add_library(EncryptedBackuperLib ${SOURCES} ${SOURCES_AES})

file(GLOB CI_TESTS_SOURCES "CI_tests/src/*.cxx")

add_executable(Encryptor "utils/Encryptor.cxx")
add_executable(Decryptor "utils/Decryptor.cxx")
add_executable(generate_key_file "utils/generate_key_file.cxx")
add_executable(tests ${CI_TESTS_SOURCES} "utils/tests.cxx")

add_dependencies(Encryptor EncryptedBackuperLib )
add_dependencies(Decryptor EncryptedBackuperLib )
add_dependencies(tests EncryptedBackuperLib )
add_dependencies(generate_key_file EncryptedBackuperLib )

target_link_libraries(Encryptor EncryptedBackuperLib)
target_link_libraries(Decryptor EncryptedBackuperLib)
target_link_libraries(tests EncryptedBackuperLib)
target_link_libraries(generate_key_file EncryptedBackuperLib)
