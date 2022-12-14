cmake_minimum_required(VERSION 2.8.13)
project(EncryptedBackuper)

find_package (AES PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../AES/ NO_DEFAULT_PATH)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/AES/aes/)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/AES/bin/)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "-Wall -O3")

file(GLOB SOURCES "src/*.cxx")
file(GLOB CI_TESTS_SOURCES "CI_tests/src/*.cxx")
add_executable(main ${SOURCES} "utils/main.cxx")
add_executable(generate_key_file ${SOURCES} "utils/generate_key_file.cxx")
add_executable(tests ${SOURCES} ${CI_TESTS_SOURCES})
target_link_libraries(main ${ROOT_LIBRARIES} libAES.a)
target_link_libraries(tests ${ROOT_LIBRARIES} libAES.a)
target_link_libraries(generate_key_file ${ROOT_LIBRARIES} libAES.a)
