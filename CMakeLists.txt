cmake_minimum_required(VERSION 2.8.13)
project(EncryptedBackuper)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "-O3")

file(GLOB SOURCES "src/*.cxx")
file(GLOB CI_TESTS_SOURCES "CI_tests/src/*.cxx")
add_executable(main ${SOURCES} "utils/main.cxx")
add_executable(tests ${SOURCES} ${CI_TESTS_SOURCES})
target_link_libraries(main ${ROOT_LIBRARIES})
target_link_libraries(tests ${ROOT_LIBRARIES})
