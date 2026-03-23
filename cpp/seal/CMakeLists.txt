cmake_minimum_required(VERSION 3.16)

project(SEAL_SERVER_EXAMPLE)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SEAL 4.1 REQUIRED)

add_executable(server      main.cpp)
add_executable(test        test.cpp)
add_executable(test_server ../server/test_servidor.cpp)

target_link_libraries(server      SEAL::seal)
target_link_libraries(test        SEAL::seal)
target_link_libraries(test_server SEAL::seal)

target_include_directories(test        PRIVATE ${SEAL_INCLUDE_DIRS})
target_include_directories(test_server PRIVATE ${SEAL_INCLUDE_DIRS})