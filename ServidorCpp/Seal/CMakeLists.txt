cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_COMPILER gcc-9)
set(CMAKE_CXX_COMPILER g++-9)

project(SEAL_SERVER_EXAMPLE)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SEAL 3.6 REQUIRED)

add_executable(server main.cpp)

target_link_libraries(server SEAL::seal)