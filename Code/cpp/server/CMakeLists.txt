cmake_minimum_required(VERSION 3.16)

project(servidor_seal)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SEAL 4.1 REQUIRED)

add_executable(servidor_seal servidor_seal.cpp)

target_link_libraries(servidor_seal SEAL::seal)