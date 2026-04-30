cmake_minimum_required(VERSION 3.16)

project(servidor_seal)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED SEAL_DIR)
    set(SEAL_BUILD_DIR "${CMAKE_SOURCE_DIR}/../seal/SEAL/build")
    if(EXISTS "${SEAL_BUILD_DIR}/cmake/SEALConfig.cmake")
        list(APPEND CMAKE_PREFIX_PATH "${SEAL_BUILD_DIR}")
        message(STATUS "Using local SEAL build from ${SEAL_BUILD_DIR}")
    endif()
endif()

find_package(SEAL 4.1 REQUIRED CONFIG)

add_executable(servidor_seal servidor_seal.cpp)

target_link_libraries(servidor_seal SEAL::seal)