cmake_minimum_required(VERSION 3.16)

project(SEAL_SERVER_EXAMPLE)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED SEAL_DIR)
    set(SEAL_BUILD_DIR "${CMAKE_SOURCE_DIR}/SEAL/build")
    if(EXISTS "${SEAL_BUILD_DIR}/cmake/SEALConfig.cmake")
        list(APPEND CMAKE_PREFIX_PATH "${SEAL_BUILD_DIR}")
        message(STATUS "Using local SEAL build from ${SEAL_BUILD_DIR}")
    endif()
endif()

find_package(SEAL 4.1 REQUIRED CONFIG)

# Servidor completo: recibe comando + 2 ciphertexts, calcula media o suma cifrada
add_executable(servidor_seal  ../server/servidor_seal.cpp)

target_link_libraries(servidor_seal  SEAL::seal)

target_include_directories(servidor_seal  PRIVATE ${SEAL_INCLUDE_DIRS})