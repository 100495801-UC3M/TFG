cmake_minimum_required(VERSION 3.16)

project(SEAL_SERVER_EXAMPLE)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SEAL 4.1 REQUIRED)

# Servidor completo: recibe comando + 2 ciphertexts, calcula media o suma cifrada
add_executable(servidor_seal  ../server/servidor_seal.cpp)

target_link_libraries(servidor_seal  SEAL::seal)

target_include_directories(servidor_seal  PRIVATE ${SEAL_INCLUDE_DIRS})