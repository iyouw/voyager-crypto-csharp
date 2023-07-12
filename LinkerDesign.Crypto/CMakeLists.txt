cmake_minimum_required(VERSION 3.20)
project(native LANGUAGES C CXX)

add_subdirectory(Native)

set(NATIVE_LIB_DIR "${PROJECT_SOURCE_DIR}/lib")

install(TARGETS kcrypto DESTINATION ${NATIVE_LIB_DIR})