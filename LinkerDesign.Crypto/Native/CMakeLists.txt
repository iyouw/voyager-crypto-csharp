cmake_minimum_required(VERSION 3.20)
project(native LANGUAGES C CXX)

add_library(kcrypto SHARED aes.c md.c stream.c crypto_base.c)

# include directories
set(openssl_include_dir  "C:/Program Files/OpenSSL/include")

set(include_paths ${CMAKE_CURRENT_SOURCE_DIR})
if(MSVC)
  list(APPEND include_paths ${openssl_include_dir})
endif()

target_include_directories(kcrypto PUBLIC ${include_paths})

# link librarys
set(openssl_lib "C:/Program Files/OpenSSL/lib/libcrypto.lib")

set(link_libs)
if(MSVC)
  list(APPEND link_libs ${openssl_lib})
else()
  list(APPEND link_libs "crypto" "m")
endif()

target_link_libraries(kcrypto ${link_libs})