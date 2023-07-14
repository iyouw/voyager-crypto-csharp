add_library(kcrypto SHARED crypto_base.c aes_context.c md_context.c aes.c md.c)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  set_target_properties(kcrypto PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
endif()

# include directories
set(OPENSSL_WIN "C:/Program Files/OpenSSL")
set(OPENSSL_INCLUDE_DIR_WIN  "${OPENSSL_WIN}/include")
set(OPENSSL_LIB_WIN "${OPENSSL_WIN}/lib/libcrypto.lib")

set(INCLUDE_PATHS ${CMAKE_CURRENT_SOURCE_DIR})

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  list(APPEND INCLUDE_PATHS ${OPENSSL_INCLUDE_DIR_WIN})
endif()

target_include_directories(kcrypto PUBLIC ${INCLUDE_PATHS})

# link librarys
if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  list(APPEND LINK_LIBS ${OPENSSL_LIB_WIN})
else()
  list(APPEND LINK_LIBS "crypto" "m")
endif()

target_link_libraries(kcrypto ${LINK_LIBS})