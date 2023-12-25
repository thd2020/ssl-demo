cmake_minimum_required(VERSION 3.0.0)
project(ssl-demo VERSION 0.1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Debug")

include(CTest)
enable_testing()
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)  # 设置可执行文件的输出目录
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
aux_source_directory(./src/ SRCS)
include_directories(./src/
                    /usr/include/)
find_package(OpenSSL REQUIRED)
message(${OPENSSL_CRYPTO_LIBRARY})
message(${OPENSSL_SSL_LIBRARY})
link_libraries(${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
add_executable(ssl-demo ${SRCS})

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
