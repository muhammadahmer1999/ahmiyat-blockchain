cmake_minimum_required(VERSION 3.10)
project(AhmiyatBlockchain)

set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(LevelDB REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR} ${CURL_INCLUDE_DIRS} ${LEVELDB_INCLUDE_DIRS})
file(GLOB SOURCES "src/*.cpp")

add_executable(ahmiyat ${SOURCES})
target_link_libraries(ahmiyat ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES} ${LEVELDB_LIBRARIES} pthread)
