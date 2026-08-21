set(CMAKE_PREFIX_PATH "/home/user/libOTe") #replace user with your username

cmake_minimum_required(VERSION 3.15)
project(ote_c_integration LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(libOTe REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(emp-tool REQUIRED)
find_package(emp-ot REQUIRED)
find_package(emp-sh2pc REQUIRED)
find_library(SODIUM_LIB sodium HINTS ${CMAKE_PREFIX_PATH}/lib)
find_path(SODIUM_INCLUDE sodium.h HINTS ${CMAKE_PREFIX_PATH}/include)#

add_library(gc_wrapper STATIC gc_wrap.cpp)
target_link_libraries(gc_wrapper PRIVATE emp-tool emp-ot OpenSSL::Crypto)

add_library(ote_wrapper STATIC libote_wrap.cpp)
target_include_directories(ote_wrapper PRIVATE ${SODIUM_INCLUDE})
target_link_libraries(ote_wrapper PRIVATE oc::libOTe ${SODIUM_LIB})

add_library(aux STATIC aux.c)
target_include_directories(aux PRIVATE ${SODIUM_INCLUDE})
target_link_libraries(aux PRIVATE ${SODIUM_LIB})

add_executable(intersect_server1 intersect_server1.c)
target_include_directories(intersect_server1 PRIVATE ${SODIUM_INCLUDE})
target_link_libraries(intersect_server1 PRIVATE gc_wrapper ote_wrapper aux ${SODIUM_LIB})

add_executable(intersect_server2 intersect_server2.c)
target_include_directories(intersect_server2 PRIVATE ${SODIUM_INCLUDE})
target_link_libraries(intersect_server2 PRIVATE gc_wrapper ote_wrapper aux ${SODIUM_LIB})

add_executable(intersect_client intersect_client.c)
target_include_directories(intersect_client PRIVATE ${SODIUM_INCLUDE})
target_link_libraries(intersect_client PRIVATE ote_wrapper aux ${SODIUM_LIB})

target_compile_options(intersect_server1 PRIVATE -g)
target_compile_options(intersect_server2 PRIVATE -g)
target_compile_options(intersect_client PRIVATE -g)
target_compile_options(gc_wrapper PRIVATE -march=native)
