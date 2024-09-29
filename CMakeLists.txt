cmake_minimum_required (VERSION 3.3.0)
cmake_policy(VERSION 3.2.2)
cmake_policy(SET CMP0054 NEW)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR})
INCLUDE_DIRECTORIES(/home/ching/openssl/include)
LINK_DIRECTORIES(/home/ching/openssl/lib64)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
SET(SRC_LIST 
	
	sm2sign.cpp
	38540.cpp
	hare_crypto_export.cpp
)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
add_compile_options(-fvisibility=hidden)
ADD_LIBRARY(harecrypto SHARED ${SRC_LIST})

TARGET_LINK_LIBRARIES(harecrypto libssl.a)
TARGET_LINK_LIBRARIES(harecrypto libcrypto.a)
set(CMAKE_C_FLAGS"${CMAKE_C_FLAGS} -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
set_target_properties(harecrypto PROPERTIES C_VISIBILITY_PRESET hidden)
SET_TARGET_PROPERTIES(harecrypto PROPERTIES OUTPUT_NAME "harecrypto")
