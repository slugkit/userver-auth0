cmake_minimum_required(VERSION 3.12...3.31)
project(auth0_validator CXX)

# jwt-cpp is header-only and pulled via FetchContent. Guarded so a parent
# project that already declares jwt-cpp picks up its own copy and we don't
# fetch twice.
include(FetchContent)
if(NOT TARGET jwt-cpp)
    FetchContent_Declare(
        jwt-cpp
        GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
        GIT_TAG v0.7.1
    )
    set(JWT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(JWT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(jwt-cpp)
endif()

set(AUTH0_SRC
    include/userver_auth0/components/jwt_validator.hpp
    src/userver_auth0/components/jwt_validator.cpp
)

add_library(auth0_validator OBJECT ${AUTH0_SRC})
target_link_libraries(auth0_validator
    PUBLIC
        userver::core
        jwt-cpp::jwt-cpp
)
target_include_directories(auth0_validator
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(AUTH0_BUILD_TESTS)
    add_executable(auth0_unittest
        tests/jwt_validator_test.cpp
    )
    target_link_libraries(auth0_unittest
        PRIVATE
            auth0_validator
            userver::utest
            jwt-cpp::jwt-cpp
    )
    target_include_directories(auth0_unittest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    add_google_tests(auth0_unittest)
endif()
