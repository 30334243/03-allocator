cmake_minimum_required(VERSION 3.22)

set(PROJECT_VERSION_PATCH $ENV{GITHUB_RUN_NUMBER})

if (NOT DEFINED PROJECT_VERSION_PATCH OR PROJECT_VERSION_PATCH STREQUAL "")
    set(PROJECT_VERSION_PATCH 1)
endif ()
set(PATCH_VERSION "${PROJECT_VERSION_PATCH}" CACHE INTERNAL "Patch version")
set(PROJECT_VERSION 0.0.${PATCH_VERSION})

project(ip_filter VERSION ${PROJECT_VERSION})

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost CONFIG REQUIRED system filesystem program_options)
find_package(GTest CONFIG REQUIRED)

message(STATUS "************************************")
if (Boost_FOUND)
    message(STATUS "===> Boost version=${Boost_VERSION}")
else ()
    message(FATAL_ERROR "Boost not found")
endif ()
if (GTest_FOUND)
    message(STATUS "===> GTest version=${GTest_VERSION}")
else ()
    message(FATAL_ERROR "GTest not found")
endif ()
message(STATUS "************************************")

configure_file(version.h.in version.h)

if (WINDOWS_SPECIFIC_FLAG)
    add_definitions(-DWINDOWS_SPECIFIC_FLAG=${WINDOWS_SPECIFIC_FLAG})
    add_compile_options(-D_WIN32_WINNT=0x0601)
elseif (WSL_SPECIFIC_FLAG)
    add_definitions(-DWSL_SPECIFIC_FLAG=${WSL_SPECIFIC_FLAG})
else ()
    message(FATAL_ERROR "Error. Stopping. Unknown Platform")
endif ()

add_subdirectory(lib)
add_subdirectory(app)

target_include_directories(${PROJECT_NAME}_lib PUBLIC ${CMAKE_BINARY_DIR})

enable_testing()
add_subdirectory(tests)

if (WINDOWS_SPECIFIC_FLAG)
    target_compile_options(${PROJECT_NAME}_app PRIVATE
            /W4
    )
    target_compile_options(${PROJECT_NAME}_lib PRIVATE
            /W4
    )
    target_compile_options(${PROJECT_NAME}_test PRIVATE
            /W4
    )
elseif (WSL_SPECIFIC_FLAG)
    target_compile_options(${PROJECT_NAME}_app PRIVATE
            -Wall -Wextra -pedantic -Werror
    )
    target_compile_options(${PROJECT_NAME}_lib PRIVATE
            -Wall -Wextra -pedantic -Werror
    )
    target_compile_options(${PROJECT_NAME}_test PRIVATE
            -Wall -Wextra -pedantic -Werror
    )
else ()
    message(FATAL_ERROR "Error. Stopping. Unknown Platform")
endif ()

install(TARGETS ${PROJECT_NAME}_app RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT fabish@bk.ru)
include(CPack)
