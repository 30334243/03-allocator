file(GLOB HEADERS "${CMAKE_CURRENT_LIST_DIR}/include/*.h")
file(GLOB SOURCES "${CMAKE_CURRENT_LIST_DIR}/src/*.cpp")

add_library(${PROJECT_NAME}_lib STATIC ${HEADERS} ${SOURCES})

target_include_directories(${PROJECT_NAME}_lib PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(${PROJECT_NAME}_lib PRIVATE Boost::system)
