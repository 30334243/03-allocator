add_executable(${PROJECT_NAME}_app main.cpp)
target_link_libraries(${PROJECT_NAME}_app PRIVATE Boost::program_options ${PROJECT_NAME}_lib)