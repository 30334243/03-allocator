add_executable(${PROJECT_NAME}_test
        test_main.cpp
        test_ip_filter.cpp
)

target_link_libraries(${PROJECT_NAME}_test
        PRIVATE
        Boost::filesystem
        GTest::gtest
        GTest::gtest_main
        ip_filter_lib
)

add_test(NAME ${PROJECT_NAME}_test COMMAND ${PROJECT_NAME}_test)

set(TEST_FILES ${CMAKE_SOURCE_DIR}/tests/files/ip_filter.tsv)

if (WINDOWS_SPECIFIC_FLAG)
    add_custom_command(
            TARGET ${PROJECT_NAME}_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:GTest::gtest>
            $<TARGET_FILE:GTest::gtest_main>
            ${TEST_FILES}
            ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE}
    )
endif ()

add_custom_command(
        TARGET ${PROJECT_NAME}_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${TEST_FILES}
        ${CMAKE_CURRENT_BINARY_DIR}
)
