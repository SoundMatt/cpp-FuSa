add_executable(cpfusa_tests
    test_main.cpp
    test_config.cpp
    test_engine.cpp
    test_lint.cpp
    test_trace.cpp
    test_report.cpp
    test_runtime.cpp
)

target_include_directories(cpfusa_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(cpfusa_tests
    PRIVATE
        cpfusa_lib
        Catch2::Catch2WithMain
)

include(CTest)
include(Catch)
catch_discover_tests(cpfusa_tests)
