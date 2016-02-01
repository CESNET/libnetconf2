cmake_minimum_required(VERSION 2.6)
find_package(CMocka 1.0.0 REQUIRED)

# list of all the tests
set(tests test_io test_fd_comm)

foreach(test_name IN LISTS tests)
    add_executable(${test_name} ${test_name}.c)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} ${LIBYANG_LIBRARIES} netconf2)
    add_test(${test_name} ${test_name})
endforeach(test_name)

if(ENABLE_VALGRIND_TESTS)
    find_program(valgrind_FOUND valgrind)
    if(valgrind_FOUND)
        foreach(test_name IN LISTS tests)
            add_test(${test_name}_valgrind valgrind --leak-check=full ${CMAKE_BINARY_DIR}/tests/${test_name})
        endforeach(test_name)
    else(valgrind_FOUND)
        Message("-- valgrind executable not found! Disabling memory leaks tests")
    endif(valgrind_FOUND)
endif()

include_directories(${CMAKE_SOURCE_DIR}/src)
configure_file("${PROJECT_SOURCE_DIR}/tests/config.h.in" "${PROJECT_SOURCE_DIR}/tests/config.h" ESCAPE_QUOTES @ONLY)
