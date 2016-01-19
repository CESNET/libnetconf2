cmake_minimum_required(VERSION 2.6)
find_package(CMocka 1.0.0 REQUIRED)

add_executable(test_io test_io.c)
target_link_libraries(test_io ${CMOCKA_LIBRARIES} ${LIBYANG_LIBRARIES} netconf2)
add_test(test_io test_io)

if(ENABLE_VALGRIND_TESTS)
	find_program(valgrind_FOUND valgrind)
	if(valgrind_FOUND)
		add_test(test_io_valgrind valgrind --leak-check=full ${CMAKE_BINARY_DIR}/tests/test_io)
	else(valgrind_FOUND)
		Message("-- valgrind executable not found! Disabling memory leaks tests")
	endif(valgrind_FOUND)
endif()

include_directories(${CMAKE_SOURCE_DIR}/src)
configure_file("${PROJECT_SOURCE_DIR}/tests/config.h.in" "${PROJECT_SOURCE_DIR}/tests/config.h" ESCAPE_QUOTES @ONLY)
