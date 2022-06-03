if(NOT LIBNETCONF2_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

# correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# include all the library headers
include_directories(BEFORE "${CMAKE_SOURCE_DIR}/src")

# generate example header
include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})
configure_file(example.h.in example.h)

# list of all the examples
set(examples server client)

foreach(app_name IN LISTS examples)
    add_executable(${app_name} ${app_name}.c)
    target_link_libraries(${app_name} netconf2)
endforeach(app_name)
