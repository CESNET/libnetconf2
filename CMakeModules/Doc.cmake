# Prepare building doxygen documentation
macro(LIBNETCONF_DOC)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_SKIP_DOT TRUE)
        add_custom_target(doc
                COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
        configure_file(Doxyfile.in Doxyfile)
    endif()
endmacro()
