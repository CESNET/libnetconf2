find_program(PYTHON "python3")

if (PYTHON)
    set(SETUP_PY_IN      "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in")
    set(SETUP_PY         "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
    set(PYAPI_BUILD_DIR  "${CMAKE_CURRENT_BINARY_DIR}/build")
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${PYAPI_BUILD_DIR})
    
    if(CMAKE_BUILD_TYPE STREQUAL debug)
        set(DEBUG "--debug")
    endif()

    configure_file(${SETUP_PY_IN} ${SETUP_PY})
	add_custom_target(pyapi ALL COMMAND ${PYTHON} ${SETUP_PY} build -b ${PYAPI_BUILD_DIR} ${DEBUG})
    install(CODE "execute_process(COMMAND ${PYTHON} ${SETUP_PY} build -b ${PYAPI_BUILD_DIR} install --prefix=${CMAKE_INSTALL_PREFIX})")
endif()
