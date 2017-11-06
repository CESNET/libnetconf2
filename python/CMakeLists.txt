find_program(PYTHON "python3")

if (PYTHON)
    set(SETUP_PY_IN      "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in")
    set(SETUP_PY         "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
    set(PYAPI_BUILD_DIR  "${CMAKE_CURRENT_BINARY_DIR}/build")
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${PYAPI_BUILD_DIR})
    
    if(CMAKE_BUILD_TYPE STREQUAL debug)
        set(DEBUG "--debug")
    endif()

    if(ENABLE_SSH)
        set(SSH_DEFINE ",\"-DNC_ENABLED_SSH\"")
    endif()

    if(ENABLE_TLS)
        set(TLS_DEFINE ",\"-DNC_ENABLED_TLS\"")
    endif()

    configure_file(${SETUP_PY_IN} ${SETUP_PY})
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/docs/Makefile.in ${CMAKE_CURRENT_SOURCE_DIR}/docs/Makefile)
	add_custom_target(pyapi ALL COMMAND ${PYTHON} ${SETUP_PY} build -b ${PYAPI_BUILD_DIR} ${DEBUG})
	add_custom_target(pyapidoc COMMAND make -f ${CMAKE_CURRENT_SOURCE_DIR}/docs/Makefile html)
    install(CODE "execute_process(COMMAND ${PYTHON} ${SETUP_PY} build -b ${PYAPI_BUILD_DIR} install --prefix=${CMAKE_INSTALL_PREFIX})")
endif()
