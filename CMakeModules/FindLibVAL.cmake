# - Try to find LibVAL
# Once done this will define
#
#  LIBVAL_FOUND - system has LibVAL
#  LIBVAL_INCLUDE_DIRS - the LibVAL include directory
#  LIBVAL_LIBRARIES - link these to use LibVAL
#
#  Author Michal Vasko <mvasko@cesnet.cz>
#  Copyright (c) 2015 CESNET, z.s.p.o.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. The name of the author may not be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
#  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
#  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
#  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

if(LIBVAL_LIBRARIES AND LIBVAL_INCLUDE_DIRS)
  # in cache already
  set(LIBVAL_FOUND TRUE)
else()

  find_path(LIBVAL_INCLUDE_DIR
    NAMES
      validator/validator.h
      validator/resolver.h
      validator/validator-compat.h
      validator/val_dane.h
      validator/val_errors.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBVAL_LIBRARY
    NAMES
      libval-threads
      val-threads
    PATHS
      /usr/lib
      /usr/lib64
      /usr/local/lib
      /usr/local/lib64
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  find_library(LIBSRES_LIBRARY
    NAMES
      libsres
      sres
    PATHS
      /usr/lib
      /usr/lib64
      /usr/local/lib
      /usr/local/lib64
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if(LIBVAL_INCLUDE_DIR AND LIBVAL_LIBRARY AND LIBSRES_LIBRARY)
    set(LIBVAL_FOUND TRUE)
  else()
    set(LIBVAL_FOUND FALSE)
  endif()

  set(LIBVAL_INCLUDE_DIRS ${LIBVAL_INCLUDE_DIR})
  set(LIBVAL_LIBRARIES ${LIBSRES_LIBRARY} ${LIBVAL_LIBRARY})

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(LibVAL DEFAULT_MSG LIBVAL_LIBRARIES LIBVAL_INCLUDE_DIRS)

  # show the LIBVAL_INCLUDE_DIRS and LIBVAL_LIBRARIES variables only in the advanced view
  mark_as_advanced(LIBVAL_INCLUDE_DIRS LIBVAL_LIBRARIES)

endif()

