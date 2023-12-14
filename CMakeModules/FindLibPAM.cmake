# - Try to find LibPAM
# Once done this will define
#
#  LIBPAM_FOUND - system has LibPAM
#  LIBPAM_INCLUDE_DIRS - the LibPAM include directory
#  LIBPAM_LIBRARIES - link these to use LibPAM
#
#  Author Roman Janota <xjanot04@fit.vutbr.cz>
#  Copyright (c) 2022 CESNET, z.s.p.o.
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

if(LIBPAM_LIBRARIES AND LIBPAM_INCLUDE_DIRS)
  # in cache already
  set(LIBPAM_FOUND TRUE)
else()

  find_path(LIBPAM_INCLUDE_DIR
    NAMES
      security/pam_appl.h
      security/pam_modules.h
    PATHS
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBPAM_LIBRARY
    NAMES
      pam
    PATHS
      /usr/lib
      /usr/lib64
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if(LIBPAM_INCLUDE_DIR AND LIBPAM_LIBRARY)
    set(LIBPAM_FOUND TRUE)

    # check if the function pam_start_confdir is in pam_appl.h header (added in PAM 1.4)
    file(STRINGS ${LIBPAM_INCLUDE_DIR}/security/pam_appl.h PAM_CONFDIR REGEX "pam_start_confdir")
    if ("${PAM_CONFDIR}" STREQUAL "")
      set(LIBPAM_HAVE_CONFDIR FALSE)
    else()
      set(LIBPAM_HAVE_CONFDIR TRUE)
    endif()
  else()
    set(LIBPAM_FOUND FALSE)
  endif()

  set(LIBPAM_INCLUDE_DIRS ${LIBPAM_INCLUDE_DIR})
  set(LIBPAM_LIBRARIES ${LIBPAM_LIBRARY})

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(LibPAM DEFAULT_MSG LIBPAM_LIBRARIES LIBPAM_INCLUDE_DIRS)

  # show the LIBPAM_INCLUDE_DIRS and LIBPAM_LIBRARIES variables only in the advanced view
  mark_as_advanced(LIBPAM_INCLUDE_DIRS LIBPAM_LIBRARIES)

endif()
