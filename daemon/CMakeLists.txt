project(certifierd)

file(GLOB SOURCES "*.c")

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} certifier)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/internal_headers)

# The rule to install daemon binary
install (TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

# Directory with systemd unit files
set (SYSTEMD_UNIT_DIR "/usr/lib/systemd/system")

set (SYSTEMV_UNIT_DIR "/etc/init.d")

# Default directory for log file
set (DAEMON_LOG_DIR "/var/log/certifier")

# Default directory for PID file
set (DAEMON_PID_DIR "/run/certifier")

# Default directory for certificates
set (DAEMON_CERTS_DIR "/etc/certifier/certificates")

# Macro for installing configuration files
function(install_conf src dest)
  if(NOT IS_ABSOLUTE "${src}")
    set(src "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
  endif()
  get_filename_component(src_name "${src}" NAME)
  if (NOT IS_ABSOLUTE "${dest}")
    set(dest "${CMAKE_INSTALL_PREFIX}/${dest}")
  endif()
  install(CODE "
    if(NOT EXISTS \"\$ENV{DESTDIR}${dest}/${src_name}\")
      #file(INSTALL \"${src}\" DESTINATION \"${dest}\")
      message(STATUS \"Installing: \$ENV{DESTDIR}${dest}/${src_name}\")
      execute_process(COMMAND \${CMAKE_COMMAND} -E copy \"${src}\"
                      \"\$ENV{DESTDIR}${dest}/${src_name}\"
                      RESULT_VARIABLE copy_result
                      ERROR_VARIABLE error_output)
      if(copy_result)
        message(FATAL_ERROR \${error_output})
      endif()
    else()
      message(STATUS \"Skipping  : \$ENV{DESTDIR}${dest}/${src_name}\")
    endif()
  ")
endfunction(install_conf)

if (NOT ${SYSTEMV_DAEMON})
  # Install systemd unit files
  install_conf (./certifierd.service ${SYSTEMD_UNIT_DIR})
elseif(${SYSTEMV_DAEMON})
  set(PROGRAM_PERMISSIONS_DEFAULT
      OWNER_WRITE OWNER_READ OWNER_EXECUTE
      GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)

  # Install systemv unit files
  install(FILES certifierd.init DESTINATION ${SYSTEMV_UNIT_DIR} PERMISSIONS ${PROGRAM_PERMISSIONS_DEFAULT} RENAME certifierd)

  install(CODE "set(CMAKE_INSTALL_PREFIX \"${CMAKE_INSTALL_PREFIX}\")")
  install(SCRIPT InstallScript.cmake ${SYSTEMV_UNIT_DIR})
endif()

# Create empty directory for default log file
install(DIRECTORY DESTINATION ${DAEMON_LOG_DIR})

# Create empty directory for default PID file
install(DIRECTORY DESTINATION ${DAEMON_PID_DIR})

# Create empty directory for certificates to be renewed
install(DIRECTORY DESTINATION ${DAEMON_CERTS_DIR})
