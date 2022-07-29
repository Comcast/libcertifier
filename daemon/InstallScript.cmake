if("${CMAKE_INSTALL_PREFIX}" STREQUAL "/")
  execute_process(COMMAND update-rc.d certifierd defaults
                  RESULT_VARIABLE Result
                  OUTPUT_VARIABLE Output
                  ERROR_VARIABLE Error)
  if(Result EQUAL 0)
    message(STATUS "Ran update-rc.d as CMAKE_INSTALL_PREFIX == \"/\"")
  else()
    message(FATAL_ERROR "Result - ${Result}\nOutput - ${Output}\nError - Error")
  endif()
else()
  message(STATUS "Not running update-rc.d as CMAKE_INSTALL_PREFIX != \"/\"")
endif()