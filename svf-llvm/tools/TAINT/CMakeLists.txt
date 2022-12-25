if(DEFINED IN_SOURCE_BUILD)
  add_llvm_tool(taint taint.cpp)
else()
  add_executable(taint taint.cpp lib/TaintChecker.cpp lib/JsonReaderWriter.cpp)

  target_link_libraries(taint SvfLLVM ${llvm_libs})

  target_include_directories(taint PUBLIC include)

  set_target_properties(taint PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                         ${CMAKE_BINARY_DIR}/bin)
endif()
