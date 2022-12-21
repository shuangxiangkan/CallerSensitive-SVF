llvm_map_components_to_libnames(llvm_libs bitwriter core ipo irreader instcombine instrumentation target linker analysis scalaropts support )
file (GLOB SOURCES
   *.cpp
)
add_executable(taint ${SOURCES} lib/TaintChecker.cpp lib/JsonReaderWriter.cpp)

target_link_libraries(taint ${SVF_LIB} ${llvm_libs})
target_include_directories(taint PUBLIC include)
target_link_libraries(taint ${Z3_LIBRARIES})
set_target_properties( taint PROPERTIES
                       RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
