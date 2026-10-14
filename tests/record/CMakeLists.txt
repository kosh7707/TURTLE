add_executable(turtle_record_test record_test.cpp)
target_link_libraries(turtle_record_test PRIVATE turtle_record)
target_include_directories(turtle_record_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party")
add_test(NAME record COMMAND turtle_record_test)
