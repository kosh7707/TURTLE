add_executable(turtle_capture_test capture_test.cpp)
target_include_directories(turtle_capture_test PRIVATE ../../src ../../include)
target_link_libraries(turtle_capture_test PRIVATE turtle_record)
add_test(NAME lifecycle_capture_return_order COMMAND turtle_capture_test)
