add_library(turtle_mock MODULE mock.cpp)
target_include_directories(turtle_mock PRIVATE ${PROJECT_SOURCE_DIR}/include)
set_target_properties(turtle_mock PROPERTIES PREFIX "" OUTPUT_NAME mock LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/adapters")
