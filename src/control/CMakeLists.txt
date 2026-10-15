add_library(turtle_control control.cpp)
target_include_directories(turtle_control PUBLIC ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include)
target_include_directories(turtle_control SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party)
