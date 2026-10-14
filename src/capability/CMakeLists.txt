add_library(turtle_capability capability.cpp)
target_include_directories(turtle_capability PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
target_link_libraries(turtle_capability PUBLIC turtle_model)
