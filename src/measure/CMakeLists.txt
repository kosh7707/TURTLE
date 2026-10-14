add_library(turtle_measure measure.cpp)
target_include_directories(turtle_measure PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
target_link_libraries(turtle_measure PUBLIC turtle_model)
