add_library(turtle_lifecycle lifecycle.cpp)
target_include_directories(turtle_lifecycle PUBLIC ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(turtle_lifecycle PUBLIC turtle_model turtle_transport turtle_control turtle_measure turtle_capability turtle_record ${CMAKE_DL_LIBS})
