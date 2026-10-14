add_library(turtle_measure measure.cpp)
target_include_directories(turtle_measure PUBLIC ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(turtle_measure PUBLIC turtle_model)
