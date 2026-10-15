add_library(turtle_lookup lookup.cpp)
target_include_directories(turtle_lookup PUBLIC ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(turtle_lookup PUBLIC turtle_model)
