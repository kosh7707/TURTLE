add_library(turtle_transport tcp.cpp channel.cpp)
target_include_directories(turtle_transport PUBLIC ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(turtle_transport PUBLIC turtle_model)
