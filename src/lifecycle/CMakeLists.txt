add_library(turtle_lifecycle endpoint.cpp role_runtime.cpp endpoint_protocol.cpp peer_session.cpp lookup_runtime.cpp)
target_include_directories(turtle_lifecycle PUBLIC ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/include)
target_include_directories(turtle_lifecycle PRIVATE ${PROJECT_SOURCE_DIR}/third_party)
target_link_libraries(turtle_lifecycle PUBLIC turtle_model turtle_transport turtle_control turtle_measure turtle_capability turtle_record turtle_lookup ${CMAKE_DL_LIBS})
