add_executable(turtle_adapter_smoke smoke.cpp)
target_include_directories(turtle_adapter_smoke PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../../include)
target_compile_features(turtle_adapter_smoke PRIVATE cxx_std_20)
target_link_libraries(turtle_adapter_smoke PRIVATE ${CMAKE_DL_LIBS})
# 실제 모듈/인증서 경로는 통합 테스트에서 전달합니다. 네트워크 내려받기는 하지 않습니다.
add_executable(turtle_adapter_memory memory.cpp)
target_include_directories(turtle_adapter_memory PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../../include)
target_compile_features(turtle_adapter_memory PRIVATE cxx_std_20)
target_link_libraries(turtle_adapter_memory PRIVATE ${CMAKE_DL_LIBS})

add_executable(turtle_adapter_cli_endpoint cli_endpoint.cpp)
target_include_directories(turtle_adapter_cli_endpoint PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../../include)
target_compile_features(turtle_adapter_cli_endpoint PRIVATE cxx_std_20)
target_link_libraries(turtle_adapter_cli_endpoint PRIVATE ${CMAKE_DL_LIBS})
