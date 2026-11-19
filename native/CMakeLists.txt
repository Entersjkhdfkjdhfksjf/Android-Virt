cmake_minimum_required(VERSION 3.18)
project(guest_runner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(vguest_core STATIC
    src/path_translator.cpp
    src/prop_service.cpp
    src/pseudo_fs.cpp
    src/seccomp_bpf.cpp
    src/supervisor.cpp
    src/vbinder.cpp
)

target_include_directories(vguest_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_compile_options(vguest_core PRIVATE
    -Wall -Wextra -Wpedantic -O2
)

if(NOT ANDROID)
    find_package(Threads REQUIRED)
    target_link_libraries(vguest_core PUBLIC Threads::Threads)
endif()

add_executable(guest_runner src/main.cpp)
target_link_libraries(guest_runner PRIVATE vguest_core)

if(ANDROID)
    target_compile_options(guest_runner PRIVATE -fPIE)
    target_link_options(guest_runner PRIVATE -fPIE -pie -static-libstdc++)
else()
    enable_testing()
    add_executable(test_phase2 ../tests/test_phase2.cpp)
    target_link_libraries(test_phase2 PRIVATE vguest_core)
    add_test(NAME phase2_unit_tests COMMAND test_phase2)

    add_executable(test_phase3 ../tests/test_phase3.cpp)
    target_link_libraries(test_phase3 PRIVATE vguest_core)
    add_test(NAME phase3_unit_tests COMMAND test_phase3)

    add_executable(test_phase4 ../tests/test_phase4.cpp)
    target_link_libraries(test_phase4 PRIVATE vguest_core)
    add_test(NAME phase4_unit_tests COMMAND test_phase4)
endif()
