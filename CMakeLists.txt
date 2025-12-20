cmake_minimum_required(VERSION 3.14)
project(Crunch
    VERSION 2.0.0
    DESCRIPTION "A Message Definition Language for Getting Things Right"
    LANGUAGES CXX
)

# Header-only library
add_library(crunch INTERFACE)
add_library(Crunch::crunch ALIAS crunch)

target_include_directories(crunch INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(crunch INTERFACE cxx_std_23)

# Installation
include(GNUInstallDirs)
install(TARGETS crunch
    EXPORT crunchTargets
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/crunch
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT crunchTargets
    FILE crunchTargets.cmake
    NAMESPACE Crunch::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crunch
)

# Optional: Enable testing
option(CRUNCH_BUILD_TESTS "Build tests" OFF)
if(CRUNCH_BUILD_TESTS)
    enable_testing()
    find_package(Catch2 3 REQUIRED)
    
    # Add test files
    file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS "test/*.cpp")
    foreach(test_src ${TEST_SOURCES})
        get_filename_component(test_name ${test_src} NAME_WE)
        add_executable(${test_name} ${test_src})
        target_link_libraries(${test_name} PRIVATE crunch Catch2::Catch2WithMain)
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()
