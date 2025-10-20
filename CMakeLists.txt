cmake_minimum_required(VERSION 3.16)
project(innovative-1 LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)     
set(CMAKE_AUTOUIC ON)     
set(CMAKE_AUTORCC ON)     

find_package(Qt6 COMPONENTS Widgets QUIET)
if (NOT Qt6_FOUND)
    find_package(Qt5 COMPONENTS Widgets REQUIRED)
endif()


add_executable(innovative-1
    innovative-1.cpp
)



if (Qt6_FOUND)
    target_link_libraries(innovative-1 PRIVATE Qt6::Widgets)
else()
    target_link_libraries(innovative-1 PRIVATE Qt5::Widgets)
endif()


if(APPLE)
    set_target_properties(innovative-1 PROPERTIES MACOSX_BUNDLE FALSE)
endif()



set_target_properties(innovative-1 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

message(STATUS "-------------------------------------------------------")
if (Qt6_FOUND)
    message(STATUS "Using Qt6 for build.")
else()
    message(STATUS "Using Qt5 for build.")
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Output binary: ${CMAKE_BINARY_DIR}/bin/innovative-1")
message(STATUS "-------------------------------------------------------")
