cmake_minimum_required (VERSION 3.8)

if (WIN32)
set(CMAKE_C_COMPILER "C:/Program Files/mingw64/bin/gcc.exe")
set(CMAKE_CXX_COMPILER "C:/Program Files/mingw64/bin/g++.exe")
endif ()

project ("nsign-tool")

add_subdirectory ("src")

install(TARGETS nsign)
