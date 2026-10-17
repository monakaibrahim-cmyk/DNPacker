cmake_minimum_required(VERSION 3.15)
project(DNPacker VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Static linking options
option(BUILD_STATIC "Build completely static executable" ON)

if(BUILD_STATIC)
    if(MSVC)
        # Statically link C/C++ runtime library (/MT or /MTd)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        # GCC / Clang on Linux
        if(NOT APPLE)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
        endif()
    endif()
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/pak.cpp
    src/crypto.cpp
    src/key_extractor.cpp
    src/miniz.c
)

set(HEADERS
    src/pak.h
    src/crypto.h
    src/key_table.h
    src/key_extractor.h
    src/miniz.h
)

add_executable(dnpacker ${SOURCES} ${HEADERS})

target_include_directories(dnpacker PRIVATE src)

# Platform-specific dependencies
if(WIN32)
    target_link_libraries(dnpacker PRIVATE bcrypt user32)
    target_compile_definitions(dnpacker PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_link_libraries(dnpacker PRIVATE pthread)
endif()

# Output binary names
set_target_properties(dnpacker PROPERTIES
    OUTPUT_NAME "dnpacker"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
