cmake_minimum_required(VERSION 3.20)

project(AntiTrusted LANGUAGES CXX)

add_executable(AntiTrusted
    src/main.cpp
)

target_compile_features(AntiTrusted PRIVATE cxx_std_17)

target_compile_definitions(AntiTrusted PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

if(MSVC)
    target_compile_options(AntiTrusted PRIVATE /W4 /permissive- /utf-8)
    target_link_options(AntiTrusted PRIVATE
        /MANIFEST:EMBED
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
        "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/src/AntiTrusted.exe.manifest"
    )
endif()

target_link_libraries(AntiTrusted PRIVATE
    Advapi32
    Bcrypt
)

if(MSVC)
    set_target_properties(AntiTrusted PROPERTIES
        VS_GLOBAL_VcpkgEnabled false
        VS_GLOBAL_VcpkgApplocalDeps false
    )
endif()
