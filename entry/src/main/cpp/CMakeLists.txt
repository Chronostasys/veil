cmake_minimum_required(VERSION 3.5.0)
project(veil)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

# The OpenHarmony NDK toolchain file is injected by hvigor through
# PACKAGE_FIND_FILE; include it when present so `cmake` also works standalone.
if(DEFINED PACKAGE_FIND_FILE)
    include(${PACKAGE_FIND_FILE})
endif()

include_directories(${NATIVERENDER_ROOT_PATH}
                    ${NATIVERENDER_ROOT_PATH}/include)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(veil SHARED
    napi_init.cpp
)

target_link_libraries(veil PUBLIC
    libace_napi.z.so
    libhilog_ndk.z.so
    libdl.so
)

# The Go engine is linked *statically* (c-archive) into this shim.
#
# Why not a separate libveilcore.so + dlopen: the Go runtime uses initial-exec
# TLS, and on HarmonyOS the loader rejects a dynamically loaded Go library with
#   "Error relocating libveilcore.so: initial-exec TLS resolves to dynamic
#    definition in libveilcore.so"
# Linking the archive in makes the relocation local to libveil.so, which loads
# fine. Build the archive first: scripts/build-core.sh
set(VEIL_CORE_ARCHIVE "${CMAKE_CURRENT_SOURCE_DIR}/libs/${OHOS_ARCH}/libveilcore.a")
if(EXISTS "${VEIL_CORE_ARCHIVE}")
    message(STATUS "Veil: linking Go core from ${VEIL_CORE_ARCHIVE}")
    target_link_libraries(veil PUBLIC
        -Wl,--whole-archive "${VEIL_CORE_ARCHIVE}" -Wl,--no-whole-archive
        # Keep every Go symbol local to libveil.so: a Go runtime TLS symbol
        # exported as a *dynamic* definition makes the HarmonyOS loader reject
        # the module ("initial-exec TLS resolves to dynamic definition").
        -Wl,--exclude-libs,ALL -Wl,-Bsymbolic
    )
    target_compile_definitions(veil PRIVATE VEIL_STATIC_CORE=1)
    # Without LINK_DEPENDS, ninja keeps the old libveil.so when only the Go
    # archive changed (the archive is not a declared input of the link step).
    set_target_properties(veil PROPERTIES LINK_DEPENDS "${VEIL_CORE_ARCHIVE}")
else()
    message(WARNING "Veil: ${VEIL_CORE_ARCHIVE} not found; run scripts/build-core.sh (app will report 核心不可用)")
endif()
