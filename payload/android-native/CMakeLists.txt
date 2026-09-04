cmake_minimum_required(VERSION 3.22)

project(rasp_android_native C CXX)

include(CheckIPOSupported)
include(CheckCCompilerFlag)

add_library(security SHARED src/security.c)
set_target_properties(security PROPERTIES NO_SONAME ON)

option(RASP_ENABLE_NATIVE_BRANCH_PROTECTION "Enable arm64 native branch-protection hardening when supported" ON)

target_compile_features(security PRIVATE c_std_11)
target_compile_options(security PRIVATE
  -fvisibility=hidden
  -ffunction-sections
  -fdata-sections
  -fstack-protector-strong
  $<$<CONFIG:Release>:-g0>
  -Wall
  -Wextra
  -Werror
)

foreach(rasp_compile_flag
    -fno-semantic-interposition
    -ftrivial-auto-var-init=zero
    -fno-ident)
  string(MAKE_C_IDENTIFIER "RASP_HAS_${rasp_compile_flag}" rasp_compile_flag_var)
  check_c_compiler_flag("${rasp_compile_flag}" "${rasp_compile_flag_var}")
  if(${rasp_compile_flag_var})
    target_compile_options(security PRIVATE "${rasp_compile_flag}")
  endif()
endforeach()

if(RASP_ENABLE_NATIVE_BRANCH_PROTECTION AND ANDROID_ABI STREQUAL "arm64-v8a")
  check_c_compiler_flag("-mbranch-protection=standard" RASP_HAS_BRANCH_PROTECTION_STANDARD)
  if(RASP_HAS_BRANCH_PROTECTION_STANDARD)
    target_compile_options(security PRIVATE -mbranch-protection=standard)
  endif()
endif()

target_link_options(security PRIVATE
  LINKER:--gc-sections
  LINKER:-z,relro
  LINKER:-z,now
  LINKER:-z,noexecstack
  LINKER:--exclude-libs,ALL
)

target_include_directories(security PRIVATE include)

check_ipo_supported(RESULT rasp_ipo_supported OUTPUT rasp_ipo_error LANGUAGES C)
if(rasp_ipo_supported)
  set_property(TARGET security PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
else()
  message(STATUS "IPO/LTO not enabled for security: ${rasp_ipo_error}")
endif()
