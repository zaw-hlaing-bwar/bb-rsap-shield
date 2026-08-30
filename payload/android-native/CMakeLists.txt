cmake_minimum_required(VERSION 3.22)

project(rasp_android_native C CXX)

include(CheckIPOSupported)

add_library(security SHARED src/security.c)

target_compile_features(security PRIVATE c_std_11)
target_compile_options(security PRIVATE
  -fvisibility=hidden
  -ffunction-sections
  -fdata-sections
  -fstack-protector-strong
  -Wall
  -Wextra
  -Werror
)

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
