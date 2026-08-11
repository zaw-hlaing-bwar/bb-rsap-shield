cmake_minimum_required(VERSION 3.22)

project(rasp_android_native C CXX)

add_library(security SHARED src/security.c)

target_compile_features(security PRIVATE c_std_11)
target_compile_options(security PRIVATE
  -fvisibility=hidden
  -fstack-protector-strong
  -Wall
  -Wextra
  -Werror
)

target_include_directories(security PRIVATE include)
