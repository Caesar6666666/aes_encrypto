# CMakeList.txt: aescrypto 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()


set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
  CACHE STRING "Vcpkg toolchain file")

project ("aescrypto")
set(CMAKE_CXX_STANDARD 23)
find_package(cryptopp CONFIG REQUIRED)
# 将源代码添加到此项目的可执行文件。
add_executable (aescrypto "main.cpp" "aescrypto.cpp" "aescrypto.h")

find_package(argparse CONFIG REQUIRED)

target_link_libraries(aescrypto cryptopp::cryptopp argparse::argparse)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET aescrypto PROPERTY CXX_STANDARD 20)
endif()

# TODO: 如有需要，请添加测试并安装目标。
