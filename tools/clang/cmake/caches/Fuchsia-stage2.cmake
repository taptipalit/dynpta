# This file sets up a CMakeCache for the second stage of a Fuchsia toolchain
# build.

set(LLVM_TARGETS_TO_BUILD X86;ARM;AArch64 CACHE STRING "")

set(PACKAGE_VENDOR Fuchsia CACHE STRING "")

set(LLVM_INCLUDE_EXAMPLES OFF CACHE BOOL "")
set(LLVM_INCLUDE_DOCS OFF CACHE BOOL "")
set(LLVM_ENABLE_BACKTRACES OFF CACHE BOOL "")
set(LLVM_ENABLE_TERMINFO OFF CACHE BOOL "")
set(LLVM_ENABLE_ZLIB ON CACHE BOOL "")
set(LLVM_EXTERNALIZE_DEBUGINFO ON CACHE BOOL "")
set(CLANG_PLUGIN_SUPPORT OFF CACHE BOOL "")

set(LLVM_ENABLE_LTO ON CACHE BOOL "")
if(NOT APPLE)
  set(LLVM_ENABLE_LLD ON CACHE BOOL "")
  set(CLANG_DEFAULT_LINKER lld CACHE STRING "")
  set(CLANG_DEFAULT_OBJCOPY llvm-objcopy CACHE STRING "")
endif()
set(CLANG_DEFAULT_CXX_STDLIB libc++ CACHE STRING "")
set(CLANG_DEFAULT_RTLIB compiler-rt CACHE STRING "")

set(LLVM_ENABLE_ASSERTIONS ON CACHE BOOL "")
set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -gline-tables-only -DNDEBUG" CACHE STRING "")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O3 -gline-tables-only -DNDEBUG" CACHE STRING "")

set(FUCHSIA_BUILTINS_BUILD_TYPE Release CACHE STRING "")
set(FUCHSIA_RUNTIMES_BUILD_TYPE Release CACHE STRING "")
set(FUCHSIA_RUNTIMES_ENABLE_ASSERTIONS ON CACHE BOOL "")

set(LLVM_BUILTIN_TARGETS "default;x86_64-fuchsia;aarch64-fuchsia" CACHE STRING "")

# Set the per-target builtins options.
foreach(target x86_64;aarch64)
  set(BUILTINS_${target}-fuchsia_CMAKE_SYSTEM_NAME Fuchsia CACHE STRING "")
  set(BUILTINS_${target}-fuchsia_CMAKE_BUILD_TYPE ${FUCHSIA_BUILTINS_BUILD_TYPE} CACHE STRING "")
  set(BUILTINS_${target}-fuchsia_CMAKE_ASM_FLAGS ${FUCHSIA_${target}_C_FLAGS} CACHE PATH "")
  set(BUILTINS_${target}-fuchsia_CMAKE_C_FLAGS ${FUCHSIA_${target}_C_FLAGS} CACHE PATH "")
  set(BUILTINS_${target}-fuchsia_CMAKE_CXX_FLAGS ${FUCHSIA_${target}_CXX_FLAGS} CACHE PATH "")
  set(BUILTINS_${target}-fuchsia_CMAKE_EXE_LINKER_FLAGS ${FUCHSIA_${target}_LINKER_FLAGS} CACHE PATH "")
  set(BUILTINS_${target}-fuchsia_CMAKE_SHARED_LINKER_FLAGS ${FUCHSIA_${target}_LINKER_FLAGS} CACHE PATH "")
  set(BUILTINS_${target}-fuchsia_CMAKE_MODULE_LINKER_FLAGS ${FUCHSIA_${target}_LINKER_FLAGS} CACHE PATH "")
  set(BUILTINS_${target}-fuchsia_CMAKE_SYSROOT ${FUCHSIA_${target}_SYSROOT} CACHE PATH "")
endforeach()

set(LLVM_RUNTIME_TARGETS "default;x86_64-fuchsia;aarch64-fuchsia;x86_64-fuchsia-asan:x86_64-fuchsia;aarch64-fuchsia-asan:aarch64-fuchsia" CACHE STRING "")

# Set the default target runtimes options.
if(NOT APPLE)
  set(LIBUNWIND_ENABLE_SHARED OFF CACHE BOOL "")
  set(LIBUNWIND_USE_COMPILER_RT ON CACHE BOOL "")
  set(LIBUNWIND_INSTALL_LIBRARY OFF CACHE BOOL "")
  set(LIBCXXABI_USE_COMPILER_RT ON CACHE BOOL "")
  set(LIBCXXABI_ENABLE_SHARED OFF CACHE BOOL "")
  set(LIBCXXABI_USE_LLVM_UNWINDER ON CACHE BOOL "")
  set(LIBCXXABI_ENABLE_STATIC_UNWINDER ON CACHE BOOL "")
  set(LIBCXXABI_INSTALL_LIBRARY OFF CACHE BOOL "")
  set(LIBCXX_USE_COMPILER_RT ON CACHE BOOL "")
  set(LIBCXX_ENABLE_SHARED OFF CACHE BOOL "")
  set(LIBCXX_ENABLE_STATIC_ABI_LIBRARY ON CACHE BOOL "")
endif()

# Set the per-target runtimes options.
foreach(target x86_64;aarch64)
  set(RUNTIMES_${target}-fuchsia_CMAKE_SYSTEM_NAME Fuchsia CACHE STRING "")
  set(RUNTIMES_${target}-fuchsia_CMAKE_BUILD_TYPE ${FUCHSIA_RUNTIMES_BUILD_TYPE} CACHE STRING "")
  set(RUNTIMES_${target}-fuchsia_CMAKE_BUILD_WITH_INSTALL_RPATH ON CACHE STRING "")
  set(RUNTIMES_${target}-fuchsia_CMAKE_ASM_FLAGS ${FUCHSIA_${target}_C_FLAGS} CACHE PATH "")
  set(RUNTIMES_${target}-fuchsia_CMAKE_C_FLAGS ${FUCHSIA_${target}_C_FLAGS} CACHE PATH "")
  set(RUNTIMES_${target}-fuchsia_CMAKE_CXX_FLAGS ${FUCHSIA_${target}_CXX_FLAGS} CACHE PATH "")
  set(RUNTIMES_${target}-fuchsia_CMAKE_EXE_LINKER_FLAGS ${FUCHSIA_${target}_LINKER_FLAGS} CACHE PATH "")
  set(RUNTIMES_${target}-fuchsia_CMAKE_SHARED_LINKER_FLAGS ${FUCHSIA_${target}_LINKER_FLAGS} CACHE PATH "")
  set(RUNTIMES_${target}-fuchsia_CMAKE_MODULE_LINKER_FLAGS ${FUCHSIA_${target}_LINKER_FLAGS} CACHE PATH "")
  set(RUNTIMES_${target}-fuchsia_CMAKE_SYSROOT ${FUCHSIA_${target}_SYSROOT} CACHE PATH "")
  set(RUNTIMES_${target}-fuchsia_LLVM_ENABLE_ASSERTIONS ${FUCHSIA_RUNTIMES_ENABLE_ASSERTIONS} CACHE BOOL "")
  set(RUNTIMES_${target}-fuchsia_LIBUNWIND_USE_COMPILER_RT ON CACHE BOOL "")
  set(RUNTIMES_${target}-fuchsia_LIBUNWIND_ENABLE_STATIC OFF CACHE BOOL "")
  set(RUNTIMES_${target}-fuchsia_LIBCXXABI_USE_COMPILER_RT ON CACHE BOOL "")
  set(RUNTIMES_${target}-fuchsia_LIBCXXABI_USE_LLVM_UNWINDER ON CACHE BOOL "")
  set(RUNTIMES_${target}-fuchsia_LIBCXXABI_ENABLE_STATIC OFF CACHE BOOL "")
  set(RUNTIMES_${target}-fuchsia_LIBCXX_USE_COMPILER_RT ON CACHE BOOL "")
  set(RUNTIMES_${target}-fuchsia_LIBCXX_ENABLE_STATIC OFF CACHE BOOL "")
  set(RUNTIMES_${target}-fuchsia_SANITIZER_USE_COMPILER_RT ON CACHE BOOL "")

  set(RUNTIMES_${target}-fuchsia-asan_LLVM_USE_SANITIZER Address CACHE STRING "")
  set(RUNTIMES_${target}-fuchsia-asan_LLVM_RUNTIMES_PREFIX "${target}-fuchsia/" CACHE STRING "")
  set(RUNTIMES_${target}-fuchsia-asan_LLVM_RUNTIMES_LIBDIR_SUFFIX "/asan" CACHE STRING "")
  set(RUNTIMES_${target}-fuchsia-asan_LIBCXX_INSTALL_HEADERS OFF CACHE BOOL "")
endforeach()

# Setup toolchain.
set(LLVM_INSTALL_TOOLCHAIN_ONLY ON CACHE BOOL "")
set(LLVM_TOOLCHAIN_TOOLS
  dsymutil
  llc
  llvm-ar
  llvm-cov
  llvm-cxxfilt
  llvm-dwarfdump
  llvm-lib
  llvm-nm
  llvm-objcopy
  llvm-objdump
  llvm-profdata
  llvm-ranlib
  llvm-readelf
  llvm-readobj
  llvm-size
  llvm-strip
  llvm-symbolizer
  opt
  sancov
  CACHE STRING "")

set(LLVM_DISTRIBUTION_COMPONENTS
  clang
  libclang
  lld
  LTO
  clang-format
  clang-headers
  clang-include-fixer
  clang-refactor
  clang-tidy
  clangd
  builtins
  runtimes
  ${LLVM_TOOLCHAIN_TOOLS}
  CACHE STRING "")
