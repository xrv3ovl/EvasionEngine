cmake_minimum_required(VERSION 3.15)
project(EvasionEngine LANGUAGES C ASM_MASM)

option(INDIRECT_SYSCALLS "Toggle between Direct and Indirect Syscalls" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/bin")

# Enable MASM only on x64
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_language(ASM_MASM)
    set(IS_X64 TRUE)
else()
    set(IS_X64 FALSE)
endif()

# Core C sources
set(PROJECT_SOURCES
    src/utils.c    
    src/peb-eat-utils.c
    src/ps-utils.c
    src/syscall-utils.c  
    src/payload.c 
    src/cli.c
    src/allocate.c
    src/write.c
    src/protect.c
    src/invoke.c
    src/dispatch.c
    src/engine.c
    src/EvasionEngine.c
    src/hash_loader.c
    src/hashed_values.c
    src/unwindraven_integration.c
)

# Build BOTH ASM files
set(ASM_SOURCES
    src/direct-syscalls.asm
    src/indirect-syscalls.asm
)

# Mark ASM files as MASM BEFORE creating the target
if(IS_X64)
    foreach(ASM_FILE ${ASM_SOURCES})
        set_source_files_properties(${ASM_FILE} PROPERTIES LANGUAGE ASM_MASM)
        set_source_files_properties(${ASM_FILE} PROPERTIES ASM_MASM_FLAGS "/nologo /Cx")
    endforeach()
endif()

add_library(unwindraven_core STATIC
    UnwindRaven/src/common.c
    UnwindRaven/src/pe_loader.c
    UnwindRaven/src/stack_blueprint.c
    UnwindRaven/src/synthetic_stack.c
    UnwindRaven/src/unwindraven_core.c
    UnwindRaven/src/veh.c
    src/blueprint_library.c
)

# target_include_directories(unwindraven_core PUBLIC UnwindRaven/include include)

# Define pre-compiled imported library
add_library(HashIt STATIC IMPORTED GLOBAL)
set_target_properties(HashIt PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/HashIt/HashIt.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/HashIt/include"
)

add_library(MaskIt STATIC IMPORTED GLOBAL)
set_target_properties(MaskIt PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/MaskIt/MaskIt.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/MaskIt/include"
)

target_include_directories(unwindraven_core PUBLIC 
    UnwindRaven/include 
    include
    MaskIt/include
    HashIt/include
)

target_link_libraries(unwindraven_core PUBLIC
    HashIt
    dbghelp
    psapi
    advapi32
    user32
    kernel32
)

# Define target (ASM must be included here)
add_executable(EvasionEngine
    ${PROJECT_SOURCES}
    $<$<BOOL:${IS_X64}>:${ASM_SOURCES}>
)

target_link_libraries(EvasionEngine PRIVATE HashIt MaskIt unwindraven_core)

# Include paths
target_include_directories(EvasionEngine PRIVATE include HashIt/include MaskIt/include UnwindRaven/include)

# MSVC flags (C only)
if(MSVC)
    target_compile_options(EvasionEngine PRIVATE 
        $<$<COMPILE_LANGUAGE:C>:/W4>
        $<$<COMPILE_LANGUAGE:C>:/WX>
        $<$<COMPILE_LANGUAGE:C>:/permissive->
        $<$<COMPILE_LANGUAGE:C>:/wd4100>
        $<$<COMPILE_LANGUAGE:C>:/wd4189>
    )

    set_target_properties(EvasionEngine PROPERTIES 
        INTERPROCEDURAL_OPTIMIZATION FALSE
        INTERPROCEDURAL_OPTIMIZATION_RELEASE FALSE
        STATIC_LIBRARY_OPTIONS_RELEASE ""
    )
endif()
