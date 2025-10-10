# define system dependent compiler flags

INCLUDE(CheckCCompilerFlag)

IF (UNIX AND NOT WIN32)

    ADD_DEFINITIONS(-D_GNU_SOURCE)

    # Modern hardening: Use FORTIFY_SOURCE=3 if available (GCC 12+), fallback to =2
    CHECK_C_COMPILER_FLAG("-D_FORTIFY_SOURCE=3" WITH_FORTIFY_SOURCE_3)
    IF (WITH_FORTIFY_SOURCE_3)
        ADD_DEFINITIONS(-D_FORTIFY_SOURCE=3)
    ELSE()
        CHECK_C_COMPILER_FLAG("-D_FORTIFY_SOURCE=2" WITH_FORTIFY_SOURCE_2)
        IF (WITH_FORTIFY_SOURCE_2)
            ADD_DEFINITIONS(-D_FORTIFY_SOURCE=2)
        ENDIF (WITH_FORTIFY_SOURCE_2)
    ENDIF (WITH_FORTIFY_SOURCE_3)

    # Stack protector (will be upgraded to -strong later)
    CHECK_C_COMPILER_FLAG("-fstack-protector" WITH_STACK_PROTECTOR)
    IF (WITH_STACK_PROTECTOR)
        ADD_DEFINITIONS(-fstack-protector)
    ENDIF (WITH_STACK_PROTECTOR)


    SET(CMAKE_INCLUDE_PATH "/usr/include/ /usr/local/include" )

    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -W -Wreturn-type  -Wstrict-prototypes")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W -Wmissing-prototypes -Wmissing-declarations -Wpointer-arith -Wchar-subscripts -Wformat=2 -Wbad-function-cast -Wno-strict-aliasing -Wshadow")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wdeclaration-after-statement -Wuninitialized -Wno-format-nonliteral" )

    # Hardening: Format string security (make format-security warnings into errors)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat-security -Werror=format-security")

    #SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -Wstrict-aliasing=2")
    #SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused -Wno-unused-parameter" )
    #SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
    #SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all")

    # Hardening: Strong stack protector
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")

    # Hardening: Stack clash protection (GCC 8+)
    CHECK_C_COMPILER_FLAG("-fstack-clash-protection" WITH_STACK_CLASH_PROTECTION)
    IF (WITH_STACK_CLASH_PROTECTION)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-clash-protection")
    ENDIF (WITH_STACK_CLASH_PROTECTION)

    # Hardening: Control Flow Integrity (x86_64, GCC 8+)
    CHECK_C_COMPILER_FLAG("-fcf-protection=full" WITH_CF_PROTECTION)
    IF (WITH_CF_PROTECTION)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fcf-protection=full")
    ENDIF (WITH_CF_PROTECTION)

    #SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fno-sanitize-recover")

    # Hardening: Position Independent Code (for PIE executables)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fPIE" )

    # Hardening: Linker flags for security
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,noexecstack")
    SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now")
    SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,noexecstack")

    IF ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wno-strict-aliasing")
    ENDIF ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")

    IF ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wstrict-aliasing=2 -fno-omit-frame-pointer")
    ENDIF ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")


ENDIF (UNIX AND NOT WIN32)
