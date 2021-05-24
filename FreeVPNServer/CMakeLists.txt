project(FreeVpnServer)
cmake_minimum_required(VERSION 2.8)

set (TUNTAP_PATH "linux")
set(UNIX ON)
add_definitions(-DUNIX)
add_definitions(-D_SERVER_)
add_definitions(-DUNIX_LINUX)

if (CMAKE_SYSTEM_NAME STREQUAL Linux)
	set (TUNTAP_PATH "linux")
	set(UNIX ON)
	add_definitions(-DUNIX)
	add_definitions(-DUNIX_LINUX)
endif ()

# N2n information
set(FREEVPN_VERSION 2.5.0)
set(FREEVPN_OSNAME ${CMAKE_SYSTEM})

# Build information
OPTION(BUILD_SHARED_LIBS "BUILD Shared Library" OFF)


if(NOT DEFINED FREEVPN_OPTION_AES)
set(FREEVPN_OPTION_AES OFF)
endif(NOT DEFINED FREEVPN_OPTION_AES)

if(UNIX)
	#add_definitions(-DOS_UNIX)
	include(GNUInstallDirs)
	set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")

	include(CheckIncludeFile)
	Check_Include_File(sys/auxv.h HAVE_SYS_AUXV)
endif()

add_definitions(-DFREEVPN_VERSION="${FREEVPN_VERSION}" -DFREEVPN_OSNAME="${FREEVPN_OSNAME}")

if(FREEVPN_OPTION_AES)
add_definitions(-DFREEVPN_HAVE_AES)
endif(FREEVPN_OPTION_AES)

if(NOT DEFINED CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE None)
endif(NOT DEFINED CMAKE_BUILD_TYPE)
#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

if (UNIX)
# None
set(CMAKE_C_FLAGS " -pthread -ldl -Wpointer-arith -Wmissing-declarations -Wnested-externs")
set(CMAKE_CXX_FLAGS " -pthread  -ldl -Wpointer-arith -Wmissing-declarations -Wnested-externss")
# Debug 
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
# Release
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
endif()



## DEBUG FOR CMAKE
#message(${FREEVPN_VERSION}) 
#message(${FREEVPN_OSNAME})
##message(${CMAKE_BUILD_TYPE})
#message(${FREEVPN_OPTION_AES})
## DEBUG FOR CMAKE

if (CMAKE_SYSTEM_PROCESSOR MATCHES "^x86")
	set (OPENSSL_LIB_PATH "x86_64")
endif ()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3456]86")
	set (OPENSSL_LIB_PATH "i686")
endif ()

include_directories (
    "${CMAKE_CURRENT_LIST_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/../Common/"
    "${CMAKE_CURRENT_LIST_DIR}/../Common/SSL/linux/${OPENSSL_LIB_PATH}/include/"
    "${CMAKE_CURRENT_LIST_DIR}/../Common/JWT/"
    "${CMAKE_CURRENT_LIST_DIR}/../Common/JANSSON/"
    "${CMAKE_CURRENT_LIST_DIR}/../include/"
)


add_executable(server  ../src/sn.c
                       ../src/init_script.c
                       ../src/n2n.c
                       ../src/n2n_keyfile.c
                       ../src/transform_null.c
                       ../src/transform_cc20.c
                       ../src/wire.c
                       ../src/cc20.c
                       ../Common/ECDH/curve25519-donna.c
                       ../Common/JWT/jwt.c
                       ../Common/JWT/jwt-openssl.c
                       ../Common/JWT/main-auth.c
                       ../Common/JWT/base64.c
                       ../Common/JANSSON/dump.c
                       ../Common/JANSSON/error.c
                       ../Common/JANSSON/hashtable.c
                       ../Common/JANSSON/hashtable_seed.c
                       ../Common/JANSSON/jansson_memory.c
                       ../Common/JANSSON/load.c
                       ../Common/JANSSON/pack_unpack.c
                       ../Common/JANSSON/strbuffer.c
                       ../Common/JANSSON/strconv.c
                       ../Common/JANSSON/utf.c
                       ../Common/JANSSON/utf.h
                       ../Common/JANSSON/value.c
                       ../Common/JANSSON/version.c
                       ../Common/Cedar/Cedar.c
                        ../Common/Cedar/CedarPch.c
                        ../Common/Cedar/Connection.c
                        ../Common/Cedar/SecureNAT.c
                        ../Common/Cedar/Virtual.c
                        ../Common/Mayaqua/Mayaqua.c
                        ../Common/Mayaqua/Cfg.c
                        ../Common/Mayaqua/Encrypt.c
                        ../Common/Mayaqua/FileIO.c
                        ../Common/Mayaqua/Internat.c
                        ../Common/Mayaqua/Unix.c
                        ../Common/Mayaqua/Kernel.c
                        ../Common/Mayaqua/Memory.c
                        ../Common/Mayaqua/Network.c
                        ../Common/Mayaqua/Object.c
                        ../Common/Mayaqua/OS.c
                        ../Common/Mayaqua/Pack.c
                        ../Common/Mayaqua/Secure.c
                        ../Common/Mayaqua/Str.c
                        ../Common/Mayaqua/Table.c
                        ../Common/Mayaqua/TcpIp.c
                        ../Common/Mayaqua/Tick64.c
                        ../Common/Mayaqua/Tracking.c
                        ${TUNTAP_PATH}/tuntap.c
        )

find_library(dl NAMES dl PATH /usr/lib/x86_64-linux-gnu/libdl.so)

target_link_libraries(server
                             ${CMAKE_CURRENT_LIST_DIR}/../Common/SSL/linux/${OPENSSL_LIB_PATH}/libssl.a
                             ${CMAKE_CURRENT_LIST_DIR}/../Common/SSL/linux/${OPENSSL_LIB_PATH}/libcrypto.a
                             ${dl}
	)

install(TARGETS server
        RUNTIME DESTINATION sbin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
       )
