cmake_minimum_required(VERSION 3.12)
include(GNUInstallDirs)

set(APP_NAME "uFastAuthD2")
set(SVERSION 2.0.0)

project(${APP_NAME})
project(${PROJECT_NAME} VERSION ${SVERSION} DESCRIPTION "Unmanarc's Fast Authentication Daemon 2")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

configure_file(src/config.h.in ${${APP_NAME}_SOURCE_DIR}/src/config.h)

file(GLOB_RECURSE EDV_INCLUDE_FILES "src/*.h*")
file(GLOB_RECURSE EDV_SOURCE_FILES "src/*.c*")
add_executable( ${APP_NAME} ${EDV_INCLUDE_FILES} ${EDV_SOURCE_FILES} )

install( TARGETS ${APP_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} )

if (EXTRAPREFIX)
    target_include_directories(${APP_NAME} PUBLIC ${EXTRAPREFIX}/include)
    target_link_libraries(${APP_NAME} "-L${EXTRAPREFIX}/lib")
    target_link_libraries(${APP_NAME} "-L${EXTRAPREFIX}/lib64")
endif()

if (CMAKE_INSTALL_PREFIX)
    target_include_directories(${APP_NAME} PUBLIC ${CMAKE_INSTALL_PREFIX}/include)
    target_include_directories(${APP_NAME} PUBLIC ${CMAKE_INSTALL_PREFIX}/usr/include)
    target_link_libraries(${APP_NAME} "-L${CMAKE_INSTALL_PREFIX}/lib")
    target_link_libraries(${APP_NAME} "-L${CMAKE_INSTALL_PREFIX}/lib64")
endif()

# Find Mantids29 package using pkg-config
find_package(PkgConfig REQUIRED)

# List of Mantids29 libraries to link against
set(MANTIDS29_LIBRARIES
    Mantids29_Protocol_FastRPC1
    Mantids29_Server_MonolithWebAPI
    Mantids29_API_Core
    Mantids29_API_Templates
    Mantids29_Auth
    Mantids29_Auth_DB
    Mantids29_DB
    Mantids29_DB_SQLite3
    Mantids29_Protocol_HTTP
    Mantids29_Protocol_MIME
    Mantids29_Net_Sockets
    Mantids29_Threads
    Mantids29_Program_Service
    Mantids29_Program_Logs
    Mantids29_Memory
    Mantids29_Helpers
)

set(ENV{PKG_CONFIG_PATH} "/opt/osslibsl64d/share/pkgconfig:$ENV{PKG_CONFIG_PATH}")

# Iterate over the list of Mantids29 libraries and add include directories and linker flags to the target
foreach(LIBRARY ${MANTIDS29_LIBRARIES})
    # Find the library using pkg-config
    pkg_check_modules(${LIBRARY} REQUIRED ${LIBRARY})
    # Add include directory to target
    target_include_directories(${APP_NAME} PUBLIC ${${LIBRARY}_INCLUDEDIR})
    # Link target against the library
    target_link_libraries(${APP_NAME} ${${LIBRARY}_LDFLAGS})
endforeach()

target_link_libraries(${APP_NAME} "-lsqlite3")
target_link_libraries(${APP_NAME} "-ljsoncpp")

option(SSLRHEL7 "OpenSSL 1.1 For Red Hat 7.x provided by EPEL" OFF)
find_package(PkgConfig REQUIRED)
if (SSLRHEL7)
    pkg_check_modules(OPENSSL REQUIRED libssl11)
else()
    pkg_check_modules(OPENSSL REQUIRED libssl)
endif()
target_include_directories(${APP_NAME} PUBLIC ${OPENSSL_INCLUDE_DIRS})
target_compile_options(${APP_NAME} PUBLIC ${OPENSSL_CFLAGS_OTHER})
target_link_libraries(${APP_NAME} ${OPENSSL_STATIC_LDFLAGS})

if (WIN32)
    target_link_libraries(${APP_NAME} "-lboost_regex-mt")
else()
    target_link_libraries(${APP_NAME} "-lboost_regex")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
link_libraries(${JSONCPP_LIBRARIES})
target_include_directories(${APP_NAME} PUBLIC ${JSONCPP_INCLUDE_DIRS})
target_link_libraries(${APP_NAME} ${JSONCPP_LIBRARIES})
