cmake_minimum_required(VERSION 3.13)
set(CMAKE_CXX_STANDARD 17)

set(PACKETATOR_VERSION_MAJOR 1)
set(PACKETATOR_VERSION_MINOR 0)
set(PACKETATOR_VERSION_PATCH 0)
set(PACKETATOR_VERSION "${PACKETATOR_VERSION_MAJOR}.${PACKETATOR_VERSION_MINOR}.${PACKETATOR_VERSION_PATCH}")
project("packetator"
        VERSION ${PACKETATOR_VERSION}
        DESCRIPTION "A stateful packet replayer"
        )
option(PACKETATOR_BUILD_TESTS "Build tests" OFF)




# BUILD/INSTALL

include(GNUInstallDirs)

# libtins
option(LIBTINS_BUILD_EXAMPLES "Build examples" ON)
option(LIBTINS_BUILD_TESTS "Build tests" ON)
option(LIBTINS_BUILD_SHARED "Build libtins as a shared library." ON)
option(LIBTINS_ENABLE_CXX11 "Compile libtins with c++11 features" ON)
option(LIBTINS_ENABLE_DOT11 "Compile libtins with IEEE 802.11 support" ON)
option(LIBTINS_ENABLE_WPA2 "Compile libtins with WPA2 decryption features (requires OpenSSL)" ON)
option(LIBTINS_ENABLE_ACK_TRACKER "Enable TCP ACK tracking support" ON)
option(LIBTINS_ENABLE_TCP_STREAM_CUSTOM_DATA "Enable TCP stream custom data support" ON)
set(LIBTINS_BUILD_EXAMPLES OFF)
set(LIBTINS_BUILD_TESTS OFF)
set(LIBTINS_BUILD_SHARED OFF)
set(LIBTINS_ENABLE_CXX11 ON)
set(LIBTINS_ENABLE_ACK_TRACKER OFF)
set(LIBTINS_ENABLE_TCP_STREAM_CUSTOM_DATA OFF)
# Setting OPENSSL variables to empty strings is needed when this is true: !(LIBTINS_ENABLE_DOT11 & LIBTINS_ENABLE_WPA2)
set(OPENSSL_INCLUDE_DIR "")
set(OPENSSL_LIBRARIES "")
set(LIBTINS_ENABLE_DOT11 OFF)
set(LIBTINS_ENABLE_WPA2 OFF)
include_directories ("external/libtins/include")
add_subdirectory (external/libtins EXCLUDE_FROM_ALL)

# tclap
include_directories ("external/tclap/include")

# yaml-cpp
include_directories ("external/yaml-cpp/include")
add_subdirectory (external/yaml-cpp EXCLUDE_FROM_ALL)

# customhttparser
include_directories ("external/customhttparser/include")
add_subdirectory (external/customhttparser EXCLUDE_FROM_ALL)

# cutomftparser
include_directories ("external/customftparser/include")
add_subdirectory (external/customftparser EXCLUDE_FROM_ALL)

# packetator
include_directories ("include")
add_subdirectory (src)
install(
        TARGETS packetator
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
# documentation files
install(
        DIRECTORY doc/
        DESTINATION "${CMAKE_INSTALL_DOCDIR}"
        )
# supporting files
install(
        DIRECTORY config
        DESTINATION "${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}"
)


# TESTS

IF(PACKETATOR_BUILD_TESTS)
    IF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/googletest/CMakeLists.txt")
        message(STATUS "Building tests.")
        include_directories ("external/googletest/googletest/include")
        include_directories ("external/googletest/googlemock/include")
        option(INSTALL_GTEST "Enable installation of googletest. (Projects embedding googletest may want to turn this OFF.)" ON)
        set(INSTALL_GTEST OFF)
        option(gtest_disable_pthreads "Disable uses of pthreads in gtest." OFF)
        set(gtest_disable_pthreads ON)
        add_subdirectory (external/googletest EXCLUDE_FROM_ALL)
        add_subdirectory (test)
    ELSE()
        message(STATUS "googletest git submodule is missing. Skipping building of tests")
    ENDIF()
ENDIF()



# CPACK

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VENDOR "ZwCreatePhoton")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Stateful Packet Replayer")
set(CPACK_PACKAGE_INSTALL_DIRECTORY ${CPACK_PACKAGE_NAME})
set(CPACK_OUTPUT_FILE_PREFIX "packages")
set(CPACK_PACKAGING_INSTALL_PREFIX "/opt/${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_VERBATIM_VARIABLES YES)

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_CONTACT "ZwCreatePhoton@gmail.com")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "ZwCreatePhoton")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/doc/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/doc/README.md")

set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

include(CPack)
