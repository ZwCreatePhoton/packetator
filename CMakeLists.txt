cmake_minimum_required(VERSION 3.13)
project(packetator)

set(CMAKE_CXX_STANDARD 17)

include(ExternalProject)


set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


file(COPY packetatortots.py DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
file(COPY resources/configs/packetator/L5.yaml DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
file(COPY resources/configs/packetator/L4.yaml DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
file(COPY resources/configs/packetator/L3.yaml DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
file(COPY resources/configs/packetatortots/example_nics.yaml DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
file(COPY resources/configs/packetatortots/example_modes.csv DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})


# CLion is not finding the headers from /usr/include/pcap or /usr/local/include (or any absolute path?) even if we include the directory...
# but CMake still finds it (since the program gets compiled correctly)
# For convenience, lets just copy /usr/include/pcap to include/pcap and /usr/local/include/tins to include/tins ...

include_directories ("submodules/libpcap/pcap")
include_directories ("submodules/libpcap")
#ExternalProject_Add(libpcap
#        PREFIX libpcap
#        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/submodules/libpcap"
#        )

include_directories ("submodules/libtins/include")
OPTION(LIBTINS_BUILD_EXAMPLES "Build examples" ON)
set(LIBTINS_BUILD_EXAMPLES OFF)
OPTION(LIBTINS_BUILD_TESTS "Build tests" ON)
set(LIBTINS_BUILD_TESTS OFF)
OPTION(LIBTINS_BUILD_SHARED "Build libtins as a shared library." ON)
set(LIBTINS_BUILD_SHARED OFF)
add_subdirectory (submodules/libtins)

include_directories ("submodules/tclap/include")

include_directories ("submodules/yaml-cpp/include")
add_subdirectory (submodules/yaml-cpp)

include_directories ("submodules/customhttparser/include")
add_subdirectory (submodules/customhttparser)

include_directories ("submodules/customftparser/include")
add_subdirectory (submodules/customftparser)

include_directories ("include")
add_subdirectory (src)

# tests
include_directories ("submodules/googletest/googletest/include")
include_directories ("submodules/googletest/googlemock/include")
option(INSTALL_GTEST "Enable installation of googletest. (Projects embedding googletest may want to turn this OFF.)" ON)
set(INSTALL_GTEST OFF)
option(gtest_disable_pthreads "Disable uses of pthreads in gtest." OFF)
set(gtest_disable_pthreads ON)
add_subdirectory (submodules/googletest)
add_subdirectory (test)

