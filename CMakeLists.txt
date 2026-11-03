cmake_minimum_required(VERSION 3.20)
project(pp_search LANGUAGES CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()
# Never define NDEBUG: MP-SPDZ's objects are built without it (mixing the two
# in inline templates is an ODR violation), and assertions stay active in
# release builds and tests.
set(CMAKE_CXX_FLAGS_RELEASE "-O3" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g" CACHE STRING "" FORCE)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

# ---- OpenSSL (TLS transport, CSPRNG, SHA-256) --------------------------------
if(APPLE AND NOT OPENSSL_ROOT_DIR)
	execute_process(COMMAND brew --prefix openssl@3
		OUTPUT_VARIABLE PPS_BREW_OPENSSL OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
	if(PPS_BREW_OPENSSL)
		set(OPENSSL_ROOT_DIR "${PPS_BREW_OPENSSL}")
	endif()
endif()
find_package(OpenSSL 3.0 REQUIRED)

include(cmake/MpSpdz.cmake)

# ---- Project code --------------------------------------------------------------
set(PPS_WARNINGS -Wall -Wextra -Wpedantic)

add_library(pps_common STATIC
	src/common/arguments.cpp
	src/common/crypto.cpp
	src/common/json.cpp
	src/net/tls_transport.cpp
	src/net/wire.cpp)
target_include_directories(pps_common PUBLIC src)
target_link_libraries(pps_common PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(pps_common PRIVATE ${PPS_WARNINGS})

pps_add_mpspdz_backend(pps_mpspdz)

add_executable(pp_party
	src/party/main.cpp
	src/party/party_server.cpp
	src/party/party_server_inputs.cpp
	src/party/party_server_outputs.cpp
	src/party/peer_channel.cpp
	src/party/session_stats.cpp)
target_link_libraries(pp_party PRIVATE pps_mpspdz pps_common)
target_compile_options(pp_party PRIVATE ${PPS_WARNINGS})

add_executable(pp_client
	src/client/main.cpp
	src/client/client_common.cpp
	src/client/coordinator.cpp
	src/client/fault_injection.cpp
	src/client/input_owner.cpp)
target_link_libraries(pp_client PRIVATE pps_common)
target_compile_options(pp_client PRIVATE ${PPS_WARNINGS})

# ---- MP-SPDZ bytecode for the exported comparison function --------------------
set(PPS_MPC_OUT "${CMAKE_BINARY_DIR}/mpc")
set(PPS_MPC_STAMP "${PPS_MPC_OUT}/Programs/Schedules/pp_ops.sch")
file(MAKE_DIRECTORY "${PPS_MPC_OUT}")
add_custom_command(
	OUTPUT "${PPS_MPC_STAMP}"
	COMMAND ${CMAKE_COMMAND} -E rm -rf "${PPS_MPC_OUT}/Programs"
	COMMAND ${Python3_EXECUTABLE} "${PPS_MPSPDZ_DIR}/compile.py" -E semi2k -R 128
		"${CMAKE_SOURCE_DIR}/mpc/pp_ops.py"
	WORKING_DIRECTORY "${PPS_MPC_OUT}"
	DEPENDS "${CMAKE_SOURCE_DIR}/mpc/pp_ops.py"
	COMMENT "Compiling MP-SPDZ functions (semi2k, Z_2^128)"
	VERBATIM)
add_custom_target(pp_mpc_programs ALL DEPENDS "${PPS_MPC_STAMP}")

# ---- Tests -----------------------------------------------------------------------
if(BUILD_TESTING)
	add_executable(test_units
		tests/unit/main.cpp
		tests/unit/test_encoding.cpp
		tests/unit/test_search.cpp
		tests/unit/test_wire.cpp)
	target_include_directories(test_units PRIVATE tests)
	target_link_libraries(test_units PRIVATE pps_common)
	target_compile_options(test_units PRIVATE ${PPS_WARNINGS})
	add_test(NAME unit_tests COMMAND test_units)

	pps_add_mpspdz_backend(pps_mpspdz_test_harness PPS_TEST_HARNESS)
	add_executable(test_preprocessing tests/integration/preprocessing_party.cpp)
	target_include_directories(test_preprocessing PRIVATE tests)
	target_link_libraries(test_preprocessing PRIVATE pps_mpspdz_test_harness pps_common)
	target_compile_options(test_preprocessing PRIVATE ${PPS_WARNINGS})

	set(PPS_TEST_ARGS --build-dir "${CMAKE_BINARY_DIR}" --source-dir "${CMAKE_SOURCE_DIR}"
		--mpspdz-dir "${PPS_MPSPDZ_DIR}")
	add_test(NAME preprocessing_two_process
		COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/integration/test_preprocessing.py"
			${PPS_TEST_ARGS})
	add_test(NAME process_integration
		COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/integration/test_processes.py"
			${PPS_TEST_ARGS})
	set_tests_properties(preprocessing_two_process process_integration PROPERTIES
		TIMEOUT 3600 RUN_SERIAL TRUE)
endif()
