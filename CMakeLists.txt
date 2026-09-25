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

# ---- MP-SPDZ backend (built by scripts/build_mpspdz.sh) ----------------------
set(PPS_MPSPDZ_DIR "${CMAKE_SOURCE_DIR}/third_party/mp-spdz" CACHE PATH
	"MP-SPDZ checkout built by scripts/build_mpspdz.sh")
set(PPS_MPSPDZ_ARCHIVE "${PPS_MPSPDZ_DIR}/libpps_mpspdz.a")
if(NOT EXISTS "${PPS_MPSPDZ_ARCHIVE}" OR NOT EXISTS "${PPS_MPSPDZ_DIR}/pps-cflags.txt")
	message(FATAL_ERROR
		"MP-SPDZ backend not found in ${PPS_MPSPDZ_DIR}. "
		"Run scripts/build_mpspdz.sh first (pinned in third_party/mp-spdz.lock).")
endif()
file(STRINGS "${CMAKE_SOURCE_DIR}/third_party/mp-spdz.lock" PPS_LOCK_COMMIT REGEX "^commit ")
string(REGEX REPLACE "^commit " "" PPS_LOCK_COMMIT "${PPS_LOCK_COMMIT}")
execute_process(COMMAND git -C "${PPS_MPSPDZ_DIR}" rev-parse HEAD
	OUTPUT_VARIABLE PPS_MPSPDZ_HEAD OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT PPS_MPSPDZ_HEAD STREQUAL PPS_LOCK_COMMIT)
	message(FATAL_ERROR "MP-SPDZ checkout is at ${PPS_MPSPDZ_HEAD}, lock requires ${PPS_LOCK_COMMIT}")
endif()

file(READ "${PPS_MPSPDZ_DIR}/pps-cflags.txt" PPS_MPSPDZ_CFLAGS_RAW)
separate_arguments(PPS_MPSPDZ_CFLAGS_LIST UNIX_COMMAND "${PPS_MPSPDZ_CFLAGS_RAW}")
set(PPS_MPSPDZ_COMPILE_OPTIONS)
set(PPS_MPSPDZ_INCLUDES)
foreach(flag IN LISTS PPS_MPSPDZ_CFLAGS_LIST)
	if(flag MATCHES "^-I(.*)$")
		set(path "${CMAKE_MATCH_1}")
		if(NOT IS_ABSOLUTE "${path}")
			get_filename_component(path "${PPS_MPSPDZ_DIR}/${path}" ABSOLUTE)
		endif()
		list(APPEND PPS_MPSPDZ_INCLUDES "${path}")
	elseif(flag MATCHES "^-D(PREP_DIR|SSL_DIR)=")
		# re-added below with correct string quoting
	elseif(flag MATCHES "^-std=|^-Werror$|^-MMD$|^-MP$|^-O[0-3s]$|^-g$")
		# language level, optimisation and warning policy come from this project
	else()
		list(APPEND PPS_MPSPDZ_COMPILE_OPTIONS "${flag}")
	endif()
endforeach()

file(READ "${PPS_MPSPDZ_DIR}/pps-ldlibs.txt" PPS_MPSPDZ_LDLIBS_RAW)
separate_arguments(PPS_MPSPDZ_LDLIBS_LIST UNIX_COMMAND "${PPS_MPSPDZ_LDLIBS_RAW}")
# MP-SPDZ code is linked statically; drop its "-Wl,-rpath -Wl,<dir>" pairs.
set(PPS_MPSPDZ_LDLIBS)
set(pps_skip_next FALSE)
foreach(flag IN LISTS PPS_MPSPDZ_LDLIBS_LIST)
	if(pps_skip_next)
		set(pps_skip_next FALSE)
	elseif(flag STREQUAL "-Wl,-rpath")
		set(pps_skip_next TRUE)
	else()
		list(APPEND PPS_MPSPDZ_LDLIBS "${flag}")
	endif()
endforeach()
file(READ "${PPS_MPSPDZ_DIR}/pps-libsimpleot.txt" PPS_MPSPDZ_SIMPLEOT_RAW)
separate_arguments(PPS_MPSPDZ_SIMPLEOT_REL UNIX_COMMAND "${PPS_MPSPDZ_SIMPLEOT_RAW}")
set(PPS_MPSPDZ_SIMPLEOT)
foreach(lib IN LISTS PPS_MPSPDZ_SIMPLEOT_REL)
	list(APPEND PPS_MPSPDZ_SIMPLEOT "${PPS_MPSPDZ_DIR}/${lib}")
endforeach()

# ---- Project code --------------------------------------------------------------
set(PPS_WARNINGS -Wall -Wextra -Wpedantic)

add_library(pps_common STATIC src/wire.cpp src/tls_transport.cpp src/util.cpp)
target_include_directories(pps_common PUBLIC include)
target_link_libraries(pps_common PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(pps_common PRIVATE ${PPS_WARNINGS})

# Builds the MP-SPDZ-backed SecureOps implementation, optionally with the
# test-harness-only triple opening compiled in.
function(pps_add_mpspdz_backend name)
	add_library(${name} STATIC src/mpspdz_party.cpp)
	target_include_directories(${name} PUBLIC include)
	target_include_directories(${name} SYSTEM PRIVATE ${PPS_MPSPDZ_INCLUDES})
	target_compile_options(${name} PRIVATE ${PPS_MPSPDZ_COMPILE_OPTIONS})
	target_compile_definitions(${name} PRIVATE PREP_DIR="Player-Data/" SSL_DIR="Player-Data/")
	target_compile_definitions(${name} PUBLIC ${ARGN})
	target_link_libraries(${name} PUBLIC
		"${PPS_MPSPDZ_ARCHIVE}"
		${PPS_MPSPDZ_SIMPLEOT}
		"${PPS_MPSPDZ_DIR}/local/lib/liblibOTe.a"
		"${PPS_MPSPDZ_DIR}/local/lib/libcryptoTools.a"
		${PPS_MPSPDZ_LDLIBS})
endfunction()

pps_add_mpspdz_backend(pps_mpspdz)

add_executable(pp_party src/party_main.cpp)
target_link_libraries(pp_party PRIVATE pps_mpspdz pps_common)
target_compile_options(pp_party PRIVATE ${PPS_WARNINGS})

add_executable(pp_client src/client_main.cpp)
target_link_libraries(pp_client PRIVATE pps_common)
target_compile_options(pp_client PRIVATE ${PPS_WARNINGS})

# ---- MP-SPDZ bytecode for the exported comparison/truncation functions --------
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
	add_executable(test_units tests/test_units.cpp)
	target_link_libraries(test_units PRIVATE pps_common)
	target_compile_options(test_units PRIVATE ${PPS_WARNINGS})
	add_test(NAME unit_tests COMMAND test_units)

	pps_add_mpspdz_backend(pps_mpspdz_test_harness PPS_TEST_HARNESS)
	add_executable(test_preprocessing tests/test_preprocessing.cpp)
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
