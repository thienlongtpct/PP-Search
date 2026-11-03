# Locates the pinned MP-SPDZ build and defines pps_add_mpspdz_backend().

# Built by scripts/build_mpspdz.sh; the checkout must match third_party/mp-spdz.lock.
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

# Builds the MP-SPDZ-backed SecureOps implementation, optionally with the
# test-harness-only triple opening compiled in.
function(pps_add_mpspdz_backend name)
	add_library(${name} STATIC src/backend/mpspdz_party.cpp)
	target_include_directories(${name} PUBLIC src)
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
