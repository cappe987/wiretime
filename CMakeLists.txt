# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

cmake_minimum_required(VERSION 3.12)

# ============= Linktest shared ===============
project(tslm VERSION 1.0)

add_library(link STATIC include/liblink.h src/liblink.c)
target_include_directories(link PUBLIC ${PROJECT_SOURCE_DIR}/include/)

macro(m_install)
	install(TARGETS ${arg1}
		CONFIGURATIONS Debug
		RUNTIME DESTINATION bin)
	install(TARGETS ${arg1}
		CONFIGURATIONS Release
		RUNTIME DESTINATION bin)
endmacro()

set(PROJECT_INCLUDES ${PROJECT_SOURCE_DIR}/include ${PROJECT_BINARY_DIR}/include)

# ============= latency ===============
project(tslm VERSION 1.0)

# ---- BUILD ----
add_executable(tslm)
target_sources(tslm PRIVATE src/latency.c)

target_include_directories(tslm PUBLIC ${PROJECT_INCLUDES})
target_link_libraries(tslm PUBLIC pthread link)
m_install(tslm)

# ============= Configure ===============
configure_file(include/version.h.in include/version.h)

