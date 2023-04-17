# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

cmake_minimum_required(VERSION 3.12)

# ============= Linktest shared ===============
project(wiretime VERSION 1.0)

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

# ============= Wiretime ===============
project(wiretime VERSION 1.0)

# ---- BUILD ----
add_executable(wiretime)
target_sources(wiretime PRIVATE src/wiretime.c)

target_include_directories(wiretime PUBLIC ${PROJECT_INCLUDES})
target_link_libraries(wiretime PUBLIC pthread link)
m_install(wiretime)

# ============= Configure ===============
configure_file(include/version.h.in include/version.h)

