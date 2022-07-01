cmake_minimum_required(VERSION 3.5)

project(rtp_parser LANGUAGES C)

add_executable(rtp_parser main.c)

target_link_libraries(rtp_parser -lpcap)
