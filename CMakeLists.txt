cmake_minimum_required(VERSION 3.22)
project(analyzer C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -O0 -fno-omit-frame-pointer -g -DLOG_USE_COLOR")

include_directories(./inc)
include_directories(./inc/ext)

add_executable(
        analyzer main.c
        src/ext/log.c
        src/ext/toml.c
        src/model/conn.c
        src/model/descriptor_cleaner.c
        src/model/ip_set.c
        src/model/packet.c
        src/model/parser.c
        src/model/processor.c
        src/model/reader.c
        src/model/tls_packet.c
        src/model/utils.c
        src/app.c
        src/cli.c
        src/common_processor.c
        src/config.c
        src/domain_processor.c
        src/ip_parser.c
        src/nfqueue.c
        src/nftables.c
        src/retransmit_processor.c
        src/tcp_parser.c
        src/tcp_stream_processor.c
        src/tls_parser.c
)

target_link_libraries(analyzer netfilter_queue nftnl mnl)

install(TARGETS analyzer RUNTIME DESTINATION bin)
