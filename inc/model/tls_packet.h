#pragma once

#include <stdbool.h>
#include <stdint.h>

#define TLS_MAJOR_VERSION 3
#define TLS_MINOR_VERSION_MAX 3

#define TLS_EXTENSION_SERVER_NAME_CAP 2
#define TLS_EXTENSION_SERVER_NAME_LEN 255

#define normalize_tls_handshake_len(LEN) (ntohl((LEN)) >> 8)

typedef enum __attribute__((__packed__)) {
    tls_content_type_change_cipher_spec = 0x14,
    tls_content_type_alert = 0x15,
    tls_content_type_handshake = 0x16,
    tls_content_type_application_data = 0x17,
    tls_content_type_heartbeat = 0x18
} tls_content_type_t;

typedef enum __attribute__((__packed__)) {
    tls_handshake_type_encrypted_message = 0x00,
    tls_handshake_type_client_hello = 0x01,
    tls_handshake_type_server_hello = 0x02,
} tls_handshake_type_t;

typedef enum __attribute__((__packed__)) {
    tls_extension_server_name = 0x00,
    tls_extension_reserved = 0xffff,
} tls_extension_type_t;

typedef struct __attribute__((__packed__)) {
    uint8_t major;
    uint8_t minor;
} tls_version_t;

typedef struct __attribute__((__packed__)) {
    tls_content_type_t content_type;
    tls_version_t version;
    uint16_t length;
} tls_header_t;

typedef struct __attribute__((__packed__)) {
    tls_handshake_type_t type;
    uint32_t length: 24;
} tls_handshake_header_t;

typedef struct __attribute__((__packed__)) {
    tls_extension_type_t type;
    uint16_t length;
} tls_extension_header_t;

typedef struct {
    uint16_t len;
    char sni[TLS_EXTENSION_SERVER_NAME_CAP][TLS_EXTENSION_SERVER_NAME_LEN];
} tls_extension_server_name_t;

bool tls_header_valid(const tls_header_t *hdr);
