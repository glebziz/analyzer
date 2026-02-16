#include "model/tls_packet.h"

bool tls_header_valid(const tls_header_t *hdr) {
    switch (hdr->content_type) {
        case tls_content_type_change_cipher_spec:
        case tls_content_type_alert:
        case tls_content_type_handshake:
        case tls_content_type_application_data:
        case tls_content_type_heartbeat:
            break;
        default:
            return false;
    }

    if (hdr->version.major != TLS_MAJOR_VERSION || hdr->version.minor > TLS_MINOR_VERSION_MAX) {
        return false;
    }

    return true;
}
