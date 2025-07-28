#include "SSLHelpers.h"

bool SSLSendData(SSL* ssl, const void* data, size_t size) {
    const BYTE* bytes = static_cast<const BYTE*>(data);
    size_t sent = 0;
    while (sent < size) {
        int result = SSL_write(ssl, bytes + sent, static_cast<int>(size - sent));
        if (result <= 0) return false;
        sent += result;
    }
    return true;
}

bool SSLReceiveData(SSL* ssl, void* buffer, size_t size) {
    BYTE* bytes = static_cast<BYTE*>(buffer);
    size_t received = 0;
    while (received < size) {
        int result = SSL_read(ssl, bytes + received, static_cast<int>(size - received));
        if (result <= 0) return false;
        received += result;
    }
    return true;
}