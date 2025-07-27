#ifndef SSL_HELPERS_H
#define SSL_HELPERS_H

#include <Windows.h>
#include <openssl/ssl.h>

// SSL communication helpers
bool SSLSendData(SSL* ssl, const void* data, size_t size);
bool SSLReceiveData(SSL* ssl, void* buffer, size_t size);

#endif // SSL_HELPERS_H