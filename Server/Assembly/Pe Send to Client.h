#ifndef DATA_SENDER_H
#define DATA_SENDER_H

#include <Windows.h>
#include <vector>
#include <openssl/ssl.h>
#include "Pe Extract Info.h"

// Send PE data to client using pre-extracted information
// peData should be the PE data after removing first 1024 bytes
bool SendData(SSL* ssl, const ExtractedPEInfo& extractedInfo, const std::vector<BYTE>& peData);

#endif // DATA_SENDER_H