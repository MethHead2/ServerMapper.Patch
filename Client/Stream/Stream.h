#ifndef FILERECEIVER_H
#define FILERECEIVER_H

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <string>

// Function to receive streamed file data from server
bool ReceiveFileStream(BIO* bio, const std::string& outputFileName);

#endif // FILERECEIVER_H