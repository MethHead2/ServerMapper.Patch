#ifndef BanHWID_H
#define BanHWID_H

#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include "../pch.h"


// Constants for server communication
#define PORT 8080
#define BUFFER_SIZE 1024

// Function to send a ban request for the given HWID to the server
// @param hwid - The hashed HWID string to be banned
// @return - Returns true if the HWID was banned successfully, false otherwise
bool SendBanRequest(BIO* bio, const std::string& hwid);

#endif 