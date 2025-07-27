#ifndef HASHCHECK_H
#define HASHCHECK_H

#include "../HWID/BanHWID.h"
#include "../HWID/GetHWID.h"
#include <iostream>
#include <vector>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ws2tcpip.h>
#include <openssl/bio.h>
#include "../pch.h"

#define SERVER_IP "127.0.0.1"  
#define SERVER_PORT 8080
#define BUFFER_SIZE 1024

// Function to send a ban request for the given HWID to the server
// @param hwid - The hashed HWID string to be banned
// @return - Returns true if the HWID was banned successfully, false otherwise

void HashCheck(BIO* bio);

#endif 