#include <iostream>
#include <openssl/ssl.h>
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <sqlite3.h>
#include <ctime>
#include <sstream>
#include <string>
#include "CheckKey/CheckKey.h"
#include "BanRequest/BanRequest.h"
#include "Imports/Imports.h"
#include <thread>
#include <vector>
#include <cstring> // Include for strerror_s

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#define PORT 8080
#define BUFFER_SIZE 1024

// Function to get expected hash from the database
std::string getExpectedHashFromDatabase() {
    // Example: in practice, this should be fetched from a file or database
    return "de8d9fdbc3414df6208274e85b988128ec09c4cfb897283bf2dee2fe8c209a1f";  // Replace with your actual expected hash
}


#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Assembly/Pe Loader.h"
#include "Assembly/Pe Relocation.h"
#include "Assembly/Pe Remove Header.h"
#include "Assembly/Pe Send to Client.h"
#include "Assembly/PE Find Import References.h"
#include "Assembly/Pe Create Stub Section.h"
#include "Assembly/Pe Create Import Stubs.h"
#include "Assembly/Debug/Pe Save To File.h"
#include "Assembly/Pe Redirect To Stubs.h"
#include "Assembly/Pe Clean IAT.h"

// Assume BUFFER_SIZE is defined appropriately
#define BUFFER_SIZE 1024

void handleClient(SSL* ssl) {
    char buffer[BUFFER_SIZE] = { 0 };
    int bytesReceived;
    std::string response;

    while (true) {
        // Clear the buffer for each new message
        memset(buffer, 0, BUFFER_SIZE);

        // Read data from the client
        bytesReceived = SSL_read(ssl, buffer, BUFFER_SIZE - 1);

        if (bytesReceived <= 0) {
            int ssl_error = SSL_get_error(ssl, bytesReceived);
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                // Connection was closed cleanly by the client
                std::cout << "Client disconnected cleanly." << std::endl;
            }
            else if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                // Non-fatal error, try again
                continue;
            }
            else {
                std::cerr << "SSL read error: " << ssl_error << std::endl;
            }
            break;  // Exit the loop and close the connection
        }

        buffer[bytesReceived] = '\0';
        std::string receivedMessage(buffer);

        std::string hashedHwid;
        std::string key;

        // Process the received message
        // Check if it's a ban request
        if (receivedMessage.find("ban:") == 0) {
            hashedHwid = receivedMessage.substr(4);  // Extract the HWID after "ban:"
            if (banHWID(hashedHwid)) {
                response = "ban success";
            }
            else {
                response = "ban failed";
            }
            SSL_shutdown(ssl);
        }
        // Handle hash check request
        else if (receivedMessage.find("hash:") == 0) {
            std::string clientHash = receivedMessage.substr(5);  // Extract the hash after "hash:"

            // Assume getExpectedHashFromDatabase() is a function that retrieves the expected hash
            std::string expectedHash = getExpectedHashFromDatabase();

            if (clientHash == expectedHash) {
                response = "Hash matches";
                std::cout << "Client hash matches: " << clientHash << std::endl;
            }
            else {
                response = "Hash mismatch";
                std::cerr << "Client hash mismatch. Received: " << clientHash << " Expected: " << expectedHash << std::endl;
                //    SSL_shutdown(ssl);
            }
        }
        else if (receivedMessage.find("key:") == 0) {
            // Remove "key:" prefix
            std::string content = receivedMessage.substr(4);
            // Find the position of the next ":"
            size_t separatorPos = content.find(':');
            if (separatorPos != std::string::npos) {
                // Extract the key and hashed HWID
                std::string key = content.substr(0, separatorPos);
                std::string hashedHwid = content.substr(separatorPos + 1);
                // Remove any trailing newline characters from hashedHwid
                hashedHwid.erase(std::remove(hashedHwid.begin(), hashedHwid.end(), '\n'), hashedHwid.end());
                // Process the key and hashed HWID
                response = checkKeyInAllTables(key, hashedHwid);
                // Send the response FIRST
                int bytesSent = SSL_write(ssl, response.c_str(), response.length());
                if (bytesSent <= 0) {
                    int ssl_error = SSL_get_error(ssl, bytesSent);
                    std::cerr << "SSL write error: " << ssl_error << std::endl;
                    break;
                }
                response = "";

                if (ValidKey) {
                    // 1. Load the PE file to check architecture
                    std::vector<BYTE> peData;
                    if (!LoadPEIntoMemory(applicationId, peData)) {
                        std::cerr << "Failed to load PE file into memory" << std::endl;
                        break;
                    }

                    // 2. Check if it's 32-bit or 64-bit
                    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
                    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(peData.data() + dosHeader->e_lfanew);
                    bool is64Bit = (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

                    // 3. Send architecture info to client (1 for 64-bit, 0 for 32-bit)
                    uint32_t archInfo = is64Bit ? 1 : 0;
                    bytesSent = SSL_write(ssl, &archInfo, sizeof(archInfo));
                    if (bytesSent <= 0) {
                        std::cerr << "Failed to send architecture info" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }
                    std::cout << "Sent architecture info: " << (is64Bit ? "64-bit" : "32-bit") << std::endl;

                    // 4. Request target base address from client
                    std::string targetBaseRequest = "GET_TARGET_BASE";
                    bytesSent = SSL_write(ssl, targetBaseRequest.c_str(), targetBaseRequest.length());
                    if (bytesSent <= 0) {
                        std::cerr << "Failed to send target base request" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    // 5. Receive target base address
                    void* targetBase = nullptr;
                    int bytesReceived = SSL_read(ssl, &targetBase, sizeof(targetBase));
                    if (bytesReceived <= 0) {
                        std::cerr << "Failed to receive target base address" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    std::cout << "Received target base address: 0x" << std::hex << targetBase << std::dec << std::endl;

                    if (!ProcessPEFileFromMemory(applicationId, peData, ssl, targetBase)) {
                        std::cerr << "Failed to process PE file in memory" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    std::vector<ImportReference> importReferences;
                    std::cout << "\n[*] Finding import references for VMP protection..." << std::endl;

                    if (!FindImportReferences(peData, importReferences, is64Bit)) {
                        std::cerr << "Failed to find import references" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    StubSectionInfo stubInfo;
                    if (!CreateStubSection(peData, importReferences, is64Bit, stubInfo)) {
                        std::cerr << "Failed to create stub section" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    if (!CreateImportStubs(peData, importReferences, stubInfo, is64Bit)) {
                        std::cerr << "Failed to create import stubs" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    if (!RedirectImportsToStubs(peData, importReferences, stubInfo, is64Bit)) {
                        std::cerr << "Failed to redirect imports to stubs" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    std::cout << "\n[*] Cleaning IAT..." << std::endl;
                    if (!CleanIAT(peData, importReferences, is64Bit)) {
                        std::cerr << "Failed to clean IAT" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    SavePEToFile(peData, "output_with_stubs.exe");

                    ExtractedPEInfo extractedInfo;
                    if (!ExtractPEInfo(peData, extractedInfo)) {
                        std::cerr << "Failed to extract PE information" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    if (!RemovePEHeaderFromMemory(peData)) {
                        std::cerr << "Failed to remove PE header" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    if (!SendData(ssl, extractedInfo, peData)) {
                        std::cerr << "Failed to send data to client" << std::endl;
                        UnloadPE(applicationId);
                        break;
                    }

                    UnloadPE(applicationId);

                    std::cout << "[+] Successfully completed processing for application ID: " << applicationId << std::endl;
                }
            }
        }

        // Send the response to the client
        int bytesSent = SSL_write(ssl, response.c_str(), response.length());
        if (bytesSent <= 0) {
            int ssl_error = SSL_get_error(ssl, bytesSent);
            if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                std::cout << "Client disconnected during write." << std::endl;
            }
            else {
                std::cerr << "SSL write error: " << ssl_error << std::endl;
            }
            break;
        }

        // Optionally, you can decide whether to keep the connection open based on the message
        // For now, we'll keep the connection open to handle multiple requests
    }

    // Clean up SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
}


int main() {
    SSL_load_error_strings();
    OPENSSL_init_ssl(0, NULL);

#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    int wsaStartupResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaStartupResult != 0) {
        std::cerr << "WSAStartup failed: " << wsaStartupResult << std::endl;
        return 1;
    }
#endif

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Set the certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    int serverFd;
    struct sockaddr_in serverAddr;
    serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
#ifdef _WIN32
        char errorMessage[BUFFER_SIZE];
        strerror_s(errorMessage, sizeof(errorMessage), errno);
#else
        const char* errorMessage = strerror(errno);
#endif
        std::cerr << "Error creating socket: " << errorMessage << std::endl;
        return 1;
    }
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
#ifdef _WIN32
        char errorMessage[BUFFER_SIZE];
        strerror_s(errorMessage, sizeof(errorMessage), errno);
#else
        const char* errorMessage = strerror(errno);
#endif
        std::cerr << "Error binding socket: " << errorMessage << std::endl;
        closesocket(serverFd);
        return 1;
    }
    if (listen(serverFd, 5) < 0) {
#ifdef _WIN32
        char errorMessage[BUFFER_SIZE];
        strerror_s(errorMessage, sizeof(errorMessage), errno);
#else
        const char* errorMessage = strerror(errno);
#endif
        std::cerr << "Error listening on socket: " << errorMessage << std::endl;
        closesocket(serverFd);
        return 1;
    }
    std::cout << "Server listening on port " << PORT << std::endl;

    std::vector<std::thread> threads;

    while (true) {
        struct sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);
        int clientFd = accept(serverFd, (struct sockaddr*)&clientAddr, &clientLen);

        if (clientFd < 0) {
#ifdef _WIN32
            char errorMessage[BUFFER_SIZE];
            strerror_s(errorMessage, sizeof(errorMessage), errno);
#else
            const char* errorMessage = strerror(errno);
#endif
            std::cerr << "Unable to accept client connection: " << errorMessage << std::endl;
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientFd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            closesocket(clientFd);
            continue;
        }

        threads.emplace_back(handleClient, ssl);
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    closesocket(serverFd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
