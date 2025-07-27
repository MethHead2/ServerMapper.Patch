#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <atomic>
#include <vector>
#include <thread>
#include <chrono>

#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "ws2_32.lib")

#include "Stream/Stream.h"
#include "MemoryLoader/MemoryLoader.h"
#include "HWID/GetHWID.h"
#include "HWID/BanHWID.h"
#include "HashCheck/HashCheck.h"
#include "GetHash/Integrity.h"
#include "GetHash/HashUtils.h"
#include "Anti-tamper/Sha Implementation.h"
#include "Stream/ImportHandler.h"


#define PORT 8080
#define BUFFER_SIZE 1024


// This line will be replaced by the server with the user's key
const std::string LICENSE_KEY = VMProtectDecryptStringA("F06080BCBFC71255-C153819F79CEBEB4-3D64FF3D51F8A499-B1615521559A2E51-89DEE8E0BA1A11EA");

std::vector<BYTE> ComputeSHA256Hash(const std::wstring& filePath);
std::vector<BYTE> ComputeSHA256Hash(const std::string& filePath);
std::string HashToString(const std::vector<BYTE>& hash);
std::string ReadExpectedHash(const std::string& filePath);

std::atomic<bool> key_entered(false);

void CheckServerResponse(const std::string& serverResponse, BIO* bio) {
    VMProtectBeginUltra("ServerResponse");
    if (serverResponse.find((VMProtectDecryptStringA("valid_key"))) != std::string::npos) {
        std::cout << (VMProtectDecryptStringA("Welcome to XXX!")) << std::endl;
        std::cout << (VMProtectDecryptStringA("Loading executable...")) << std::endl;

        std::cout << (VMProtectDecryptStringA("Processing server requests...")) << std::endl;
        if (!HandleServerImportRequests(bio)) {
            std::cerr << (VMProtectDecryptStringA("Failed to handle import resolution")) << std::endl;
            BIO_free_all(bio);
        }

        HeaderlessExecutable executable;
        if (LoadHeaderlessExecutableFromStream(bio, executable)) {
            std::cout << (VMProtectDecryptStringA("Executing...")) << std::endl;
            ExecuteHeaderlessExecutable(executable);
            UnloadHeaderlessExecutable(executable);
        }
        else {
            std::cerr << (VMProtectDecryptStringA("Failed to load executable")) << std::endl;
        }
    }
    else if (serverResponse == (VMProtectDecryptStringA("user is banned"))) {
        std::cout << (VMProtectDecryptStringA("Banned HWID!")) << std::endl;
        std::cout << (VMProtectDecryptStringA("Create a ticket on our discord")) << std::endl;
        system((VMProtectDecryptStringA("timeout /t 5 >nul")));
        exit(1543);
    }
    else if (serverResponse == (VMProtectDecryptStringA("invalid HWID"))) {
        std::cout << (VMProtectDecryptStringA("Invalid HWID!")) << std::endl;
        std::cout << (VMProtectDecryptStringA("Create a ticket on our discord")) << std::endl;
        system((VMProtectDecryptStringA("timeout /t 5 >nul")));
        exit(1543);
    }
    else if (serverResponse == (VMProtectDecryptStringA("key_expired"))) {
        std::cout << (VMProtectDecryptStringA("Key has expired!")) << std::endl;
        system((VMProtectDecryptStringA("timeout /t 5 >nul")));
        exit(1543);
    }
    else if (serverResponse == (VMProtectDecryptStringA("key_invalid"))) {
        std::cout << (VMProtectDecryptStringA("Invalid Key!")) << std::endl;
        system((VMProtectDecryptStringA("timeout /t 5 >nul")));
        exit(1543);
    }
    else {
        std::cout << (VMProtectDecryptStringA("Unknown response: ")) << serverResponse << std::endl;
        system((VMProtectDecryptStringA("timeout /t 5 >nul")));
        exit(1543);
    }
    VMProtectEnd();
}

int main()
{
    VMProtectBeginUltra("MainFunction");
    SetConsoleTitleA((VMProtectDecryptStringA(" ")));

    unsigned char* HashFunctionPtr = reinterpret_cast<unsigned char*>(&HashCheck);
    size_t HashFunctionSize = 1024;
    std::string hashBefore = computeHash(HashFunctionPtr, HashFunctionSize);

    unsigned char* AuthFunctionPtr = reinterpret_cast<unsigned char*>(&CheckServerResponse);
    size_t AuthFunctionSize = 1024;
    std::string AuthhashBefore = AuthcomputeHash(AuthFunctionPtr, AuthFunctionSize);

    auto hwids = GetHWIDs();
    std::string combinedHwid;
    for (const auto& hwid : hwids) {
        combinedHwid += hwid;
    }
    std::string hashedHwid = HashHWID(combinedHwid);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << (VMProtectDecryptStringA("Unable to create SSL context")) << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL* ssl;
    BIO* bio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        std::cerr << (VMProtectDecryptStringA("Unable to allocate SSL structure")) << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    BIO_set_conn_hostname(bio, (VMProtectDecryptStringA("127.0.0.1:8080")));

    if (BIO_do_connect(bio) <= 0) {
        std::cerr << (VMProtectDecryptStringA("Failed to connect to server")) << std::endl;
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    // HashCheck(bio);

    std::string hashAfter = computeHash(HashFunctionPtr, HashFunctionSize);
    std::cout << (VMProtectDecryptStringA("Hash after execution: ")) << hashAfter << std::endl;

    if (hashBefore == hashAfter) {
        // No tampering detected
    }
    if (hashBefore != hashAfter) {
        SendBanRequest(bio, hashedHwid);
    }

    // Use the embedded LICENSE_KEY instead of getting it from user input
    std::string message = (VMProtectDecryptStringA("key:")) + LICENSE_KEY + (VMProtectDecryptStringA(":")) + hashedHwid + (VMProtectDecryptStringA("\n"));

    int writeResult = BIO_write(bio, message.c_str(), message.length());
    if (writeResult <= 0) {
        if (!BIO_should_retry(bio)) {
            std::cerr << (VMProtectDecryptStringA("Failed to send key and HWID to server")) << std::endl;
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }

    if (BIO_flush(bio) <= 0) {
        std::cout << (VMProtectDecryptStringA("Failed to flush BIO after sending key and HWID"));
        ERR_print_errors_fp(stderr);
        return 1;
    }

    char buffer[BUFFER_SIZE] = { 0 };
    int bytesReceived = BIO_read(bio, buffer, BUFFER_SIZE - 1);
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        std::string serverResponse(buffer);
        CheckServerResponse(serverResponse, bio);  // Pass bio parameter for file reception
    }
    else {
        if (!BIO_should_retry(bio)) {
            std::cerr << (VMProtectDecryptStringA("Failed to read response from server after sending key and HWID")) << std::endl;
            ERR_print_errors_fp(stderr);
            return 1;
        }
    }

    std::string AuthhashAfter = AuthcomputeHash(AuthFunctionPtr, AuthFunctionSize);

    if (AuthhashBefore == AuthhashAfter) {
        // No tampering detected
    }
    if (AuthhashBefore != AuthhashAfter) {
        SendBanRequest(bio, hashedHwid);
    }

    system((VMProtectDecryptStringA("pause")));

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
    VMProtectEnd();
}