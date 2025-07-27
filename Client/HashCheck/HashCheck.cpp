#include "HashCheck.h"


#define BUFFER_SIZE 1024

// Assuming these functions exist in your code
std::vector<BYTE> ComputeSHA256Hash(const std::wstring& exePath);
std::string HashToString(const std::vector<BYTE>& hash);

// Function to send the computed hash to the server and receive the response
std::string sendHashToServer(BIO* bio, const std::string& hashToSend) {
    VMProtectBeginUltra("sendHashToServer");
    // Ensure the BIO object is valid
    if (!bio) {
        std::cout << (VMProtectDecryptStringA("Invalid BIO object"));
        return "";
    }

    // Send the computed hash to the server
    std::string message = (VMProtectDecryptStringA("hash:")) + hashToSend;  // Prefix the hash with "hash:"
    int writeResult = BIO_write(bio, message.c_str(), message.length());
    if (writeResult <= 0) {
        if (!BIO_should_retry(bio)) {
            //            std::cout << (VMProtectDecryptStringA("Failed to write to server"));
            ERR_print_errors_fp(stderr);
            return "";
        }
        // Handle retry logic if necessary
    }

    // Flush the BIO to ensure the data is sent
    if (BIO_flush(bio) <= 0) {
        //        std::cout << (VMProtectDecryptStringA("Failed to flush BIO"));
        ERR_print_errors_fp(stderr);
        return "";
    }

    // Receive the server's response
    char buffer[BUFFER_SIZE] = { 0 };
    int bytesReceived = BIO_read(bio, buffer, BUFFER_SIZE - 1);
    if (bytesReceived <= 0) {
        if (!BIO_should_retry(bio)) {
            //            std::cout << (VMProtectDecryptStringA("Failed to receive response from server"));
            ERR_print_errors_fp(stderr);
            return "";
        }
        // Handle retry logic if necessary
    }

    // Null-terminate and construct the response string
    buffer[bytesReceived] = '\0';
    std::string response(buffer);

    return response;
    VMProtectEnd();
}

void HashCheck(BIO* bio) {
    VMProtectBeginUltra("HashCheck");
    // Define paths
    std::wstring exePath = (L"LoaderP2C.exe");  // Replace with your executable path

    // Compute the SHA-256 hash of the executable
    std::vector<BYTE> hash = ComputeSHA256Hash(exePath);
    if (!hash.empty()) {
        std::string currentHashStr = HashToString(hash);

        // Debug output for computed hash
//        std::cout << ("Computed Hash: ") << currentHashStr << std::endl;

        // Send the computed hash to the server for verification
        std::string serverResponse = sendHashToServer(bio, currentHashStr);

        // Output the server's response
        if (!serverResponse.empty()) {
//            std::cout << "Server Response: " << serverResponse << std::endl;
        }
        else {
            std::cout << (VMProtectDecryptStringA("Failed to get a response from the server."));
        }

        // Additional decision based on the server's response (optional)
        if (serverResponse == (VMProtectDecryptStringA("Hash matches"))) {
//            std::cout << ("Server confirms the executable is unmodified.") << std::endl;
        }
        else {
            std::cout << (VMProtectDecryptStringA("Server detected modification in the executable!"));
         //   system("timeout /t 5 >nul");
         //   exit(1543);
        }
    }
    VMProtectEnd();
}