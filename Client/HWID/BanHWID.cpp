#include "BanHWID.h"

// Assume BUFFER_SIZE is defined appropriately
#define BUFFER_SIZE 1024

// Function to send a ban request using the existing BIO connection
bool SendBanRequest(BIO* bio, const std::string& hwid) {
    VMProtectBeginUltra("SendBanRequest");
    // Ensure the BIO object is valid
    if (!bio) {
        std::cout << (VMProtectDecryptStringA("Invalid BIO object"));
        return false;
    }

    // Prepare the ban request
    std::string banMessage = (VMProtectDecryptStringA("ban:")) + hwid;

    // Send the ban request to the server
    int writeResult = BIO_write(bio, banMessage.c_str(), banMessage.length());
    if (writeResult <= 0) {
        if (!BIO_should_retry(bio)) {
           std::cout << (VMProtectDecryptStringA("Failed to write to server")); 
            ERR_print_errors_fp(stderr);
            return false;
        }
        // Optionally, handle retry logic here
    }

    // Flush the BIO to ensure the data is sent
    if (BIO_flush(bio) <= 0) {
        std::cout << (VMProtectDecryptStringA("Failed to flush BIO"));
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Receive the server's response
    char buffer[BUFFER_SIZE] = { 0 };
    int bytesReceived = BIO_read(bio, buffer, BUFFER_SIZE - 1);
    if (bytesReceived <= 0) {
        if (!BIO_should_retry(bio)) {
            std::cout << (VMProtectDecryptStringA("Failed to receive response from server"));
            ERR_print_errors_fp(stderr);
            return false;
        }
        // Optionally, handle retry logic here
    }

    // Null-terminate and construct the response string
    buffer[bytesReceived] = '\0';
    std::string response(buffer);

    // Determine if the ban request was successful
    if (response == (VMProtectDecryptStringA("ban success"))) {
//        std::cout << (VMProtectDecryptStringA("HWID banned successfully!"));
        exit(234653246);
    }
    else {
//        std::cout << (VMProtectDecryptStringA("Failed to ban HWID!"));
        exit(235626);
    }
    VMProtectEnd();
}
