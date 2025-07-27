#include "Stream.h"
#include "../pch.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#define BUFFER_SIZE 1024

bool ReceiveFileStream(BIO* bio, const std::string& outputFileName) {
    VMProtectBeginUltra("ReceiveFileStream");
    try {
        std::vector<char> fileData;
        char buffer[BUFFER_SIZE];
        int totalBytesReceived = 0;

        std::cout << VMProtectDecryptStringA("Receiving file stream...") << std::endl;

        // Keep reading until connection is closed or no more data
        while (true) {
            int bytesReceived = BIO_read(bio, buffer, BUFFER_SIZE);

            if (bytesReceived <= 0) {
                if (BIO_should_retry(bio)) {
                    // Temporary error, try again
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                else {
                    // Connection closed or permanent error
                    break;
                }
            }

            // Append received data to our buffer
            fileData.insert(fileData.end(), buffer, buffer + bytesReceived);
            totalBytesReceived += bytesReceived;

            // Show progress every 64KB
            if (totalBytesReceived % (64 * 1024) == 0) {
                std::cout << VMProtectDecryptStringA("Received: ") << totalBytesReceived << VMProtectDecryptStringA(" bytes") << std::endl;
            }
        }

        if (totalBytesReceived == 0) {
            std::cerr << VMProtectDecryptStringA("No file data received") << std::endl;
            VMProtectEnd();
            return false;
        }

        std::cout << VMProtectDecryptStringA("Total received: ") << totalBytesReceived << VMProtectDecryptStringA(" bytes") << std::endl;

        // Write the received data to file
        std::ofstream outFile(outputFileName, std::ios::binary);
        if (!outFile.is_open()) {
            std::cerr << VMProtectDecryptStringA("Failed to create output file: ") << outputFileName << std::endl;
            VMProtectEnd();
            return false;
        }

        outFile.write(fileData.data(), fileData.size());
        outFile.close();

        std::cout << VMProtectDecryptStringA("File saved as: ") << outputFileName << std::endl;

        VMProtectEnd();
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << VMProtectDecryptStringA("Exception during file reception: ") << e.what() << std::endl;
        VMProtectEnd();
        return false;
    }
}