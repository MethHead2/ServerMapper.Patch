#include "PE Remove Header.h"
#include <iostream>
#include <algorithm>

bool RemovePEHeaderFromMemory(std::vector<BYTE>& peData) {
    try {
        // Check if file is larger than 1024 bytes
        if (peData.size() <= 1024) {
            std::cerr << "[!] PE too small to remove header (size: " << peData.size() << " bytes)" << std::endl;
            return false;
        }

        // Calculate remaining data size after removing header
        size_t originalSize = peData.size();
        size_t remainingSize = originalSize - 1024;

        // Remove first 1024 bytes by erasing them
        peData.erase(peData.begin(), peData.begin() + 1024);

        std::cout << "[+] Successfully removed PE header from memory" << std::endl;
        std::cout << "    Original size: " << originalSize << " bytes" << std::endl;
        std::cout << "    New size: " << peData.size() << " bytes" << std::endl;
        std::cout << "    Removed: 1024 bytes (PE header)" << std::endl;

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception during PE header removal: " << e.what() << std::endl;
        return false;
    }
}