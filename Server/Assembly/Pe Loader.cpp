#include "PE Loader.h"

// Thread-safe storage for loaded PEs
static std::unordered_map<int, std::vector<BYTE>> loadedPEs;
static std::mutex peMapMutex;

bool LoadPEIntoMemory(int applicationId, std::vector<BYTE>& peData) {
    try {
        std::string filePath = "Resources\\" + std::to_string(applicationId) + ".exe";

        // Check if already loaded
        {
            std::lock_guard<std::mutex> lock(peMapMutex);
            auto it = loadedPEs.find(applicationId);
            if (it != loadedPEs.end()) {
                peData = it->second;
                std::cout << "[+] PE already loaded for ID: " << applicationId << std::endl;
                return true;
            }
        }

        // Open the file
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "[!] Failed to open file: " << filePath << std::endl;
            return false;
        }

        // Get file size
        size_t fileSize = file.tellg();
        file.seekg(0);

        // Allocate memory
        peData.resize(fileSize);

        // Read file into memory
        file.read(reinterpret_cast<char*>(peData.data()), fileSize);
        file.close();

        // Store in cache
        {
            std::lock_guard<std::mutex> lock(peMapMutex);
            loadedPEs[applicationId] = peData;
        }

        std::cout << "[+] Loaded PE file into memory: " << filePath << " (" << fileSize << " bytes)" << std::endl;

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception loading PE: " << e.what() << std::endl;
        return false;
    }
}

bool GetLoadedPE(int applicationId, std::vector<BYTE>& peData) {
    std::lock_guard<std::mutex> lock(peMapMutex);
    auto it = loadedPEs.find(applicationId);
    if (it != loadedPEs.end()) {
        peData = it->second;
        return true;
    }
    return false;
}

void UnloadPE(int applicationId) {
    std::lock_guard<std::mutex> lock(peMapMutex);
    auto it = loadedPEs.find(applicationId);
    if (it != loadedPEs.end()) {
        loadedPEs.erase(it);
        std::cout << "[+] Unloaded PE for ID: " << applicationId << std::endl;
    }
}

void UnloadAllPEs() {
    std::lock_guard<std::mutex> lock(peMapMutex);
    loadedPEs.clear();
    std::cout << "[+] Unloaded all PEs from memory" << std::endl;
}