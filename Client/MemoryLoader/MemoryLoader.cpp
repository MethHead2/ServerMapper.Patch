#include "MemoryLoader.h"
#include <iostream>
#include <iomanip>

// External reference to ImportHandler instance
extern ImportHandler* g_handlerInstance;

// Define SectionInfo structure to match old project
struct SectionInfo {
    std::vector<BYTE> data;
    uintptr_t virtualAddress;
    size_t virtualSize;
    DWORD protection;
    bool isCode;
    bool isShared;
    std::string name;
};

// Function to map a section exactly like the old project
bool MapSection(HANDLE processHandle, void* baseAddress, size_t imageSize, const SectionInfo& section) {
    std::cout << "MapSection: Starting for VA: " << std::hex << section.virtualAddress << std::endl;

    if (!baseAddress || !processHandle) {
        std::cout << "Invalid base address or process handle" << std::endl;
        return false;
    }

    // Validate the section
    if (section.virtualAddress + section.virtualSize > imageSize) {
        std::cout << "Section extends beyond allocated memory" << std::endl;
        return false;
    }

    // Calculate destination address
    void* destAddress = (BYTE*)baseAddress + section.virtualAddress;

    // First zero the memory region
    std::vector<BYTE> zeroBuffer(section.virtualSize, 0);
    SIZE_T bytesWritten;

    if (!WriteProcessMemory(
        processHandle,
        destAddress,
        zeroBuffer.data(),
        section.virtualSize,
        &bytesWritten
    ) || bytesWritten != section.virtualSize) {
        std::cout << "Failed to zero memory in dummy process. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Copy the actual data
    if (!section.data.empty()) {
        if (!WriteProcessMemory(
            processHandle,
            destAddress,
            section.data.data(),
            section.data.size(),
            &bytesWritten
        ) || bytesWritten != section.data.size()) {
            std::cout << "Failed to write section data. Error: " << GetLastError() << std::endl;
            return false;
        }
    }

    std::cout << "Successfully mapped section to dummy process" << std::endl;
    return true;
}

// Function to set protections for all sections
bool SetProtections(HANDLE processHandle, void* baseAddress, const std::vector<SectionInfo>& sections) {
    if (!processHandle || !baseAddress) {
        std::cout << "Invalid process handle or base address" << std::endl;
        return false;
    }

    // Set protection for each section
    for (const auto& section : sections) {
        void* sectionAddress = (BYTE*)baseAddress + section.virtualAddress;
        DWORD oldProtect;

        if (!VirtualProtectEx(
            processHandle,
            sectionAddress,
            section.virtualSize,
            section.protection,
            &oldProtect
        )) {
            std::cout << "Failed to set protection for section at "
                << std::hex << section.virtualAddress
                << ". Error: " << GetLastError() << std::endl;
            return false;
        }
    }

    return true;
}

bool LoadHeaderlessExecutableFromStream(BIO* bio, HeaderlessExecutable& executable) {
    executable.baseAddress = nullptr;
    executable.dataSize = 0;
    executable.isLoaded = false;
    executable.processHandle = NULL;
    executable.pipeHandle = INVALID_HANDLE_VALUE;

    std::cout << "[MemoryLoader] Loading headerless executable from stream..." << std::endl;

    // Get the ImportHandler instance to access dummy process
    if (!g_handlerInstance) {
        std::cerr << "[MemoryLoader] No ImportHandler instance available" << std::endl;
        return false;
    }

    // Get dummy process info from ImportHandler
    executable.processHandle = g_handlerInstance->GetProcessHandle();
    executable.pipeHandle = g_handlerInstance->GetPipeHandle();
    executable.is32Bit = g_handlerInstance->Is32Bit();

    if (!executable.processHandle || executable.pipeHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "[MemoryLoader] Dummy process not initialized" << std::endl;
        return false;
    }

    // CRITICAL FIX: Get the already allocated base address from ImportHandler
    // DO NOT allocate new memory - use what was already allocated and reported to server
    void* allocatedBase = GetAllocatedBase(); // Use global function
    if (!allocatedBase) {
        std::cerr << "[MemoryLoader] No base address allocated by ImportHandler" << std::endl;
        return false;
    }

    executable.baseAddress = allocatedBase;
    size_t imageSize = g_handlerInstance->GetImageSize(); // Get the image size for validation

    std::cout << "[MemoryLoader] Using pre-allocated base address: 0x"
        << std::hex << executable.baseAddress << std::dec << std::endl;

    // Read entry point first
    uintptr_t entryPoint;
    if (BIO_read(bio, &entryPoint, sizeof(entryPoint)) != sizeof(entryPoint)) {
        std::cerr << "[MemoryLoader] Failed to read entry point" << std::endl;
        return false;
    }
    std::cout << "[MemoryLoader] Entry point RVA: 0x" << std::hex << entryPoint << std::dec << std::endl;

    // Read section count
    uint32_t sectionCount;
    if (BIO_read(bio, &sectionCount, sizeof(sectionCount)) != sizeof(sectionCount)) {
        std::cerr << "[MemoryLoader] Failed to read section count" << std::endl;
        return false;
    }
    std::cout << "[MemoryLoader] Section count: " << sectionCount << std::endl;

    // Store sections for later protection setting (exactly like old project)
    std::vector<SectionInfo> sections;
    std::vector<uintptr_t> tlsCallbacks;

    // Process each section
    for (uint32_t i = 0; i < sectionCount; i++) {
        std::cout << "[MemoryLoader] Processing section " << i << "..." << std::endl;

        SectionInfo section;
        uint32_t dataSize;

        // Read section header info exactly as old project expects
        if (BIO_read(bio, &section.virtualAddress, sizeof(section.virtualAddress)) != sizeof(section.virtualAddress) ||
            BIO_read(bio, &section.virtualSize, sizeof(section.virtualSize)) != sizeof(section.virtualSize) ||
            BIO_read(bio, &section.protection, sizeof(section.protection)) != sizeof(section.protection) ||
            BIO_read(bio, &section.isCode, sizeof(section.isCode)) != sizeof(section.isCode) ||
            BIO_read(bio, &dataSize, sizeof(dataSize)) != sizeof(dataSize)) {
            std::cout << "Failed to receive section info for section " << i << ". Error: " << GetLastError() << std::endl;
            return false;
        }

        std::cout << "Section " << i << " VA: " << std::hex << section.virtualAddress
            << " Size: " << section.virtualSize
            << " Protection: " << section.protection
            << " IsCode: " << section.isCode << std::endl;

        // Validation checks exactly like old project
        if (dataSize > 1024 * 1024 * 64) { // Sanity check for 64MB max section size
            std::cout << "Suspiciously large section size: " << dataSize << std::endl;
            return false;
        }
        if (section.virtualSize > imageSize) {
            std::cout << "Section virtual size exceeds image size" << std::endl;
            return false;
        }

        std::cout << "Section " << i << " data size: " << std::dec << dataSize << std::endl;

        // Read section data
        section.data.resize(dataSize);
        if (dataSize > 0) {
            size_t totalRead = 0;
            while (totalRead < dataSize) {
                int bytesRead = BIO_read(bio, section.data.data() + totalRead, dataSize - totalRead);
                if (bytesRead <= 0) {
                    if (BIO_should_retry(bio)) {
                        continue;
                    }
                    else {
                        std::cout << "Failed to receive section data for section " << i << ". Error: " << GetLastError() << std::endl;
                        return false;
                    }
                }
                totalRead += bytesRead;
            }
        }

        // Map section using the exact same logic as old project
        std::cout << "Mapping section " << i << "..." << std::endl;
        if (!MapSection(executable.processHandle, executable.baseAddress, imageSize, section)) {
            std::cout << "Failed to map section " << i << std::endl;
            return false;
        }

        // Store section for protection setting later
        sections.push_back(section);
    }

    // Process TLS callbacks exactly like old project
    uint32_t callbackCount;
    std::cout << "Receiving TLS callback count..." << std::endl;
    if (BIO_read(bio, &callbackCount, sizeof(callbackCount)) != sizeof(callbackCount)) {
        std::cout << "Failed to receive callback count. Error: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << "TLS callback count: " << callbackCount << std::endl;

    for (uint32_t i = 0; i < callbackCount; i++) {
        uintptr_t callback;
        if (BIO_read(bio, &callback, sizeof(callback)) != sizeof(callback)) {
            std::cout << "Failed to receive callback " << i << ". Error: " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "TLS callback " << i << " at " << std::hex << callback << std::endl;
        tlsCallbacks.push_back(callback);
    }

    // Set final memory protections exactly like old project
    std::cout << "Setting final memory protections..." << std::endl;
    if (!SetProtections(executable.processHandle, executable.baseAddress, sections)) {
        std::cout << "Failed to set protections" << std::endl;
        return false;
    }

    // Calculate actual entry point address
    uintptr_t actualEntryPoint = reinterpret_cast<uintptr_t>(executable.baseAddress) + entryPoint;

    // Send execute info to dummy process via pipe (exactly like old Memory::Execute)
    std::cout << "Execute: Starting execution in dummy process..." << std::endl;
    std::cout << "Entry point address: " << std::hex << actualEntryPoint << std::endl;

    BYTE messageType = 3; // Execute
    DWORD bytesWritten, bytesRead;

    // Send message type
    if (!WriteFile(executable.pipeHandle, &messageType, sizeof(messageType), &bytesWritten, NULL) ||
        bytesWritten != sizeof(messageType)) {
        std::cout << "Failed to send execute message type. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Send entry point with architecture-aware handling (exactly like old project)
    if (executable.is32Bit) {
        // For 32-bit, send as DWORD
        DWORD entryPoint32 = static_cast<DWORD>(actualEntryPoint);
        if (!WriteFile(executable.pipeHandle, &entryPoint32, sizeof(entryPoint32), &bytesWritten, NULL) ||
            bytesWritten != sizeof(entryPoint32)) {
            std::cout << "Failed to send 32-bit entry point. Error: " << GetLastError() << std::endl;
            return false;
        }
    }
    else {
        // For 64-bit, send as UINT64
        UINT64 entryPoint64 = static_cast<UINT64>(actualEntryPoint);
        if (!WriteFile(executable.pipeHandle, &entryPoint64, sizeof(entryPoint64), &bytesWritten, NULL) ||
            bytesWritten != sizeof(entryPoint64)) {
            std::cout << "Failed to send 64-bit entry point. Error: " << GetLastError() << std::endl;
            return false;
        }
    }

    // Send base address with architecture-aware handling (exactly like old project)
    if (executable.is32Bit) {
        // For 32-bit, send as DWORD
        DWORD baseAddr32 = static_cast<DWORD>(reinterpret_cast<uintptr_t>(executable.baseAddress));
        if (!WriteFile(executable.pipeHandle, &baseAddr32, sizeof(baseAddr32), &bytesWritten, NULL) ||
            bytesWritten != sizeof(baseAddr32)) {
            std::cout << "Failed to send 32-bit base address. Error: " << GetLastError() << std::endl;
            return false;
        }
    }
    else {
        // For 64-bit, send as UINT64
        UINT64 baseAddr64 = reinterpret_cast<UINT64>(executable.baseAddress);
        if (!WriteFile(executable.pipeHandle, &baseAddr64, sizeof(baseAddr64), &bytesWritten, NULL) ||
            bytesWritten != sizeof(baseAddr64)) {
            std::cout << "Failed to send 64-bit base address. Error: " << GetLastError() << std::endl;
            return false;
        }
    }

    // Read acknowledgment
    BYTE ack;
    if (!ReadFile(executable.pipeHandle, &ack, sizeof(ack), &bytesRead, NULL) ||
        bytesRead != sizeof(ack) || ack != 1) {
        std::cout << "Failed to receive execute acknowledgment. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Execute TLS callbacks first (exactly like old project)
    for (const auto& callback : tlsCallbacks) {
        uintptr_t callbackAddr = (uintptr_t)executable.baseAddress + callback;

        HANDLE hThread = CreateRemoteThread(
            executable.processHandle,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)callbackAddr,
            executable.baseAddress,
            0,
            NULL
        );

        if (!hThread) {
            std::cout << "Failed to create TLS callback thread. Error: " << GetLastError() << std::endl;
            continue;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    // Send auto-execute message - let dummy process know to execute after we disconnect
    BYTE autoExecuteMsg = 6; // New message type for auto-execute
    if (WriteFile(executable.pipeHandle, &autoExecuteMsg, sizeof(autoExecuteMsg), &bytesWritten, NULL) &&
        bytesWritten == sizeof(autoExecuteMsg)) {
        // Read acknowledgment
        if (ReadFile(executable.pipeHandle, &ack, sizeof(ack), &bytesRead, NULL) &&
            bytesRead == sizeof(ack) && ack == 1) {
            std::cout << "Auto-execute acknowledged by dummy process" << std::endl;
        }
    }

    executable.isLoaded = true;
    executable.dataSize = 0; // We don't track total size since it's already mapped

    std::cout << "Successfully mapped executable" << std::endl;
    std::cout << "Execution initiated in dummy process and client detached successfully" << std::endl;

    return true;
}

bool ExecuteHeaderlessExecutable(const HeaderlessExecutable& executable) {
    if (!executable.isLoaded || !executable.baseAddress) {
        std::cerr << "[MemoryLoader] Executable not loaded" << std::endl;
        return false;
    }

    // Immediately detach from the dummy process (exactly like old project)
    std::cout << "Auto-detaching from dummy process to let it run independently..." << std::endl;

    if (g_handlerInstance) {
        g_handlerInstance->DetachFromDummy();
    }

    std::cout << "[MemoryLoader] Execution initiated in dummy process" << std::endl;
    std::cout << "[MemoryLoader] Dummy process will continue running independently" << std::endl;
    std::cout << "[MemoryLoader] Main loader can now exit safely" << std::endl;

    return true;
}

void UnloadHeaderlessExecutable(const HeaderlessExecutable& executable) {
    // Since we detach from the dummy process and let it run independently,
    // we don't actually unload anything here. The dummy process will
    // clean up when it exits.
    std::cout << "[MemoryLoader] Executable remains in dummy process (detached)" << std::endl;

    // Clean up the global handler instance
    if (g_handlerInstance) {
        delete g_handlerInstance;
        g_handlerInstance = nullptr;
    }
}