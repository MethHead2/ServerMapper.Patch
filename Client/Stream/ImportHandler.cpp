#include "ImportHandler.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <sstream>
#include <filesystem>

// Global variables
static void* g_allocatedBase = nullptr;
ImportHandler* g_handlerInstance = nullptr;  // Remove static to make it accessible externally

// Constructor
ImportHandler::ImportHandler() : m_processHandle(NULL), m_threadHandle(NULL),
m_processId(0), m_is32Bit(false), m_pipe(INVALID_HANDLE_VALUE) {
}

// Destructor
ImportHandler::~ImportHandler() {
    Cleanup();
}

void ImportHandler::Cleanup() {
    // Don't send any messages, just close our handles
    if (m_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }

    CloseHandles();
}

void ImportHandler::DetachFromDummy() {
    if (m_pipe != INVALID_HANDLE_VALUE) {
        // Send detach message
        BYTE messageType = 2; // Detach
        DWORD bytesWritten;

        std::cout << "[ImportHandler] Sending detach message to dummy process..." << std::endl;
        if (WriteFile(m_pipe, &messageType, sizeof(messageType), &bytesWritten, NULL) &&
            bytesWritten == sizeof(messageType)) {
            // Read acknowledgment
            BYTE ack;
            DWORD bytesRead;
            if (ReadFile(m_pipe, &ack, sizeof(ack), &bytesRead, NULL) &&
                bytesRead == sizeof(ack) && ack == 1) {
                std::cout << "[ImportHandler] Detach acknowledged by dummy process" << std::endl;
            }
        }

        // Close pipe handle
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }

    // Close process handles but don't terminate the process
    CloseHandles();
    std::cout << "[ImportHandler] Detached from dummy process - it will continue running" << std::endl;
}

void ImportHandler::CloseHandles() {
    if (m_threadHandle) {
        CloseHandle(m_threadHandle);
        m_threadHandle = NULL;
    }

    if (m_processHandle) {
        CloseHandle(m_processHandle);
        m_processHandle = NULL;
    }

    m_processId = 0;
}

bool ImportHandler::CreateDummyProcess(bool is32Bit) {
    m_is32Bit = is32Bit;

    // Determine which dummy process to use
    std::string dummyProcessPath = is32Bit ? "DummyProcess32.exe" : "DummyProcess64.exe";

    // Add stay-alive parameter
    std::string cmdLine = dummyProcessPath + " --stay-alive";

    std::cout << "[ImportHandler] Creating dummy process: " << dummyProcessPath << std::endl;

    // Create startup info - NO STDOUT REDIRECTION
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;  // Only show window, don't redirect streams
    si.wShowWindow = SW_SHOW;           // Make the dummy process window visible
    // DON'T redirect stdout/stderr - let them go to the console

    // Create the process
    if (!CreateProcessA(
        NULL,                    // No module name (use command line)
        (LPSTR)cmdLine.c_str(),  // Command line with stay-alive flag
        NULL,                    // Process security attributes
        NULL,                    // Thread security attributes
        FALSE,                   // DON'T inherit handles
        CREATE_NEW_CONSOLE,      // Creation flags - visible console
        NULL,                    // Environment
        NULL,                    // Current directory
        &si,                     // Startup info
        &pi                      // Process information
    )) {
        std::cout << "[ImportHandler] Failed to create dummy process. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Store process handles
    m_processHandle = pi.hProcess;
    m_threadHandle = pi.hThread;
    m_processId = pi.dwProcessId;

    std::cout << "[ImportHandler] Created dummy process with ID: " << m_processId << std::endl;
    std::cout << "[ImportHandler] Dummy process window should now be visible!" << std::endl;

    // Generate predictable pipe name instead of reading from stdout
    m_pipeName = "\\\\.\\pipe\\DummyProcess_" + std::to_string(m_processId);

    std::cout << "[ImportHandler] Using pipe name: " << m_pipeName << std::endl;

    // Wait a moment for dummy process to initialize and create pipe
    Sleep(2000);


    // Connect to the pipe
    return ConnectToDummyProcess();
}

bool ImportHandler::ConnectToDummyProcess() {
    // Try to connect to the pipe with retries
    for (int attempt = 0; attempt < 20; attempt++) {
        m_pipe = CreateFileA(
            m_pipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (m_pipe != INVALID_HANDLE_VALUE) {
            break;
        }

        DWORD error = GetLastError();
        if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND) {
            std::cout << "[ImportHandler] Failed to connect to pipe. Error: " << error << std::endl;
            return false;
        }

        // Wait for the pipe
        if (!WaitNamedPipeA(m_pipeName.c_str(), 1000)) {
            // Just retry after a delay
            Sleep(200);
        }
    }

    if (m_pipe == INVALID_HANDLE_VALUE) {
        std::cout << "[ImportHandler] Failed to connect to dummy process pipe after retries" << std::endl;
        return false;
    }

    // Set pipe to message mode
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(m_pipe, &mode, NULL, NULL)) {
        std::cout << "[ImportHandler] Failed to set pipe read mode. Error: " << GetLastError() << std::endl;
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
        return false;
    }

    // Send stay-alive message
    BYTE msgType = 99; // Stay alive command
    DWORD bytesWritten;

    if (WriteFile(m_pipe, &msgType, sizeof(msgType), &bytesWritten, NULL) &&
        bytesWritten == sizeof(msgType)) {
        // Read acknowledgment
        BYTE ack;
        DWORD bytesRead;
        if (ReadFile(m_pipe, &ack, sizeof(ack), &bytesRead, NULL) &&
            bytesRead == sizeof(ack) && ack == 1) {
            std::cout << "[ImportHandler] Stay-alive acknowledged by dummy process" << std::endl;
        }
    }

    // Send architecture info to the dummy process
    BYTE archMsgType = 5; // Architecture info message
    BYTE is64Bit = !m_is32Bit ? 1 : 0;

    if (WriteFile(m_pipe, &archMsgType, sizeof(archMsgType), &bytesWritten, NULL) &&
        bytesWritten == sizeof(archMsgType)) {
        // Send architecture flag
        if (WriteFile(m_pipe, &is64Bit, sizeof(is64Bit), &bytesWritten, NULL) &&
            bytesWritten == sizeof(is64Bit)) {
            // Read acknowledgment
            BYTE ack;
            DWORD bytesRead;
            if (ReadFile(m_pipe, &ack, sizeof(ack), &bytesRead, NULL) &&
                bytesRead == sizeof(ack) && ack == 1) {
                std::cout << "[ImportHandler] Architecture info acknowledged by dummy process" << std::endl;
            }
        }
    }

    std::cout << "[ImportHandler] Connected to dummy process pipe" << std::endl;
    return true;
}

// Resolve import through dummy process
uintptr_t ImportHandler::ResolveImportThroughDummy(const char* moduleName, const char* functionName) {
    if (m_pipe == INVALID_HANDLE_VALUE) {
        std::cout << "[ImportHandler] No pipe connection to dummy process" << std::endl;
        return 0;
    }

    // 1. Send message type
    BYTE messageType = 1; // Import resolution
    DWORD bytesWritten, bytesRead;

    if (!WriteFile(m_pipe, &messageType, sizeof(messageType), &bytesWritten, NULL) ||
        bytesWritten != sizeof(messageType)) {
        std::cout << "[ImportHandler] Failed to send message type. Error: " << GetLastError() << std::endl;
        return 0;
    }

    // 2. Send module name length, then module name
    DWORD moduleNameLen = (DWORD)strlen(moduleName);
    if (!WriteFile(m_pipe, &moduleNameLen, sizeof(moduleNameLen), &bytesWritten, NULL) ||
        bytesWritten != sizeof(moduleNameLen)) {
        std::cout << "[ImportHandler] Failed to send module name length. Error: " << GetLastError() << std::endl;
        return 0;
    }

    if (!WriteFile(m_pipe, moduleName, moduleNameLen, &bytesWritten, NULL) ||
        bytesWritten != moduleNameLen) {
        std::cout << "[ImportHandler] Failed to send module name. Error: " << GetLastError() << std::endl;
        return 0;
    }

    // 3. Send function name length, then function name
    DWORD funcNameLen = (DWORD)strlen(functionName);
    if (!WriteFile(m_pipe, &funcNameLen, sizeof(funcNameLen), &bytesWritten, NULL) ||
        bytesWritten != sizeof(funcNameLen)) {
        std::cout << "[ImportHandler] Failed to send function name length. Error: " << GetLastError() << std::endl;
        return 0;
    }

    if (!WriteFile(m_pipe, functionName, funcNameLen, &bytesWritten, NULL) ||
        bytesWritten != funcNameLen) {
        std::cout << "[ImportHandler] Failed to send function name. Error: " << GetLastError() << std::endl;
        return 0;
    }

    // 4. Read the result - handle different architectures
    uintptr_t address = 0;

    if (m_is32Bit) {
        // For 32-bit processes, read 4 bytes
        DWORD address32 = 0;
        if (!ReadFile(m_pipe, &address32, sizeof(address32), &bytesRead, NULL) ||
            bytesRead != sizeof(address32)) {
            std::cout << "[ImportHandler] Failed to receive 32-bit address. Error: " << GetLastError() << std::endl;
            return 0;
        }
        address = static_cast<uintptr_t>(address32);
    }
    else {
        // For 64-bit processes, read 8 bytes
        UINT64 address64 = 0;
        if (!ReadFile(m_pipe, &address64, sizeof(address64), &bytesRead, NULL) ||
            bytesRead != sizeof(address64)) {
            std::cout << "[ImportHandler] Failed to receive 64-bit address. Error: " << GetLastError() << std::endl;
            return 0;
        }
        address = static_cast<uintptr_t>(address64);
    }

    return address;
}

// Main handler function
bool HandleServerImportRequests(BIO* bio) {
    std::cout << "\n[*] === Starting Import Resolution Handler (Dummy Process) ===" << std::endl;

    // First, receive architecture info from server (before creating dummy process)
    uint32_t archInfo = 0;
    int bytesRead = BIO_read(bio, &archInfo, sizeof(archInfo));
    if (bytesRead != sizeof(archInfo)) {
        std::cerr << "[-] Failed to receive architecture info from server" << std::endl;
        return false;
    }

    bool is32Bit = (archInfo == 0);
    std::cout << "[*] Server PE architecture: " << (is32Bit ? "32-bit" : "64-bit") << std::endl;

    // Create handler instance if not exists
    if (!g_handlerInstance) {
        g_handlerInstance = new ImportHandler();

        // Initialize dummy process with correct architecture
        if (!g_handlerInstance->CreateDummyProcess(is32Bit)) {
            std::cerr << "[-] Failed to create dummy process for import resolution" << std::endl;
            delete g_handlerInstance;
            g_handlerInstance = nullptr;
            return false;
        }
    }

    // Check if server wants target base address
    char requestBuffer[32] = { 0 };
    int peekBytes = BIO_read(bio, requestBuffer, 15);

    // In HandleServerImportRequests function, replace the allocation section:

    if (peekBytes >= 15 && memcmp(requestBuffer, "GET_TARGET_BASE", 15) == 0) {
        std::cout << "[*] Server requested target base address" << std::endl;

        // Allocate memory for the executable if not already done
        if (!g_allocatedBase) {
            // For 32-bit processes, allocate in lower memory space
            size_t allocSize = 50 * 1024 * 1024;

            // CRITICAL FIX: Allocate in the DUMMY PROCESS, not local process!
            HANDLE dummyProcess = g_handlerInstance->GetProcessHandle();
            if (!dummyProcess) {
                std::cerr << "[-] No dummy process handle available" << std::endl;
                return false;
            }

            if (is32Bit) {
                // For 32-bit, try to allocate below 2GB for compatibility
                g_allocatedBase = VirtualAllocEx(dummyProcess, (LPVOID)0x10000000, allocSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (!g_allocatedBase) {
                    // If that fails, let Windows choose but ensure it's below 4GB
                    g_allocatedBase = VirtualAllocEx(dummyProcess, NULL, allocSize,
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                }
            }
            else {
                // For 64-bit, let Windows choose
                g_allocatedBase = VirtualAllocEx(dummyProcess, NULL, allocSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            }

            if (!g_allocatedBase) {
                std::cerr << "[-] Failed to allocate memory in dummy process. Error: " << GetLastError() << std::endl;
                return false;
            }

            // Verify address is valid for architecture
            if (is32Bit && reinterpret_cast<uintptr_t>(g_allocatedBase) > 0xFFFFFFFF) {
                std::cerr << "[-] Allocated address too high for 32-bit process" << std::endl;
                VirtualFreeEx(dummyProcess, g_allocatedBase, 0, MEM_RELEASE);
                g_allocatedBase = nullptr;
                return false;
            }

            std::cout << "[*] Allocated " << (allocSize / 1024 / 1024) << "MB at: 0x"
                << std::hex << g_allocatedBase << std::dec << " in dummy process" << std::endl;
        }

        // Rest of the code remains the same...

        // Send the target base address
        int bytesWritten = BIO_write(bio, &g_allocatedBase, sizeof(g_allocatedBase));
        if (bytesWritten != sizeof(g_allocatedBase)) {
            std::cerr << "[-] Failed to send target base address" << std::endl;
            return false;
        }

        // Flush to ensure it's sent
        BIO_flush(bio);
        std::cout << "[+] Target base address sent: 0x" << std::hex << g_allocatedBase << std::dec << std::endl;

        // Now read the import count
        uint32_t importCount = 0;
        int bytesRead = BIO_read(bio, &importCount, sizeof(importCount));

        if (bytesRead != sizeof(importCount)) {
            std::cerr << "[-] Failed to receive import count from server" << std::endl;
            return false;
        }

        std::cout << "[*] Server requested resolution for " << importCount << " imports" << std::endl;

        // Process imports
        return ProcessImports(bio, importCount);
    }
    else {
        // No GET_TARGET_BASE, treat the data as import count
        uint32_t importCount = 0;

        // We already read some bytes, check if it's enough for uint32_t
        if (peekBytes >= sizeof(uint32_t)) {
            memcpy(&importCount, requestBuffer, sizeof(uint32_t));
            std::cout << "[*] Server requested resolution for " << importCount << " imports" << std::endl;
            return ProcessImports(bio, importCount);
        }
        else {
            std::cerr << "[-] Unexpected protocol - not enough data" << std::endl;
            return false;
        }
    }
}

// Process imports using dummy process
bool ProcessImports(BIO* bio, uint32_t importCount) {
    if (!g_handlerInstance) {
        std::cerr << "[-] No handler instance available" << std::endl;
        return false;
    }

    // Sanity check
    if (importCount > 10000) {
        std::cerr << "[-] Suspicious import count: " << importCount << std::endl;
        return false;
    }

    // Statistics
    uint32_t resolvedCount = 0;
    uint32_t failedCount = 0;
    std::vector<std::string> failedImports;

    // Process each import
    for (uint32_t i = 0; i < importCount; i++) {
        // 1. Receive module name size
        uint32_t moduleNameSize = 0;
        int bytesRead = BIO_read(bio, &moduleNameSize, sizeof(moduleNameSize));
        if (bytesRead != sizeof(moduleNameSize)) {
            std::cerr << "[-] Failed to receive module name size for import " << i << std::endl;
            return false;
        }

        // Sanity check
        if (moduleNameSize == 0 || moduleNameSize > 260) {
            std::cerr << "[-] Invalid module name size: " << moduleNameSize << std::endl;
            return false;
        }

        // 2. Receive module name
        std::vector<char> moduleNameBuffer(moduleNameSize + 1, 0);
        bytesRead = BIO_read(bio, moduleNameBuffer.data(), moduleNameSize);
        if (bytesRead != moduleNameSize) {
            std::cerr << "[-] Failed to receive module name for import " << i << std::endl;
            return false;
        }
        std::string moduleName(moduleNameBuffer.data());

        // 3. Receive function name size
        uint32_t functionNameSize = 0;
        bytesRead = BIO_read(bio, &functionNameSize, sizeof(functionNameSize));
        if (bytesRead != sizeof(functionNameSize)) {
            std::cerr << "[-] Failed to receive function name size for import " << i << std::endl;
            return false;
        }

        // Sanity check
        if (functionNameSize == 0 || functionNameSize > 512) {
            std::cerr << "[-] Invalid function name size: " << functionNameSize << std::endl;
            return false;
        }

        // 4. Receive function name
        std::vector<char> functionNameBuffer(functionNameSize + 1, 0);
        bytesRead = BIO_read(bio, functionNameBuffer.data(), functionNameSize);
        if (bytesRead != functionNameSize) {
            std::cerr << "[-] Failed to receive function name for import " << i << std::endl;
            return false;
        }
        std::string functionName(functionNameBuffer.data());

        std::cout << "[*] Import #" << (i + 1) << "/" << importCount
            << ": " << moduleName << "." << functionName;

        // 5. Resolve the import through dummy process
        uintptr_t resolvedAddress = g_handlerInstance->ResolveImportThroughDummy(moduleName.c_str(), functionName.c_str());

        if (resolvedAddress == 0) {
            std::cout << " - FAILED" << std::endl;
            failedCount++;
            failedImports.push_back(moduleName + "." + functionName);
        }
        else {
            std::cout << " -> 0x" << std::hex << resolvedAddress << std::dec << std::endl;
            resolvedCount++;
        }

        // 6. Send the resolved address back to server
        int bytesWritten = BIO_write(bio, &resolvedAddress, sizeof(resolvedAddress));
        if (bytesWritten != sizeof(resolvedAddress)) {
            std::cerr << "[-] Failed to send resolved address" << std::endl;
            return false;
        }

        // Flush after each write
        BIO_flush(bio);

        // Show progress for large import tables
        if (importCount > 20 && (i + 1) % 10 == 0) {
            std::cout << "[*] Progress: " << (i + 1) << "/" << importCount
                << " imports (" << ((i + 1) * 100 / importCount) << "%)" << std::endl;
        }
    }

    // Print summary
    std::cout << "\n[+] Import Resolution Summary:" << std::endl;
    std::cout << "    Total imports: " << importCount << std::endl;
    std::cout << "    Successfully resolved: " << resolvedCount << std::endl;
    std::cout << "    Failed to resolve: " << failedCount << std::endl;

    if (failedCount > 0 && failedCount < 50) { // Don't spam if too many failures
        std::cout << "    Failed imports:" << std::endl;
        for (const auto& failed : failedImports) {
            std::cout << "      - " << failed << std::endl;
        }
    }

    std::cout << "[*] === Import Resolution Complete ===" << std::endl;
    return true;
}

// Get the allocated base address
void* GetAllocatedBase() {
    return g_allocatedBase;
}