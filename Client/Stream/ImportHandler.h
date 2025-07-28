#ifndef IMPORT_HANDLER_H
#define IMPORT_HANDLER_H

#include <Windows.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <string>
#include <vector>

class ImportHandler {
private:
    // Dummy process handling
    HANDLE m_processHandle;
    HANDLE m_threadHandle;
    DWORD m_processId;
    bool m_is32Bit;
    std::string m_pipeName;
    HANDLE m_pipe;

    // Helper functions
    void CloseHandles();

public:
    ImportHandler();
    ~ImportHandler();

    // Create and connect to dummy process
    bool CreateDummyProcess(bool is32Bit);
    bool ConnectToDummyProcess();

    // Resolve a single import through dummy process
    uintptr_t ResolveImportThroughDummy(const char* moduleName, const char* functionName);

    // Getters for MemoryLoader
    HANDLE GetProcessHandle() const { return m_processHandle; }
    HANDLE GetPipeHandle() const { return m_pipe; }
    bool Is32Bit() const { return m_is32Bit; }

    // NEW: Added methods for MemoryLoader compatibility
    void* GetAllocatedBase() const { return GetAllocatedBase(); } // Uses global function
    size_t GetImageSize() const { return 50 * 1024 * 1024; } // 50MB as allocated in your code

    // Cleanup
    void Cleanup();
    void DetachFromDummy();  // Detach and let dummy process continue running
};

// Main function to handle server import requests using dummy process
bool HandleServerImportRequests(BIO* bio);

// Helper function to process imports after receiving count
bool ProcessImports(BIO* bio, uint32_t importCount);

// Get the allocated base address (for use by LoadHeaderlessExecutableFromStream)
void* GetAllocatedBase();

// Global instance pointer for MemoryLoader access
extern ImportHandler* g_handlerInstance;

#endif // IMPORT_HANDLER_H