#ifndef IMPROVEDHEADERLESSLOADER_H
#define IMPROVEDHEADERLESSLOADER_H

#include <windows.h>
#include <openssl/bio.h>
#include <vector>
#include "../Stream/ImportHandler.h"

struct HeaderlessExecutable {
    LPVOID baseAddress;      // Base address in dummy process
    size_t dataSize;
    bool isLoaded;
    HANDLE processHandle;    // Handle to dummy process
    HANDLE pipeHandle;       // Pipe for communication
    bool is32Bit;           // Architecture of dummy process
    uintptr_t entryPoint;   // Entry point RVA - ADD THIS LINE
};

// Load executable from stream and map it into dummy process
bool LoadHeaderlessExecutableFromStream(BIO* bio, HeaderlessExecutable& executable);

// Execute the loaded executable in dummy process
bool ExecuteHeaderlessExecutable(const HeaderlessExecutable& executable);

// Unload executable (currently a no-op since we detach from dummy)
void UnloadHeaderlessExecutable(const HeaderlessExecutable& executable);

#endif // IMPROVEDHEADERLESSLOADER_H