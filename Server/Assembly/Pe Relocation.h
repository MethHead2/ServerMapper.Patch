#ifndef PE_PROCESSOR_MEMORY_H
#define PE_PROCESSOR_MEMORY_H

#include <Windows.h>
#include <vector>
#include <string>
#include <openssl/ssl.h>
#include "Pe Create Stub Section.h"

// Main processing function using in-memory PE (modifies peData in-place)
bool ProcessPEFileFromMemory(int applicationId, std::vector<BYTE>& peData, SSL* ssl, void* targetBase);

// Validation function
bool ValidateLoadedPE(const std::vector<BYTE>& peData, int applicationId);

// Helper functions
DWORD RvaToOffsetMemory(const std::vector<BYTE>& peData, DWORD rva);

// Processing functions for in-memory PE (modify peData in-place)
bool ProcessRelocationsInMemory(std::vector<BYTE>& peData, void* targetBase, bool is64Bit);
bool ResolveImportsInMemory(std::vector<BYTE>& peData, SSL* ssl, bool is64Bit, std::vector<ImportInfo>& imports);

#endif // PE_PROCESSOR_MEMORY_H