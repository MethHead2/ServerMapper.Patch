#ifndef PE_MEMORY_LOADER_H
#define PE_MEMORY_LOADER_H

#include <iostream>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <Windows.h>
#include <vector>
#include <string>

// Load PE file into memory buffer (thread-safe)
bool LoadPEIntoMemory(int applicationId, std::vector<BYTE>& peData);

// Get already loaded PE data (thread-safe)
bool GetLoadedPE(int applicationId, std::vector<BYTE>& peData);

// Unload specific PE from memory
void UnloadPE(int applicationId);

// Unload all PEs from memory
void UnloadAllPEs();

#endif // PE_MEMORY_LOADER_H