#ifndef PE_HEADER_REMOVER_MEMORY_H
#define PE_HEADER_REMOVER_MEMORY_H

#include <Windows.h>
#include <vector>

// Remove PE header from in-memory PE data (modifies the vector in-place)
bool RemovePEHeaderFromMemory(std::vector<BYTE>& peData);

#endif // PE_HEADER_REMOVER_MEMORY_H