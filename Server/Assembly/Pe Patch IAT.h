#ifndef PE_PATCH_IAT_H
#define PE_PATCH_IAT_H

#include <Windows.h>
#include <vector>
#include "Pe Create Stub Section.h"

// Patch the Import Address Table to point to stubs instead of original addresses
// This makes all import calls automatically go through our stubs
bool PatchIATToStubs(std::vector<BYTE>& peData,
    const std::vector<ImportInfo>& imports,
    const StubSectionInfo& stubInfo,
    bool is64Bit);

#endif // PE_PATCH_IAT_H