#ifndef PE_REDIRECT_TO_STUBS_H
#define PE_REDIRECT_TO_STUBS_H

#include <Windows.h>
#include <vector>
#include "PE Find Import References.h"
#include "Pe Create Stub Section.h"

// Redirect all import references from IAT to stubs
// This modifies the code to call/jmp to stubs instead of reading from IAT
bool RedirectImportsToStubs(std::vector<BYTE>& peData,
    const std::vector<ImportReference>& importReferences,
    const StubSectionInfo& stubInfo,
    bool is64Bit);

#endif // PE_REDIRECT_TO_STUBS_H