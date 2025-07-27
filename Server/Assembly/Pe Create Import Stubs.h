#ifndef PE_CREATE_IMPORT_STUBS_H
#define PE_CREATE_IMPORT_STUBS_H

#include <Windows.h>
#include <vector>
#include "Pe Create Stub Section.h"

// Create JMP stubs in the stub section for each import
// Each stub will JMP to the actual import address from the client's dummy process
bool CreateImportStubs(std::vector<BYTE>& peData,
    const std::vector<ImportInfo>& imports,
    const StubSectionInfo& stubInfo,
    bool is64Bit);

#endif // PE_CREATE_IMPORT_STUBS_H