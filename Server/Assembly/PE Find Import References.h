#ifndef IMPORT_REFERENCE_DETECTOR_H
#define IMPORT_REFERENCE_DETECTOR_H

#include <Windows.h>
#include <vector>
#include <string>
#include <unordered_map>

// Structure to hold information about each import reference found in the code
struct ImportReference {
    DWORD rva;              // RVA where the import is referenced in the code
    std::string moduleName; // Module name (e.g., "kernel32.dll")
    std::string funcName;   // Function name (e.g., "VirtualAlloc") or ordinal (e.g., "#123")
    ULONGLONG resolvedAddr; // The resolved address from IAT
    bool isDirectCall;      // true if CALL instruction, false if JMP/MOV/LEA/etc
};

bool FindImportReferences(std::vector<BYTE>& peData,
    std::vector<ImportReference>& references,
    bool is64Bit);


#endif // IMPORT_REFERENCE_DETECTOR_H