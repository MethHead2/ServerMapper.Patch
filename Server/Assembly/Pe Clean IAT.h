#ifndef PE_CLEAN_IAT_H
#define PE_CLEAN_IAT_H

#include <Windows.h>
#include <vector>
#include <string>
#include <unordered_set>
#include "PE Find Import References.h"

// Structure to hold information about data imports that should be kept
struct DataImportInfo {
    std::string moduleName;
    std::string funcName;
    DWORD iatRva;           // RVA of the IAT entry
    ULONGLONG resolvedAddr; // The resolved address
};

// Clean the IAT by removing function imports and keeping only data imports
bool CleanIAT(std::vector<BYTE>& peData,
    const std::vector<ImportReference>& allImportReferences,
    bool is64Bit);

// Helper function to build list of data imports to preserve
std::vector<DataImportInfo> BuildDataImportList(std::vector<BYTE>& peData, bool is64Bit);

// Helper function to rebuild import descriptors with only data imports
bool RebuildImportDescriptors(std::vector<BYTE>& peData,
    const std::vector<DataImportInfo>& dataImports,
    bool is64Bit);

#endif // PE_CLEAN_IAT_H