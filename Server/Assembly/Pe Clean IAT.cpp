#include "Pe Clean IAT.h"
#include "Pe Relocation.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <unordered_map>
#include <cstring>

std::vector<DataImportInfo> BuildDataImportList(std::vector<BYTE>& peData, bool is64Bit) {
    std::vector<DataImportInfo> dataImports;

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(peData.data() + dosHeader->e_lfanew);

    PIMAGE_DATA_DIRECTORY importDir = nullptr;
    if (is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
        importDir = &ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }
    else {
        PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
        importDir = &ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    if (!importDir->Size || !importDir->VirtualAddress) {
        return dataImports;
    }

    DWORD importOffset = RvaToOffsetMemory(peData, importDir->VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(peData.data() + importOffset);

    while (importDesc->Name != 0) {
        DWORD nameOffset = RvaToOffsetMemory(peData, importDesc->Name);
        char* moduleName = reinterpret_cast<char*>(peData.data() + nameOffset);

        DWORD iatRva = importDesc->FirstThunk;
        DWORD intRva = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;

        DWORD iatOffset = RvaToOffsetMemory(peData, iatRva);
        DWORD intOffset = RvaToOffsetMemory(peData, intRva);

        if (is64Bit) {
            PIMAGE_THUNK_DATA64 intThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(peData.data() + intOffset);
            PIMAGE_THUNK_DATA64 iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(peData.data() + iatOffset);

            while (intThunk->u1.AddressOfData != 0) {
                std::string functionName;

                if (IMAGE_SNAP_BY_ORDINAL64(intThunk->u1.Ordinal)) {
                    functionName = "#" + std::to_string(IMAGE_ORDINAL64(intThunk->u1.Ordinal));
                }
                else {
                    DWORD nameOffset = RvaToOffsetMemory(peData, static_cast<DWORD>(intThunk->u1.AddressOfData));
                    if (nameOffset != 0) {
                        PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameOffset);
                        functionName = reinterpret_cast<char*>(importByName->Name);
                    }
                }

                // Check if this is a data import that should be preserved
                if (IsDataImport(moduleName, functionName)) {
                    DataImportInfo dataImport;
                    dataImport.moduleName = moduleName;
                    dataImport.funcName = functionName;
                    dataImport.iatRva = iatRva;
                    dataImport.resolvedAddr = iatThunk->u1.Function;
                    dataImports.push_back(dataImport);
                }

                intThunk++;
                iatThunk++;
                iatRva += sizeof(IMAGE_THUNK_DATA64);
            }
        }
        else {
            PIMAGE_THUNK_DATA32 intThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(peData.data() + intOffset);
            PIMAGE_THUNK_DATA32 iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(peData.data() + iatOffset);

            while (intThunk->u1.AddressOfData != 0) {
                std::string functionName;

                if (IMAGE_SNAP_BY_ORDINAL32(intThunk->u1.Ordinal)) {
                    functionName = "#" + std::to_string(IMAGE_ORDINAL32(intThunk->u1.Ordinal));
                }
                else {
                    DWORD nameOffset = RvaToOffsetMemory(peData, intThunk->u1.AddressOfData);
                    if (nameOffset != 0) {
                        PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameOffset);
                        functionName = reinterpret_cast<char*>(importByName->Name);
                    }
                }

                // Check if this is a data import that should be preserved
                if (IsDataImport(moduleName, functionName)) {
                    DataImportInfo dataImport;
                    dataImport.moduleName = moduleName;
                    dataImport.funcName = functionName;
                    dataImport.iatRva = iatRva;
                    dataImport.resolvedAddr = static_cast<ULONGLONG>(iatThunk->u1.Function);
                    dataImports.push_back(dataImport);
                }

                intThunk++;
                iatThunk++;
                iatRva += sizeof(IMAGE_THUNK_DATA32);
            }
        }
        importDesc++;
    }

    return dataImports;
}

bool RebuildImportDescriptors(std::vector<BYTE>& peData,
    const std::vector<DataImportInfo>& dataImports,
    bool is64Bit) {

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
    PIMAGE_DATA_DIRECTORY importDir = nullptr;

    if (is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
        importDir = &ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }
    else {
        PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
        importDir = &ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    if (dataImports.empty()) {
        std::cout << "[*] No data imports to preserve - completely removing import directory" << std::endl;

        // Get the original import directory location and size
        DWORD originalImportRva = importDir->VirtualAddress;
        DWORD originalImportSize = importDir->Size;

        // Zero out the import directory data
        if (originalImportRva && originalImportSize) {
            DWORD importOffset = RvaToOffsetMemory(peData, originalImportRva);
            if (importOffset && importOffset + originalImportSize <= peData.size()) {
                memset(peData.data() + importOffset, 0, originalImportSize);
                std::cout << "[*] Zeroed " << originalImportSize << " bytes of import directory data" << std::endl;
            }
        }

        // Remove import directory reference
        importDir->VirtualAddress = 0;
        importDir->Size = 0;

        return true;
    }

    // Create a set of data import RVAs for quick lookup
    std::unordered_set<DWORD> dataImportRvas;
    for (const auto& dataImport : dataImports) {
        dataImportRvas.insert(dataImport.iatRva);
    }

    std::cout << "[*] Clearing function import names from IAT while preserving data imports..." << std::endl;

    // Process each import descriptor and clear function imports
    DWORD originalImportRva = importDir->VirtualAddress;
    DWORD originalImportOffset = RvaToOffsetMemory(peData, originalImportRva);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(peData.data() + originalImportOffset);

    int clearedFunctionImports = 0;
    int preservedDataImports = 0;

    while (importDesc->Name != 0) {
        DWORD nameOffset = RvaToOffsetMemory(peData, importDesc->Name);
        char* moduleName = reinterpret_cast<char*>(peData.data() + nameOffset);

        DWORD iatRva = importDesc->FirstThunk;
        DWORD intRva = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;

        DWORD iatOffset = RvaToOffsetMemory(peData, iatRva);
        DWORD intOffset = RvaToOffsetMemory(peData, intRva);

        std::cout << "[*] Processing module: " << moduleName << std::endl;

        if (is64Bit) {
            PIMAGE_THUNK_DATA64 intThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(peData.data() + intOffset);
            PIMAGE_THUNK_DATA64 iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(peData.data() + iatOffset);

            while (intThunk->u1.AddressOfData != 0) {
                // Check if this specific IAT entry should be preserved (data import)
                if (dataImportRvas.find(iatRva) != dataImportRvas.end()) {
                    // This is a data import - preserve it
                    preservedDataImports++;

                    // Get function name for logging
                    std::string functionName;
                    if (IMAGE_SNAP_BY_ORDINAL64(intThunk->u1.Ordinal)) {
                        functionName = "#" + std::to_string(IMAGE_ORDINAL64(intThunk->u1.Ordinal));
                    }
                    else {
                        DWORD nameRvaOffset = RvaToOffsetMemory(peData, static_cast<DWORD>(intThunk->u1.AddressOfData));
                        if (nameRvaOffset != 0) {
                            PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameRvaOffset);
                            functionName = reinterpret_cast<char*>(importByName->Name);
                        }
                    }
                    std::cout << "    Preserved data import: " << functionName << std::endl;
                }
                else {
                    // This is a function import - clear name, address, hint, and OFT entry
                    if (!IMAGE_SNAP_BY_ORDINAL64(intThunk->u1.Ordinal)) {
                        // Clear the name structure to hide the function name and hint
                        DWORD nameRvaOffset = RvaToOffsetMemory(peData, static_cast<DWORD>(intThunk->u1.AddressOfData));
                        if (nameRvaOffset != 0) {
                            PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameRvaOffset);

                            // Clear the function name
                            memset(importByName->Name, 0, strlen(reinterpret_cast<char*>(importByName->Name)));
                            // Clear the hint too
                            importByName->Hint = 0;
                        }

                        // Clear the Original First Thunk (OFT) entry
                        intThunk->u1.AddressOfData = 0;
                    }
                    else {
                        // For ordinal imports, clear the ordinal in OFT
                        intThunk->u1.Ordinal = 0;
                    }

                    // Clear the IAT address too since stubs have the real addresses
                    iatThunk->u1.Function = 0;
                    clearedFunctionImports++;
                }

                intThunk++;
                iatThunk++;
                iatRva += sizeof(IMAGE_THUNK_DATA64);
            }
        }
        else {
            // 32-bit processing - similar logic
            PIMAGE_THUNK_DATA32 intThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(peData.data() + intOffset);
            PIMAGE_THUNK_DATA32 iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(peData.data() + iatOffset);

            while (intThunk->u1.AddressOfData != 0) {
                if (dataImportRvas.find(iatRva) != dataImportRvas.end()) {
                    preservedDataImports++;

                    std::string functionName;
                    if (IMAGE_SNAP_BY_ORDINAL32(intThunk->u1.Ordinal)) {
                        functionName = "#" + std::to_string(IMAGE_ORDINAL32(intThunk->u1.Ordinal));
                    }
                    else {
                        DWORD nameRvaOffset = RvaToOffsetMemory(peData, intThunk->u1.AddressOfData);
                        if (nameRvaOffset != 0) {
                            PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameRvaOffset);
                            functionName = reinterpret_cast<char*>(importByName->Name);
                        }
                    }
                    std::cout << "    Preserved data import: " << functionName << std::endl;
                }
                else {
                    // This is a function import - clear name, address, hint, and OFT entry
                    if (!IMAGE_SNAP_BY_ORDINAL32(intThunk->u1.Ordinal)) {
                        DWORD nameRvaOffset = RvaToOffsetMemory(peData, intThunk->u1.AddressOfData);
                        if (nameRvaOffset != 0) {
                            PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameRvaOffset);
                            // Clear the function name
                            memset(importByName->Name, 0, strlen(reinterpret_cast<char*>(importByName->Name)));
                            // Clear the hint too
                            importByName->Hint = 0;
                        }

                        // Clear the Original First Thunk (OFT) entry
                        intThunk->u1.AddressOfData = 0;
                    }
                    else {
                        // For ordinal imports, clear the ordinal in OFT
                        intThunk->u1.Ordinal = 0;
                    }

                    // Clear the IAT address too since stubs have the real addresses
                    iatThunk->u1.Function = 0;
                    clearedFunctionImports++;
                }

                intThunk++;
                iatThunk++;
                iatRva += sizeof(IMAGE_THUNK_DATA32);
            }
        }
        importDesc++;
    }

    std::cout << "[+] Cleared " << clearedFunctionImports << " function imports completely (names, addresses, hints, OFT entries)" << std::endl;
    std::cout << "[+] Preserved " << preservedDataImports << " data import names and addresses" << std::endl;
    std::cout << "[*] Function imports completely sanitized - zero recoverable information remains" << std::endl;

    return true;
}

bool CleanIAT(std::vector<BYTE>& peData,
    const std::vector<ImportReference>& allImportReferences,
    bool is64Bit) {
    try {
        std::cout << "\n[*] Cleaning IAT - removing function imports, keeping data imports..." << std::endl;

        // Calculate original IAT size for comparison
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
        PIMAGE_DATA_DIRECTORY importDir = nullptr;

        if (is64Bit) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
            importDir = &ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
        else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
            importDir = &ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }

        DWORD originalImportSize = importDir->Size;

        // First, build a list of all data imports that need to be preserved
        std::vector<DataImportInfo> dataImports = BuildDataImportList(peData, is64Bit);

        std::cout << "[*] Found " << dataImports.size() << " data imports to preserve:" << std::endl;
        for (size_t i = 0; i < min(dataImports.size(), static_cast<size_t>(10)); i++) {
            std::cout << "    " << dataImports[i].moduleName << "!" << dataImports[i].funcName
                << " at RVA 0x" << std::hex << dataImports[i].iatRva << std::dec << std::endl;
        }
        if (dataImports.size() > 10) {
            std::cout << "    ... and " << (dataImports.size() - 10) << " more" << std::endl;
        }

        // Rebuild the import descriptors with only data imports
        if (!RebuildImportDescriptors(peData, dataImports, is64Bit)) {
            std::cerr << "[!] Failed to rebuild import descriptors" << std::endl;
            return false;
        }

        // Calculate space saved
        DWORD newImportSize = importDir->Size;
        if (newImportSize < originalImportSize) {
            std::cout << "[+] Import directory reduced from " << originalImportSize
                << " to " << newImportSize << " bytes (saved "
                << (originalImportSize - newImportSize) << " bytes)" << std::endl;
        }

        std::cout << "[+] Successfully cleaned IAT" << std::endl;
        return true;

    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception in CleanIAT: " << e.what() << std::endl;
        return false;
    }
}