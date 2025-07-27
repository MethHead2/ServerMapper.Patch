#include "PE Relocation.h"
#include "PE Loader.h"
#include "../SSL Helper/SSLHelpers.h"
#include "Pe Create Stub Section.h"
#include "Pe Create Import Stubs.h"
#include "Pe Patch IAT.h"
#include <iostream>
#include <iomanip>

// Validate that the loaded PE matches the expected application ID
bool ValidateLoadedPE(const std::vector<BYTE>& peData, int applicationId) {
    if (peData.empty()) {
        std::cerr << "[!] PE data is empty for application ID: " << applicationId << std::endl;
        return false;
    }

    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::cout << "[*] Data appears to be headerless, skipping header validation" << std::endl;
        return true;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE*>(peData.data()));
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[*] No valid DOS signature found, data might be headerless" << std::endl;
        return true;
    }

    if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > peData.size()) {
        std::cerr << "[!] PE too small for NT headers" << std::endl;
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<BYTE*>(peData.data()) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[*] No valid NT signature found, data might be headerless" << std::endl;
        return true;
    }

    std::cout << "[+] PE validation passed for application ID: " << applicationId << std::endl;
    return true;
}

// Process PE file from memory
bool ProcessPEFileFromMemory(int applicationId, std::vector<BYTE>& peData, SSL* ssl, void* targetBase) {
    try {
        if (!ValidateLoadedPE(peData, applicationId)) {
            std::cerr << "[!] PE validation failed for application ID: " << applicationId << std::endl;
            return false;
        }

        if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::cerr << "[!] PE data too small to process" << std::endl;
            return false;
        }

        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "[!] Cannot process headerless PE for relocations and imports" << std::endl;
            return false;
        }

        std::cout << "[*] Processing PE from memory for application ID: " << applicationId
            << " (" << peData.size() << " bytes)" << std::endl;

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(peData.data() + dosHeader->e_lfanew);
        bool is64Bit = (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

        std::cout << "\n[*] PE Information:" << std::endl;
        std::cout << "    Application ID: " << applicationId << std::endl;
        std::cout << "    Architecture: " << (is64Bit ? "64-bit" : "32-bit") << std::endl;
        std::cout << "    Target client base: 0x" << std::hex << targetBase << std::dec << std::endl;
        std::cout << "    Number of sections: " << ntHeaders->FileHeader.NumberOfSections << std::endl;

        DWORD entryPointRVA = 0;
        if (is64Bit) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
            entryPointRVA = ntHeaders64->OptionalHeader.AddressOfEntryPoint;
        }
        else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
            entryPointRVA = ntHeaders32->OptionalHeader.AddressOfEntryPoint;
        }
        std::cout << "    Entry point RVA: 0x" << std::hex << entryPointRVA << std::dec << std::endl;

        // Process relocations
        std::cout << "\n[*] Processing relocations..." << std::endl;
        if (!ProcessRelocationsInMemory(peData, targetBase, is64Bit)) {
            std::cerr << "[!] Failed to process relocations" << std::endl;
            return false;
        }

        // Resolve imports and collect import information
        std::cout << "\n[*] Resolving imports..." << std::endl;
        std::vector<ImportInfo> imports;
        if (!ResolveImportsInMemory(peData, ssl, is64Bit, imports)) {
            std::cerr << "[!] Failed to resolve imports" << std::endl;
            return false;
        }

        // Create stub section for import protection
        std::cout << "\n[*] Creating import protection stubs..." << std::endl;
        StubSectionInfo stubInfo;
        if (!CreateStubSection(peData, imports, is64Bit, stubInfo)) {
            std::cerr << "[!] Failed to create stub section" << std::endl;
            return false;
        }

        // Create the actual stubs
        if (!CreateImportStubs(peData, imports, stubInfo, is64Bit)) {
            std::cerr << "[!] Failed to create import stubs" << std::endl;
            return false;
        }

        // Patch IAT to point to stubs instead of original addresses
        if (!PatchIATToStubs(peData, imports, stubInfo, is64Bit)) {
            std::cerr << "[!] Failed to patch IAT to stubs" << std::endl;
            return false;
        }

        std::cout << "\n[+] PE file successfully processed with import protection" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception: " << e.what() << std::endl;
        return false;
    }
}

// Helper function to convert RVA to file offset
DWORD RvaToOffsetMemory(const std::vector<BYTE>& peData, DWORD rva) {
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE*>(peData.data()));
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<BYTE*>(peData.data()) + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

    if (rva < ntHeaders->OptionalHeader.SizeOfHeaders) {
        return rva;
    }

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= sections[i].VirtualAddress &&
            rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
            return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
        }
    }

    return 0;
}

// Process relocations in memory
bool ProcessRelocationsInMemory(std::vector<BYTE>& peData, void* targetBase, bool is64Bit) {
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());

    ULONGLONG originalBase;
    PIMAGE_DATA_DIRECTORY relocDir = nullptr;

    if (is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
        originalBase = ntHeaders64->OptionalHeader.ImageBase;
        relocDir = &ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }
    else {
        PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
        originalBase = ntHeaders32->OptionalHeader.ImageBase;
        relocDir = &ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }

    LONGLONG delta = reinterpret_cast<LONGLONG>(targetBase) - static_cast<LONGLONG>(originalBase);

    std::cout << "[*] Relocation info:" << std::endl;
    std::cout << "    Original base: 0x" << std::hex << originalBase << std::dec << std::endl;
    std::cout << "    Target base: 0x" << std::hex << targetBase << std::dec << std::endl;
    std::cout << "    Delta: 0x" << std::hex << delta << std::dec << std::endl;

    if (delta == 0) {
        std::cout << "[*] No relocation needed (delta is 0)" << std::endl;
        return true;
    }

    if (!relocDir->Size || !relocDir->VirtualAddress) {
        std::cout << "[!] No relocation directory found" << std::endl;
        return true;
    }

    DWORD relocOffset = RvaToOffsetMemory(peData, relocDir->VirtualAddress);
    if (relocOffset == 0 || relocOffset + relocDir->Size > peData.size()) {
        std::cerr << "[!] Invalid relocation directory offset" << std::endl;
        return false;
    }

    PIMAGE_BASE_RELOCATION reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(peData.data() + relocOffset);
    DWORD processedSize = 0;
    int relocBlockCount = 0;
    int totalRelocations = 0;

    while (processedSize < relocDir->Size && reloc->VirtualAddress != 0) {
        if (reloc->SizeOfBlock == 0 || reloc->SizeOfBlock > relocDir->Size - processedSize) {
            std::cerr << "[!] Invalid relocation block size" << std::endl;
            break;
        }

        WORD* relocItem = reinterpret_cast<WORD*>(reloc + 1);
        DWORD relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        relocBlockCount++;

        for (DWORD i = 0; i < relocCount; i++) {
            WORD type = relocItem[i] >> 12;
            WORD offset = relocItem[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;
            }

            DWORD rva = reloc->VirtualAddress + offset;
            DWORD fileOffset = RvaToOffsetMemory(peData, rva);

            if (fileOffset == 0 || fileOffset + 8 > peData.size()) {
                continue;
            }

            if (is64Bit && type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* pAddress = reinterpret_cast<ULONGLONG*>(peData.data() + fileOffset);
                ULONGLONG oldValue = *pAddress;
                *pAddress += delta;
                totalRelocations++;

                if (totalRelocations <= 5) {
                    std::cout << "    Reloc[" << totalRelocations << "]: 0x" << std::hex << oldValue
                        << " -> 0x" << *pAddress << std::dec << std::endl;
                }
            }
            else if (!is64Bit && type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* pAddress = reinterpret_cast<DWORD*>(peData.data() + fileOffset);
                DWORD oldValue = *pAddress;
                *pAddress += static_cast<DWORD>(delta);
                totalRelocations++;

                if (totalRelocations <= 5) {
                    std::cout << "    Reloc[" << totalRelocations << "]: 0x" << std::hex << oldValue
                        << " -> 0x" << *pAddress << std::dec << std::endl;
                }
            }
        }

        processedSize += reloc->SizeOfBlock;
        reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<BYTE*>(reloc) + reloc->SizeOfBlock);
    }

    std::cout << "[+] Processed " << totalRelocations << " relocations in " << relocBlockCount << " blocks" << std::endl;

    // Update ImageBase in header
    if (is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
        ntHeaders64->OptionalHeader.ImageBase = reinterpret_cast<ULONGLONG>(targetBase);
        std::cout << "[+] Updated 64-bit ImageBase to: 0x" << std::hex << ntHeaders64->OptionalHeader.ImageBase << std::dec << std::endl;
    }
    else {
        PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
        ntHeaders32->OptionalHeader.ImageBase = reinterpret_cast<DWORD>(targetBase);
        std::cout << "[+] Updated 32-bit ImageBase to: 0x" << std::hex << ntHeaders32->OptionalHeader.ImageBase << std::dec << std::endl;
    }

    return true;
}

// Resolve imports in memory and collect import information
bool ResolveImportsInMemory(std::vector<BYTE>& peData, SSL* ssl, bool is64Bit, std::vector<ImportInfo>& imports) {
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

    if (!importDir->Size || !importDir->VirtualAddress) {
        std::cout << "[!] No import directory found" << std::endl;
        uint32_t zero = 0;
        SSLSendData(ssl, &zero, sizeof(zero));
        return true;
    }

    DWORD importOffset = RvaToOffsetMemory(peData, importDir->VirtualAddress);
    if (importOffset == 0 || importOffset + importDir->Size > peData.size()) {
        std::cerr << "[!] Invalid import directory offset" << std::endl;
        uint32_t zero = 0;
        SSLSendData(ssl, &zero, sizeof(zero));
        return false;
    }

    // Count imports first
    uint32_t importCount = 0;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(peData.data() + importOffset);
    PIMAGE_IMPORT_DESCRIPTOR tempDesc = importDesc;

    while (tempDesc->Name != 0) {
        DWORD nameOffset = RvaToOffsetMemory(peData, tempDesc->Name);
        if (nameOffset == 0) break;

        DWORD thunkOffset = RvaToOffsetMemory(peData, tempDesc->OriginalFirstThunk ? tempDesc->OriginalFirstThunk : tempDesc->FirstThunk);
        if (thunkOffset == 0) break;

        if (is64Bit) {
            PIMAGE_THUNK_DATA64 thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(peData.data() + thunkOffset);
            while (thunk->u1.AddressOfData) {
                importCount++;
                thunk++;
            }
        }
        else {
            PIMAGE_THUNK_DATA32 thunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(peData.data() + thunkOffset);
            while (thunk->u1.AddressOfData) {
                importCount++;
                thunk++;
            }
        }
        tempDesc++;
    }

    std::cout << "[*] Found " << importCount << " imports to resolve" << std::endl;

    if (!SSLSendData(ssl, &importCount, sizeof(importCount))) {
        std::cerr << "[!] Failed to send import count" << std::endl;
        return false;
    }

    // Process each import
    int resolvedCount = 0;
    while (importDesc->Name != 0) {
        DWORD nameOffset = RvaToOffsetMemory(peData, importDesc->Name);
        if (nameOffset == 0) break;

        char* moduleName = reinterpret_cast<char*>(peData.data() + nameOffset);
        std::cout << "\n[*] Processing module: " << moduleName << std::endl;

        DWORD iatRva = importDesc->FirstThunk;
        DWORD intRva = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;

        DWORD iatOffset = RvaToOffsetMemory(peData, iatRva);
        DWORD intOffset = RvaToOffsetMemory(peData, intRva);

        if (iatOffset == 0 || intOffset == 0) {
            std::cerr << "[!] Invalid thunk offset for " << moduleName << std::endl;
            continue;
        }

        if (is64Bit) {
            PIMAGE_THUNK_DATA64 intThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(peData.data() + intOffset);
            PIMAGE_THUNK_DATA64 iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(peData.data() + iatOffset);

            while (intThunk->u1.AddressOfData != 0) {
                std::string functionName;

                if (IMAGE_SNAP_BY_ORDINAL64(intThunk->u1.Ordinal)) {
                    WORD ordinal = IMAGE_ORDINAL64(intThunk->u1.Ordinal);
                    functionName = "#" + std::to_string(ordinal);
                }
                else {
                    DWORD nameRva = static_cast<DWORD>(intThunk->u1.AddressOfData);
                    DWORD nameOffsetVal = RvaToOffsetMemory(peData, nameRva);
                    if (nameOffsetVal != 0) {
                        PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameOffsetVal);
                        functionName = reinterpret_cast<char*>(importByName->Name);
                    }
                }

                if (!functionName.empty()) {
                    uint32_t moduleLen = static_cast<uint32_t>(strlen(moduleName));
                    if (!SSLSendData(ssl, &moduleLen, sizeof(moduleLen)) ||
                        !SSLSendData(ssl, moduleName, moduleLen)) {
                        return false;
                    }

                    uint32_t funcLen = static_cast<uint32_t>(functionName.length());
                    if (!SSLSendData(ssl, &funcLen, sizeof(funcLen)) ||
                        !SSLSendData(ssl, functionName.c_str(), funcLen)) {
                        return false;
                    }

                    ULONGLONG clientAddress;
                    if (!SSLReceiveData(ssl, &clientAddress, sizeof(clientAddress))) {
                        return false;
                    }

                    ImportInfo importInfo;
                    importInfo.moduleName = moduleName;
                    importInfo.funcName = functionName;
                    importInfo.resolvedAddr = clientAddress;
                    importInfo.iatRva = iatRva;
                    imports.push_back(importInfo);

                    ULONGLONG oldValue = iatThunk->u1.Function;
                    iatThunk->u1.Function = clientAddress;
                    resolvedCount++;

                    if (resolvedCount <= 10) {
                        std::cout << "    " << functionName << ": 0x" << std::hex << oldValue
                            << " -> 0x" << clientAddress << std::dec << std::endl;
                    }
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
                    WORD ordinal = IMAGE_ORDINAL32(intThunk->u1.Ordinal);
                    functionName = "#" + std::to_string(ordinal);
                }
                else {
                    DWORD nameOffsetVal = RvaToOffsetMemory(peData, intThunk->u1.AddressOfData);
                    if (nameOffsetVal != 0) {
                        PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameOffsetVal);
                        functionName = reinterpret_cast<char*>(importByName->Name);
                    }
                }

                if (!functionName.empty()) {
                    uint32_t moduleLen = static_cast<uint32_t>(strlen(moduleName));
                    if (!SSLSendData(ssl, &moduleLen, sizeof(moduleLen)) ||
                        !SSLSendData(ssl, moduleName, moduleLen)) {
                        return false;
                    }

                    uint32_t funcLen = static_cast<uint32_t>(functionName.length());
                    if (!SSLSendData(ssl, &funcLen, sizeof(funcLen)) ||
                        !SSLSendData(ssl, functionName.c_str(), funcLen)) {
                        return false;
                    }

                    ULONGLONG clientAddress;
                    if (!SSLReceiveData(ssl, &clientAddress, sizeof(clientAddress))) {
                        return false;
                    }

                    ImportInfo importInfo;
                    importInfo.moduleName = moduleName;
                    importInfo.funcName = functionName;
                    importInfo.resolvedAddr = clientAddress;
                    importInfo.iatRva = iatRva;
                    imports.push_back(importInfo);

                    DWORD oldValue = iatThunk->u1.Function;
                    iatThunk->u1.Function = static_cast<DWORD>(clientAddress);
                    resolvedCount++;

                    if (resolvedCount <= 10) {
                        std::cout << "    " << functionName << ": 0x" << std::hex << oldValue
                            << " -> 0x" << static_cast<DWORD>(clientAddress) << std::dec << std::endl;
                    }
                }

                intThunk++;
                iatThunk++;
                iatRva += sizeof(IMAGE_THUNK_DATA32);
            }
        }

        importDesc++;
    }

    std::cout << "\n[+] Successfully resolved " << resolvedCount << " imports" << std::endl;
    return resolvedCount == importCount;
}