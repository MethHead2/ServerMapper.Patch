#include "Pe Patch IAT.h"
#include "Pe Relocation.h"
#include <iostream>
#include <iomanip>

bool PatchIATToStubs(std::vector<BYTE>& peData,
    const std::vector<ImportInfo>& imports,
    const StubSectionInfo& stubInfo,
    bool is64Bit) {
    try {
        if (!stubInfo.created) {
            std::cerr << "[!] Stub section was not created!" << std::endl;
            return false;
        }

        if (imports.empty()) {
            std::cout << "[*] No imports to patch in IAT" << std::endl;
            return true;
        }

        std::cout << "[*] Patching IAT to point to stubs..." << std::endl;

        // Get image base
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
        ULONGLONG imageBase;
        if (is64Bit) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
            imageBase = ntHeaders64->OptionalHeader.ImageBase;
        }
        else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
            imageBase = ntHeaders32->OptionalHeader.ImageBase;
        }

        int patchedCount = 0;
        DWORD stubSize = is64Bit ? STUB_SIZE_64BIT : STUB_SIZE_32BIT;

        // Patch each import's IAT entry
        for (size_t i = 0; i < imports.size(); i++) {
            const ImportInfo& import = imports[i];

            // Calculate stub address
            DWORD stubRva = stubInfo.sectionRVA + static_cast<DWORD>(i * stubSize);
            ULONGLONG stubAddress = imageBase + stubRva;

            // Convert IAT RVA to file offset
            DWORD iatOffset = RvaToOffsetMemory(peData, import.iatRva);
            if (iatOffset == 0 || iatOffset + 8 > peData.size()) {
                std::cerr << "[!] Invalid IAT offset for " << import.moduleName << "!" << import.funcName << std::endl;
                continue;
            }

            // Patch the IAT entry
            if (is64Bit) {
                // 64-bit: Write 8-byte address
                ULONGLONG* iatEntry = reinterpret_cast<ULONGLONG*>(peData.data() + iatOffset);
                ULONGLONG oldValue = *iatEntry;
                *iatEntry = stubAddress;

                if (patchedCount < 10) {
                    std::cout << "    IAT[" << i << "] " << import.moduleName << "!" << import.funcName
                        << ": 0x" << std::hex << oldValue << " -> 0x" << stubAddress << std::dec << std::endl;
                }
            }
            else {
                // 32-bit: Write 4-byte address
                DWORD* iatEntry = reinterpret_cast<DWORD*>(peData.data() + iatOffset);
                DWORD oldValue = *iatEntry;
                *iatEntry = static_cast<DWORD>(stubAddress);

                if (patchedCount < 10) {
                    std::cout << "    IAT[" << i << "] " << import.moduleName << "!" << import.funcName
                        << ": 0x" << std::hex << oldValue << " -> 0x" << static_cast<DWORD>(stubAddress) << std::dec << std::endl;
                }
            }

            patchedCount++;
        }

        if (patchedCount > 10) {
            std::cout << "    ... and " << (patchedCount - 10) << " more IAT patches" << std::endl;
        }

        std::cout << "[+] Successfully patched " << patchedCount << " IAT entries to point to stubs" << std::endl;
        return true;

    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception in PatchIATToStubs: " << e.what() << std::endl;
        return false;
    }
}