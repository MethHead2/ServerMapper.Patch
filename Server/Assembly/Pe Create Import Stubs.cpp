#include "Pe Create Import Stubs.h"
#include "Pe Relocation.h"
#include <iostream>
#include <iomanip>
#include <cstring>

bool CreateImportStubs(std::vector<BYTE>& peData,
    const std::vector<ImportReference>& importReferences,
    const StubSectionInfo& stubInfo,
    bool is64Bit) {
    try {
        if (!stubInfo.created) {
            std::cerr << "[!] Stub section was not created!" << std::endl;
            return false;
        }

        if (importReferences.empty()) {
            std::cout << "[*] No import references to create stubs for" << std::endl;
            return true;
        }

        std::cout << "[*] Creating import stubs..." << std::endl;
        std::cout << "    Import references: " << importReferences.size() << std::endl;
        std::cout << "    Stub section RVA: 0x" << std::hex << stubInfo.sectionRVA << std::dec << std::endl;

        // Validate PE headers
        if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::cerr << "[!] PE data too small" << std::endl;
            return false;
        }

        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "[!] Invalid DOS signature" << std::endl;
            return false;
        }

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(peData.data() + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

        // Find stub section
        PIMAGE_SECTION_HEADER stubSection = nullptr;
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (strncmp(reinterpret_cast<const char*>(sections[i].Name), STUB_SECTION_NAME, 8) == 0) {
                stubSection = &sections[i];
                break;
            }
        }

        if (!stubSection) {
            std::cerr << "[!] Stub section not found!" << std::endl;
            return false;
        }

        // Get image base
        ULONGLONG imageBase;
        if (is64Bit) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
            imageBase = ntHeaders64->OptionalHeader.ImageBase;
        }
        else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
            imageBase = ntHeaders32->OptionalHeader.ImageBase;
        }

        // Process each import reference and create a stub
        int stubsCreated = 0;
        DWORD stubSize = is64Bit ? STUB_SIZE_64BIT : STUB_SIZE_32BIT;

        for (size_t i = 0; i < importReferences.size(); i++) {
            const ImportReference& ref = importReferences[i];

            // Calculate stub RVA and file offset
            DWORD stubRva = stubInfo.sectionRVA + static_cast<DWORD>(i * stubSize);
            DWORD stubFileOffset = stubSection->PointerToRawData + (stubRva - stubSection->VirtualAddress);

            if (stubFileOffset + stubSize > peData.size()) {
                std::cerr << "[!] Stub offset out of bounds!" << std::endl;
                continue;
            }

            // Use the resolved address directly - it's already the actual function address from the client
            ULONGLONG actualFunctionAddress = ref.resolvedAddr;

            // Write JMP stub using your improved format
            BYTE* stubLocation = peData.data() + stubFileOffset;

            if (is64Bit) {
                // RIP-relative JMP to avoid destroying registers
                // FF 25 00 00 00 00    - JMP QWORD PTR [RIP+6]
                // XX XX XX XX XX XX XX XX - target address (8 bytes)
                stubLocation[0] = 0xFF;  // JMP QWORD PTR [RIP+offset]
                stubLocation[1] = 0x25;  // ModR/M byte for RIP-relative
                *reinterpret_cast<DWORD*>(stubLocation + 2) = 0x00000000;  // RIP+6
                *reinterpret_cast<ULONGLONG*>(stubLocation + 6) = actualFunctionAddress;

                // Fill remaining bytes with INT3 (0xCC) for safety
                for (int j = 14; j < STUB_SIZE_64BIT; j++) {
                    stubLocation[j] = 0xCC;
                }
            }
            else {
                // 32-bit stub: JMP [address] 
                // FF 25 XX XX XX XX - JMP DWORD PTR [address]
                // XX XX XX XX       - target function address
                DWORD targetAddressLocation = static_cast<DWORD>(imageBase) + stubRva + 6;

                stubLocation[0] = 0xFF;  // JMP DWORD PTR [address]
                stubLocation[1] = 0x25;  // ModR/M byte
                *reinterpret_cast<DWORD*>(stubLocation + 2) = targetAddressLocation;
                *reinterpret_cast<DWORD*>(stubLocation + 6) = static_cast<DWORD>(actualFunctionAddress);

                // Fill remaining bytes with INT3
                for (int j = 10; j < STUB_SIZE_32BIT; j++) {
                    stubLocation[j] = 0xCC;
                }
            }

            stubsCreated++;

            if (stubsCreated <= 10) {
                std::cout << "    Stub[" << i << "] at RVA 0x" << std::hex << stubRva
                    << " -> " << ref.moduleName << "!" << ref.funcName
                    << " (0x" << actualFunctionAddress << ")" << std::dec;

                // Debug: show first few bytes of stub
                std::cout << " [";
                for (int j = 0; j < (is64Bit ? 14 : 10); j++) {
                    printf("%02X ", stubLocation[j]);
                }
                std::cout << "]" << std::endl;
            }
        }

        if (stubsCreated > 10) {
            std::cout << "    ... and " << (stubsCreated - 10) << " more stubs" << std::endl;
        }

        std::cout << "[+] Successfully created " << stubsCreated << " import stubs" << std::endl;

        return stubsCreated > 0;

    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception in CreateImportStubs: " << e.what() << std::endl;
        return false;
    }
}