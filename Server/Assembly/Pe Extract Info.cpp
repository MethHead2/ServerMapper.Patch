#include "Pe Extract Info.h"
#include <iostream>
#include <cstring>

DWORD GetSectionProtection(DWORD characteristics) {
    DWORD protection = PAGE_NOACCESS;

    if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
        if (characteristics & IMAGE_SCN_MEM_WRITE) {
            protection = PAGE_EXECUTE_READWRITE;
        }
        else if (characteristics & IMAGE_SCN_MEM_READ) {
            protection = PAGE_EXECUTE_READ;
        }
        else {
            protection = PAGE_EXECUTE;
        }
    }
    else if (characteristics & IMAGE_SCN_MEM_WRITE) {
        protection = PAGE_READWRITE;
    }
    else if (characteristics & IMAGE_SCN_MEM_READ) {
        protection = PAGE_READONLY;
    }

    return protection;
}

DWORD RvaToOffset(const std::vector<BYTE>& peData, DWORD rva) {
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE*>(peData.data()));
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<BYTE*>(peData.data()) + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

    // Check if RVA is in headers
    if (rva < ntHeaders->OptionalHeader.SizeOfHeaders) {
        return rva;
    }

    // Check each section
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= sections[i].VirtualAddress &&
            rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
            return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
        }
    }

    return 0; // Invalid RVA
}

std::vector<uintptr_t> GetTLSCallbacks(const std::vector<BYTE>& peData, bool is64Bit) {
    std::vector<uintptr_t> callbacks;

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE*>(peData.data()));
    PIMAGE_DATA_DIRECTORY tlsDir = nullptr;

    if (is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(const_cast<BYTE*>(peData.data()) + dosHeader->e_lfanew);
        tlsDir = &ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    }
    else {
        PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(const_cast<BYTE*>(peData.data()) + dosHeader->e_lfanew);
        tlsDir = &ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    }

    if (!tlsDir->Size || !tlsDir->VirtualAddress) {
        return callbacks; // No TLS directory
    }

    DWORD tlsOffset = RvaToOffset(peData, tlsDir->VirtualAddress);
    if (tlsOffset == 0 || tlsOffset + tlsDir->Size > peData.size()) {
        return callbacks; // Invalid TLS directory
    }

    // TLS callbacks extraction is complex and would need proper VA to RVA conversion
    // For now, returning empty as in the original implementation
    std::cout << "[*] TLS directory found but callback extraction not implemented" << std::endl;

    return callbacks;
}

bool ExtractPEInfo(const std::vector<BYTE>& peData, ExtractedPEInfo& extractedInfo) {
    try {
        // Clear the output structure
        extractedInfo = ExtractedPEInfo();

        if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::cerr << "[!] PE data too small" << std::endl;
            return false;
        }

        std::cout << "[*] Extracting PE information..." << std::endl;

        // Parse PE headers
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE*>(peData.data()));
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "[!] Invalid DOS signature" << std::endl;
            return false;
        }

        if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > peData.size()) {
            std::cerr << "[!] Invalid e_lfanew" << std::endl;
            return false;
        }

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<BYTE*>(peData.data()) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "[!] Invalid NT signature" << std::endl;
            return false;
        }

        // Determine architecture
        extractedInfo.is64Bit = (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

        // Get entry point
        if (extractedInfo.is64Bit) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeaders);
            extractedInfo.entryPoint = ntHeaders64->OptionalHeader.AddressOfEntryPoint;
        }
        else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(ntHeaders);
            extractedInfo.entryPoint = ntHeaders32->OptionalHeader.AddressOfEntryPoint;
        }

        std::cout << "[*] PE is " << (extractedInfo.is64Bit ? "64-bit" : "32-bit") << std::endl;
        std::cout << "[*] Entry point RVA: 0x" << std::hex << extractedInfo.entryPoint << std::dec << std::endl;

        // Process sections
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        extractedInfo.sectionCount = ntHeaders->FileHeader.NumberOfSections;

        std::cout << "[*] Extracting " << extractedInfo.sectionCount << " sections..." << std::endl;

        // Extract each section's information
        for (uint32_t i = 0; i < extractedInfo.sectionCount; i++) {
            ExtractedSectionInfo secInfo;

            // Copy section name (ensure null termination)
            memset(secInfo.name, 0, sizeof(secInfo.name));
            memcpy(secInfo.name, sections[i].Name, 8);

            secInfo.virtualAddress = sections[i].VirtualAddress;
            secInfo.virtualSize = sections[i].Misc.VirtualSize;
            secInfo.protection = GetSectionProtection(sections[i].Characteristics);
            secInfo.isCode = (sections[i].Characteristics & IMAGE_SCN_CNT_CODE) != 0;
            secInfo.originalFileOffset = sections[i].PointerToRawData;

            // Determine actual data size
            if (sections[i].PointerToRawData != 0 && sections[i].SizeOfRawData != 0 &&
                sections[i].PointerToRawData + sections[i].SizeOfRawData <= peData.size()) {
                secInfo.dataSize = sections[i].SizeOfRawData;
            }
            else {
                secInfo.dataSize = 0;
            }

            std::cout << "[*] Section " << i << ": " << secInfo.name
                << " VA=0x" << std::hex << secInfo.virtualAddress
                << " VSize=0x" << secInfo.virtualSize
                << " FileOffset=0x" << secInfo.originalFileOffset
                << " DataSize=" << std::dec << secInfo.dataSize
                << (secInfo.isCode ? " [CODE]" : "") << std::endl;

            extractedInfo.sections.push_back(secInfo);
        }

        // Extract TLS callbacks
        extractedInfo.tlsCallbacks = GetTLSCallbacks(peData, extractedInfo.is64Bit);
        std::cout << "[*] Found " << extractedInfo.tlsCallbacks.size() << " TLS callbacks" << std::endl;

        std::cout << "[+] Successfully extracted PE information" << std::endl;
        return true;

    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception during PE info extraction: " << e.what() << std::endl;
        return false;
    }
}