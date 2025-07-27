#include "Pe Create Stub Section.h"
#include <iostream>
#include <cstring>
#include <algorithm>

DWORD AlignUp(DWORD value, DWORD alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

DWORD CalculateStubSectionSize(size_t referenceCount, bool is64Bit) {
    // Calculate size based on stub size per reference
    DWORD stubSize = is64Bit ? STUB_SIZE_64BIT : STUB_SIZE_32BIT;
    DWORD totalSize = static_cast<DWORD>(referenceCount * stubSize);

    // Add some padding for safety
    totalSize += 0x100;

    // Align to page boundary
    return AlignUp(totalSize, 0x1000);
}

DWORD GetStubSectionRVA(const std::vector<BYTE>& peData) {
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE*>(peData.data()));
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<BYTE*>(peData.data()) + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

    // Find the stub section
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp(reinterpret_cast<const char*>(sections[i].Name), STUB_SECTION_NAME, 8) == 0) {
            return sections[i].VirtualAddress;
        }
    }

    return 0;
}

DWORD GetStubRVA(const std::vector<BYTE>& peData, size_t referenceIndex, bool is64Bit) {
    DWORD stubSectionRVA = GetStubSectionRVA(peData);
    if (stubSectionRVA == 0) {
        return 0;
    }

    DWORD stubSize = is64Bit ? STUB_SIZE_64BIT : STUB_SIZE_32BIT;
    return stubSectionRVA + static_cast<DWORD>(referenceIndex * stubSize);
}

bool CreateStubSection(std::vector<BYTE>& peData,
    const std::vector<ImportReference>& importReferences,
    bool is64Bit,
    StubSectionInfo& stubInfo) {
    try {
        // Initialize stub info
        stubInfo = StubSectionInfo{};
        stubInfo.created = false;

        // Validate PE
        if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::cerr << "[!] PE data too small" << std::endl;
            return false;
        }

        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "[!] Invalid DOS signature" << std::endl;
            return false;
        }

        if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > peData.size()) {
            std::cerr << "[!] Invalid e_lfanew" << std::endl;
            return false;
        }

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(peData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "[!] Invalid NT signature" << std::endl;
            return false;
        }

        // Check if we have room for another section
        DWORD sectionOffset = dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
            ntHeaders->FileHeader.SizeOfOptionalHeader;
        DWORD maxSections = (ntHeaders->OptionalHeader.SizeOfHeaders - sectionOffset) / sizeof(IMAGE_SECTION_HEADER);

        if (ntHeaders->FileHeader.NumberOfSections >= maxSections - 1) {
            std::cerr << "[!] No room for additional section header" << std::endl;
            return false;
        }

        // Calculate new section parameters
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        PIMAGE_SECTION_HEADER lastSection = &sections[ntHeaders->FileHeader.NumberOfSections - 1];

        // Calculate virtual address for new section
        DWORD newVirtualAddress = AlignUp(
            lastSection->VirtualAddress + lastSection->Misc.VirtualSize,
            ntHeaders->OptionalHeader.SectionAlignment
        );

        // Calculate raw offset for new section
        DWORD newRawOffset = AlignUp(
            lastSection->PointerToRawData + lastSection->SizeOfRawData,
            ntHeaders->OptionalHeader.FileAlignment
        );

        // Calculate sizes
        DWORD stubSectionSize = CalculateStubSectionSize(importReferences.size(), is64Bit);
        DWORD virtualSize = stubSectionSize;
        DWORD rawSize = AlignUp(stubSectionSize, ntHeaders->OptionalHeader.FileAlignment);

        // Store stub info
        stubInfo.sectionRVA = newVirtualAddress;
        stubInfo.sectionSize = virtualSize;
        stubInfo.sectionFileOffset = newRawOffset;
        stubInfo.stubCount = importReferences.size();

        std::cout << "[*] Creating stub section:" << std::endl;
        std::cout << "    Name: " << STUB_SECTION_NAME << std::endl;
        std::cout << "    Virtual Address: 0x" << std::hex << newVirtualAddress << std::dec << std::endl;
        std::cout << "    Virtual Size: 0x" << std::hex << virtualSize << std::dec << std::endl;
        std::cout << "    Raw Offset: 0x" << std::hex << newRawOffset << std::dec << std::endl;
        std::cout << "    Raw Size: 0x" << std::hex << rawSize << std::dec << std::endl;
        std::cout << "    Import References: " << importReferences.size() << std::endl;
        std::cout << "    Stub size per reference: " << (is64Bit ? STUB_SIZE_64BIT : STUB_SIZE_32BIT) << " bytes" << std::endl;

        // Add new section header
        PIMAGE_SECTION_HEADER newSection = &sections[ntHeaders->FileHeader.NumberOfSections];
        memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));

        // Set section name
        strncpy_s(reinterpret_cast<char*>(newSection->Name), 8, STUB_SECTION_NAME, _TRUNCATE);

        // Set section parameters
        newSection->Misc.VirtualSize = virtualSize;
        newSection->VirtualAddress = newVirtualAddress;
        newSection->SizeOfRawData = rawSize;
        newSection->PointerToRawData = newRawOffset;

        // Set section characteristics - must be executable and readable
        newSection->Characteristics = IMAGE_SCN_CNT_CODE |          // Contains code
            IMAGE_SCN_MEM_EXECUTE |       // Executable
            IMAGE_SCN_MEM_READ;           // Readable

        // Update PE headers
        ntHeaders->FileHeader.NumberOfSections++;

        // Update SizeOfImage
        DWORD newSizeOfImage = AlignUp(
            newVirtualAddress + virtualSize,
            ntHeaders->OptionalHeader.SectionAlignment
        );

        if (is64Bit) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
            ntHeaders64->OptionalHeader.SizeOfImage = newSizeOfImage;
        }
        else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
            ntHeaders32->OptionalHeader.SizeOfImage = newSizeOfImage;
        }

        // Resize PE data to accommodate new section
        size_t oldSize = peData.size();
        size_t newSize = newRawOffset + rawSize;

        if (newSize > oldSize) {
            peData.resize(newSize);
            // Zero out the new section data
            memset(peData.data() + newRawOffset, 0, rawSize);
        }

        std::cout << "[+] Stub section created successfully" << std::endl;
        std::cout << "    Old file size: " << oldSize << " bytes" << std::endl;
        std::cout << "    New file size: " << newSize << " bytes" << std::endl;

        // Initialize stub section with INT3 (0xCC) for safety
        memset(peData.data() + newRawOffset, 0xCC, rawSize);

        // Important: Since we remove 1024 bytes of header later, we need to ensure
        // our stub section's raw offset is beyond the first 1024 bytes
        if (newRawOffset < 1024) {
            std::cerr << "[!] Warning: Stub section raw offset is within first 1024 bytes!" << std::endl;
            std::cerr << "    This section will be lost when headers are removed!" << std::endl;
            // This should never happen in practice as sections usually start after headers
        }

        stubInfo.created = true;
        return true;

    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception in CreateStubSection: " << e.what() << std::endl;
        return false;
    }
}

bool AddSectionHeader(std::vector<BYTE>& peData,
    const char* sectionName,
    DWORD virtualSize,
    DWORD virtualAddress,
    DWORD rawSize,
    DWORD rawOffset,
    DWORD characteristics) {
    // This is a helper function that could be used for more generic section addition
    // For now, the functionality is integrated into CreateStubSection
    return true;
}