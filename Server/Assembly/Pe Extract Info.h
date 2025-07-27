#ifndef PE_EXTRACT_INFO_H
#define PE_EXTRACT_INFO_H

#include <Windows.h>
#include <vector>
#include <cstdint>

// Structure to hold section information extracted from PE
struct ExtractedSectionInfo {
    char name[9];              // Section name (null terminated)
    uintptr_t virtualAddress;  // RVA where section should be loaded
    size_t virtualSize;        // Size in memory
    DWORD protection;          // Memory protection flags
    bool isCode;              // Is this a code section?
    uint32_t dataSize;        // Size of raw data
    DWORD originalFileOffset;  // Original offset in PE (before header removal)
};

// Structure to hold all extracted PE information
struct ExtractedPEInfo {
    uintptr_t entryPoint;                           // Entry point RVA
    std::vector<ExtractedSectionInfo> sections;    // All sections info
    std::vector<uintptr_t> tlsCallbacks;           // TLS callback RVAs
    bool is64Bit;                                  // Architecture
    uint32_t sectionCount;                         // Number of sections
};

// Extract all necessary information from PE headers
bool ExtractPEInfo(const std::vector<BYTE>& peData, ExtractedPEInfo& extractedInfo);

// Helper function to determine protection flags
DWORD GetSectionProtection(DWORD characteristics);

// Helper function to convert RVA to file offset
DWORD RvaToOffset(const std::vector<BYTE>& peData, DWORD rva);

// Get TLS callbacks from the PE
std::vector<uintptr_t> GetTLSCallbacks(const std::vector<BYTE>& peData, bool is64Bit);

#endif // PE_EXTRACT_INFO_H