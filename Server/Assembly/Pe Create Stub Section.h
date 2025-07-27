#ifndef PE_CREATE_STUB_SECTION_H
#define PE_CREATE_STUB_SECTION_H

#include <Windows.h>
#include <vector>
#include <string>

// Structure to hold information about each import
struct ImportInfo {
    std::string moduleName;
    std::string funcName;
    ULONGLONG resolvedAddr;  // Address from client's dummy process
    DWORD iatRva;           // RVA of IAT entry
    DWORD stubRva;          // RVA of generated stub
};

// Configuration for stub section
#define STUB_SECTION_NAME ".stub"
#define STUB_SIZE_32BIT 16      // Size of each 32-bit stub in bytes
#define STUB_SIZE_64BIT 24      // Size of each 64-bit stub in bytes
#define STUB_ALIGNMENT 16       // Alignment for each stub

// Information about the created stub section
struct StubSectionInfo {
    DWORD sectionRVA;           // RVA of the stub section
    DWORD sectionSize;          // Total size of stub section
    DWORD sectionFileOffset;    // File offset of stub section
    size_t stubCount;           // Number of stubs
    bool created;               // Was section successfully created
};

// Create a new stub section in the PE file
bool CreateStubSection(std::vector<BYTE>& peData,
    const std::vector<ImportInfo>& imports,
    bool is64Bit,
    StubSectionInfo& stubInfo);

// Helper functions
DWORD AlignUp(DWORD value, DWORD alignment);
DWORD CalculateStubSectionSize(size_t importCount, bool is64Bit);

// Get the RVA where stubs will be placed
DWORD GetStubSectionRVA(const std::vector<BYTE>& peData);

// Get stub address for a specific import index
DWORD GetStubRVA(const std::vector<BYTE>& peData, size_t importIndex, bool is64Bit);

#endif // PE_CREATE_STUB_SECTION_H