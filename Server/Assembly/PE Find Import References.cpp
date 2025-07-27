#include "Pe Find Import References.h"
#include "Pe Instruction Parser.h"
#include "Pe Relocation.h"
#include <iostream>
#include <iomanip>

bool FindImportReferences(std::vector<BYTE>& peData, std::vector<ImportReference>& references, bool is64Bit) {
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(peData.data() + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

    // Build IAT map
    std::unordered_map<ULONGLONG, std::pair<std::string, std::string>> iatMap;
    std::unordered_map<DWORD, ULONGLONG> iatRvaToAddr;

    PIMAGE_DATA_DIRECTORY importDir = nullptr;
    ULONGLONG imageBase;
    DWORD iatStartRva = UINT_MAX, iatEndRva = 0;

    if (is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
        importDir = &ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        imageBase = ntHeaders64->OptionalHeader.ImageBase;
    }
    else {
        PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
        importDir = &ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        imageBase = ntHeaders32->OptionalHeader.ImageBase;
    }

    // Build IAT map
    if (importDir->Size && importDir->VirtualAddress) {
        DWORD importOffset = RvaToOffsetMemory(peData, importDir->VirtualAddress);
        PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(peData.data() + importOffset);

        while (importDesc->Name != 0) {
            DWORD nameOffset = RvaToOffsetMemory(peData, importDesc->Name);
            char* moduleName = reinterpret_cast<char*>(peData.data() + nameOffset);

            DWORD iatRva = importDesc->FirstThunk;
            if (iatRva < iatStartRva) iatStartRva = iatRva;

            // Use OriginalFirstThunk if available, otherwise use FirstThunk
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
                        PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameOffset);
                        functionName = reinterpret_cast<char*>(importByName->Name);
                    }

                    ULONGLONG resolvedAddr = iatThunk->u1.Function;
                    iatMap[resolvedAddr] = { moduleName, functionName };
                    iatRvaToAddr[iatRva] = resolvedAddr;

                    intThunk++;
                    iatThunk++;
                    iatRva += sizeof(IMAGE_THUNK_DATA64);
                }
                if (iatRva > iatEndRva) iatEndRva = iatRva;
            }
            else {
                // 32-bit processing
                PIMAGE_THUNK_DATA32 intThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(peData.data() + intOffset);
                PIMAGE_THUNK_DATA32 iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(peData.data() + iatOffset);

                while (intThunk->u1.AddressOfData != 0) {
                    std::string functionName;

                    if (IMAGE_SNAP_BY_ORDINAL32(intThunk->u1.Ordinal)) {
                        functionName = "#" + std::to_string(IMAGE_ORDINAL32(intThunk->u1.Ordinal));
                    }
                    else {
                        DWORD nameOffset = RvaToOffsetMemory(peData, intThunk->u1.AddressOfData);
                        PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(peData.data() + nameOffset);
                        functionName = reinterpret_cast<char*>(importByName->Name);
                    }

                    ULONGLONG resolvedAddr = iatThunk->u1.Function;
                    iatMap[resolvedAddr] = { moduleName, functionName };
                    iatRvaToAddr[iatRva] = resolvedAddr;

                    intThunk++;
                    iatThunk++;
                    iatRva += sizeof(IMAGE_THUNK_DATA32);
                }
                if (iatRva > iatEndRva) iatEndRva = iatRva;
            }
            importDesc++;
        }
    }

    std::cout << "[*] Built IAT map with " << iatMap.size() << " imports" << std::endl;
    std::cout << "[*] IAT range: 0x" << std::hex << iatStartRva << " - 0x" << iatEndRva << std::dec << std::endl;

    // Create instruction parser
    InstructionParser parser(is64Bit);

    // Scan all code sections
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (!(sections[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
            continue;
        }

        DWORD sectionOffset = sections[i].PointerToRawData;
        DWORD sectionSize = sections[i].SizeOfRawData;
        DWORD sectionRva = sections[i].VirtualAddress;

        std::cout << "[*] Scanning code section: " << sections[i].Name
            << " at RVA 0x" << std::hex << sectionRva << std::dec << std::endl;

        // Track register state for this section
        RegisterState regState;
        regState.lastPushWasIAT = false;
        regState.lastPushedAddress = 0;

        DWORD offset = 0;
        while (offset < sectionSize) {
            uint8_t* code = peData.data() + sectionOffset + offset;
            uint64_t rip = imageBase + sectionRva + offset;

            ParsedInstruction inst;
            if (parser.ParseInstruction(code, rip, inst)) {
                // Update register tracking
                parser.UpdateRegisterState(inst, regState, imageBase + iatStartRva, imageBase + iatEndRva);

                // Check direct IAT references
                if (inst.hasMemoryOperand) {
                    uint64_t targetAddr = parser.GetMemoryTarget(inst, imageBase);
                    DWORD targetRva = static_cast<DWORD>(targetAddr - imageBase);

                    if (targetRva >= iatStartRva && targetRva < iatEndRva) {
                        auto it = iatRvaToAddr.find(targetRva);
                        if (it != iatRvaToAddr.end()) {
                            auto importIt = iatMap.find(it->second);
                            if (importIt != iatMap.end()) {
                                ImportReference ref;
                                ref.rva = sectionRva + offset;
                                ref.moduleName = importIt->second.first;
                                ref.funcName = importIt->second.second;
                                ref.resolvedAddr = it->second;
                                ref.isDirectCall = (inst.type == INST_CALL_INDIRECT);

                                references.push_back(ref);

                                if (references.size() <= 10) {
                                    const char* instName = "";
                                    switch (inst.type) {
                                    case INST_CALL_INDIRECT: instName = "CALL [mem]"; break;
                                    case INST_JMP_INDIRECT: instName = "JMP [mem]"; break;
                                    case INST_MOV_FROM_MEM: instName = "MOV"; break;
                                    case INST_LEA_FROM_MEM: instName = "LEA"; break;
                                    case INST_PUSH_MEM: instName = "PUSH [mem]"; break;
                                    }
                                    std::cout << "  Found import ref at 0x" << std::hex << ref.rva
                                        << ": " << ref.moduleName << "!" << ref.funcName
                                        << " (" << instName << ")" << std::dec << std::endl;
                                }
                            }
                        }
                    }
                }

                // Check indirect calls through registers
                if (inst.type == INST_CALL_REGISTER || inst.type == INST_JMP_REGISTER) {
                    if (inst.srcReg != REG_NONE) {
                        auto regIt = regState.regFromIAT.find(inst.srcReg);
                        if (regIt != regState.regFromIAT.end() && regIt->second) {
                            auto addrIt = regState.regToAddress.find(inst.srcReg);
                            if (addrIt != regState.regToAddress.end()) {
                                // Apply any tracked offset
                                uint64_t adjustedAddr = addrIt->second;
                                auto offsetIt = regState.regAddOffset.find(inst.srcReg);
                                if (offsetIt != regState.regAddOffset.end()) {
                                    adjustedAddr += offsetIt->second;
                                }

                                DWORD targetRva = static_cast<DWORD>(adjustedAddr - imageBase);
                                auto iatIt = iatRvaToAddr.find(targetRva);
                                if (iatIt != iatRvaToAddr.end()) {
                                    auto importIt = iatMap.find(iatIt->second);
                                    if (importIt != iatMap.end()) {
                                        ImportReference ref;
                                        ref.rva = sectionRva + offset;
                                        ref.moduleName = importIt->second.first;
                                        ref.funcName = importIt->second.second;
                                        ref.resolvedAddr = iatIt->second;
                                        ref.isDirectCall = (inst.type == INST_CALL_REGISTER);

                                        references.push_back(ref);

                                        if (references.size() <= 10) {
                                            const char* regName[] = { "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
                                                                   "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15" };
                                            std::cout << "  Found indirect ref at 0x" << std::hex << ref.rva
                                                << ": " << ref.moduleName << "!" << ref.funcName
                                                << " (CALL " << regName[inst.srcReg] << ")" << std::dec << std::endl;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Check PUSH/RET pattern
                if (inst.type == INST_RET && regState.lastPushWasIAT) {
                    DWORD targetRva = static_cast<DWORD>(regState.lastPushedAddress - imageBase);
                    auto iatIt = iatRvaToAddr.find(targetRva);
                    if (iatIt != iatRvaToAddr.end()) {
                        auto importIt = iatMap.find(iatIt->second);
                        if (importIt != iatMap.end()) {
                            ImportReference ref;
                            ref.rva = sectionRva + offset;
                            ref.moduleName = importIt->second.first;
                            ref.funcName = importIt->second.second;
                            ref.resolvedAddr = iatIt->second;
                            ref.isDirectCall = false;

                            references.push_back(ref);

                            if (references.size() <= 10) {
                                std::cout << "  Found PUSH/RET ref at 0x" << std::hex << ref.rva
                                    << ": " << ref.moduleName << "!" << ref.funcName
                                    << " (PUSH/RET pattern)" << std::dec << std::endl;
                            }
                        }
                    }
                }

                // Check conditional jumps to IAT (Jcc)
                if (inst.type == INST_JCC) {
                    DWORD targetRva = static_cast<DWORD>(inst.targetAddress - imageBase);

                    // Check if Jcc targets an IAT entry directly (rare but possible)
                    if (targetRva >= iatStartRva && targetRva < iatEndRva) {
                        auto it = iatRvaToAddr.find(targetRva);
                        if (it != iatRvaToAddr.end()) {
                            auto importIt = iatMap.find(it->second);
                            if (importIt != iatMap.end()) {
                                ImportReference ref;
                                ref.rva = sectionRva + offset;
                                ref.moduleName = importIt->second.first;
                                ref.funcName = importIt->second.second;
                                ref.resolvedAddr = it->second;
                                ref.isDirectCall = false;

                                references.push_back(ref);

                                if (references.size() <= 10) {
                                    std::cout << "  Found Jcc ref at 0x" << std::hex << ref.rva
                                        << ": " << ref.moduleName << "!" << ref.funcName
                                        << " (Conditional jump)" << std::dec << std::endl;
                                }
                            }
                        }
                    }
                }

                offset += inst.length;
            }
            else {
                offset++; // Skip unknown instruction
            }
        }
    }

    std::cout << "[+] Found " << references.size() << " import references total" << std::endl;
    return true;
}