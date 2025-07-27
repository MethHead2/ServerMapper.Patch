#include "Pe Redirect To Stubs.h"
#include "Pe Relocation.h"
#include "Pe Instruction Parser.h"
#include <iostream>
#include <iomanip>
#include <cstring>

// Helper function to patch a RIP-relative address
bool PatchRipRelativeAddress(std::vector<BYTE>& peData, DWORD instructionRva,
    DWORD instructionLength, ULONGLONG oldTarget, ULONGLONG newTarget) {
    // Find where in the instruction the displacement is
    // For most RIP-relative instructions, it's in the last 4 bytes
    DWORD instOffset = RvaToOffsetMemory(peData, instructionRva);
    if (instOffset == 0 || instOffset + instructionLength > peData.size()) {
        return false;
    }

    // Calculate what the displacement should be
    // RIP-relative addressing: target = RIP + displacement
    // RIP = instruction address + instruction length
    ULONGLONG rip = instructionRva + instructionLength;
    int32_t newDisplacement = static_cast<int32_t>(newTarget - rip);

    // Write the new displacement (last 4 bytes of instruction)
    *reinterpret_cast<int32_t*>(peData.data() + instOffset + instructionLength - 4) = newDisplacement;

    return true;
}

bool RedirectImportsToStubs(std::vector<BYTE>& peData,
    const std::vector<ImportReference>& importReferences,
    const StubSectionInfo& stubInfo,
    bool is64Bit) {
    try {
        if (!stubInfo.created) {
            std::cerr << "[!] Stub section was not created!" << std::endl;
            return false;
        }

        if (importReferences.empty()) {
            std::cout << "[*] No import references to redirect" << std::endl;
            return true;
        }

        std::cout << "[*] Redirecting import references to stubs..." << std::endl;
        std::cout << "    Total references to redirect: " << importReferences.size() << std::endl;

        // Get image base
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peData.data());
        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(peData.data() + dosHeader->e_lfanew);
        ULONGLONG imageBase;

        if (is64Bit) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(peData.data() + dosHeader->e_lfanew);
            imageBase = ntHeaders64->OptionalHeader.ImageBase;
        }
        else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(peData.data() + dosHeader->e_lfanew);
            imageBase = ntHeaders32->OptionalHeader.ImageBase;
        }

        // Create instruction parser
        InstructionParser parser(is64Bit);
        int redirectedCount = 0;
        DWORD stubSize = is64Bit ? STUB_SIZE_64BIT : STUB_SIZE_32BIT;

        // Process each import reference
        for (size_t refIdx = 0; refIdx < importReferences.size(); refIdx++) {
            const ImportReference& ref = importReferences[refIdx];
            DWORD stubRva = stubInfo.sectionRVA + static_cast<DWORD>(refIdx * stubSize);

            // Find the instruction at the reference RVA
            DWORD instOffset = RvaToOffsetMemory(peData, ref.rva);
            if (instOffset == 0 || instOffset >= peData.size()) {
                std::cerr << "[!] Invalid instruction offset for reference at RVA 0x"
                    << std::hex << ref.rva << std::dec << std::endl;
                continue;
            }

            // Parse the instruction
            uint8_t* code = peData.data() + instOffset;
            uint64_t rip = imageBase + ref.rva;
            ParsedInstruction inst;

            if (!parser.ParseInstruction(code, rip, inst)) {
                std::cerr << "[!] Failed to parse instruction at RVA 0x"
                    << std::hex << ref.rva << std::dec << std::endl;
                continue;
            }

            // Handle different instruction types
            bool patched = false;

            switch (inst.type) {
            case INST_CALL_INDIRECT:  // CALL [mem] -> Convert to CALL stub
            {
                // Convert indirect CALL to direct CALL
                if (is64Bit) {
                    // Calculate relative offset from instruction end to stub
                    ULONGLONG instructionEnd = ref.rva + 5; // E8 + 4 byte offset
                    int32_t relativeOffset = static_cast<int32_t>(stubRva - instructionEnd);

                    // Replace with: E8 XX XX XX XX (CALL rel32)
                    code[0] = 0xE8;
                    *reinterpret_cast<int32_t*>(code + 1) = relativeOffset;

                    // NOP out remaining bytes if original instruction was longer
                    for (int i = 5; i < inst.length; i++) {
                        code[i] = 0x90;
                    }
                    patched = true;
                }
                else {
                    // 32-bit: same approach
                    DWORD instructionEnd = ref.rva + 5;
                    int32_t relativeOffset = static_cast<int32_t>(stubRva - instructionEnd);

                    code[0] = 0xE8;
                    *reinterpret_cast<int32_t*>(code + 1) = relativeOffset;

                    for (int i = 5; i < inst.length; i++) {
                        code[i] = 0x90;
                    }
                    patched = true;
                }
                break;
            }

            case INST_JMP_INDIRECT:   // JMP [mem] -> Convert to JMP stub
            {
                // Convert indirect JMP to direct JMP
                if (is64Bit) {
                    // Calculate relative offset from instruction end to stub
                    ULONGLONG instructionEnd = ref.rva + 5; // E9 + 4 byte offset
                    int32_t relativeOffset = static_cast<int32_t>(stubRva - instructionEnd);

                    // Replace with: E9 XX XX XX XX (JMP rel32)
                    code[0] = 0xE9;
                    *reinterpret_cast<int32_t*>(code + 1) = relativeOffset;

                    // NOP out remaining bytes
                    for (int i = 5; i < inst.length; i++) {
                        code[i] = 0x90;
                    }
                    patched = true;
                }
                else {
                    // 32-bit: same approach
                    DWORD instructionEnd = ref.rva + 5;
                    int32_t relativeOffset = static_cast<int32_t>(stubRva - instructionEnd);

                    code[0] = 0xE9;
                    *reinterpret_cast<int32_t*>(code + 1) = relativeOffset;

                    for (int i = 5; i < inst.length; i++) {
                        code[i] = 0x90;
                    }
                    patched = true;
                }
                break;
            }

            case INST_MOV_FROM_MEM:  // MOV reg, [mem]
            case INST_LEA_FROM_MEM:  // LEA reg, [mem]
            {
                // For MOV/LEA, we need to load the stub address
                if (is64Bit) {
                    // Convert to LEA reg, [RIP+offset] to load stub address
                    ULONGLONG stubAddress = imageBase + stubRva;

                    // Change to LEA if it's MOV
                    if (inst.type == INST_MOV_FROM_MEM) {
                        for (int i = 0; i < inst.length; i++) {
                            if (code[i] == 0x8B) {
                                code[i] = 0x8D;
                                break;
                            }
                        }
                    }

                    patched = PatchRipRelativeAddress(peData, ref.rva, inst.length,
                        inst.targetAddress, stubAddress);
                }
                else {
                    // 32-bit
                    DWORD stubAbsoluteAddress = static_cast<DWORD>(imageBase + stubRva);

                    if (inst.hasMemoryOperand && inst.length >= 6) {
                        *reinterpret_cast<DWORD*>(code + inst.length - 4) = stubAbsoluteAddress;

                        if (inst.type == INST_MOV_FROM_MEM) {
                            for (int i = 0; i < inst.length; i++) {
                                if (code[i] == 0x8B || code[i] == 0xA1) {
                                    code[i] = (code[i] == 0xA1) ? 0xB8 : 0x8D;
                                    break;
                                }
                            }
                        }
                        patched = true;
                    }
                }
                break;
            }

            case INST_PUSH_MEM:  // PUSH [mem]
            {
                // Convert to PUSH immediate with stub address
                if (inst.length >= 6) {
                    if (is64Bit) {
                        code[0] = 0x68;
                        *reinterpret_cast<DWORD*>(code + 1) = static_cast<DWORD>(imageBase + stubRva);
                        for (int i = 5; i < inst.length; i++) {
                            code[i] = 0x90;
                        }
                    }
                    else {
                        code[0] = 0x68;
                        *reinterpret_cast<DWORD*>(code + 1) = static_cast<DWORD>(imageBase + stubRva);
                        for (int i = 5; i < inst.length; i++) {
                            code[i] = 0x90;
                        }
                    }
                    patched = true;
                }
                break;
            }
            }

            if (patched) {
                redirectedCount++;
                if (redirectedCount <= 10) {
                    std::cout << "    Redirected: " << ref.moduleName << "!" << ref.funcName
                        << " at RVA 0x" << std::hex << ref.rva
                        << " -> DIRECT CALL/JMP to stub at 0x" << stubRva << std::dec << std::endl;
                }
            }
            else {
                std::cerr << "[!] Failed to redirect: " << ref.moduleName << "!" << ref.funcName
                    << " at RVA 0x" << std::hex << ref.rva << std::dec
                    << " (instruction type: " << inst.type << ")" << std::endl;
            }
        }

        if (redirectedCount > 10) {
            std::cout << "    ... and " << (redirectedCount - 10) << " more redirections" << std::endl;
        }

        std::cout << "[+] Successfully redirected " << redirectedCount << " of "
            << importReferences.size() << " import references" << std::endl;

        return redirectedCount > 0;

    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception in RedirectImportsToStubs: " << e.what() << std::endl;
        return false;
    }
}