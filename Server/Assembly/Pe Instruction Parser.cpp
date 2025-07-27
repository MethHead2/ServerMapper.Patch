#include "Pe Instruction Parser.h"
#include <cstring>

InstructionParser::InstructionParser(bool is64Bit) : is64Bit(is64Bit), currentRip(0) {}

bool InstructionParser::HasREXPrefix(uint8_t byte) {
    return is64Bit && (byte >= 0x40 && byte <= 0x4F);
}

bool InstructionParser::HasOperandSizePrefix(uint8_t byte) {
    return byte == 0x66;
}

bool InstructionParser::HasAddressSizePrefix(uint8_t byte) {
    return byte == 0x67;
}

int32_t InstructionParser::ReadInt32(const uint8_t* code) {
    return *reinterpret_cast<const int32_t*>(code);
}

int64_t InstructionParser::ReadInt64(const uint8_t* code) {
    return *reinterpret_cast<const int64_t*>(code);
}

X86Register InstructionParser::GetRegFromModRM(uint8_t modrm, bool isDestination, bool hasREX, uint8_t rex) {
    uint8_t reg;
    if (isDestination) {
        reg = (modrm >> 3) & 0x07;
    }
    else {
        reg = modrm & 0x07;
    }

    if (hasREX) {
        if (isDestination && (rex & 0x04)) reg += 8;  // REX.R
        if (!isDestination && (rex & 0x01)) reg += 8; // REX.B
    }

    return reg;  // Now X86Register is just an int
}

uint8_t InstructionParser::ParseModRM(const uint8_t* code, ParsedInstruction& inst) {
    uint8_t modrm = code[0];
    uint8_t mod = (modrm >> 6) & 0x03;
    uint8_t rm = modrm & 0x07;
    uint8_t length = 1;

    // Check for SIB byte
    if (rm == 0x04 && mod != 0x03) {
        length += ParseSIB(&code[1], modrm);
    }

    // Parse displacement
    if (mod == 0x00) {
        if (rm == 0x05) {
            // [disp32] or [RIP+disp32]
            inst.displacement = ReadInt32(&code[length]);
            inst.hasMemoryOperand = true;
            inst.isRipRelative = is64Bit;
            length += 4;
        }
    }
    else if (mod == 0x01) {
        // [reg+disp8]
        inst.displacement = static_cast<int8_t>(code[length]);
        inst.hasMemoryOperand = true;
        length += 1;
    }
    else if (mod == 0x02) {
        // [reg+disp32]
        inst.displacement = ReadInt32(&code[length]);
        inst.hasMemoryOperand = true;
        length += 4;
    }
    else if (mod == 0x03) {
        // Direct register operand, no memory
        inst.hasMemoryOperand = false;
    }

    return length;
}

uint8_t InstructionParser::ParseSIB(const uint8_t* code, const uint8_t modRM) {
    uint8_t sib = code[0];
    uint8_t base = sib & 0x07;
    uint8_t length = 1;

    uint8_t mod = (modRM >> 6) & 0x03;

    // Special case: base == 5
    if (base == 0x05) {
        if (mod == 0x00) {
            // [disp32]
            length += 4;
        }
    }

    return length;
}

bool InstructionParser::ParseInstruction(const uint8_t* code, uint64_t rip, ParsedInstruction& result) {
    currentRip = rip;
    memset(&result, 0, sizeof(result));
    result.destReg = REG_NONE;
    result.srcReg = REG_NONE;

    uint8_t offset = 0;
    bool hasREX = false;
    uint8_t rexByte = 0;
    bool hasOpSize = false;
    bool hasAddrSize = false;

    // Parse prefixes
    while (offset < 15) {
        uint8_t byte = code[offset];

        if (HasOperandSizePrefix(byte)) {
            hasOpSize = true;
            offset++;
        }
        else if (HasAddressSizePrefix(byte)) {
            hasAddrSize = true;
            offset++;
        }
        else if (HasREXPrefix(byte)) {
            hasREX = true;
            rexByte = byte;
            offset++;
        }
        else {
            break;
        }
    }

    // Parse opcode
    uint8_t opcode = code[offset++];

    switch (opcode) {
    case 0xFF: {
        // CALL/JMP/PUSH indirect
        uint8_t modrm = code[offset];
        uint8_t modrmReg = (modrm >> 3) & 0x07;
        uint8_t mod = (modrm >> 6) & 0x03;

        if (modrmReg == 0x02) {
            // CALL [mem] or CALL reg
            if (mod == 0x03) {
                result.type = INST_CALL_REGISTER;
                result.srcReg = GetRegFromModRM(modrm, false, hasREX, rexByte);
                offset++;
            }
            else {
                result.type = INST_CALL_INDIRECT;
                offset += ParseModRM(&code[offset], result);
            }
        }
        else if (modrmReg == 0x04) {
            // JMP [mem] or JMP reg  
            if (mod == 0x03) {
                result.type = INST_JMP_REGISTER;
                result.srcReg = GetRegFromModRM(modrm, false, hasREX, rexByte);
                offset++;
            }
            else {
                result.type = INST_JMP_INDIRECT;
                offset += ParseModRM(&code[offset], result);
            }
        }
        else if (modrmReg == 0x06) {
            // PUSH [mem] or PUSH reg
            if (mod != 0x03) {
                result.type = INST_PUSH_MEM;
                offset += ParseModRM(&code[offset], result);
            }
            else {
                result.type = INST_PUSH_REG;
                result.srcReg = GetRegFromModRM(modrm, false, hasREX, rexByte);
                offset++;
            }
        }
        else {
            result.type = INST_UNKNOWN;
            return false;
        }
        break;
    }

    case 0xC3:  // RET
    case 0xC2:  // RET imm16
        result.type = INST_RET;
        if (opcode == 0xC2) {
            offset += 2;  // Skip imm16
        }
        break;

    case 0x50: case 0x51: case 0x52: case 0x53:  // PUSH reg (short form)
    case 0x54: case 0x55: case 0x56: case 0x57:
        result.type = INST_PUSH_REG;
        result.srcReg = opcode - 0x50;
        if (hasREX && (rexByte & 0x01)) {
            result.srcReg = result.srcReg + 8;
        }
        break;

    case 0x83:  // ADD/SUB reg, imm8
    {
        uint8_t modrm = code[offset];
        uint8_t modrmReg = (modrm >> 3) & 0x07;
        if (modrmReg == 0x00) {  // ADD
            result.type = INST_ADD_TO_REG;
        }
        else if (modrmReg == 0x05) {  // SUB
            result.type = INST_SUB_FROM_REG;
        }
        else {
            result.type = INST_UNKNOWN;
            return false;
        }
        result.destReg = GetRegFromModRM(modrm, false, hasREX, rexByte);
        offset++;
        result.immediate = static_cast<int8_t>(code[offset]);
        offset++;
    }
    break;

    case 0x81:  // ADD/SUB reg, imm32
    {
        uint8_t modrm = code[offset];
        uint8_t modrmReg = (modrm >> 3) & 0x07;
        if (modrmReg == 0x00) {  // ADD
            result.type = INST_ADD_TO_REG;
        }
        else if (modrmReg == 0x05) {  // SUB
            result.type = INST_SUB_FROM_REG;
        }
        else {
            result.type = INST_UNKNOWN;
            return false;
        }
        result.destReg = GetRegFromModRM(modrm, false, hasREX, rexByte);
        offset++;
        result.immediate = ReadInt32(&code[offset]);
        offset += 4;
    }
    break;

    case 0x70: case 0x71: case 0x72: case 0x73:  // Jcc rel8
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        result.type = INST_JCC;
        result.displacement = static_cast<int8_t>(code[offset]);
        offset++;
        result.targetAddress = rip + offset + result.displacement;
        break;

    case 0x0F:  // Two-byte opcodes
    {
        uint8_t secondOpcode = code[offset++];
        if (secondOpcode >= 0x80 && secondOpcode <= 0x8F) {  // Jcc rel32
            result.type = INST_JCC;
            result.displacement = ReadInt32(&code[offset]);
            offset += 4;
            result.targetAddress = rip + offset + result.displacement;
        }
        else {
            result.type = INST_UNKNOWN;
            return false;
        }
    }
    break;

    case 0xE8:
        // CALL rel32
        result.type = INST_CALL_DIRECT;
        result.displacement = ReadInt32(&code[offset]);
        offset += 4;
        result.targetAddress = rip + offset + result.displacement;
        break;

    case 0xE9:
        // JMP rel32
        result.type = INST_JMP_DIRECT;
        result.displacement = ReadInt32(&code[offset]);
        offset += 4;
        result.targetAddress = rip + offset + result.displacement;
        break;

    case 0x8B: {
        // MOV reg, [mem] or MOV reg, reg
        uint8_t modrm = code[offset];
        uint8_t mod = (modrm >> 6) & 0x03;

        result.destReg = GetRegFromModRM(modrm, true, hasREX, rexByte);

        if (mod != 0x03) {
            result.type = INST_MOV_FROM_MEM;
            offset += ParseModRM(&code[offset], result);
        }
        else {
            // Register to register move
            result.type = INST_UNKNOWN;
            return false;
        }
        break;
    }

    case 0x8D: {
        // LEA reg, [mem]
        result.type = INST_LEA_FROM_MEM;
        uint8_t modrm = code[offset];
        result.destReg = GetRegFromModRM(modrm, true, hasREX, rexByte);
        offset += ParseModRM(&code[offset], result);
        break;
    }

    case 0xA1: {
        // MOV EAX/RAX, [moffs]
        if (!is64Bit) {
            result.type = INST_MOV_FROM_MEM;
            result.hasMemoryOperand = true;
            result.displacement = ReadInt32(&code[offset]);
            result.targetAddress = result.displacement;
            result.destReg = REG_RAX;
            offset += 4;
        }
        else {
            // In 64-bit mode, this is different
            result.type = INST_UNKNOWN;
            return false;
        }
        break;
    }

    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
        // MOV reg, imm32/64
        result.type = INST_MOV_TO_REG;
        result.destReg = opcode - 0xB8;
        if (hasREX && (rexByte & 0x01)) {
            result.destReg = result.destReg + 8;
        }

        if (is64Bit && hasREX && (rexByte & 0x08)) {
            // REX.W - 64-bit immediate
            result.immediate = *reinterpret_cast<const uint64_t*>(&code[offset]);
            offset += 8;
        }
        else {
            // 32-bit immediate
            result.immediate = ReadInt32(&code[offset]);
            offset += 4;
        }
        break;
    }

    case 0x48:
        // Could be REX prefix + instruction
        if (is64Bit && offset < 15) {
            // This is actually a REX prefix, re-parse
            hasREX = true;
            rexByte = opcode;
            opcode = code[offset++];

            // Re-check the actual opcode
            if (opcode == 0x8B || opcode == 0x8D) {
                uint8_t modrm = code[offset];
                uint8_t mod = (modrm >> 6) & 0x03;

                if (opcode == 0x8B && mod != 0x03) {
                    result.type = INST_MOV_FROM_MEM;
                    result.destReg = GetRegFromModRM(modrm, true, hasREX, rexByte);
                    offset += ParseModRM(&code[offset], result);
                }
                else if (opcode == 0x8D) {
                    result.type = INST_LEA_FROM_MEM;
                    result.destReg = GetRegFromModRM(modrm, true, hasREX, rexByte);
                    offset += ParseModRM(&code[offset], result);
                }
                else {
                    result.type = INST_UNKNOWN;
                    return false;
                }
            }
            else {
                result.type = INST_UNKNOWN;
                return false;
            }
        }
        else {
            result.type = INST_UNKNOWN;
            return false;
        }
        break;

    default:
        result.type = INST_UNKNOWN;
        return false;
    }

    result.length = offset;

    // Calculate target address for memory operands
    if (result.hasMemoryOperand) {
        if (result.isRipRelative) {
            result.targetAddress = rip + result.length + result.displacement;
        }
        else if (!is64Bit) {
            result.targetAddress = result.displacement;
        }
    }

    return result.type != INST_UNKNOWN;
}

bool InstructionParser::IsIATReference(const ParsedInstruction& inst, uint64_t iatStart, uint64_t iatEnd) {
    if (!inst.hasMemoryOperand) {
        return false;
    }

    return inst.targetAddress >= iatStart && inst.targetAddress < iatEnd;
}

uint64_t InstructionParser::GetMemoryTarget(const ParsedInstruction& inst, uint64_t imageBase) {
    if (inst.hasMemoryOperand) {
        if (is64Bit && inst.isRipRelative) {
            return inst.targetAddress;
        }
        else if (!is64Bit) {
            return inst.targetAddress;
        }
    }
    return 0;
}

void InstructionParser::UpdateRegisterState(const ParsedInstruction& inst, RegisterState& state,
    uint64_t iatStart, uint64_t iatEnd) {
    switch (inst.type) {
    case INST_MOV_FROM_MEM:
    case INST_LEA_FROM_MEM:
        if (inst.destReg != REG_NONE && inst.hasMemoryOperand) {
            if (inst.targetAddress >= iatStart && inst.targetAddress < iatEnd) {
                state.regToAddress[inst.destReg] = inst.targetAddress;
                state.regFromIAT[inst.destReg] = true;
                state.regAddOffset[inst.destReg] = 0;  // Reset offset
            }
            else {
                state.regFromIAT[inst.destReg] = false;
                state.regAddOffset[inst.destReg] = 0;
            }
        }
        break;

    case INST_MOV_TO_REG:
        if (inst.destReg != REG_NONE) {
            // MOV reg, imm clears IAT association
            state.regFromIAT[inst.destReg] = false;
            state.regAddOffset[inst.destReg] = 0;
        }
        break;

    case INST_ADD_TO_REG:
    case INST_SUB_FROM_REG:
        if (inst.destReg != REG_NONE) {
            // Track offset modifications to registers
            if (state.regFromIAT.find(inst.destReg) != state.regFromIAT.end() &&
                state.regFromIAT[inst.destReg]) {
                int offset = static_cast<int>(inst.immediate);
                if (inst.type == INST_SUB_FROM_REG) offset = -offset;
                state.regAddOffset[inst.destReg] += offset;
            }
        }
        break;

    case INST_PUSH_MEM:
        if (inst.hasMemoryOperand && inst.targetAddress >= iatStart && inst.targetAddress < iatEnd) {
            state.lastPushedAddress = inst.targetAddress;
            state.lastPushWasIAT = true;
        }
        else {
            state.lastPushWasIAT = false;
        }
        break;

    case INST_PUSH_REG:
        if (inst.srcReg != REG_NONE) {
            auto it = state.regFromIAT.find(inst.srcReg);
            if (it != state.regFromIAT.end() && it->second) {
                auto addrIt = state.regToAddress.find(inst.srcReg);
                if (addrIt != state.regToAddress.end()) {
                    state.lastPushedAddress = addrIt->second;
                    state.lastPushWasIAT = true;
                }
            }
            else {
                state.lastPushWasIAT = false;
            }
        }
        break;

    case INST_RET:
        // RET after PUSH clears the push state
        state.lastPushWasIAT = false;
        break;
    }
}