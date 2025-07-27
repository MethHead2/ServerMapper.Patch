#ifndef INSTRUCTION_PARSER_H
#define INSTRUCTION_PARSER_H

#include <Windows.h>
#include <vector>
#include <cstdint>
#include <unordered_map>

// Forward declarations
struct ParsedInstruction;
struct RegisterState;
class InstructionParser;

// Instruction types we care about
enum InstructionType {
    INST_UNKNOWN = 0,
    INST_CALL_INDIRECT = 1,   // CALL [addr]
    INST_JMP_INDIRECT = 2,    // JMP [addr]
    INST_MOV_FROM_MEM = 3,    // MOV reg, [addr]
    INST_LEA_FROM_MEM = 4,    // LEA reg, [addr]
    INST_CALL_DIRECT = 5,     // CALL rel32
    INST_JMP_DIRECT = 6,      // JMP rel32
    INST_CALL_REGISTER = 7,   // CALL reg
    INST_JMP_REGISTER = 8,    // JMP reg
    INST_PUSH_MEM = 9,        // PUSH [mem]
    INST_MOV_TO_REG = 10,     // MOV reg, immediate (for tracking)
    INST_RET = 11,            // RET instruction
    INST_ADD_TO_REG = 12,     // ADD reg, imm
    INST_SUB_FROM_REG = 13,   // SUB reg, imm
    INST_JCC = 14,            // Conditional jump
    INST_PUSH_REG = 15,       // PUSH reg
    INST_CALL_MEM_INDIRECT = 16  // CALL [reg+offset]
};

// x86/x64 registers - using #define to avoid linkage issues
typedef int X86Register;

#define REG_NONE -1
#define REG_RAX 0
#define REG_RCX 1
#define REG_RDX 2
#define REG_RBX 3
#define REG_RSP 4
#define REG_RBP 5
#define REG_RSI 6
#define REG_RDI 7
#define REG_R8 8
#define REG_R9 9
#define REG_R10 10
#define REG_R11 11
#define REG_R12 12
#define REG_R13 13
#define REG_R14 14
#define REG_R15 15

// Parsed instruction info
struct ParsedInstruction {
    InstructionType type;
    uint8_t length;           // Total instruction length
    bool hasMemoryOperand;    // Does it reference memory?
    bool isRipRelative;       // Is it RIP-relative? (64-bit only)
    int32_t displacement;     // Memory displacement or relative offset
    uint64_t targetAddress;   // Calculated target address (if applicable)
    X86Register destReg;      // Destination register (if applicable)
    X86Register srcReg;       // Source register (if applicable)
    uint64_t immediate;       // Immediate value (if applicable)
};

// Track register contents for indirect calls
struct RegisterState {
    std::unordered_map<int, uint64_t> regToAddress;  // Register -> IAT address
    std::unordered_map<int, bool> regFromIAT;        // Is register loaded from IAT?
    std::unordered_map<int, int> regAddOffset;       // Track ADD/SUB offsets to registers
    uint64_t lastPushedAddress;                       // Track last pushed address for PUSH/RET pattern
    bool lastPushWasIAT;                             // Was last push from IAT?
};

// Main parser class
class InstructionParser {
private:
    bool is64Bit;
    uint64_t currentRip;  // Current instruction pointer

    // Helper functions
    bool HasREXPrefix(uint8_t byte);
    bool HasOperandSizePrefix(uint8_t byte);
    bool HasAddressSizePrefix(uint8_t byte);
    uint8_t ParseModRM(const uint8_t* code, ParsedInstruction& inst);
    uint8_t ParseSIB(const uint8_t* code, const uint8_t modRM);
    int32_t ReadInt32(const uint8_t* code);
    int64_t ReadInt64(const uint8_t* code);
    X86Register GetRegFromModRM(uint8_t modrm, bool isDestination, bool hasREX, uint8_t rex);

public:
    InstructionParser(bool is64Bit);

    // Parse a single instruction
    bool ParseInstruction(const uint8_t* code, uint64_t rip, ParsedInstruction& result);

    // Check if instruction references an IAT entry
    bool IsIATReference(const ParsedInstruction& inst, uint64_t iatStart, uint64_t iatEnd);

    // Get actual target address for memory reference
    uint64_t GetMemoryTarget(const ParsedInstruction& inst, uint64_t imageBase);

    // Track register state for indirect calls
    void UpdateRegisterState(const ParsedInstruction& inst, RegisterState& state,
        uint64_t iatStart, uint64_t iatEnd);
};

#endif // INSTRUCTION_PARSER_H