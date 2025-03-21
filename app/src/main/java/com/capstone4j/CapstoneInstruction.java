package com.capstone4j;

/**
 * Represents a disassembled machine code instruction from the Capstone engine.
 * <p>
 * This class encapsulates a single instruction that has been disassembled by the Capstone engine,
 * providing access to various properties of the instruction such as its mnemonic representation,
 * operand string, size, and memory address. It also provides access to detailed information about
 * the instruction through the {@link CapstoneInstructionDetails} class.
 * <p>
 * Instances of this class are immutable and are typically created by the
 * {@link CapstoneInstructionFactory#createFromMemorySegment} method when the 
 * {@link CapstoneHandle#disassembleInstruction} method is called.
 * <p>
 * Example usage:
 * <pre>{@code
 * // Disassemble a single instruction
 * CapstoneInstruction instruction = handle.disassembleInstruction(bytes, address);
 * 
 * // Get basic information about the instruction
 * System.out.println("Address: 0x" + Long.toHexString(instruction.getAddress()));
 * System.out.println("Mnemonic: " + instruction.getMnemonic());
 * System.out.println("Operands: " + instruction.getOpStr());
 * System.out.println("Size: " + instruction.getSize() + " bytes");
 * 
 * // Get detailed information if available
 * if (instruction.getDetails() != null) {
 *     System.out.println("Registers read: " + Arrays.toString(instruction.getDetails().getRegsRead()));
 *     System.out.println("Registers written: " + Arrays.toString(instruction.getDetails().getRegsWrite()));
 * }
 * }</pre>
 * 
 * @see CapstoneHandle
 * @see CapstoneInstructionDetails
 */
public class CapstoneInstruction {

    private final int id;
    private final long aliasId;
    private final long address;
    private final int size;
    private final byte[] bytes;
    private final String mnemonic;
    private final String opStr;
    private final boolean isAlias;
    private final boolean usesAliasDetails;
    private final CapstoneInstructionDetails details;
    private final CapstoneArch arch;

    /**
     * Constructs a new CapstoneInstruction with the specified properties.
     * <p>
     * This constructor is package-private and is intended to be used only by
     * the {@link CapstoneInstructionFactory} class.
     *
     * @param id the unique identifier of the instruction
     * @param aliasId the alias identifier (if this instruction is an alias of another)
     * @param address the memory address where this instruction is located
     * @param size the size of the instruction in bytes
     * @param bytes the raw bytes of the instruction
     * @param mnemonic the mnemonic representation of the instruction (e.g., "mov", "add", "jmp")
     * @param opStr the string representation of the instruction's operands
     * @param isAlias whether this instruction is an alias of another instruction
     * @param usesAliasDetails whether alias details should be used for this instruction
     * @param details detailed information about the instruction, or null if not available
     */
    CapstoneInstruction(int id, long aliasId, long address, int size, byte[] bytes, String mnemonic, String opStr, boolean isAlias, boolean usesAliasDetails, CapstoneInstructionDetails details, CapstoneArch arch) {
        this.id = id;
        this.aliasId = aliasId;
        this.address = address;
        this.size = size;
        this.bytes = bytes;
        this.mnemonic = mnemonic;
        this.opStr = opStr;
        this.isAlias = isAlias;
        this.usesAliasDetails = usesAliasDetails;
        this.details = details;
        this.arch = arch;
    }

    /**
     * Returns the unique identifier of this instruction.
     * <p>
     * This ID is architecture-specific and corresponds to the internal Capstone ID for this instruction.
     *
     * @return the unique identifier of this instruction
     */
    public int getId() {
        return this.id;
    }

    /**
     * Returns the alias identifier of this instruction.
     * <p>
     * If this instruction is an alias, this method returns the ID of the instruction it aliases.
     * Otherwise, it returns the same value as {@link #getId()}.
     *
     * @return the alias identifier of this instruction
     * @see #isAlias()
     */
    public long getAliasId() {
        return this.aliasId;
    }

    /**
     * Returns the memory address where this instruction is located.
     * <p>
     * This address is the virtual address provided when disassembling the instruction.
     *
     * @return the memory address of this instruction
     */
    public long getAddress() {
        return this.address;
    }

    /**
     * Returns the size of this instruction in bytes.
     * <p>
     * The size represents how many bytes this instruction occupies in memory.
     * This can vary depending on the architecture and the specific instruction.
     *
     * @return the size of this instruction in bytes
     */
    public int getSize() {
        return this.size;
    }

    /**
     * Returns the raw bytes of this instruction.
     * <p>
     * This is the actual machine code representation of the instruction.
     * The length of the returned array corresponds to the value returned by {@link #getSize()}.
     *
     * @return the raw bytes of this instruction
     */
    public byte[] getBytes() {
        return this.bytes;
    }

    /**
     * Returns the mnemonic representation of this instruction.
     * <p>
     * The mnemonic is the human-readable name of the instruction (e.g., "mov", "add", "jmp").
     * It is architecture-specific and follows the assembly language conventions for the target architecture.
     *
     * @return the mnemonic representation of this instruction
     */
    public String getMnemonic() {
        return this.mnemonic;
    }

    /**
     * Returns the string representation of this instruction's operands.
     * <p>
     * This string contains the operands of the instruction in a human-readable format.
     * The format follows the assembly language conventions for the target architecture.
     *
     * @return the string representation of this instruction's operands
     */
    public String getOpStr() {
        return this.opStr;
    }

    /**
     * Returns whether this instruction is an alias of another instruction.
     * <p>
     * Some architectures define aliases for certain instructions. For example,
     * in x86, "xchg eax, eax" is an alias for "nop".
     *
     * @return {@code true} if this instruction is an alias, {@code false} otherwise
     * @see #getAliasId()
     */
    public boolean isAlias() {
        return this.isAlias;
    }

    /**
     * Returns whether alias details should be used for this instruction.
     * <p>
     * This flag indicates whether the details of the aliased instruction
     * should be used when accessing detailed information about this instruction.
     *
     * @return {@code true} if alias details should be used, {@code false} otherwise
     */
    public boolean usesAliasDetails() {
        return this.usesAliasDetails;
    }    

    /**
     * Returns detailed information about this instruction.
     * <p>
     * The returned object provides access to additional information about the instruction,
     * such as registers read and written, instruction groups, and more. This information
     * is only available if the {@link CapstoneHandle} was configured to provide details
     * by setting the {@link CapstoneOption#DETAIL} option to {@link CapstoneOptionValue#ON}.
     *
     * @return detailed information about this instruction, or {@code null} if not available
     * @see CapstoneInstructionDetails
     * @see CapstoneHandle#setOption(CapstoneOption, CapstoneOptionValue)
     */
    public CapstoneInstructionDetails getDetails() {
        return this.details;
    }

    /**
     * Returns the architecture for which this instruction was disassembled.
     * <p>
     * This method provides access to the architecture information associated with
     * this instruction. The architecture determines the instruction set, register
     * names, and various other processor-specific details that affect how the
     * instruction should be interpreted.
     * <p>
     * This information is particularly useful when working with code that might
     * contain instructions from different architectures, or when implementing
     * architecture-specific handling logic.
     * <p>
     * Example usage:
     * <pre>{@code
     * // Disassemble an instruction
     * CapstoneInstruction instruction = handle.disassembleInstruction(code, address);
     * 
     * // Perform architecture-specific processing
     * switch (instruction.getArch()) {
     *     case X86:
     *         processX86Instruction(instruction);
     *         break;
     *     case ARM:
     *         processArmInstruction(instruction);
     *         break;
     *     // Handle other architectures...
     * }
     * }</pre>
     *
     * @return the architecture for which this instruction was disassembled
     * @see CapstoneArch
     * @see CapstoneHandle#disassembleInstruction(byte[], long)
     */
    public CapstoneArch getArch() {
        return this.arch;
    }

    /**
     * Checks if this instruction belongs to a specific instruction group.
     * <p>
     * Instruction groups are categories that classify instructions based on their functionality 
     * or behavior (e.g., jump instructions, call instructions, etc.). This method provides
     * a convenient way to check if an instruction belongs to a particular group without having
     * to manually iterate through the groups array from the instruction details.
     * <p>
     * This is particularly useful for filtering instructions based on their characteristics
     * during code analysis or when implementing instruction set simulators, emulators, or
     * static analysis tools.
     * <p>
     * Example usage:
     * <pre>{@code
     * // Disassemble an instruction
     * CapstoneInstruction instruction = handle.disassembleInstruction(code, address);
     * 
     * // Check if this is a jump instruction
     * if (instruction.isInsnGroup(CapstoneGroup.JUMP)) {
     *     System.out.println("This is a jump instruction");
     * }
     * 
     * // Check if this is a call instruction
     * if (instruction.isInsnGroup(CapstoneGroup.CALL)) {
     *     System.out.println("This is a call instruction");
     * }
     * }</pre>
     * <p>
     * Note that this method requires instruction details to be available, which means
     * the {@link CapstoneOption#DETAIL} option must have been enabled when creating the
     * Capstone handle.
     *
     * @param csGroup the instruction group to check for, one of the predefined groups in {@link CapstoneGroup}
     * @return {@code true} if the instruction belongs to the specified group, {@code false} otherwise
     *         or if instruction details are not available
     * @see CapstoneGroup
     * @see CapstoneInstructionDetails#getGroups()
     * @see CapstoneHandle#getGroupName(int)
     */
    public boolean isInsnGroup(CapstoneGroup csGroup) {
        if(this.details == null) {
            return false;
        }
        for(int group : this.details.getGroups()) {
            if(group == csGroup.getValue()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if this instruction belongs to a specific instruction group identified by its numeric ID.
     * <p>
     * This is an alternative to {@link #isInsnGroup(CapstoneGroup)} that accepts a raw group ID
     * directly instead of a {@link CapstoneGroup} enum value. It checks if the instruction belongs
     * to the group by comparing the ID directly against the group IDs in the instruction details.
     * <p>
     * This method is useful when:
     * <ul>
     *   <li>Working with architecture-specific group IDs that may not be defined in the {@link CapstoneGroup} enum</li>
     *   <li>Dealing with raw group IDs from external sources or databases</li>
     *   <li>Processing groups programmatically where group IDs are determined at runtime</li>
     * </ul>
     * <p>
     * Example usage:
     * <pre>{@code
     * // Disassemble an instruction
     * CapstoneInstruction instruction = handle.disassembleInstruction(code, address);
     * 
     * // Check if this is a jump instruction using raw group ID
     * if (instruction.isInsnGroup(1)) {  // Assuming 1 is the ID for jump instructions
     *     System.out.println("This is a jump instruction");
     * }
     * }</pre>
     * <p>
     * When possible, it's generally recommended to use the {@link #isInsnGroup(CapstoneGroup)}
     * method with the enum constants for better code readability and type safety.
     * <p>
     * Note that this method requires instruction details to be available, which means
     * the {@link CapstoneOption#DETAIL} option must have been enabled when creating the
     * Capstone handle.
     *
     * @param groupId the numeric identifier of the instruction group to check for
     * @return {@code true} if the instruction belongs to the specified group, {@code false} otherwise
     *         or if instruction details are not available
     * @see CapstoneGroup
     * @see CapstoneInstructionDetails#getGroups()
     * @see CapstoneHandle#getGroupName(int)
     */
    public boolean isInsnGroup(int groupId) {
        if(this.details == null) {
            return false;
        }
        for(int group : this.details.getGroups()) {
            if(group == groupId) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if this instruction reads from a specific register.
     * <p>
     * This method examines the instruction details to determine if the instruction reads
     * from the register identified by the provided register ID. Instructions often read from
     * registers to obtain operands for their operations.
     * <p>
     * This method provides a convenient way to check for specific register usage without
     * having to manually iterate through the registers read array from the instruction details.
     * <p>
     * Example usage:
     * <pre>{@code
     * // Disassemble an instruction
     * CapstoneInstruction instruction = handle.disassembleInstruction(code, address);
     * 
     * // Check if this instruction reads from EAX register (example with hypothetical ID)
     * if (instruction.isRegRead(X86_REG_EAX)) {
     *     System.out.println("This instruction reads from EAX");
     * }
     * }</pre>
     * <p>
     * This method is particularly useful when analyzing data flow in a program, tracking
     * register usage across multiple instructions, or when implementing register allocation
     * strategies in a code generation context.
     * <p>
     * Note that this method requires instruction details to be available, which means
     * the {@link CapstoneOption#DETAIL} option must have been enabled when creating the
     * Capstone handle.
     *
     * @param regId the numeric identifier of the register to check for
     * @return {@code true} if the instruction reads from the specified register, {@code false} otherwise
     *         or if instruction details are not available
     * @see CapstoneInstructionDetails#getRegsRead()
     * @see CapstoneInstructionDetails#getRegsReadCount()
     * @see CapstoneHandle#getRegName(int)
     */
    public boolean isRegRead(int regId) {
        if(this.details == null) {
            return false;
        }
        for(int reg : this.details.getRegsRead()) {
            if(reg == regId) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if this instruction writes to a specific register.
     * <p>
     * This method examines the instruction details to determine if the instruction writes
     * to (modifies) the register identified by the provided register ID. Instructions often
     * write to registers to store results of their operations or to update processor state.
     * <p>
     * This method provides a convenient way to check for specific register modification without
     * having to manually iterate through the registers written array from the instruction details.
     * <p>
     * Example usage:
     * <pre>{@code
     * // Disassemble an instruction
     * CapstoneInstruction instruction = handle.disassembleInstruction(code, address);
     * 
     * // Check if this instruction writes to EAX register (example with hypothetical ID)
     * if (instruction.isRegWrite(X86_REG_EAX)) {
     *     System.out.println("This instruction modifies EAX");
     * }
     * }</pre>
     * <p>
     * This method is particularly useful for:
     * <ul>
     *   <li>Tracking register modifications through a sequence of instructions</li>
     *   <li>Identifying register dependencies in code analysis</li>
     *   <li>Determining where values in registers are defined or redefined</li>
     *   <li>Implementing liveness analysis in compiler optimizations</li>
     * </ul>
     * <p>
     * Note that this method requires instruction details to be available, which means
     * the {@link CapstoneOption#DETAIL} option must have been enabled when creating the
     * Capstone handle.
     *
     * @param regId the numeric identifier of the register to check for
     * @return {@code true} if the instruction writes to the specified register, {@code false} otherwise
     *         or if instruction details are not available
     * @see CapstoneInstructionDetails#getRegsWrite()
     * @see CapstoneInstructionDetails#getRegsWriteCount()
     * @see CapstoneHandle#getRegName(int)
     * @see #isRegRead(int)
     */
    public boolean isRegWrite(int regId) {
        if(this.details == null) {
            return false;
        }
        for(int reg : this.details.getRegsWrite()) {
            if(reg == regId) {
                return true;
            }
        }
        return false;
    }
}
