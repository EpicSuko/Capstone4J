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
    CapstoneInstruction(int id, long aliasId, long address, int size, byte[] bytes, String mnemonic, String opStr, boolean isAlias, boolean usesAliasDetails, CapstoneInstructionDetails details) {
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
}
