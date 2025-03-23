package com.capstone4j;

/**
 * Provides information about register access by disassembled instructions.
 * <p>
 * This class encapsulates information about which registers are read from and written to
 * by an instruction during its execution. It stores arrays of register IDs along with
 * counts of how many registers are being accessed.
 * <p>
 * Register access information is essential for various types of code analysis:
 * <ul>
 *   <li>Data flow analysis to track how register values propagate through a program</li>
 *   <li>Register allocation in compilers, to determine when registers can be reused</li>
 *   <li>Identifying dependencies between instructions that may affect scheduling</li>
 *   <li>Detecting potential hazards in pipelined processor implementations</li>
 * </ul>
 * <p>
 * This class is typically not instantiated directly by users but is created by the Capstone
 * engine during disassembly when the {@link CapstoneOption#DETAIL} option is enabled.
 * Instances are accessed through the {@link CapstoneInstruction#getRegAccess()} method.
 * <p>
 * Example usage:
 * <pre>{@code
 * // Assuming we have a disassembled instruction with details enabled
 * CapstoneInstruction instruction = handle.disassembleInstruction(code, address);
 * 
 * // Get register access information
 * CapstoneRegAccess regAccess = instruction.getRegAccess();
 * if (regAccess != null) {
 *     // Get registers read by the instruction
 *     int[] regsRead = regAccess.getRegsRead();
 *     for (int regId : regsRead) {
 *         System.out.println("Instruction reads from register: " + handle.getRegName(regId));
 *     }
 *     
 *     // Get registers written by the instruction
 *     int[] regsWrite = regAccess.getRegsWrite();
 *     for (int regId : regsWrite) {
 *         System.out.println("Instruction writes to register: " + handle.getRegName(regId));
 *     }
 * }
 * }</pre>
 * 
 * @see CapstoneInstruction#getRegAccess()
 * @see CapstoneInstructionDetails
 * @see CapstoneOption#DETAIL
 */
public class CapstoneRegAccess {

    /**
     * Array of register IDs that are read by the instruction.
     */
    private final int[] regsRead;
    
    /**
     * Number of registers that are read by the instruction.
     */
    private final int regsReadCount;
    
    /**
     * Array of register IDs that are written to by the instruction.
     */
    private final int[] regsWrite;
    
    /**
     * Number of registers that are written to by the instruction.
     */
    private final int regsWriteCount;

    /**
     * Constructs a new CapstoneRegAccess object with the specified register access information.
     * <p>
     * This constructor is package-private and is intended to be used internally by the
     * Capstone engine during disassembly.
     *
     * @param regsRead array of register IDs that are read by the instruction
     * @param regsReadCount number of registers that are read by the instruction
     * @param regsWrite array of register IDs that are written to by the instruction
     * @param regsWriteCount number of registers that are written to by the instruction
     */
    CapstoneRegAccess(int[] regsRead, int regsReadCount, int[] regsWrite, int regsWriteCount) {
        this.regsRead = regsRead;
        this.regsReadCount = regsReadCount;
        this.regsWrite = regsWrite;
        this.regsWriteCount = regsWriteCount;
    }

    /**
     * Returns an array of register IDs that are read by the instruction.
     * <p>
     * The returned array contains the IDs of all registers that the instruction
     * reads from as part of its operation. These IDs are architecture-specific
     * and can be converted to register names using the {@code getRegName} method
     * of the {@link CapstoneHandle} class.
     * <p>
     * Example usage:
     * <pre>{@code
     * int[] regsRead = regAccess.getRegsRead();
     * for (int regId : regsRead) {
     *     System.out.println("Register read: " + handle.getRegName(regId));
     * }
     * }</pre>
     *
     * @return an array of register IDs that are read by the instruction
     * @see #getRegsReadCount()
     * @see CapstoneHandle#getRegName(int)
     */
    public int[] getRegsRead() {
        return this.regsRead;
    }

    /**
     * Returns the number of registers that are read by the instruction.
     * <p>
     * This count represents how many elements in the array returned by
     * {@link #getRegsRead()} contain valid register IDs. This information
     * is particularly useful for processing the registers array without
     * having to check its length.
     *
     * @return the number of registers that are read by the instruction
     * @see #getRegsRead()
     */
    public int getRegsReadCount() {
        return this.regsReadCount;
    }

    /**
     * Returns an array of register IDs that are written to by the instruction.
     * <p>
     * The returned array contains the IDs of all registers that the instruction
     * writes to or modifies as part of its operation. These IDs are architecture-specific
     * and can be converted to register names using the {@code getRegName} method
     * of the {@link CapstoneHandle} class.
     * <p>
     * Example usage:
     * <pre>{@code
     * int[] regsWrite = regAccess.getRegsWrite();
     * for (int regId : regsWrite) {
     *     System.out.println("Register written: " + handle.getRegName(regId));
     * }
     * }</pre>
     *
     * @return an array of register IDs that are written to by the instruction
     * @see #getRegsWriteCount()
     * @see CapstoneHandle#getRegName(int)
     */
    public int[] getRegsWrite() {
        return this.regsWrite;
    }

    /**
     * Returns the number of registers that are written to by the instruction.
     * <p>
     * This count represents how many elements in the array returned by
     * {@link #getRegsWrite()} contain valid register IDs. This information
     * is particularly useful for processing the registers array without
     * having to check its length.
     *
     * @return the number of registers that are written to by the instruction
     * @see #getRegsWrite()
     */
    public int getRegsWriteCount() {
        return this.regsWriteCount;
    }
}
