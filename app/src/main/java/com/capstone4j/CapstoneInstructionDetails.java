package com.capstone4j;

import java.util.HashSet;
import java.util.Set;

/**
 * Contains detailed information about a disassembled instruction.
 * <p>
 * This class provides access to additional information about a disassembled instruction,
 * including instruction groups, architecture-specific details, and access to register
 * information through the {@link #getRegAccess()} method.
 * <p>
 * The generic type parameter {@code A} represents the architecture-specific details
 * associated with this instruction.
 * 
 * @param <A> the type of architecture-specific details, must extend {@link CapstoneArchDetails}
 * @see CapstoneInstruction
 * @see CapstoneRegAccess
 * @see CapstoneArchDetails
 */
public class CapstoneInstructionDetails<A extends CapstoneArchDetails<?>> {
    private final CapstoneRegAccess regAccess;
    private final int[] groups;
    private final int groupsCount;
    private final boolean writeback;
    private final A archDetails;

    /**
     * Constructs a new CapstoneInstructionDetails object with the specified properties.
     * <p>
     * This constructor is package-private and is intended to be used internally by the
     * Capstone engine during disassembly.
     *
     * @param regsRead array of register IDs that are read by the instruction
     * @param regsReadCount number of registers that are read by the instruction
     * @param regsWrite array of register IDs that are written to by the instruction
     * @param regsWriteCount number of registers that are written to by the instruction
     * @param groups array of instruction group IDs that this instruction belongs to
     * @param groupsCount number of instruction groups that this instruction belongs to
     * @param writeback whether this instruction performs a memory write-back
     * @param archDetails architecture-specific details for this instruction
     */
    CapstoneInstructionDetails(int[] regsRead, int regsReadCount, int[] regsWrite, int regsWriteCount, int[] groups, int groupsCount, boolean writeback, A archDetails) {
        this.regAccess = new CapstoneRegAccess(regsRead, regsReadCount, regsWrite, regsWriteCount);
        this.groups = groups;
        this.groupsCount = groupsCount;
        this.writeback = writeback;
        this.archDetails = archDetails;
    }

    /**
     * Returns register access information for this instruction.
     * <p>
     * This method provides access to information about which registers are read
     * from and written to by this instruction. To access register information, use:
     * <pre>{@code
     * // Get registers read
     * int[] regsRead = details.getRegAccess().getRegsRead();
     * 
     * // Get registers written
     * int[] regsWrite = details.getRegAccess().getRegsWrite();
     * }</pre>
     *
     * @return a {@link CapstoneRegAccess} object containing register access information
     */
    public CapstoneRegAccess getRegAccess() {
        return this.regAccess;
    }

    /**
     * Returns comprehensive register access information for this instruction,
     * including both implicit register access and operand-based register access.
     * <p>
     * Unlike {@link #getRegAccess()}, which only provides information about
     * implicit register reads and writes, this method also includes registers
     * used in operands that have READ, WRITE, or READ_WRITE access types.
     * <p>
     * This provides a more complete picture of all registers affected by
     * the instruction's execution, which is essential for thorough data flow
     * analysis and register dependency tracking.
     * <p>
     * Example usage:
     * <pre>{@code
     * // Get comprehensive register access info
     * CapstoneInstructionDetails details = instruction.getDetails();
     * if (details != null) {
     *     CapstoneRegAccess fullRegAccess = details.getComprehensiveRegAccess();
     *     System.out.println("All registers read: " + Arrays.toString(fullRegAccess.getRegsRead()));
     *     System.out.println("All registers written: " + Arrays.toString(fullRegAccess.getRegsWrite()));
     * }
     * }</pre>
     *
     * @return a {@link CapstoneRegAccess} object containing comprehensive register access information
     * @see CapstoneRegAccess
     * @see #getRegAccess()
     * @see CapstoneAccessType
     */
    public CapstoneRegAccess getComprehensiveRegAccess() {
        // Get the basic register access information
        CapstoneRegAccess basicRegAccess = this.regAccess;
        
        // Create sets to hold all unique register IDs
        // Using sets to avoid duplicates
        Set<Integer> allRegsRead = new HashSet<>();
        Set<Integer> allRegsWrite = new HashSet<>();
        
        // Add the basic register access information
        for (int reg : basicRegAccess.getRegsRead()) {
            allRegsRead.add(reg);
        }
        
        for (int reg : basicRegAccess.getRegsWrite()) {
            allRegsWrite.add(reg);
        }
        
        A archDetails = this.archDetails;
        
        // Get operands with different access types
        Object[] readOperands = archDetails.getOperandsOfAccess(CapstoneAccessType.READ);
        Object[] writeOperands = archDetails.getOperandsOfAccess(CapstoneAccessType.WRITE);
        Object[] readWriteOperands = archDetails.getOperandsOfAccess(CapstoneAccessType.READ_WRITE);
        
        // Process READ operands
        if (readOperands != null) {
            for (Object operand : readOperands) {
                int[] regsInOperand = archDetails.extractRegistersFromOperand(operand);
                for (int reg : regsInOperand) {
                    if (reg != 0) { // Assuming 0 might be an invalid/empty register ID
                        allRegsRead.add(reg);
                    }
                }
            }
        }
        
        // Process WRITE operands
        if (writeOperands != null) {
            for (Object operand : writeOperands) {
                int[] regsInOperand = archDetails.extractRegistersFromOperand(operand);
                for (int reg : regsInOperand) {
                    if (reg != 0) {
                        allRegsWrite.add(reg);
                    }
                }
            }
        }
        
        // Process READ_WRITE operands (add to both read and write sets)
        if (readWriteOperands != null) {
            for (Object operand : readWriteOperands) {
                int[] regsInOperand = archDetails.extractRegistersFromOperand(operand);
                for (int reg : regsInOperand) {
                    if (reg != 0) {
                        allRegsRead.add(reg);
                        allRegsWrite.add(reg);
                    }
                }
            }
        }
        
        // Convert sets back to arrays
        int[] completeRegsRead = new int[allRegsRead.size()];
        int[] completeRegsWrite = new int[allRegsWrite.size()];
        
        int index = 0;
        for (Integer reg : allRegsRead) {
            completeRegsRead[index++] = reg;
        }
        
        index = 0;
        for (Integer reg : allRegsWrite) {
            completeRegsWrite[index++] = reg;
        }
        
        // Create a new CapstoneRegAccess with the complete information
        return new CapstoneRegAccess(
            completeRegsRead, completeRegsRead.length,
            completeRegsWrite, completeRegsWrite.length
        );
    }

    /**
     * Returns an array of instruction group IDs that this instruction belongs to.
     * <p>
     * Instruction groups categorize instructions based on their functionality
     * or behavior (e.g., jump instructions, call instructions, etc.).
     *
     * @return an array of instruction group IDs
     * @see CapstoneInstruction#isInsnGroup(int)
     */
    public int[] getGroups() {
        return this.groups;
    }

    /**
     * Returns the number of instruction groups that this instruction belongs to.
     *
     * @return the number of instruction groups
     * @see #getGroups()
     */
    public int getGroupsCount() {
        return this.groupsCount;
    }

    /**
     * Returns whether this instruction performs a memory write-back.
     *
     * @return {@code true} if this instruction performs a memory write-back, {@code false} otherwise
     */
    public boolean isWriteback() {
        return this.writeback;
    }

    /**
     * Returns the architecture-specific details for this instruction.
     * <p>
     * The returned object provides access to architecture-specific information
     * about the instruction, such as operands, addressing modes, and more.
     * <p>
     * Example usage:
     * <pre>{@code
     * // With details enabled and using the proper generic type for X86
     * CapstoneInstruction<CapstoneX86Details> instruction = handle.disassembleInstruction(code, address);
     * if (instruction.getDetails() != null) {
     *     CapstoneX86Details x86Details = instruction.getDetails().getArchDetails();
     *     
     *     // Access X86-specific information
     *     CapstoneX86Details.X86Operand[] operands = x86Details.getOperands();
     *     for (CapstoneX86Details.X86Operand op : operands) {
     *         // Process each operand
     *     }
     * }
     * }</pre>
     *
     * @return the architecture-specific details for this instruction
     */
    public A getArchDetails() {
        return this.archDetails;
    }
}