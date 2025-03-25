package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

/**
 * An enumeration representing different memory access types in Capstone disassembly.
 * These values specify the type of access an instruction has to memory (read, write, or both).
 */
public enum CapstoneAccessType {
    /**
     * Represents an invalid or undefined memory access.
     */
    INVALID(CS_AC_INVALID()),
    
    /**
     * Represents read-only memory access.
     */
    READ(CS_AC_READ()),
    
    /**
     * Represents write-only memory access.
     */
    WRITE(CS_AC_WRITE()),
    
    /**
     * Represents both read and write memory access.
     */
    READ_WRITE(CS_AC_READ_WRITE());

    private final int value;

    /**
     * Constructs a CapstoneAccessType with the specified native value.
     *
     * @param value The integer value from the native Capstone library
     */
    CapstoneAccessType(int value) {
        this.value = value;
    }

    /**
     * Returns the integer value of this access type.
     *
     * @return The native Capstone value for this access type
     */
    public int getValue() {
        return value;
    }

    /**
     * Converts a native Capstone integer value to its corresponding CapstoneAccessType.
     *
     * @param value The native integer value to convert
     * @return The matching CapstoneAccessType enum constant
     * @throws IllegalArgumentException if the provided value doesn't match any defined access type
     */
    public static CapstoneAccessType fromValue(int value) {
        for (CapstoneAccessType accessType : CapstoneAccessType.values()) {
            if (accessType.getValue() == value) {
                return accessType;
            }
        }
        throw new IllegalArgumentException("Invalid CapstoneAccessType value: " + value);
    }
}
