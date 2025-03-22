package com.capstone4j;

import com.capstone4j.internal.cs_x86;

import java.lang.foreign.MemorySegment;

public class CapstoneX86Details extends CapstoneArchDetails {

    CapstoneX86Details(int opCount, Object[] operands) {
        super(opCount, operands);
    }

    static CapstoneX86Details createFromMemorySegment(MemorySegment segment) {
        return null;
    }

    @Override
    boolean isOperandOfType(Object operand, int opType) {
        return false;
    }

    @Override
    int getOpCounOfType(int opType) {
        return -1;
    }
}
