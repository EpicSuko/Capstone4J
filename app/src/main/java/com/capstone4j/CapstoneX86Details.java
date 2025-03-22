package com.capstone4j;

import java.lang.foreign.MemorySegment;

public class CapstoneX86Details extends CapstoneArchDetails {

    CapstoneX86Details(int opCount, Object[] operands) {
        super(opCount, operands);
    }

    static CapstoneX86Details createFromMemorySegment(MemorySegment segment) {
        return null;
    }
}
