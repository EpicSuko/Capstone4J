package com.capstone4j;

abstract class CapstoneArchDetails {

    private final int opCount;
    private final Object[] operands;

    CapstoneArchDetails(int opCount, Object[] operands) {
        this.opCount = opCount;
        this.operands = operands;
    }

    public int getOpCount() {
        return this.opCount;
    }

    public Object[] getOperands() {
        return this.operands;
    }
}
