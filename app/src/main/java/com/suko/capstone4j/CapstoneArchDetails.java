package com.suko.capstone4j;

abstract class CapstoneArchDetails<T> {

    private final int opCount;
    private final T[] operands;

    CapstoneArchDetails(int opCount, T[] operands) {
        this.opCount = opCount;
        this.operands = operands;
    }

    abstract int getOpCounOfType(int opType);
    abstract boolean isOperandOfType(T operand, int opType);

    int getOpIndex(int opType, int position) {
        if (position < 1 || position > getOpCounOfType(opType)) {
            return -1;
        }
        
        int count = 0;
        for(int i = 0; i < operands.length; i++) {
            if(isOperandOfType(operands[i], opType)) {
                count++;
                if(count == position) {
                    return i;
                }
            }
        }
        return -1;
    }

    public int getOpCount() {
        return this.opCount;
    }

    public T[] getOperands() {
        return this.operands;
    }
}