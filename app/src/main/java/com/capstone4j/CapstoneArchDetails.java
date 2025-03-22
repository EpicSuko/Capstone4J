package com.capstone4j;

abstract class CapstoneArchDetails {

    private final int opCount;
    private final Object[] operands;

    CapstoneArchDetails(int opCount, Object[] operands) {
        this.opCount = opCount;
        this.operands = operands;
    }

    abstract int getOpCounOfType(int opType);
    abstract boolean isOperandOfType(Object operand, int opType);

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

    public Object[] getOperands() {
        return this.operands;
    }
}