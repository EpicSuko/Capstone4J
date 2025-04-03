package com.suko.capstone4j;

import static com.suko.capstone4j.internal.capstone_h.*;

public enum CapstoneGroup {

    INVALID(CS_GRP_INVALID()),
	JUMP(CS_GRP_JUMP()),
	CALL(CS_GRP_CALL()),
	RET(CS_GRP_RET()),
	INT(CS_GRP_INT()),
	IRET(CS_GRP_IRET()),
	PRIVILEGE(CS_GRP_PRIVILEGE()),      
	BRANCH_RELATIVE(CS_GRP_BRANCH_RELATIVE());

    private final int value;

    CapstoneGroup(int value) {
        this.value = value;
    }

    public int getValue() {
        return this.value;
    }

    public static CapstoneGroup fromValue(int value) {
        for(CapstoneGroup group : CapstoneGroup.values()) {
            if(group.getValue() == value) {
                return group;
            }
        }
        return INVALID;
    }
}
