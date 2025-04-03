package com.suko.capstone4j;

import static com.suko.capstone4j.internal.capstone_h.*;

public enum CapstoneOptionValue {
    OFF(CS_OPT_OFF()),
	ON(CS_OPT_ON()),
	SYNTAX_DEFAULT(CS_OPT_SYNTAX_DEFAULT()),
	SYNTAX_INTEL(CS_OPT_SYNTAX_INTEL()),
	SYNTAX_ATT(CS_OPT_SYNTAX_ATT()),
	SYNTAX_NOREGNAME(CS_OPT_SYNTAX_NOREGNAME()),
	SYNTAX_MASM(CS_OPT_SYNTAX_MASM()),
	SYNTAX_MOTOROLA(CS_OPT_SYNTAX_MOTOROLA()),
	SYNTAX_CS_REG_ALIAS(CS_OPT_SYNTAX_CS_REG_ALIAS()),
	SYNTAX_PERCENT(CS_OPT_SYNTAX_PERCENT()),
	SYNTAX_NO_DOLLAR(CS_OPT_SYNTAX_NO_DOLLAR()),
	DETAIL_REAL(CS_OPT_DETAIL_REAL());

    private final int value;

    CapstoneOptionValue(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
