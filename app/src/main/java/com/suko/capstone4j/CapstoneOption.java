package com.suko.capstone4j;

import static com.suko.capstone4j.internal.capstone_h.*;

public enum CapstoneOption {

    INVALID(CS_OPT_INVALID()),
    SYNTAX(CS_OPT_SYNTAX()),
    DETAIL(CS_OPT_DETAIL()),
    MODE(CS_OPT_MODE()),
    MEM(CS_OPT_MEM()),
    SKIPDATA(CS_OPT_SKIPDATA()),
    SKIPDATA_SETUP(CS_OPT_SKIPDATA_SETUP()),
    MNEMONIC(CS_OPT_MNEMONIC()),
    UNSIGNED(CS_OPT_UNSIGNED()),
    ONLY_OFFSET_BRANCH(CS_OPT_ONLY_OFFSET_BRANCH()),
    LITBASE(CS_OPT_LITBASE());

    private final int value;

    CapstoneOption(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static CapstoneOption fromValue(int value) {
        for (CapstoneOption option : CapstoneOption.values()) {
            if (option.value == value) {
                return option;
            }
        }
        return INVALID;
    }
}