package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

public enum CapstoneError {
    OK(CS_ERR_OK()),
	MEM(CS_ERR_MEM()),
	ARCH(CS_ERR_ARCH()),
	HANDLE(CS_ERR_HANDLE()),
	CSH(CS_ERR_CSH()),
	MODE(CS_ERR_MODE()),
	OPTION(CS_ERR_OPTION()),
	DETAIL(CS_ERR_DETAIL()),
	MEMSETUP(CS_ERR_MEMSETUP()),
	VERSION(CS_ERR_VERSION()),
	DIET(CS_ERR_DIET()),
	SKIPDATA(CS_ERR_SKIPDATA()),
	X86_ATT(CS_ERR_X86_ATT()),
	X86_INTEL(CS_ERR_X86_INTEL()),
	X86_MASM(CS_ERR_X86_MASM());

    private final int value;

    CapstoneError(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static CapstoneError fromValue(int value) {
        for (CapstoneError error : CapstoneError.values()) {
            if (error.getValue() == value) {
                return error;
            }
        }
        throw new IllegalArgumentException("Invalid Capstone error value: " + value);
    }
}