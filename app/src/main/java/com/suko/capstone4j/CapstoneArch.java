package com.suko.capstone4j;

import static com.suko.capstone4j.internal.capstone_h_24.*;

public enum CapstoneArch {

    ARM(CS_ARCH_ARM()),
    AARCH64(CS_ARCH_AARCH64()),
    SYSTEMZ(CS_ARCH_SYSTEMZ()),
    MIPS(CS_ARCH_MIPS()),
    X86(CS_ARCH_X86()),
    PPC(CS_ARCH_PPC()),
    SPARC(CS_ARCH_SPARC()),
    XCORE(CS_ARCH_XCORE()),
    M68K(CS_ARCH_M68K()),
    TMS320C64X(CS_ARCH_TMS320C64X()),
    M680X(CS_ARCH_M680X()),
    EVM(CS_ARCH_EVM()),
    MOS65XX(CS_ARCH_MOS65XX()),
    WASM(CS_ARCH_WASM()),
    BPF(CS_ARCH_BPF()),
    RISCV(CS_ARCH_RISCV()),
    SH(CS_ARCH_SH()),
    TRICORE(CS_ARCH_TRICORE()),
    ALPHA(CS_ARCH_ALPHA()),
    HPPA(CS_ARCH_HPPA()),
    LOONGARCH(CS_ARCH_LOONGARCH()),
    XTENSA(CS_ARCH_XTENSA()),
    ARC(CS_ARCH_ARC()),

    MAX(CS_ARCH_MAX()),
    ALL(CS_ARCH_ALL());

    private final int value;

    CapstoneArch(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static CapstoneArch fromValue(int value) {
        for (CapstoneArch arch : CapstoneArch.values()) {
            if (arch.getValue() == value) {
                return arch;
            }
        }
        throw new IllegalArgumentException("Invalid Capstone architecture value: " + value);
    }
}