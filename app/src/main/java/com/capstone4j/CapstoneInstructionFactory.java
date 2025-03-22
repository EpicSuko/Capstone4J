package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

import com.capstone4j.internal.cs_detail;
import com.capstone4j.internal.cs_insn;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

class CapstoneInstructionFactory {

    public static <T extends CapstoneArchDetails> CapstoneInstruction<T> createFromMemorySegment(MemorySegment segment, CapstoneArch arch, boolean parseDetails) {

        int size = cs_insn.size(segment);

        MemorySegment bytesSegment = cs_insn.bytes(segment);
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            bytes[i] = bytesSegment.get(ValueLayout.JAVA_BYTE, i);
        }

        CapstoneInstructionDetails<T> details = null;

        if(parseDetails) {
            details = parseInstructionDetails(cs_insn.detail(segment), arch);
        }

        return new CapstoneInstruction<>(
            cs_insn.id(segment), 
            cs_insn.alias_id(segment), 
            cs_insn.address(segment), 
            size, 
            bytes, 
            cs_insn.mnemonic(segment).getUtf8String(0), 
            cs_insn.op_str(segment).getUtf8String(0), 
            cs_insn.is_alias(segment), 
            cs_insn.usesAliasDetails(segment),
            details,
            arch
        );
    }

    private static <T extends CapstoneArchDetails> CapstoneInstructionDetails<T> parseInstructionDetails(MemorySegment segment, CapstoneArch arch) {
        int regsReadCount = cs_detail.regs_read_count(segment);

        MemorySegment regsReadSegment = cs_detail.regs_read(segment);
        int[] regsRead = new int[regsReadCount];
        for (int i = 0; i < regsReadCount; i++) {
            regsRead[i] = regsReadSegment.get(C_SHORT, i * C_SHORT.byteSize());
        }

        MemorySegment regsWriteSegment = cs_detail.regs_write(segment);
        int regsWriteCount = cs_detail.regs_write_count(segment);
        int[] regsWrite = new int[regsWriteCount];
        for (int i = 0; i < regsWriteCount; i++) {
            regsWrite[i] = regsWriteSegment.get(C_SHORT, i * C_SHORT.byteSize());
        }

        MemorySegment groupsSegment = cs_detail.groups(segment);
        int groupsCount = cs_detail.groups_count(segment);
        int[] groups = new int[groupsCount];
        for (int i = 0; i < groupsCount; i++) {
            groups[i] = groupsSegment.get(C_CHAR, i * C_CHAR.byteSize()) & 0xFF;
        }

        boolean writeback = cs_detail.writeback(segment);

        Class<T> archDetailsClass;
        switch (arch) {
            case X86:
                @SuppressWarnings("unchecked")
                Class<T> x86Class = (Class<T>) CapstoneX86Details.class;
                archDetailsClass = x86Class;
                break;
            default:
                throw new IllegalArgumentException("Unsupported architecture: " + arch);
        }
        
        T archDetails = CapstoneArchDetailsFactory.createDetails(segment, arch, archDetailsClass);

        return new CapstoneInstructionDetails<>(regsRead, regsReadCount, regsWrite, regsWriteCount, groups, groupsCount, writeback, archDetails);
    }

}
