package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

import com.capstone4j.internal.cs_detail;
import com.capstone4j.internal.cs_insn;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

class CapstoneInstructionFactory {

    public static <A extends CapstoneArchDetails<?>> CapstoneInstruction<A> createFromMemorySegment(MemorySegment segment, CapstoneArch arch, boolean parseDetails) {

        int size = cs_insn.size(segment);

        MemorySegment bytesSegment = cs_insn.bytes(segment);
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            bytes[i] = bytesSegment.get(ValueLayout.JAVA_BYTE, i);
        }

        CapstoneInstructionDetails<A> details = null;

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

    private static <A extends CapstoneArchDetails<?>> CapstoneInstructionDetails<A> parseInstructionDetails(MemorySegment segment, CapstoneArch arch) {
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

        MemorySegment archDetailsSegment = null;

        Class<A> archDetailsClass;
        switch (arch) {
            case X86:
                @SuppressWarnings("unchecked")
                Class<A> x86Class = (Class<A>) CapstoneX86Details.class;
                archDetailsClass = x86Class;
                archDetailsSegment = cs_detail.x86(segment);
                break;
            default:
                throw new IllegalArgumentException("Unsupported architecture: " + arch);
        }
        
        A archDetails = CapstoneArchDetailsFactory.createDetails(archDetailsSegment, arch, archDetailsClass);

        return new CapstoneInstructionDetails<>(regsRead, regsReadCount, regsWrite, regsWriteCount, groups, groupsCount, writeback, archDetails);
    }

}
