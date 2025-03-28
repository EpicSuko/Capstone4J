package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

import com.capstone4j.internal.cs_detail;
import com.capstone4j.internal.cs_insn;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.reflect.Method;

class CapstoneInstructionFactory {

    public static <A extends CapstoneArchDetails<?> & MemorySegmentCreatable<A>> CapstoneInstruction<A> createFromMemorySegment(MemorySegment handle, MemorySegment instructionSegment, CapstoneArch arch, boolean parseDetails) {

        int size = cs_insn.size(instructionSegment);

        MemorySegment bytesSegment = cs_insn.bytes(instructionSegment);
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            bytes[i] = bytesSegment.get(ValueLayout.JAVA_BYTE, i);
        }

        CapstoneInstructionDetails<A> details = null;

        if(parseDetails) {
            details = parseInstructionDetails(handle, instructionSegment, cs_insn.detail(instructionSegment), arch);
        }

        return new CapstoneInstruction<>(
            cs_insn.id(instructionSegment), 
            cs_insn.alias_id(instructionSegment), 
            cs_insn.address(instructionSegment), 
            size, 
            bytes, 
            cs_insn.mnemonic(instructionSegment).getUtf8String(0), 
            cs_insn.op_str(instructionSegment).getUtf8String(0), 
            cs_insn.is_alias(instructionSegment), 
            cs_insn.usesAliasDetails(instructionSegment),
            details,
            arch
        );
    }

    private static <A extends CapstoneArchDetails<?> & MemorySegmentCreatable<? extends CapstoneArchDetails<?>>> CapstoneInstructionDetails<A> parseInstructionDetails(MemorySegment handle, MemorySegment instructionSegment, MemorySegment detailsSegment, CapstoneArch arch) {
        int[] regsRead;
        int[] regsWrite;
        int regsReadCount;
        int regsWriteCount;

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment regsReadAccessSegment = arena.allocateArray(ValueLayout.JAVA_SHORT, 64);
            MemorySegment regsWriteAccessSegment = arena.allocateArray(ValueLayout.JAVA_SHORT, 64);
            MemorySegment regsReadAccessCountSegment = arena.allocate(ValueLayout.JAVA_BYTE, (byte)0);
            MemorySegment regsWriteAccessCountSegment = arena.allocate(ValueLayout.JAVA_BYTE, (byte)0);
            
            CapstoneError res = CapstoneError.fromValue(cs_regs_access(handle.get(csh, 0), instructionSegment, regsReadAccessSegment, regsReadAccessCountSegment, regsWriteAccessSegment, regsWriteAccessCountSegment));
            // Check the result)
            if (res != CapstoneError.OK) {
                throw new RuntimeException("Failed to get register access information");
            }
            
            // Get the counts
            regsReadCount = regsReadAccessCountSegment.get(ValueLayout.JAVA_BYTE, 0);
            regsWriteCount = regsWriteAccessCountSegment.get(ValueLayout.JAVA_BYTE, 0);
            
            // Read the register access information
            regsRead = new int[regsReadCount & 0xFF];
            regsWrite = new int[regsWriteCount & 0xFF];
            
            for (int i = 0; i < (regsReadCount & 0xFF); i++) {
                regsRead[i] = regsReadAccessSegment.get(ValueLayout.JAVA_SHORT, i * ValueLayout.JAVA_SHORT.byteSize()) & 0xFFFF;
            }
            
            for (int i = 0; i < (regsWriteCount & 0xFF); i++) {
                regsWrite[i] = regsWriteAccessSegment.get(ValueLayout.JAVA_SHORT, i * ValueLayout.JAVA_SHORT.byteSize()) & 0xFFFF;
            }
        }

        MemorySegment groupsSegment = cs_detail.groups(detailsSegment);
        int groupsCount = cs_detail.groups_count(detailsSegment);
        int[] groups = new int[groupsCount];
        for (int i = 0; i < groupsCount; i++) {
            groups[i] = groupsSegment.get(C_CHAR, i * C_CHAR.byteSize()) & 0xFF;
        }

        boolean writeback = cs_detail.writeback(detailsSegment);

        MemorySegment archDetailsSegment = null;

        Class<A> archDetailsClass;
        switch (arch) {
            case X86:
                @SuppressWarnings("unchecked")
                Class<A> x86Class = (Class<A>) CapstoneX86Details.class;
                archDetailsClass = x86Class;
                archDetailsSegment = cs_detail.x86(detailsSegment);
                break;
            default:
                throw new IllegalArgumentException("Unsupported architecture: " + arch);
        }
        
        A archDetails = createDetails(archDetailsSegment, arch, archDetailsClass);

        return new CapstoneInstructionDetails<>(regsRead, regsReadCount, regsWrite, regsWriteCount, groups, groupsCount, writeback, archDetails);
    }

    @SuppressWarnings("unchecked")
    static <T extends CapstoneArchDetails<?>> T createDetails(MemorySegment segment, CapstoneArch arch, Class<? extends CapstoneArchDetails<?>> expectedType) {
        try {
            Method createFromMemorySegment = expectedType.getDeclaredMethod("createFromMemorySegment", MemorySegment.class);
            return (T) createFromMemorySegment.invoke(null, segment);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException("Failed to create architecture details for " + arch, e);
        }
    }

}
