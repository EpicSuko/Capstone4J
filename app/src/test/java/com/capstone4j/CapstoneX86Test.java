package com.capstone4j;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.capstone4j.CapstoneX86Details.X86EFlags;
import com.capstone4j.CapstoneX86Details.X86Encoding;
import com.capstone4j.CapstoneX86Details.X86OperandType;
import com.capstone4j.CapstoneX86Details.X86Operand;
import com.capstone4j.CapstoneX86Details.X86Reg;
import com.capstone4j.CapstoneX86Details.X86Prefix;
import com.capstone4j.CapstoneX86Details.X86FPUFlags;

class CapstoneX86Test {

    @BeforeAll
    public static void init() {
        try {
            Capstone.initialize();
        } catch (IOException e) {
            e.printStackTrace();
            fail("Failed to initialize Capstone");
        }
    }

    byte[] textX86_16Data = new byte[] {
        (byte)0x8d, 0x4c, 0x32, 0x08, 0x01, (byte)0xd8, (byte)0x81, (byte)0xc6, 0x34, 0x12, 
        0x00, 0x00, 0x05, 0x23, 0x01, 0x00, 0x00, 0x36, (byte)0x8b, (byte)0x84, 
        (byte)0x91, 0x23, 0x01, 0x00, 0x00, 0x41, (byte)0x8d, (byte)0x84, 0x39, (byte)0x89, 
        0x67, 0x00, 0x00, (byte)0x8d, (byte)0x87, (byte)0x89, 0x67, 0x00, 0x00, (byte)0xb4, 
        (byte)0xc6, 0x66, (byte)0xe9, (byte)0xb8, 0x00, 0x00, 0x00, 0x67, (byte)0xff, (byte)0xa0, 
        0x23, 0x01, 0x00, 0x00, 0x66, (byte)0xe8, (byte)0xcb, 0x00, 0x00, 0x00, 
        0x74, (byte)0xfc
    };

    @Test
    public void testX86_16() {
        System.out.println("Testing X86_16");
        CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();

        try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.X86, CapstoneMode.X86_16, options)) {
            // Enable detailed instruction information
            handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);

            long runtimeAddress = 0x1000;
            int offset = 0;
            final int length = textX86_16Data.length;
            int instructionIndex = 0;

            while(offset < length) {
                int maxBytesToRead = Math.min(15, length - offset);
                byte[] subData = Arrays.copyOfRange(textX86_16Data, offset, offset + maxBytesToRead);
                
                CapstoneInstruction<CapstoneX86Details> instruction = handle.disassembleInstruction(subData, runtimeAddress);
                
                // Verify instruction is not null
                assertNotNull(instruction, "Failed to disassemble instruction at offset " + offset);
                
                // Verify instruction details
                assertNotNull(instruction.getDetails(), "Instruction details should not be null");
                CapstoneX86Details details = instruction.getDetails().getArchDetails();
                assertNotNull(details, "Architecture details should not be null");

                X86Encoding encoding = details.getEncoding();
                assertNotNull(encoding, "Encoding should not be null");

                // Print instruction info for debugging
                System.out.printf("Instruction %d: %s %s (size: %d, addr: 0x%x)%n", 
                    instructionIndex, instruction.getMnemonic(), instruction.getOpStr(), 
                    instruction.getSize(), instruction.getAddress());

                switch(instructionIndex) {
                    case 0: // lea cx, [si + 0x32]
                        assertEquals("lea", instruction.getMnemonic());
                        assertEquals("cx, [si + 0x32]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes[0]);
                        assertEquals(X86Prefix._0, prefixes[1]);
                        assertEquals(X86Prefix._0, prefixes[2]);
                        assertEquals(X86Prefix._0, prefixes[3]);

                        assertEquals(0x8d, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x4c, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x2, encoding.getDispOffset());
                        assertEquals(0x1, encoding.getDispSize());

                        assertEquals(0x32, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1.getType());
                        assertEquals(X86Reg.CX, operand1.getReg());
                        assertEquals(2, operand1.getSize());
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1.getAccess());

                        X86Operand operand2 = details.getOperands()[1];
                        assertEquals(X86OperandType.MEM, operand2.getType());
                        assertEquals(X86Reg.SI, operand2.getMem().getBase());
                        assertEquals(0x32, operand2.getMem().getDisp());
                        assertEquals(2, operand2.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2.getAccess());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess = instruction.getRegAccess();
                        int[] regsRead = regAccess.getRegsRead();
                        int[] regsWrite = regAccess.getRegsWrite();
                        
                        assertTrue(contains(regsRead, X86Reg.SI.getValue()), "SI should be read");
                        assertTrue(contains(regsWrite, X86Reg.CX.getValue()), "CX should be written");
                        break;
                    case 1: // or byte ptr [bx + di], al
                        assertEquals("or", instruction.getMnemonic());
                        assertEquals("byte ptr [bx + di], al", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes1 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes1[0]);
                        assertEquals(X86Prefix._0, prefixes1[1]);
                        assertEquals(X86Prefix._0, prefixes1[2]);
                        assertEquals(X86Prefix._0, prefixes1[3]);

                        assertEquals(0x08, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x1, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_1 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_1.getType());
                        assertEquals(X86Reg.BX, operand1_1.getMem().getBase());
                        assertEquals(X86Reg.DI, operand1_1.getMem().getIndex());
                        assertEquals(1, operand1_1.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_1.getAccess());

                        X86Operand operand2_1 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_1.getType());
                        assertEquals(X86Reg.AL, operand2_1.getReg());
                        assertEquals(1, operand2_1.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_1.getAccess());

                        // Verify EFLAGS
                        X86EFlags[] eflags1 = details.getEflags();
                        X86EFlags[] expectedEFlags1 = new X86EFlags[] { 
                            X86EFlags.MODIFY_SF,
                            X86EFlags.MODIFY_ZF,
                            X86EFlags.MODIFY_PF,
                            X86EFlags.RESET_OF,
                            X86EFlags.RESET_CF,
                            X86EFlags.UNDEFINED_AF
                        };
                        assertTrue(containsAllEFlags(eflags1, expectedEFlags1), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess1 = instruction.getRegAccess();
                        int[] regsRead1 = regAccess1.getRegsRead();
                        int[] regsWrite1 = regAccess1.getRegsWrite();
                        
                        assertTrue(contains(regsRead1, X86Reg.BX.getValue()), "BX should be read");
                        assertTrue(contains(regsRead1, X86Reg.DI.getValue()), "DI should be read");
                        assertTrue(contains(regsRead1, X86Reg.AL.getValue()), "AL should be read");
                        assertTrue(contains(regsWrite1, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 2: // fadd dword ptr [bx + di + 0x34c6]
                        assertEquals("fadd", instruction.getMnemonic());
                        assertEquals("dword ptr [bx + di + 0x34c6]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes2 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes2[0]);
                        assertEquals(X86Prefix._0, prefixes2[1]);
                        assertEquals(X86Prefix._0, prefixes2[2]);
                        assertEquals(X86Prefix._0, prefixes2[3]);

                        assertEquals(0xd8, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x81, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x2, encoding.getDispOffset());
                        assertEquals(0x2, encoding.getDispSize());
                        assertEquals(0x34c6, details.getDisp());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_2 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_2.getType());
                        assertEquals(X86Reg.BX, operand1_2.getMem().getBase());
                        assertEquals(X86Reg.DI, operand1_2.getMem().getIndex());
                        assertEquals(0x34c6, operand1_2.getMem().getDisp());
                        assertEquals(4, operand1_2.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_2.getAccess());

                        // Verify FPU flags
                        X86FPUFlags[] fpuFlags2 = details.getFpuFlags();
                        X86FPUFlags[] expectedFpuFlags2 = new X86FPUFlags[] {
                            X86FPUFlags.MODIFY_C1,
                            X86FPUFlags.UNDEFINED_C0,
                            X86FPUFlags.UNDEFINED_C2,
                            X86FPUFlags.UNDEFINED_C3
                        };
                        assertTrue(containsAllFpuFlags(fpuFlags2, expectedFpuFlags2), "FPU flags should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess2 = instruction.getRegAccess();
                        int[] regsRead2 = regAccess2.getRegsRead();
                        int[] regsWrite2 = regAccess2.getRegsWrite();
                        
                        assertTrue(contains(regsRead2, X86Reg.BX.getValue()), "BX should be read");
                        assertTrue(contains(regsRead2, X86Reg.DI.getValue()), "DI should be read");
                        assertTrue(contains(regsWrite2, X86Reg.FPSW.getValue()), "FPSW should be written");
                        break;
                    case 3: // adc al, byte ptr [bx + si]
                        assertEquals("adc", instruction.getMnemonic());
                        assertEquals("al, byte ptr [bx + si]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes3 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes3[0]);
                        assertEquals(X86Prefix._0, prefixes3[1]);
                        assertEquals(X86Prefix._0, prefixes3[2]);
                        assertEquals(X86Prefix._0, prefixes3[3]);

                        assertEquals(0x12, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_3 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_3.getType());
                        assertEquals(X86Reg.AL, operand1_3.getReg());
                        assertEquals(1, operand1_3.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_3.getAccess());

                        X86Operand operand2_3 = details.getOperands()[1];
                        assertEquals(X86OperandType.MEM, operand2_3.getType());
                        assertEquals(X86Reg.BX, operand2_3.getMem().getBase());
                        assertEquals(X86Reg.SI, operand2_3.getMem().getIndex());
                        assertEquals(1, operand2_3.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_3.getAccess());

                        // Verify EFLAGS
                        X86EFlags[] eflags3 = details.getEflags();
                        X86EFlags[] expectedEFlags3 = new X86EFlags[] {
                            X86EFlags.MODIFY_AF,
                            X86EFlags.MODIFY_CF,
                            X86EFlags.MODIFY_SF,
                            X86EFlags.MODIFY_ZF,
                            X86EFlags.MODIFY_PF,
                            X86EFlags.MODIFY_OF,
                            X86EFlags.TEST_CF
                        };
                        assertTrue(containsAllEFlags(eflags3, expectedEFlags3), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess3 = instruction.getRegAccess();
                        int[] regsRead3 = regAccess3.getRegsRead();
                        int[] regsWrite3 = regAccess3.getRegsWrite();
                        
                        assertTrue(contains(regsRead3, X86Reg.AL.getValue()), "AL should be read");
                        assertTrue(contains(regsRead3, X86Reg.BX.getValue()), "BX should be read");
                        assertTrue(contains(regsRead3, X86Reg.SI.getValue()), "SI should be read");
                        assertTrue(contains(regsRead3, X86Reg.EFLAGS.getValue()), "EFLAGS should be read");
                        assertTrue(contains(regsWrite3, X86Reg.AL.getValue()), "AL should be written");
                        assertTrue(contains(regsWrite3, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 4: // add byte ptr [di], al
                        assertEquals("add", instruction.getMnemonic());
                        assertEquals("byte ptr [di], al", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes4 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes4[0]);
                        assertEquals(X86Prefix._0, prefixes4[1]);
                        assertEquals(X86Prefix._0, prefixes4[2]);
                        assertEquals(X86Prefix._0, prefixes4[3]);

                        assertEquals(0x00, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x5, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_4 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_4.getType());
                        assertEquals(X86Reg.DI, operand1_4.getMem().getBase());
                        assertEquals(1, operand1_4.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_4.getAccess());

                        X86Operand operand2_4 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_4.getType());
                        assertEquals(X86Reg.AL, operand2_4.getReg());
                        assertEquals(1, operand2_4.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_4.getAccess());

                        // Verify EFLAGS
                        X86EFlags[] eflags4 = details.getEflags();
                        X86EFlags[] expectedEFlags4 = new X86EFlags[] {
                            X86EFlags.MODIFY_AF,
                            X86EFlags.MODIFY_CF,
                            X86EFlags.MODIFY_SF,
                            X86EFlags.MODIFY_ZF,
                            X86EFlags.MODIFY_PF,
                            X86EFlags.MODIFY_OF
                        };
                        assertTrue(containsAllEFlags(eflags4, expectedEFlags4), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess4 = instruction.getRegAccess();
                        int[] regsRead4 = regAccess4.getRegsRead();
                        int[] regsWrite4 = regAccess4.getRegsWrite();
                        
                        assertTrue(contains(regsRead4, X86Reg.DI.getValue()), "DI should be read");
                        assertTrue(contains(regsRead4, X86Reg.AL.getValue()), "AL should be read");
                        assertTrue(contains(regsWrite4, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 5: // and ax, word ptr [bx + di]
                        assertEquals("and", instruction.getMnemonic());
                        assertEquals("ax, word ptr [bx + di]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes5 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes5[0]);
                        assertEquals(X86Prefix._0, prefixes5[1]);
                        assertEquals(X86Prefix._0, prefixes5[2]);
                        assertEquals(X86Prefix._0, prefixes5[3]);

                        assertEquals(0x23, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x1, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_5 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_5.getType());
                        assertEquals(X86Reg.AX, operand1_5.getReg());
                        assertEquals(2, operand1_5.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_5.getAccess());

                        X86Operand operand2_5 = details.getOperands()[1];
                        assertEquals(X86OperandType.MEM, operand2_5.getType());
                        assertEquals(X86Reg.BX, operand2_5.getMem().getBase());
                        assertEquals(X86Reg.DI, operand2_5.getMem().getIndex());
                        assertEquals(2, operand2_5.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_5.getAccess());

                        // Verify EFLAGS
                        X86EFlags[] eflags5 = details.getEflags();
                        X86EFlags[] expectedEFlags5 = new X86EFlags[] {
                            X86EFlags.MODIFY_SF,
                            X86EFlags.MODIFY_ZF,
                            X86EFlags.MODIFY_PF,
                            X86EFlags.RESET_OF,
                            X86EFlags.RESET_CF,
                            X86EFlags.UNDEFINED_AF
                        };
                        assertTrue(containsAllEFlags(eflags5, expectedEFlags5), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess5 = instruction.getRegAccess();
                        int[] regsRead5 = regAccess5.getRegsRead();
                        int[] regsWrite5 = regAccess5.getRegsWrite();
                        
                        assertTrue(contains(regsRead5, X86Reg.AX.getValue()), "AX should be read");
                        assertTrue(contains(regsRead5, X86Reg.BX.getValue()), "BX should be read");
                        assertTrue(contains(regsRead5, X86Reg.DI.getValue()), "DI should be read");
                        assertTrue(contains(regsWrite5, X86Reg.AX.getValue()), "AX should be written");
                        assertTrue(contains(regsWrite5, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 6: // add byte ptr [bx + si], al
                        assertEquals("add", instruction.getMnemonic());
                        assertEquals("byte ptr [bx + si], al", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes6 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes6[0]);
                        assertEquals(X86Prefix._0, prefixes6[1]);
                        assertEquals(X86Prefix._0, prefixes6[2]);
                        assertEquals(X86Prefix._0, prefixes6[3]);

                        assertEquals(0x00, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_6 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_6.getType());
                        assertEquals(X86Reg.BX, operand1_6.getMem().getBase());
                        assertEquals(X86Reg.SI, operand1_6.getMem().getIndex());
                        assertEquals(1, operand1_6.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_6.getAccess());

                        X86Operand operand2_6 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_6.getType());
                        assertEquals(X86Reg.AL, operand2_6.getReg());
                        assertEquals(1, operand2_6.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_6.getAccess());

                        // Verify EFLAGS
                        X86EFlags[] eflags6 = details.getEflags();
                        X86EFlags[] expectedEFlags6 = new X86EFlags[] {
                            X86EFlags.MODIFY_AF,
                            X86EFlags.MODIFY_CF,
                            X86EFlags.MODIFY_SF,
                            X86EFlags.MODIFY_ZF,
                            X86EFlags.MODIFY_PF,
                            X86EFlags.MODIFY_OF
                        };
                        assertTrue(containsAllEFlags(eflags6, expectedEFlags6), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess6 = instruction.getRegAccess();
                        int[] regsRead6 = regAccess6.getRegsRead();
                        int[] regsWrite6 = regAccess6.getRegsWrite();
                        
                        assertTrue(contains(regsRead6, X86Reg.BX.getValue()), "BX should be read");
                        assertTrue(contains(regsRead6, X86Reg.SI.getValue()), "SI should be read");
                        assertTrue(contains(regsRead6, X86Reg.AL.getValue()), "AL should be read");
                        assertTrue(contains(regsWrite6, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 7: // mov ax, word ptr ss:[si + 0x2391]
                        assertEquals("mov", instruction.getMnemonic());
                        assertEquals("ax, word ptr ss:[si + 0x2391]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes7 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes7[0]);
                        assertEquals(X86Prefix.SS, prefixes7[1]);
                        assertEquals(X86Prefix._0, prefixes7[2]);
                        assertEquals(X86Prefix._0, prefixes7[3]);

                        assertEquals(0x8b, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x84, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x2, encoding.getModrmOffset());
                        assertEquals(0x2391, details.getDisp());
                        assertEquals(0x3, encoding.getDispOffset());
                        assertEquals(0x2, encoding.getDispSize());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_7 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_7.getType());
                        assertEquals(X86Reg.AX, operand1_7.getReg());
                        assertEquals(2, operand1_7.getSize());
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_7.getAccess());

                        X86Operand operand2_7 = details.getOperands()[1];
                        assertEquals(X86OperandType.MEM, operand2_7.getType());
                        assertEquals(X86Reg.SS, operand2_7.getMem().getSegment());
                        assertEquals(X86Reg.SI, operand2_7.getMem().getBase());
                        assertEquals(0x2391, operand2_7.getMem().getDisp());
                        assertEquals(2, operand2_7.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_7.getAccess());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess7 = instruction.getRegAccess();
                        int[] regsRead7 = regAccess7.getRegsRead();
                        int[] regsWrite7 = regAccess7.getRegsWrite();
                        
                        assertTrue(contains(regsRead7, X86Reg.SS.getValue()), "SS should be read");
                        assertTrue(contains(regsRead7, X86Reg.SI.getValue()), "SI should be read");
                        assertTrue(contains(regsWrite7, X86Reg.AX.getValue()), "AX should be written");
                        break;
                    case 8: // add word ptr [bx + si], ax
                        assertEquals("add", instruction.getMnemonic());
                        assertEquals("word ptr [bx + si], ax", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes8 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes8[0]);
                        assertEquals(X86Prefix._0, prefixes8[1]);
                        assertEquals(X86Prefix._0, prefixes8[2]);
                        assertEquals(X86Prefix._0, prefixes8[3]);

                        assertEquals(0x01, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_8 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_8.getType());
                        assertEquals(X86Reg.BX, operand1_8.getMem().getBase());
                        assertEquals(X86Reg.SI, operand1_8.getMem().getIndex());
                        assertEquals(2, operand1_8.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_8.getAccess());

                        X86Operand operand2_8 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_8.getType());
                        assertEquals(X86Reg.AX, operand2_8.getReg());
                        assertEquals(2, operand2_8.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_8.getAccess());

                        // Verify EFLAGS
                        X86EFlags[] eflags8 = details.getEflags();
                        X86EFlags[] expectedEFlags8 = new X86EFlags[] {
                            X86EFlags.MODIFY_AF,
                            X86EFlags.MODIFY_CF,
                            X86EFlags.MODIFY_SF,
                            X86EFlags.MODIFY_ZF,
                            X86EFlags.MODIFY_PF,
                            X86EFlags.MODIFY_OF
                        };
                        assertTrue(containsAllEFlags(eflags8, expectedEFlags8), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess8 = instruction.getRegAccess();
                        int[] regsRead8 = regAccess8.getRegsRead();
                        int[] regsWrite8 = regAccess8.getRegsWrite();
                        
                        assertTrue(contains(regsRead8, X86Reg.BX.getValue()), "BX should be read");
                        assertTrue(contains(regsRead8, X86Reg.SI.getValue()), "SI should be read");
                        assertTrue(contains(regsRead8, X86Reg.AX.getValue()), "AX should be read");
                        assertTrue(contains(regsWrite8, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 9: // add byte ptr [bx + di - 0x73], al
                        assertEquals("add", instruction.getMnemonic());
                        assertEquals("byte ptr [bx + di - 0x73], al", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes9 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes9[0]);
                        assertEquals(X86Prefix._0, prefixes9[1]);
                        assertEquals(X86Prefix._0, prefixes9[2]);
                        assertEquals(X86Prefix._0, prefixes9[3]);

                        assertEquals(0x00, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x41, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(-0x73, details.getDisp());
                        assertEquals(0x2, encoding.getDispOffset());
                        assertEquals(0x1, encoding.getDispSize());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_9 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_9.getType());
                        assertEquals(X86Reg.BX, operand1_9.getMem().getBase());
                        assertEquals(X86Reg.DI, operand1_9.getMem().getIndex());
                        assertEquals(-0x73, operand1_9.getMem().getDisp());
                        assertEquals(1, operand1_9.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_9.getAccess());

                        X86Operand operand2_9 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_9.getType());
                        assertEquals(X86Reg.AL, operand2_9.getReg());
                        assertEquals(1, operand2_9.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_9.getAccess());

                        // Verify EFLAGS
                        X86EFlags[] eflags9 = details.getEflags();
                        X86EFlags[] expectedEFlags9 = new X86EFlags[] {
                            X86EFlags.MODIFY_AF,
                            X86EFlags.MODIFY_CF,
                            X86EFlags.MODIFY_SF,
                            X86EFlags.MODIFY_ZF,
                            X86EFlags.MODIFY_PF,
                            X86EFlags.MODIFY_OF
                        };
                        assertTrue(containsAllEFlags(eflags9, expectedEFlags9), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess9 = instruction.getRegAccess();
                        int[] regsRead9 = regAccess9.getRegsRead();
                        int[] regsWrite9 = regAccess9.getRegsWrite();
                        
                        assertTrue(contains(regsRead9, X86Reg.BX.getValue()), "BX should be read");
                        assertTrue(contains(regsRead9, X86Reg.DI.getValue()), "DI should be read");
                        assertTrue(contains(regsRead9, X86Reg.AL.getValue()), "AL should be read");
                        assertTrue(contains(regsWrite9, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 10: // test byte ptr [bx + di], bh
                        assertEquals("test", instruction.getMnemonic());
                        assertEquals("byte ptr [bx + di], bh", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes10 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes10[0]);
                        assertEquals(X86Prefix._0, prefixes10[1]);
                        assertEquals(X86Prefix._0, prefixes10[2]);
                        assertEquals(X86Prefix._0, prefixes10[3]);

                        assertEquals(0x84, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x39, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_10 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_10.getType());
                        assertEquals(X86Reg.BX, operand1_10.getMem().getBase());
                        assertEquals(X86Reg.DI, operand1_10.getMem().getIndex());
                        assertEquals(1, operand1_10.getSize());

                        X86Operand operand2_10 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_10.getType());
                        assertEquals(X86Reg.BH, operand2_10.getReg());
                        assertEquals(1, operand2_10.getSize());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess10 = instruction.getRegAccess();
                        int[] regsRead10 = regAccess10.getRegsRead();
                        
                        assertTrue(contains(regsRead10, X86Reg.BX.getValue()), "BX should be read");
                        assertTrue(contains(regsRead10, X86Reg.DI.getValue()), "DI should be read");
                        break;
                    case 11: // mov word ptr [bx], sp
                        assertEquals("mov", instruction.getMnemonic());
                        assertEquals("word ptr [bx], sp", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes11 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes11[0]);
                        assertEquals(X86Prefix._0, prefixes11[1]);
                        assertEquals(X86Prefix._0, prefixes11[2]);
                        assertEquals(X86Prefix._0, prefixes11[3]);

                        assertEquals(0x89, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x67, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x0, details.getDisp());
                        assertEquals(0x2, encoding.getDispOffset());
                        assertEquals(0x1, encoding.getDispSize());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_11 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_11.getType());
                        assertEquals(X86Reg.BX, operand1_11.getMem().getBase());
                        assertEquals(2, operand1_11.getSize());
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_11.getAccess());

                        X86Operand operand2_11 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_11.getType());
                        assertEquals(X86Reg.SP, operand2_11.getReg());
                        assertEquals(2, operand2_11.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_11.getAccess());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess11 = instruction.getRegAccess();
                        int[] regsRead11 = regAccess11.getRegsRead();
                        
                        assertTrue(contains(regsRead11, X86Reg.BX.getValue()), "BX should be read");
                        assertTrue(contains(regsRead11, X86Reg.SP.getValue()), "SP should be read");
                        break;
                    case 12: // add byte ptr [di - 0x7679], cl
                        assertEquals("add", instruction.getMnemonic());
                        assertEquals("byte ptr [di - 0x7679], cl", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes12 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes12[0]);
                        assertEquals(X86Prefix._0, prefixes12[1]);
                        assertEquals(X86Prefix._0, prefixes12[2]);
                        assertEquals(X86Prefix._0, prefixes12[3]);

                        assertEquals(0x00, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x8d, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(-0x7679, details.getDisp());
                        assertEquals(0x2, encoding.getDispOffset());
                        assertEquals(0x2, encoding.getDispSize());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_12 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_12.getType());
                        assertEquals(X86Reg.DI, operand1_12.getMem().getBase());
                        assertEquals(-0x7679, operand1_12.getMem().getDisp());
                        assertEquals(1, operand1_12.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_12.getAccess());

                        X86Operand operand2_12 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_12.getType());
                        assertEquals(X86Reg.CL, operand2_12.getReg());
                        assertEquals(1, operand2_12.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_12.getAccess());

                        // Verify EFLAGS
                        X86EFlags[] eflags12 = details.getEflags();
                        X86EFlags[] expectedEFlags12 = new X86EFlags[] {
                            X86EFlags.MODIFY_AF,
                            X86EFlags.MODIFY_CF,
                            X86EFlags.MODIFY_SF,
                            X86EFlags.MODIFY_ZF,
                            X86EFlags.MODIFY_PF,
                            X86EFlags.MODIFY_OF
                        };
                        assertTrue(containsAllEFlags(eflags12, expectedEFlags12), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess12 = instruction.getRegAccess();
                        int[] regsRead12 = regAccess12.getRegsRead();
                        int[] regsWrite12 = regAccess12.getRegsWrite();
                        
                        assertTrue(contains(regsRead12, X86Reg.DI.getValue()), "DI should be read");
                        assertTrue(contains(regsRead12, X86Reg.CL.getValue()), "CL should be read");
                        assertTrue(contains(regsWrite12, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 13: // add byte ptr [eax], al
                        assertEquals("add", instruction.getMnemonic());
                        assertEquals("byte ptr [eax], al", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes13 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes13[0]);
                        assertEquals(X86Prefix._0, prefixes13[1]);
                        assertEquals(X86Prefix._0, prefixes13[2]);
                        assertEquals(X86Prefix.ADDRSIZE, prefixes13[3]);

                        assertEquals(0x00, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x2, encoding.getModrmOffset());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_13 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_13.getType());
                        assertEquals(X86Reg.EAX, operand1_13.getMem().getBase());
                        assertEquals(1, operand1_13.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_13.getAccess());

                        X86Operand operand2_13 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_13.getType());
                        assertEquals(X86Reg.AL, operand2_13.getReg());
                        assertEquals(1, operand2_13.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_13.getAccess());

                        // Verify EFLAGS
                        X86EFlags[] eflags13 = details.getEflags();
                        X86EFlags[] expectedEFlags13 = new X86EFlags[] {
                            X86EFlags.MODIFY_AF,
                            X86EFlags.MODIFY_CF,
                            X86EFlags.MODIFY_SF,
                            X86EFlags.MODIFY_ZF,
                            X86EFlags.MODIFY_PF,
                            X86EFlags.MODIFY_OF
                        };
                        assertTrue(containsAllEFlags(eflags13, expectedEFlags13), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess13 = instruction.getRegAccess();
                        int[] regsRead13 = regAccess13.getRegsRead();
                        int[] regsWrite13 = regAccess13.getRegsWrite();
                        
                        assertTrue(contains(regsRead13, X86Reg.EAX.getValue()), "EAX should be read");
                        assertTrue(contains(regsRead13, X86Reg.AL.getValue()), "AL should be read");
                        assertTrue(contains(regsWrite13, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 14: // mov ah, 0xc6
                        assertEquals("mov", instruction.getMnemonic());
                        assertEquals("ah, 0xc6", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes14 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes14[0]);
                        assertEquals(X86Prefix._0, prefixes14[1]);
                        assertEquals(X86Prefix._0, prefixes14[2]);
                        assertEquals(X86Prefix._0, prefixes14[3]);

                        assertEquals(0xb4, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_14 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_14.getType());
                        assertEquals(X86Reg.AH, operand1_14.getReg());
                        assertEquals(1, operand1_14.getSize());
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_14.getAccess());

                        X86Operand operand2_14 = details.getOperands()[1];
                        assertEquals(X86OperandType.IMM, operand2_14.getType());
                        assertEquals(0xc6, operand2_14.getImm());
                        assertEquals(1, operand2_14.getSize());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess14 = instruction.getRegAccess();
                        int[] regsWrite14 = regAccess14.getRegsWrite();
                        
                        assertTrue(contains(regsWrite14, X86Reg.AH.getValue()), "AH should be written");
                        break;
                    case 15: // jmp 0x10e7
                        assertEquals("jmp", instruction.getMnemonic());
                        assertEquals("0x10e7", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes15 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes15[0]);
                        assertEquals(X86Prefix._0, prefixes15[1]);
                        assertEquals(X86Prefix.OPSIZE, prefixes15[2]);
                        assertEquals(X86Prefix._0, prefixes15[3]);

                        assertEquals(0xe9, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_15 = details.getOperands()[0];
                        assertEquals(X86OperandType.IMM, operand1_15.getType());
                        assertEquals(0x10e7, operand1_15.getImm());
                        assertEquals(4, operand1_15.getSize());
                        break;
                    case 16: // jmp word ptr [eax + 0x123]
                        assertEquals("jmp", instruction.getMnemonic());
                        assertEquals("word ptr [eax + 0x123]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes16 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes16[0]);
                        assertEquals(X86Prefix._0, prefixes16[1]);
                        assertEquals(X86Prefix._0, prefixes16[2]);
                        assertEquals(X86Prefix.ADDRSIZE, prefixes16[3]);

                        assertEquals(0xff, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0xa0, details.getModrm());

                        // Verify encoding details
                        assertEquals(0x2, encoding.getModrmOffset());
                        assertEquals(0x123, details.getDisp());
                        assertEquals(0x3, encoding.getDispOffset());
                        assertEquals(0x4, encoding.getDispSize());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_16 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_16.getType());
                        assertEquals(X86Reg.EAX, operand1_16.getMem().getBase());
                        assertEquals(0x123, operand1_16.getMem().getDisp());
                        assertEquals(2, operand1_16.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_16.getAccess());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess16 = instruction.getRegAccess();
                        int[] regsRead16 = regAccess16.getRegsRead();
                        
                        assertTrue(contains(regsRead16, X86Reg.EAX.getValue()), "EAX should be read");
                        break;
                    case 17: // call 0x1107
                        assertEquals("call", instruction.getMnemonic());
                        assertEquals("0x1107", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes17 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes17[0]);
                        assertEquals(X86Prefix._0, prefixes17[1]);
                        assertEquals(X86Prefix.OPSIZE, prefixes17[2]);
                        assertEquals(X86Prefix._0, prefixes17[3]);

                        assertEquals(0xe8, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_17 = details.getOperands()[0];
                        assertEquals(X86OperandType.IMM, operand1_17.getType());
                        assertEquals(0x1107, operand1_17.getImm());
                        assertEquals(4, operand1_17.getSize());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess17 = instruction.getRegAccess();
                        int[] regsRead17 = regAccess17.getRegsRead();
                        int[] regsWrite17 = regAccess17.getRegsWrite();
                        
                        assertTrue(contains(regsRead17, X86Reg.ESP.getValue()), "ESP should be read");
                        assertTrue(contains(regsRead17, X86Reg.EIP.getValue()), "EIP should be read");
                        assertTrue(contains(regsWrite17, X86Reg.ESP.getValue()), "ESP should be written");
                        assertTrue(contains(regsWrite17, X86Reg.EIP.getValue()), "EIP should be written");
                        break;
                    case 18: // je 0x103a
                        assertEquals("je", instruction.getMnemonic());
                        assertEquals("0x103a", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes18 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes18[0]);
                        assertEquals(X86Prefix._0, prefixes18[1]);
                        assertEquals(X86Prefix._0, prefixes18[2]);
                        assertEquals(X86Prefix._0, prefixes18[3]);

                        assertEquals(0x74, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(2, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_18 = details.getOperands()[0];
                        assertEquals(X86OperandType.IMM, operand1_18.getType());
                        assertEquals(0x103a, operand1_18.getImm());
                        assertEquals(2, operand1_18.getSize());

                        // Verify EFLAGS
                        X86EFlags[] eflags18 = details.getEflags();
                        boolean hasZfTest = false;
                        for (X86EFlags flag : eflags18) {
                            if (flag == X86EFlags.TEST_ZF) {
                                hasZfTest = true;
                                break;
                            }
                        }
                        assertTrue(hasZfTest, "JE should test ZF");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess18 = instruction.getRegAccess();
                        int[] regsRead18 = regAccess18.getRegsRead();
                        
                        assertTrue(contains(regsRead18, X86Reg.EFLAGS.getValue()), "EFLAGS should be read");
                        break;
                }

                // Update for next iteration
                offset += instruction.getSize();
                runtimeAddress += instruction.getSize();
                instructionIndex++;
            }

            // Verify we processed 19 instructions
            assertEquals(19, instructionIndex, "Expected 19 instructions, but processed " + instructionIndex);

        } catch (Exception e) {
            e.printStackTrace();
            fail("Failed to create Capstone handle");
        }
    }

    byte[] testX86_32Data = new byte[] {
        (byte)0x8d, 0x4c, 0x32, 0x08, 0x01, (byte)0xd8, (byte)0x81, (byte)0xc6, 0x34, 0x12, 
        0x00, 0x00, 0x05, 0x23, 0x01, 0x00, 0x00, 0x36, (byte)0x8b, (byte)0x84, 
        (byte)0x91, 0x23, 0x01, 0x00, 0x00, 0x41, (byte)0x8d, (byte)0x84, 0x39, (byte)0x89, 
        0x67, 0x00, 0x00, (byte)0x8d, (byte)0x87, (byte)0x89, 0x67, 0x00, 0x00, (byte)0xb4, 
        (byte)0xc6, (byte)0xe9, (byte)0xea, (byte)0xbe, (byte)0xad, (byte)0xde, (byte)0xff, (byte)0xa0, 0x23, 0x01, 
        0x00, 0x00, (byte)0xe8, (byte)0xdf, (byte)0xbe, (byte)0xad, (byte)0xde, 0x74, (byte)0xff,
    };

    @Test 
    public void testX86_32() {
        System.out.println("Testing X86_32");
        CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();

        try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.X86, CapstoneMode.X86_32, options)) {
            // Enable detailed instruction information
            handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);

            long runtimeAddress = 0x1000;
            int offset = 0;
            final int length = testX86_32Data.length;
            int instructionIndex = 0;

            while(offset < length) {
                int maxBytesToRead = Math.min(15, length - offset);
                byte[] subData = Arrays.copyOfRange(testX86_32Data, offset, offset + maxBytesToRead);
                
                CapstoneInstruction<CapstoneX86Details> instruction = handle.disassembleInstruction(subData, runtimeAddress);
                
                // Verify instruction is not null
                assertNotNull(instruction, "Failed to disassemble instruction at offset " + offset);
                
                // Verify instruction details
                assertNotNull(instruction.getDetails(), "Instruction details should not be null");
                CapstoneX86Details details = instruction.getDetails().getArchDetails();
                assertNotNull(details, "Architecture details should not be null");

                X86Encoding encoding = details.getEncoding();
                assertNotNull(encoding, "Encoding should not be null");

                // Print instruction info for debugging
                System.out.printf("Instruction %d: %s %s (size: %d, addr: 0x%x)%n", 
                    instructionIndex, instruction.getMnemonic(), instruction.getOpStr(), 
                    instruction.getSize(), instruction.getAddress());

                switch(instructionIndex) {
                    // lea ecx, [edx + esi + 8]
                    case 0:
                        assertEquals("lea", instruction.getMnemonic());
                        assertEquals("ecx, [edx + esi + 8]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes[0]);
                        assertEquals(0x8d, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x4c, details.getModrm());

                        assertEquals(0x1, encoding.getModrmOffset());

                        assertEquals(0x8, details.getDisp());

                        assertEquals(0x3, encoding.getDispOffset());
                        assertEquals(0x1, encoding.getDispSize());

                        assertEquals(0x32, details.getSib());
                        assertEquals(X86Reg.EDX, details.getSibBase());
                        assertEquals(X86Reg.ESI, details.getSibIndex());
                        assertEquals(1, details.getSibScale());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1.getType());
                        assertEquals(X86Reg.ECX, operand1.getReg());
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1.getAccess());
                        
                        X86Operand operand2 = details.getOperands()[1];
                        assertEquals(X86OperandType.MEM, operand2.getType());
                        assertEquals(X86Reg.EDX, operand2.getMem().getBase());
                        assertEquals(X86Reg.ESI, operand2.getMem().getIndex());
                        assertEquals(0x8, operand2.getMem().getDisp());
                        assertEquals(4, operand2.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2.getAccess());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess = instruction.getRegAccess();
                        int[] regsRead = regAccess.getRegsRead();
                        int[] regsWrite = regAccess.getRegsWrite();
                        
                        assertTrue(contains(regsRead, X86Reg.EDX.getValue()), "EDX should be read");
                        assertTrue(contains(regsRead, X86Reg.ESI.getValue()), "ESI should be read");
                        assertTrue(contains(regsWrite, X86Reg.ECX.getValue()), "ECX should be written");
                        break;
                    case 1: // add eax, ebx
                        assertEquals("add", instruction.getMnemonic());
                        assertEquals("eax, ebx", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes1 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes1[0]);
                        assertEquals(0x01, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0xd8, details.getModrm());

                        assertEquals(0x1, encoding.getModrmOffset());

                        assertEquals(0x0, details.getDisp());
                        assertEquals(0x0, details.getSib());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_1 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_1.getType());
                        assertEquals(X86Reg.EAX, operand1_1.getReg());
                        assertEquals(4, operand1_1.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_1.getAccess());

                        X86Operand operand2_1 = details.getOperands()[1];
                        assertEquals(X86OperandType.REG, operand2_1.getType());
                        assertEquals(X86Reg.EBX, operand2_1.getReg());
                        assertEquals(4, operand2_1.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_1.getAccess());

                        X86EFlags[] expectedEFlags = new X86EFlags[] { 
                            X86EFlags.MODIFY_AF, 
                            X86EFlags.MODIFY_CF, 
                            X86EFlags.MODIFY_SF, 
                            X86EFlags.MODIFY_ZF, 
                            X86EFlags.MODIFY_PF, 
                            X86EFlags.MODIFY_OF 
                        };
                        X86EFlags[] eflags = details.getEflags();
                        assertTrue(containsAllEFlags(eflags, expectedEFlags), "EFLAGS should contain all expected flags");

                        // Verfiy registers accessed
                        CapstoneRegAccess regAccess1 = instruction.getRegAccess();
                        int[] regsRead1 = regAccess1.getRegsRead();
                        int[] regsWrite1 = regAccess1.getRegsWrite();
                        
                        assertTrue(contains(regsRead1, X86Reg.EAX.getValue()), "EAX should be read");
                        assertTrue(contains(regsRead1, X86Reg.EBX.getValue()), "EBX should be read");
                        assertTrue(contains(regsWrite1, X86Reg.EAX.getValue()), "EAX should be written");
                        assertTrue(contains(regsWrite1, X86Reg.EFLAGS.getValue()), "EBX should be written");
                        break;
                    case 2: // add esi, 0x1234
                        assertEquals("add", instruction.getMnemonic());
                        assertEquals("esi, 0x1234", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes2 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes2[0]);
                        assertEquals(0x81, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0xc6, details.getModrm());

                        assertEquals(0x1, encoding.getModrmOffset());

                        assertEquals(0x0, details.getDisp());
                        assertEquals(0x0, details.getSib());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_2 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_2.getType());
                        assertEquals(X86Reg.ESI, operand1_2.getReg());
                        assertEquals(4, operand1_2.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_2.getAccess());

                        X86Operand operand2_2 = details.getOperands()[1];
                        assertEquals(X86OperandType.IMM, operand2_2.getType());
                        assertEquals(0x1234, operand2_2.getImm());
                        assertEquals(4, operand2_2.getSize());

                        // Verify eflags
                        X86EFlags[] eflags2 = details.getEflags();
                        X86EFlags[] expectedEFlags2 = new X86EFlags[] { 
                            X86EFlags.MODIFY_AF, 
                            X86EFlags.MODIFY_CF, 
                            X86EFlags.MODIFY_SF, 
                            X86EFlags.MODIFY_ZF, 
                            X86EFlags.MODIFY_PF, 
                            X86EFlags.MODIFY_OF
                        };
                        assertTrue(containsAllEFlags(eflags2, expectedEFlags2), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess2 = instruction.getRegAccess();
                        int[] regsRead2 = regAccess2.getRegsRead();
                        int[] regsWrite2 = regAccess2.getRegsWrite();
                        
                        assertTrue(contains(regsRead2, X86Reg.ESI.getValue()), "ESI should be read");
                        assertTrue(contains(regsWrite2, X86Reg.ESI.getValue()), "ESI should be written");
                        assertTrue(contains(regsWrite2, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 3: // add eax, 0x123
                        assertEquals("add", instruction.getMnemonic());
                        assertEquals("eax, 0x123", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes3 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes3[0]);
                        assertEquals(0x05, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());
                        assertEquals(0x0, details.getSib());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_3 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_3.getType());
                        assertEquals(X86Reg.EAX, operand1_3.getReg());
                        assertEquals(4, operand1_3.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_3.getAccess());

                        X86Operand operand2_3 = details.getOperands()[1];
                        assertEquals(X86OperandType.IMM, operand2_3.getType());
                        assertEquals(0x123, operand2_3.getImm());
                        assertEquals(4, operand2_3.getSize());

                        // Verify eflags
                        X86EFlags[] eflags3 = details.getEflags();
                        X86EFlags[] expectedEFlags3 = new X86EFlags[] { 
                            X86EFlags.MODIFY_AF, 
                            X86EFlags.MODIFY_CF, 
                            X86EFlags.MODIFY_SF, 
                            X86EFlags.MODIFY_ZF, 
                            X86EFlags.MODIFY_PF, 
                            X86EFlags.MODIFY_OF
                        };
                        assertTrue(containsAllEFlags(eflags3, expectedEFlags3), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess3 = instruction.getRegAccess();
                        int[] regsRead3 = regAccess3.getRegsRead();
                        int[] regsWrite3 = regAccess3.getRegsWrite();
                        
                        assertTrue(contains(regsRead3, X86Reg.EAX.getValue()), "EAX should be read");
                        assertTrue(contains(regsWrite3, X86Reg.EAX.getValue()), "EAX should be written");
                        assertTrue(contains(regsWrite3, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 4: // mov eax, dword ptr ss:[ecx + edx*4 + 0x123]
                        assertEquals("mov", instruction.getMnemonic());
                        assertEquals("eax, dword ptr ss:[ecx + edx*4 + 0x123]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes4 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes4[0]);
                        assertEquals(X86Prefix.SS, prefixes4[1]);
                        assertEquals(X86Prefix._0, prefixes4[2]);
                        assertEquals(X86Prefix._0, prefixes4[3]);

                        assertEquals(0x8b, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x84, details.getModrm());

                        assertEquals(0x2, encoding.getModrmOffset());

                        assertEquals(0x123, details.getDisp());
                        assertEquals(0x4, encoding.getDispOffset());
                        assertEquals(0x4, encoding.getDispSize());

                        assertEquals(0x91, details.getSib());
                        assertEquals(X86Reg.ECX, details.getSibBase());
                        assertEquals(X86Reg.EDX, details.getSibIndex());
                        assertEquals(4, details.getSibScale());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_4 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_4.getType());
                        assertEquals(X86Reg.EAX, operand1_4.getReg());
                        assertEquals(4, operand1_4.getSize());
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_4.getAccess());

                        X86Operand operand2_4 = details.getOperands()[1];
                        assertEquals(X86OperandType.MEM, operand2_4.getType());
                        assertEquals(X86Reg.SS, operand2_4.getMem().getSegment());
                        assertEquals(X86Reg.ECX, operand2_4.getMem().getBase());
                        assertEquals(X86Reg.EDX, operand2_4.getMem().getIndex());
                        assertEquals(4, operand2_4.getMem().getScale());
                        assertEquals(0x123, operand2_4.getMem().getDisp());
                        assertEquals(4, operand2_4.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_4.getAccess());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess4 = instruction.getRegAccess();
                        int[] regsRead4 = regAccess4.getRegsRead();
                        int[] regsWrite4 = regAccess4.getRegsWrite();
                        
                        assertTrue(contains(regsRead4, X86Reg.SS.getValue()), "SS should be read");
                        assertTrue(contains(regsRead4, X86Reg.ECX.getValue()), "ECX should be read");
                        assertTrue(contains(regsRead4, X86Reg.EDX.getValue()), "EDX should be read");
                        assertTrue(contains(regsWrite4, X86Reg.EAX.getValue()), "EAX should be written");
                        break;
                    case 5: // inc ecx
                        assertEquals("inc", instruction.getMnemonic());
                        assertEquals("ecx", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes5 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes5[0]);
                        assertEquals(X86Prefix._0, prefixes5[1]);
                        assertEquals(X86Prefix._0, prefixes5[2]);
                        assertEquals(X86Prefix._0, prefixes5[3]);

                        assertEquals(0x41, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());
                        assertEquals(0x0, details.getSib());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_5 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_5.getType());
                        assertEquals(X86Reg.ECX, operand1_5.getReg());
                        assertEquals(4, operand1_5.getSize());
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_5.getAccess());

                        // Verify eflags
                        X86EFlags[] eflags5 = details.getEflags();
                        X86EFlags[] expectedEFlags5 = new X86EFlags[] { 
                            X86EFlags.MODIFY_AF, 
                            X86EFlags.MODIFY_SF, 
                            X86EFlags.MODIFY_ZF, 
                            X86EFlags.MODIFY_PF, 
                            X86EFlags.MODIFY_OF
                        };
                        assertTrue(containsAllEFlags(eflags5, expectedEFlags5), "EFLAGS should contain all expected flags");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess5 = instruction.getRegAccess();
                        int[] regsRead5 = regAccess5.getRegsRead();
                        int[] regsWrite5 = regAccess5.getRegsWrite();
                        
                        assertTrue(contains(regsRead5, X86Reg.ECX.getValue()), "ECX should be read");
                        assertTrue(contains(regsWrite5, X86Reg.ECX.getValue()), "ECX should be written");
                        assertTrue(contains(regsWrite5, X86Reg.EFLAGS.getValue()), "EFLAGS should be written");
                        break;
                    case 6: // lea eax, [ecx + edi + 0x6789]
                        assertEquals("lea", instruction.getMnemonic());
                        assertEquals("eax, [ecx + edi + 0x6789]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes6 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes6[0]);
                        assertEquals(X86Prefix._0, prefixes6[1]);
                        assertEquals(X86Prefix._0, prefixes6[2]);
                        assertEquals(X86Prefix._0, prefixes6[3]);

                        assertEquals(0x8d, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x84, details.getModrm());

                        assertEquals(0x1, encoding.getModrmOffset());

                        assertEquals(0x6789, details.getDisp());
                        assertEquals(0x3, encoding.getDispOffset());
                        assertEquals(0x4, encoding.getDispSize());

                        assertEquals(0x39, details.getSib());
                        assertEquals(X86Reg.ECX, details.getSibBase());
                        assertEquals(X86Reg.EDI, details.getSibIndex());
                        assertEquals(1, details.getSibScale());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_6 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_6.getType());
                        assertEquals(X86Reg.EAX, operand1_6.getReg());
                        assertEquals(4, operand1_6.getSize());
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_6.getAccess());

                        X86Operand operand2_6 = details.getOperands()[1];
                        assertEquals(X86OperandType.MEM, operand2_6.getType());
                        assertEquals(X86Reg.ECX, operand2_6.getMem().getBase());
                        assertEquals(X86Reg.EDI, operand2_6.getMem().getIndex());
                        assertEquals(0x6789, operand2_6.getMem().getDisp());
                        assertEquals(4, operand2_6.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_6.getAccess());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess6 = instruction.getRegAccess();
                        int[] regsRead6 = regAccess6.getRegsRead();
                        int[] regsWrite6 = regAccess6.getRegsWrite();
                        
                        assertTrue(contains(regsRead6, X86Reg.ECX.getValue()), "ECX should be read");
                        assertTrue(contains(regsRead6, X86Reg.EDI.getValue()), "EDI should be read");
                        assertTrue(contains(regsWrite6, X86Reg.EAX.getValue()), "EAX should be written");
                        break;
                    case 7: //lea eax, [edi + 0x6789]
                        assertEquals("lea", instruction.getMnemonic());
                        assertEquals("eax, [edi + 0x6789]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes7 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes7[0]);
                        assertEquals(X86Prefix._0, prefixes7[1]);
                        assertEquals(X86Prefix._0, prefixes7[2]);
                        assertEquals(X86Prefix._0, prefixes7[3]);

                        assertEquals(0x8d, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x87, details.getModrm());

                        assertEquals(0x1, encoding.getModrmOffset());

                        assertEquals(0x6789, details.getDisp());
                        assertEquals(0x2, encoding.getDispOffset());
                        assertEquals(0x4, encoding.getDispSize());

                        assertEquals(0x0, details.getSib());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_7 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_7.getType());
                        assertEquals(X86Reg.EAX, operand1_7.getReg());
                        assertEquals(4, operand1_7.getSize());
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_7.getAccess());

                        X86Operand operand2_7 = details.getOperands()[1];
                        assertEquals(X86OperandType.MEM, operand2_7.getType());
                        assertEquals(X86Reg.EDI, operand2_7.getMem().getBase());
                        assertEquals(0x6789, operand2_7.getMem().getDisp());
                        assertEquals(4, operand2_7.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_7.getAccess());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess7 = instruction.getRegAccess();
                        int[] regsRead7 = regAccess7.getRegsRead();
                        int[] regsWrite7 = regAccess7.getRegsWrite();
                        
                        assertTrue(contains(regsRead7, X86Reg.EDI.getValue()), "EDI should be read");
                        assertTrue(contains(regsWrite7, X86Reg.EAX.getValue()), "EAX should be written");
                        break;
                    case 8: // mov ah, 0xc6
                        assertEquals("mov", instruction.getMnemonic());
                        assertEquals("ah, 0xc6", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes8 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes8[0]);
                        assertEquals(X86Prefix._0, prefixes8[1]);
                        assertEquals(X86Prefix._0, prefixes8[2]);
                        assertEquals(X86Prefix._0, prefixes8[3]);

                        assertEquals(0xb4, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());
                        assertEquals(0x0, details.getSib());

                        // Verify operands
                        assertEquals(2, details.getOpCount());

                        X86Operand operand1_8 = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand1_8.getType());
                        assertEquals(X86Reg.AH, operand1_8.getReg());
                        assertEquals(1, operand1_8.getSize());
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_8.getAccess());

                        X86Operand operand2_8 = details.getOperands()[1];
                        assertEquals(X86OperandType.IMM, operand2_8.getType());
                        assertEquals(0xc6, operand2_8.getImm());
                        assertEquals(1, operand2_8.getSize());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess8 = instruction.getRegAccess();
                        int[] regsWrite8 = regAccess8.getRegsWrite();
                        
                        assertTrue(contains(regsWrite8, X86Reg.AH.getValue()), "AH should be written");
                        break;
                    case 9: // jmp 0xdeadcf18
                        assertEquals("jmp", instruction.getMnemonic());
                        assertEquals("0xdeadcf18", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes9 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes9[0]);
                        assertEquals(X86Prefix._0, prefixes9[1]);
                        assertEquals(X86Prefix._0, prefixes9[2]);
                        assertEquals(X86Prefix._0, prefixes9[3]);

                        assertEquals(0xe9, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());
                        assertEquals(0x0, details.getSib());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_9 = details.getOperands()[0];
                        assertEquals(X86OperandType.IMM, operand1_9.getType());
                        assertEquals(0xdeadcf18L, operand1_9.getImm());
                        assertEquals(4, operand1_9.getSize());
                        break;
                    case 10: // jmp dword ptr [eax + 0x123]
                        assertEquals("jmp", instruction.getMnemonic());
                        assertEquals("dword ptr [eax + 0x123]", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes10 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes10[0]);
                        assertEquals(X86Prefix._0, prefixes10[1]);
                        assertEquals(X86Prefix._0, prefixes10[2]);
                        assertEquals(X86Prefix._0, prefixes10[3]);

                        assertEquals(0xff, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0xa0, details.getModrm());
                        assertEquals(0x123, details.getDisp());
                        assertEquals(0x0, details.getSib());

                        // Verify encoding details
                        assertEquals(0x1, encoding.getModrmOffset());
                        assertEquals(0x2, encoding.getDispOffset());
                        assertEquals(0x4, encoding.getDispSize());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_10 = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, operand1_10.getType());
                        assertEquals(X86Reg.EAX, operand1_10.getMem().getBase());
                        assertEquals(0x123, operand1_10.getMem().getDisp());
                        assertEquals(4, operand1_10.getSize());
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_10.getAccess());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess10 = instruction.getRegAccess();
                        int[] regsRead10 = regAccess10.getRegsRead();
                        
                        assertTrue(contains(regsRead10, X86Reg.EAX.getValue()), "EAX should be read");
                        break;
                    case 11: // call 0xdeadcf18
                        assertEquals("call", instruction.getMnemonic());
                        assertEquals("0xdeadcf18", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes11 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes11[0]);
                        assertEquals(X86Prefix._0, prefixes11[1]);
                        assertEquals(X86Prefix._0, prefixes11[2]);
                        assertEquals(X86Prefix._0, prefixes11[3]);

                        assertEquals(0xe8, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());
                        assertEquals(0x0, details.getSib());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_11 = details.getOperands()[0];
                        assertEquals(X86OperandType.IMM, operand1_11.getType());
                        assertEquals(0xdeadcf18L, operand1_11.getImm());
                        assertEquals(4, operand1_11.getSize());

                        // Verify registers accessed
                        CapstoneRegAccess regAccess11 = instruction.getRegAccess();
                        int[] regsRead11 = regAccess11.getRegsRead();
                        int[] regsWrite11 = regAccess11.getRegsWrite();
                        
                        assertTrue(contains(regsRead11, X86Reg.ESP.getValue()), "ESP should be read");
                        assertTrue(contains(regsRead11, X86Reg.EIP.getValue()), "EIP should be read");
                        assertTrue(contains(regsWrite11, X86Reg.ESP.getValue()), "ESP should be written");
                        assertTrue(contains(regsWrite11, X86Reg.EIP.getValue()), "EIP should be written");
                        break;
                    case 12: // je 0x103a
                        assertEquals("je", instruction.getMnemonic());
                        assertEquals("0x103a", instruction.getOpStr());

                        // Verify X86 details
                        X86Prefix[] prefixes12 = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes12[0]);
                        assertEquals(X86Prefix._0, prefixes12[1]);
                        assertEquals(X86Prefix._0, prefixes12[2]);
                        assertEquals(X86Prefix._0, prefixes12[3]);

                        assertEquals(0x74, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(4, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        assertEquals(0x0, details.getDisp());
                        assertEquals(0x0, details.getSib());

                        // Verify operands
                        assertEquals(1, details.getOpCount());

                        X86Operand operand1_12 = details.getOperands()[0];
                        assertEquals(X86OperandType.IMM, operand1_12.getType());
                        assertEquals(0x103a, operand1_12.getImm());
                        assertEquals(4, operand1_12.getSize());

                        // Verify EFLAGS
                        X86EFlags[] eflags12 = details.getEflags();
                        boolean hasZfTest = false;
                        for (X86EFlags flag : eflags12) {
                            if (flag == X86EFlags.TEST_ZF) {
                                hasZfTest = true;
                                break;
                            }
                        }
                        assertTrue(hasZfTest, "JE should test ZF");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess12 = instruction.getRegAccess();
                        int[] regsRead12 = regAccess12.getRegsRead();
                        
                        assertTrue(contains(regsRead12, X86Reg.EFLAGS.getValue()), "EFLAGS should be read");
                        break;
                }

                // Update for next iteration
                offset += instruction.getSize();
                runtimeAddress += instruction.getSize();
                instructionIndex++;
            }

            // Verify we processed 13 instructions
            assertEquals(13, instructionIndex, "Expected 13 instructions, but processed " + instructionIndex);

        } catch (Exception e) {
            e.printStackTrace();
            fail("Failed to create Capstone handle");
        }
    }

    byte[] testX86_64Data = new byte[] {
        0x55, 0x48, (byte)0x8b, 0x05, (byte)0xb8, (byte)0x13, 0x00, 0x00, (byte)0xe9, (byte)0xea, 
        (byte)0xbe, (byte)0xad, (byte)0xde, (byte)0xff, 0x25, 0x23, 0x01, 0x00, 0x00, (byte)0xe8, 
        (byte)0xdf, (byte)0xbe, (byte)0xad, (byte)0xde, 0x74, (byte)0xff
    };

    @Test 
    public void testX86_64() {
        System.out.println("Testing X86_64");
        CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();

        try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.X86, CapstoneMode.X86_64, options)) {
            // Enable detailed instruction information
            handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);
            
            long runtimeAddress = 0x1000;
            int offset = 0;
            final int length = testX86_64Data.length;
            int instructionIndex = 0;
            
            while(offset < length) {
                int maxBytesToRead = Math.min(15, length - offset);
                byte[] subData = Arrays.copyOfRange(testX86_64Data, offset, offset + maxBytesToRead);
                
                CapstoneInstruction<CapstoneX86Details> instruction = handle.disassembleInstruction(subData, runtimeAddress);
                
                // Verify instruction is not null
                assertNotNull(instruction, "Failed to disassemble instruction at offset " + offset);
                
                // Verify instruction details
                assertNotNull(instruction.getDetails(), "Instruction details should not be null");
                CapstoneX86Details details = instruction.getDetails().getArchDetails();
                assertNotNull(details, "Architecture details should not be null");
                
                // Print instruction info for debugging
                System.out.printf("Instruction %d: %s %s (size: %d, addr: 0x%x)%n", 
                    instructionIndex, instruction.getMnemonic(), instruction.getOpStr(), 
                    instruction.getSize(), instruction.getAddress());
                
                // Verify each instruction based on its index
                switch(instructionIndex) {
                    case 0: // push rbp
                        assertEquals("push", instruction.getMnemonic());
                        assertEquals("rbp", instruction.getOpStr());
                        
                        // Verify X86 details
                        X86Prefix[] prefixes = details.getPrefixs();
                        assertEquals(X86Prefix._0, prefixes[0]);
                        assertEquals(0x55, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(8, details.getAddrSize());
                        assertEquals(0, details.getModrm());
                        assertEquals(0, details.getDisp());
                        assertEquals(0, details.getSib());
                        
                        // Verify operands
                        assertEquals(1, details.getOpCount());
                        X86Operand operand = details.getOperands()[0];
                        assertEquals(X86OperandType.REG, operand.getType());
                        assertEquals(X86Reg.RBP, operand.getReg());
                        assertEquals(8, operand.getSize());
                        
                        // Verify registers accessed
                        CapstoneRegAccess regAccess = instruction.getRegAccess();
                        int[] regsRead = regAccess.getRegsRead();
                        int[] regsWrite = regAccess.getRegsWrite();
                        
                        assertTrue(contains(regsRead, X86Reg.RSP.getValue()), "RSP should be read");
                        assertTrue(contains(regsRead, X86Reg.RBP.getValue()), "RBP should be read");
                        assertTrue(contains(regsWrite, X86Reg.RSP.getValue()), "RSP should be written");
                        break;
                        
                    case 1: // mov rax, qword ptr [rip + 0x13b8]
                        assertEquals("mov", instruction.getMnemonic());
                        assertTrue(instruction.getOpStr().contains("rax") && 
                                  instruction.getOpStr().contains("qword ptr [rip") && 
                                  instruction.getOpStr().contains("0x13b8"));
                        
                        // Verify X86 details
                        assertEquals(X86Prefix._0, details.getPrefixs()[0]);
                        assertEquals(0x8b, details.getOpcodes()[0]);
                        assertEquals(0x48, details.getRex());
                        assertEquals(8, details.getAddrSize());
                        assertEquals(0x5, details.getModrm());
                        assertEquals(0x13b8, details.getDisp());
                        assertEquals(0, details.getSib());
                        
                        // Verify operands
                        assertEquals(2, details.getOpCount());
                        X86Operand op1 = details.getOperands()[0];
                        X86Operand op2 = details.getOperands()[1];
                        
                        assertEquals(X86OperandType.REG, op1.getType());
                        assertEquals(X86Reg.RAX, op1.getReg());
                        assertEquals(8, op1.getSize());
                        
                        assertEquals(X86OperandType.MEM, op2.getType());
                        assertEquals(X86Reg.RIP, op2.getMem().getBase());
                        assertEquals(0x13b8, op2.getMem().getDisp());
                        assertEquals(8, op2.getSize());

                        CapstoneRegAccess regAccess2 = instruction.getRegAccess();
                        int[] regsRead2 = regAccess2.getRegsRead();
                        int[] regsWrite2 = regAccess2.getRegsWrite();
                        
                        // Verify registers accessed
                        assertTrue(contains(regsRead2, X86Reg.RIP.getValue()), "RIP should be read");
                        assertTrue(contains(regsWrite2, X86Reg.RAX.getValue()), "RAX should be written");
                        break;
                        
                    case 2: // jmp 0xffffffffdeadcef7 (or similar)
                        assertEquals("jmp", instruction.getMnemonic());
                        
                        // Verify X86 details
                        assertEquals(X86Prefix._0, details.getPrefixs()[0]);
                        assertEquals(0xe9, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(8, details.getAddrSize());
                        assertEquals(0x0, details.getModrm());
                        
                        // Verify operands
                        assertEquals(1, details.getOpCount());
                        X86Operand jmpOp = details.getOperands()[0];
                        assertEquals(X86OperandType.IMM, jmpOp.getType());
                        assertEquals(8, jmpOp.getSize());
                        break;
                        
                    case 3: // jmp qword ptr [rip + 0x123]
                        assertEquals("jmp", instruction.getMnemonic());
                        assertTrue(instruction.getOpStr().contains("qword ptr [rip") && 
                                  instruction.getOpStr().contains("0x123"));
                        
                        // Verify X86 details
                        assertEquals(X86Prefix._0, details.getPrefixs()[0]);
                        assertEquals(0xff, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(8, details.getAddrSize());
                        assertEquals(0x25, details.getModrm());
                        assertEquals(0x123, details.getDisp());
                        
                        // Verify operands
                        assertEquals(1, details.getOpCount());
                        X86Operand jmpMemOp = details.getOperands()[0];
                        assertEquals(X86OperandType.MEM, jmpMemOp.getType());
                        assertEquals(X86Reg.RIP, jmpMemOp.getMem().getBase());
                        assertEquals(0x123, jmpMemOp.getMem().getDisp());
                        assertEquals(8, jmpMemOp.getSize());
                        
                        // Verify registers accessed
                        CapstoneRegAccess regAccess3 = instruction.getRegAccess();
                        int[] regsRead3 = regAccess3.getRegsRead();

                        assertTrue(contains(regsRead3, X86Reg.RIP.getValue()), "RIP should be read");
                        break;
                        
                    case 4: // call 0xffffffffdeadcef7 (or similar)
                        assertEquals("call", instruction.getMnemonic());
                        
                        // Verify X86 details
                        assertEquals(X86Prefix._0, details.getPrefixs()[0]);
                        assertEquals(0xe8, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(8, details.getAddrSize());
                        assertEquals(0, details.getModrm());
                        
                        // Verify operands
                        assertEquals(1, details.getOpCount());
                        X86Operand callOp = details.getOperands()[0];
                        assertEquals(X86OperandType.IMM, callOp.getType());
                        assertEquals(8, callOp.getSize());
                        
                        // Verify registers accessed
                        int[] callRegsRead = instruction.getRegAccess().getRegsRead();
                        int[] callRegsWrite = instruction.getRegAccess().getRegsWrite();
                        
                        assertTrue(contains(callRegsRead, X86Reg.RSP.getValue()), "RSP should be read");
                        assertTrue(contains(callRegsRead, X86Reg.RIP.getValue()), "RIP should be read");
                        assertTrue(contains(callRegsWrite, X86Reg.RSP.getValue()), "RSP should be written");
                        assertTrue(contains(callRegsWrite, X86Reg.RIP.getValue()), "RIP should be written");
                        break;
                        
                    case 5: // je 0x1019 (or similar)
                        assertEquals("je", instruction.getMnemonic());
                        
                        // Verify X86 details
                        assertEquals(X86Prefix._0, details.getPrefixs()[0]);
                        assertEquals(0x74, details.getOpcodes()[0]);
                        assertEquals(0, details.getRex());
                        assertEquals(8, details.getAddrSize());
                        assertEquals(0, details.getModrm());
                        
                        // Verify operands
                        assertEquals(1, details.getOpCount());
                        X86Operand jeOp = details.getOperands()[0];
                        assertEquals(X86OperandType.IMM, jeOp.getType());
                        assertEquals(8, jeOp.getSize());
                        
                        // Verify EFLAGS
                        X86EFlags[] eflags = details.getEflags();
                        boolean hasZfTest = false;
                        for (X86EFlags flag : eflags) {
                            if (flag.toString().contains("TEST_ZF")) {
                                hasZfTest = true;
                                break;
                            }
                        }
                        assertTrue(hasZfTest, "JE should test ZF");
                        
                        // Verify registers accessed
                        assertTrue(contains(instruction.getRegAccess().getRegsRead(), X86Reg.EFLAGS.getValue()), "RFLAGS should be read");
                        break;
                }
                
                // Update for next iteration
                offset += instruction.getSize();
                runtimeAddress += instruction.getSize();
                instructionIndex++;
            }
            
            // Verify we processed 6 instructions
            assertEquals(6, instructionIndex, "Expected 6 instructions, but processed " + instructionIndex);
            
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception occurred: " + e.getMessage());
        }
    }
    
    /**
     * Helper method to check if an array contains a specific value
     */
    private boolean contains(int[] array, int value) {
        for (int item : array) {
            if (item == value) {
                return true;
            }
        }
        return false;
    }

    private boolean containsEFlags(X86EFlags[] array, X86EFlags value) {
        for (X86EFlags item : array) {
            if (item == value) {
                return true;
            }
        }
        return false;
    }
    
    private boolean containsAllEFlags(X86EFlags[] array, X86EFlags[] values) {
        for (X86EFlags value : values) {
            if (!containsEFlags(array, value)) {
                return false;
            }
        }
        return true;
    }

    private boolean containsFpuFlags(X86FPUFlags[] array, X86FPUFlags value) {
        for (X86FPUFlags item : array) {
            if (item == value) {
                return true;
            }
        }
        return false;
    }
    
    private boolean containsAllFpuFlags(X86FPUFlags[] array, X86FPUFlags[] values) {
        for (X86FPUFlags value : values) {
            if (!containsFpuFlags(array, value)) {
                return false;
            }
        }
        return true;
    }
}
