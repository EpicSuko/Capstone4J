package com.suko.capstone4j;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.suko.capstone4j.Capstone;
import com.suko.capstone4j.CapstoneAccessType;
import com.suko.capstone4j.CapstoneArch;
import com.suko.capstone4j.CapstoneArmDetails;
import com.suko.capstone4j.CapstoneHandle;
import com.suko.capstone4j.CapstoneHandleOptions;
import com.suko.capstone4j.CapstoneInstruction;
import com.suko.capstone4j.CapstoneMode;
import com.suko.capstone4j.CapstoneOption;
import com.suko.capstone4j.CapstoneOptionValue;
import com.suko.capstone4j.CapstoneRegAccess;
import com.suko.capstone4j.CapstoneArmDetails.ArmCondCodes;
import com.suko.capstone4j.CapstoneArmDetails.ArmCpsFlagType;
import com.suko.capstone4j.CapstoneArmDetails.ArmCpsModeType;
import com.suko.capstone4j.CapstoneArmDetails.ArmOperand;
import com.suko.capstone4j.CapstoneArmDetails.ArmOperandType;
import com.suko.capstone4j.CapstoneArmDetails.ArmReg;
import com.suko.capstone4j.CapstoneArmDetails.ArmSetEndType;
import com.suko.capstone4j.CapstoneArmDetails.ArmShifter;
import com.suko.capstone4j.CapstoneArmDetails.ArmVectorDataType;

public class CapstoneArmTest {

    @BeforeAll
    public static void init() {
        try {
            Capstone.initialize();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Failed to initialize Capstone");
        }
    }

    byte[] testData1 = new byte[] {
        (byte)0x86, 0x48, 0x60, (byte)0xf4, 0x4d, 0x0f, (byte)0xe2, (byte)0xf4, (byte)0xed, (byte)0xff, 
        (byte)0xff, (byte)0xeb, 0x04, (byte)0xe0, 0x2d, (byte)0xe5, 0x00, 0x00, 0x00, 0x00, 
        (byte)0xe0, (byte)0x83, 0x22, (byte)0xe5, (byte)0xf1, 0x02, 0x03, 0x0e, 0x00, 0x00, 
        (byte)0xa0, (byte)0xe3, 0x02, 0x30, (byte)0xc1, (byte)0xe7, 0x00, 0x00, 0x53, (byte)0xe3, 
        0x00, 0x02, 0x01, (byte)0xf1, 0x05, 0x40, (byte)0xd0, (byte)0xe8, (byte)0xf4, (byte)0x80, 
        0x00, 0x00
    };

    @Test
    public void test1ArmDisassemble() {
        System.out.println("\ntest1ArmDisassemble\n");
        CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();

        try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.ARM, new CapstoneMode[] {CapstoneMode.ARM}, options)) {
            // Enable detailed instruction information
            handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);

            long runtimeAddress = 0x80001000L;
            int offset = 0;
            final int length = testData1.length;
            int instructionIndex = 0;
            
            while(offset < length) {
                int maxBytesToRead = Math.min(15, length - offset);
                byte[] subData = Arrays.copyOfRange(testData1, offset, offset + maxBytesToRead);

                CapstoneInstruction<CapstoneArmDetails> instruction = handle.disassembleInstruction(subData, runtimeAddress);

                // Verify instruction is not null
                assertNotNull(instruction, "Failed to disassemble instruction at offset " + offset);

                // Verify instruction details
                assertNotNull(instruction.getDetails(), "Instruction details should not be null");
                CapstoneArmDetails details = instruction.getDetails().getArchDetails();
                assertNotNull(details, "Architecture details should not be null");

                // Print instruction info for debugging
                System.out.printf("Instruction %d: %s %s (size: %d, addr: 0x%x)%n", 
                    instructionIndex, instruction.getMnemonic(), instruction.getOpStr(), 
                    instruction.getSize(), instruction.getAddress());

                switch(instructionIndex) {
                    case 0: // vld2.32 {d20, d21}, [r0], r6
                        assertEquals("vld2.32", instruction.getMnemonic());
                        assertEquals("{d20, d21}, [r0], r6", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify vector size
                        assertEquals(32, details.getVectorSize(), "Vector size should be 32");

                        // Verify post-indexed flag
                        assertTrue(details.isPostIndex(), "Should be post-indexed");

                        // Verify operands
                        assertEquals(3, details.getOpCount(), "Should have 3 operands");

                        // Verify first operand (d20)
                        ArmOperand operand1 = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1.getType(), "First operand should be a register");
                        assertTrue(contains(operand1.getReg(), ArmReg.D20), "First operand should be d20");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1.getAccess(), "d20 should be written to");

                        // Verify second operand (d21)
                        ArmOperand operand2 = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2.getReg(), ArmReg.D21), "Second operand should be d21");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand2.getAccess(), "d21 should be written to");

                        // Verify third operand (memory [r0], r6)
                        ArmOperand operand3 = details.getOperands()[2];
                        assertEquals(ArmOperandType.MEM, operand3.getType(), "Third operand should be memory type");
                        assertTrue(contains(operand3.getMem().getBase(), ArmReg.R0), "Base register should be r0");
                        assertTrue(contains(operand3.getMem().getIndex(), ArmReg.R6), "Index register should be r6");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand3.getAccess(), "Memory should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess = instruction.getRegAccess();
                        int[] regsRead = regAccess.getRegsRead();
                        int[] regsWrite = regAccess.getRegsWrite();

                        // Verify registers read
                        assertEquals(2, regsRead.length, "Should read from two registers");
                        assertTrue(contains(regsRead, ArmReg.R0.getValue()), "R0 should be read");
                        assertTrue(contains(regsRead, ArmReg.R6.getValue()), "R6 should be read");

                        // Verify registers written
                        assertEquals(3, regsWrite.length, "Should write to three registers");
                        assertTrue(contains(regsWrite, ArmReg.R0.getValue()), "R0 should be written");
                        assertTrue(contains(regsWrite, ArmReg.D20.getValue()), "d20 should be written");
                        assertTrue(contains(regsWrite, ArmReg.D21.getValue()), "d21 should be written");
                        break;
                    case 1: // vld4.16 {d16[], d17[], d18[], d19[]}, [r2]!
                        assertEquals("vld4.16", instruction.getMnemonic());
                        assertEquals("{d16[], d17[], d18[], d19[]}, [r2]!", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify vector size
                        assertEquals(16, details.getVectorSize(), "Vector size should be 16");
                    
                        // Verify post-indexed flag
                        // assertTrue(details.isPostIndex(), "Should be post-indexed");
                    
                        // Verify operands
                        assertEquals(5, details.getOpCount(), "Should have 5 operands");
                    
                        // Verify first operand (d16)
                        ArmOperand operand1_vld4 = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_vld4.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_vld4.getReg(), ArmReg.D16), "First operand should be d16");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_vld4.getAccess(), "d16 should be written to");
                    
                        // Verify second operand (d17)
                        ArmOperand operand2_vld4 = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_vld4.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_vld4.getReg(), ArmReg.D17), "Second operand should be d17");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand2_vld4.getAccess(), "d17 should be written to");
                    
                        // Verify third operand (d18)
                        ArmOperand operand3_vld4 = details.getOperands()[2];
                        assertEquals(ArmOperandType.REG, operand3_vld4.getType(), "Third operand should be a register");
                        assertTrue(contains(operand3_vld4.getReg(), ArmReg.D18), "Third operand should be d18");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand3_vld4.getAccess(), "d18 should be written to");
                    
                        // Verify fourth operand (d19)
                        ArmOperand operand4_vld4 = details.getOperands()[3];
                        assertEquals(ArmOperandType.REG, operand4_vld4.getType(), "Fourth operand should be a register");
                        assertTrue(contains(operand4_vld4.getReg(), ArmReg.D19), "Fourth operand should be d19");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand4_vld4.getAccess(), "d19 should be written to");
                    
                        // Verify fifth operand (memory [r2])
                        ArmOperand operand5_vld4 = details.getOperands()[4];
                        assertEquals(ArmOperandType.MEM, operand5_vld4.getType(), "Fifth operand should be memory type");
                        assertTrue(contains(operand5_vld4.getMem().getBase(), ArmReg.R2), "Base register should be r2");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand5_vld4.getAccess(), "Memory should be read");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess_vld4 = instruction.getRegAccess();
                        int[] regsRead_vld4 = regAccess_vld4.getRegsRead();
                        int[] regsWrite_vld4 = regAccess_vld4.getRegsWrite();
                    
                        // Verify registers read
                        assertEquals(1, regsRead_vld4.length, "Should read from one register");
                        assertTrue(contains(regsRead_vld4, ArmReg.R2.getValue()), "r2 should be read");
                    
                        // Verify registers written
                        assertEquals(5, regsWrite_vld4.length, "Should write to five registers");
                        assertTrue(contains(regsWrite_vld4, ArmReg.R2.getValue()), "r2 should be written");
                        assertTrue(contains(regsWrite_vld4, ArmReg.D16.getValue()), "d16 should be written");
                        assertTrue(contains(regsWrite_vld4, ArmReg.D17.getValue()), "d17 should be written");
                        assertTrue(contains(regsWrite_vld4, ArmReg.D18.getValue()), "d18 should be written");
                        assertTrue(contains(regsWrite_vld4, ArmReg.D19.getValue()), "d19 should be written");
                        break;
                    case 2: // bl 0x80000fc4
                        assertEquals("bl", instruction.getMnemonic());
                        assertEquals("0x80000fc4", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify operands
                        assertEquals(1, details.getOpCount(), "Should have 1 operand");
                    
                        // Verify immediate operand
                        ArmOperand operand_bl = details.getOperands()[0];
                        assertEquals(ArmOperandType.IMM, operand_bl.getType(), "Operand should be immediate type");
                        assertEquals(0x80000fc4L, operand_bl.getImm(), "Immediate value should be 0x80000fc4");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand_bl.getAccess(), "Immediate should be read");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess_bl = instruction.getRegAccess();
                        int[] regsRead_bl = regAccess_bl.getRegsRead();
                        int[] regsWrite_bl = regAccess_bl.getRegsWrite();
                    
                        // Verify registers read
                        assertEquals(1, regsRead_bl.length, "Should read from one register");
                        assertTrue(contains(regsRead_bl, ArmReg.R13.getValue()), "r13 should be read");
                    
                        // Verify registers written
                        assertEquals(1, regsWrite_bl.length, "Should write to one register");
                        assertTrue(contains(regsWrite_bl, ArmReg.R14.getValue()), "r14 should be written");
                        break;
                    case 3: // str lr, [sp, #-4]!
                        assertEquals("str", instruction.getMnemonic());
                        assertEquals("lr, [sp, #-4]!", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");
                    
                        // Verify first operand (r14/lr)
                        ArmOperand operand1_str = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_str.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_str.getReg(), ArmReg.R14), "First operand should be r14/lr");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_str.getAccess(), "lr should be read");
                    
                        // Verify second operand (memory [sp, #-4]!)
                        ArmOperand operand2_str = details.getOperands()[1];
                        assertEquals(ArmOperandType.MEM, operand2_str.getType(), "Second operand should be memory type");
                        assertTrue(contains(operand2_str.getMem().getBase(), ArmReg.R13), "Base register should be r13/sp");
                        assertEquals(0x4, operand2_str.getMem().getDisp(), "Displacement should be 0x4");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand2_str.getAccess(), "Memory should be written");
                        assertTrue(operand2_str.isSubtracted(), "Displacement should be subtracted");
                    
                        // Verify writeback
                        assertTrue(instruction.getDetails().isWriteback(), "Should have writeback");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess_str = instruction.getRegAccess();
                        int[] regsRead_str = regAccess_str.getRegsRead();
                        int[] regsWrite_str = regAccess_str.getRegsWrite();
                    
                        // Verify registers read
                        assertEquals(2, regsRead_str.length, "Should read from two registers");
                        assertTrue(contains(regsRead_str, ArmReg.R14.getValue()), "r14/lr should be read");
                        assertTrue(contains(regsRead_str, ArmReg.R13.getValue()), "r13/sp should be read");
                    
                        // Verify registers written
                        assertEquals(1, regsWrite_str.length, "Should write to one register");
                        assertTrue(contains(regsWrite_str, ArmReg.R13.getValue()), "r13/sp should be written");
                        break;
                    case 4: // andeq r0, r0, r0
                        assertEquals("andeq", instruction.getMnemonic());
                        assertEquals("r0, r0, r0", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify condition code
                        assertEquals(ArmCondCodes.EQ, details.getCc(), "Condition code should be EQ");
                    
                        // Verify operands
                        assertEquals(3, details.getOpCount(), "Should have 3 operands");
                    
                        // Verify first operand (r0 - destination)
                        ArmOperand operand1_and = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_and.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_and.getReg(), ArmReg.R0), "First operand should be r0");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_and.getAccess(), "r0 should be written to");
                    
                        // Verify second operand (r0 - first source)
                        ArmOperand operand2_and = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_and.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_and.getReg(), ArmReg.R0), "Second operand should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_and.getAccess(), "r0 should be read");
                    
                        // Verify third operand (r0 - second source)
                        ArmOperand operand3_and = details.getOperands()[2];
                        assertEquals(ArmOperandType.REG, operand3_and.getType(), "Third operand should be a register");
                        assertTrue(contains(operand3_and.getReg(), ArmReg.R0), "Third operand should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand3_and.getAccess(), "r0 should be read");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess_and = instruction.getRegAccess();
                        int[] regsRead_and = regAccess_and.getRegsRead();
                        int[] regsWrite_and = regAccess_and.getRegsWrite();
                    
                        // Verify registers read
                        assertEquals(2, regsRead_and.length, "Should read from two registers");
                        assertTrue(contains(regsRead_and, ArmReg.CPSR.getValue()), "CPSR should be read");
                        assertTrue(contains(regsRead_and, ArmReg.R0.getValue()), "r0 should be read");
                    
                        // Verify registers written
                        assertEquals(1, regsWrite_and.length, "Should write to one register");
                        assertTrue(contains(regsWrite_and, ArmReg.R0.getValue()), "r0 should be written");
                        break;
                    case 5: // str r8, [r2, #-0x3e0]!
                        assertEquals("str", instruction.getMnemonic());
                        assertEquals("r8, [r2, #-0x3e0]!", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");
                    
                        // Verify first operand (r8)
                        ArmOperand operand5_str1 = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand5_str1.getType(), "First operand should be a register");
                        assertTrue(contains(operand5_str1.getReg(), ArmReg.R8), "First operand should be r8");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand5_str1.getAccess(), "r8 should be read");
                    
                        // Verify second operand (memory [r2, #-0x3e0]!)
                        ArmOperand operand5_str2 = details.getOperands()[1];
                        assertEquals(ArmOperandType.MEM, operand5_str2.getType(), "Second operand should be memory type");
                        assertTrue(contains(operand5_str2.getMem().getBase(), ArmReg.R2), "Base register should be r2");
                        assertEquals(0x3e0, operand5_str2.getMem().getDisp(), "Displacement should be 0x3e0");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand5_str2.getAccess(), "Memory should be written");
                        assertTrue(operand5_str2.isSubtracted(), "Displacement should be subtracted");
                    
                        // Verify writeback
                        assertTrue(instruction.getDetails().isWriteback(), "Should have writeback");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess5_str = instruction.getRegAccess();
                        int[] regsRead5_str = regAccess5_str.getRegsRead();
                        int[] regsWrite5_str = regAccess5_str.getRegsWrite();
                    
                        // Verify registers read
                        assertEquals(2, regsRead5_str.length, "Should read from two registers");
                        assertTrue(contains(regsRead5_str, ArmReg.R8.getValue()), "r8 should be read");
                        assertTrue(contains(regsRead5_str, ArmReg.R2.getValue()), "r2 should be read");
                    
                        // Verify registers written
                        assertEquals(1, regsWrite5_str.length, "Should write to one register");
                        assertTrue(contains(regsWrite5_str, ArmReg.R2.getValue()), "r2 should be written");
                        break;
                    case 6: // mcreq p2, #0, r0, c3, c1, #7
                        assertEquals("mcreq", instruction.getMnemonic());
                        assertEquals("p2, #0, r0, c3, c1, #7", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify condition code
                        assertEquals(ArmCondCodes.EQ, details.getCc(), "Condition code should be EQ");
                    
                        // Verify operands
                        assertEquals(6, details.getOpCount(), "Should have 6 operands");
                    
                        // Verify first operand (p2)
                        ArmOperand operand1_mcr = details.getOperands()[0];
                        assertEquals(ArmOperandType.PIMM, operand1_mcr.getType(), "First operand should be a coprocessor immediate");
                        assertEquals(2, operand1_mcr.getImm(), "First operand should be p2");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_mcr.getAccess(), "p2 should be read");
                    
                        // Verify second operand (#0)
                        ArmOperand operand2_mcr = details.getOperands()[1];
                        assertEquals(ArmOperandType.IMM, operand2_mcr.getType(), "Second operand should be immediate");
                        assertEquals(0, operand2_mcr.getImm(), "Second operand should be 0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_mcr.getAccess(), "Immediate should be read");
                    
                        // Verify third operand (r0)
                        ArmOperand operand3_mcr = details.getOperands()[2];
                        assertEquals(ArmOperandType.REG, operand3_mcr.getType(), "Third operand should be a register");
                        assertTrue(contains(operand3_mcr.getReg(), ArmReg.R0), "Third operand should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand3_mcr.getAccess(), "r0 should be read");
                    
                        // Verify fourth operand (c3)
                        ArmOperand operand4_mcr = details.getOperands()[3];
                        assertEquals(ArmOperandType.CIMM, operand4_mcr.getType(), "Fourth operand should be a coprocessor register");
                        assertEquals(3, operand4_mcr.getImm(), "Fourth operand should be c3");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand4_mcr.getAccess(), "c3 should be read");
                    
                        // Verify fifth operand (c1)
                        ArmOperand operand5_mcr = details.getOperands()[4];
                        assertEquals(ArmOperandType.CIMM, operand5_mcr.getType(), "Fifth operand should be a coprocessor register");
                        assertEquals(1, operand5_mcr.getImm(), "Fifth operand should be c1");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand5_mcr.getAccess(), "c1 should be read");
                    
                        // Verify sixth operand (#7)
                        ArmOperand operand6_mcr = details.getOperands()[5];
                        assertEquals(ArmOperandType.IMM, operand6_mcr.getType(), "Sixth operand should be immediate");
                        assertEquals(7, operand6_mcr.getImm(), "Sixth operand should be 7");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand6_mcr.getAccess(), "Immediate should be read");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess_mcr = instruction.getRegAccess();
                        int[] regsRead_mcr = regAccess_mcr.getRegsRead();
                    
                        // Verify registers read
                        assertEquals(2, regsRead_mcr.length, "Should read from two registers");
                        assertTrue(contains(regsRead_mcr, ArmReg.CPSR.getValue()), "CPSR should be read");
                        assertTrue(contains(regsRead_mcr, ArmReg.R0.getValue()), "r0 should be read");
                        break;
                    case 7: // mov r0, #0
                        assertEquals("mov", instruction.getMnemonic());
                        assertEquals("r0, #0", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");
                    
                        // Verify first operand (r0)
                        ArmOperand operand1_mov = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_mov.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_mov.getReg(), ArmReg.R0), "First operand should be r0");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_mov.getAccess(), "r0 should be written to");
                    
                        // Verify second operand (immediate #0)
                        ArmOperand operand2_mov = details.getOperands()[1];
                        assertEquals(ArmOperandType.IMM, operand2_mov.getType(), "Second operand should be immediate");
                        assertEquals(0, operand2_mov.getImm(), "Immediate value should be 0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_mov.getAccess(), "Immediate should be read");
                    
                        // Verify registers written
                        CapstoneRegAccess regAccess_mov = instruction.getRegAccess();
                        int[] regsWrite_mov = regAccess_mov.getRegsWrite();
                    
                        // Verify registers written
                        assertEquals(1, regsWrite_mov.length, "Should write to one register");
                        assertTrue(contains(regsWrite_mov, ArmReg.R0.getValue()), "r0 should be written");
                        break;
                    case 8: // strb r3, [r1, r2]
                        assertEquals("strb", instruction.getMnemonic());
                        assertEquals("r3, [r1, r2]", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");
                    
                        // Verify first operand (r3)
                        ArmOperand operand1_strb = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_strb.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_strb.getReg(), ArmReg.R3), "First operand should be r3");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_strb.getAccess(), "r3 should be read");
                    
                        // Verify second operand (memory [r1, r2])
                        ArmOperand operand2_strb = details.getOperands()[1];
                        assertEquals(ArmOperandType.MEM, operand2_strb.getType(), "Second operand should be memory type");
                        assertTrue(contains(operand2_strb.getMem().getBase(), ArmReg.R1), "Base register should be r1");
                        assertTrue(contains(operand2_strb.getMem().getIndex(), ArmReg.R2), "Index register should be r2");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand2_strb.getAccess(), "Memory should be written");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess_strb = instruction.getRegAccess();
                        int[] regsRead_strb = regAccess_strb.getRegsRead();
                    
                        // Verify registers read
                        assertEquals(3, regsRead_strb.length, "Should read from three registers");
                        assertTrue(contains(regsRead_strb, ArmReg.R3.getValue()), "r3 should be read");
                        assertTrue(contains(regsRead_strb, ArmReg.R1.getValue()), "r1 should be read");
                        assertTrue(contains(regsRead_strb, ArmReg.R2.getValue()), "r2 should be read");
                        break;
                    case 9: // cmp r3, #0
                        assertEquals("cmp", instruction.getMnemonic());
                        assertEquals("r3, #0", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify update flags
                        assertTrue(details.isUpdateFlags(), "Should update flags");
                    
                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");
                    
                        // Verify first operand (r3)
                        ArmOperand operand1_cmp = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_cmp.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_cmp.getReg(), ArmReg.R3), "First operand should be r3");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_cmp.getAccess(), "r3 should be read");
                    
                        // Verify second operand (immediate #0)
                        ArmOperand operand2_cmp = details.getOperands()[1];
                        assertEquals(ArmOperandType.IMM, operand2_cmp.getType(), "Second operand should be immediate");
                        assertEquals(0, operand2_cmp.getImm(), "Immediate value should be 0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_cmp.getAccess(), "Immediate should be read");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess_cmp = instruction.getRegAccess();
                        int[] regsRead_cmp = regAccess_cmp.getRegsRead();
                        int[] regsWrite_cmp = regAccess_cmp.getRegsWrite();
                    
                        // Verify registers read
                        assertEquals(1, regsRead_cmp.length, "Should read from one register");
                        assertTrue(contains(regsRead_cmp, ArmReg.R3.getValue()), "r3 should be read");
                    
                        // Verify registers written
                        assertEquals(1, regsWrite_cmp.length, "Should write to one register");
                        assertTrue(contains(regsWrite_cmp, ArmReg.CPSR.getValue()), "CPSR should be written");
                        break;
                    case 10: // setend be
                        assertEquals("setend", instruction.getMnemonic());
                        assertEquals("be", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify operands
                        assertEquals(1, details.getOpCount(), "Should have 1 operand");
                    
                        // Verify setend operand
                        ArmOperand operand_setend = details.getOperands()[0];
                        assertEquals(ArmOperandType.SETEND, operand_setend.getType(), "Operand should be SETEND type");
                        assertEquals(ArmSetEndType.BE, operand_setend.getSetEnd(), "SETEND mode should be BE (Big Endian)");
                        break;
                    case 11: // ldm r0, {r0, r2, lr} ^
                        assertEquals("ldm", instruction.getMnemonic());
                        assertEquals("r0, {r0, r2, lr} ^", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify operands
                        assertEquals(4, details.getOpCount(), "Should have 4 operands");
                    
                        // Verify first operand (r0 - base register)
                        ArmOperand operand1_ldm = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_ldm.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_ldm.getReg(), ArmReg.R0), "First operand should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_ldm.getAccess(), "r0 should be read");
                    
                        // Verify second operand (r0 - destination)
                        ArmOperand operand2_ldm = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_ldm.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_ldm.getReg(), ArmReg.R0), "Second operand should be r0");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand2_ldm.getAccess(), "r0 should be written to");
                    
                        // Verify third operand (r2)
                        ArmOperand operand3_ldm = details.getOperands()[2];
                        assertEquals(ArmOperandType.REG, operand3_ldm.getType(), "Third operand should be a register");
                        assertTrue(contains(operand3_ldm.getReg(), ArmReg.R2), "Third operand should be r2");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand3_ldm.getAccess(), "r2 should be written to");
                    
                        // Verify fourth operand (r14/lr)
                        ArmOperand operand4_ldm = details.getOperands()[3];
                        assertEquals(ArmOperandType.REG, operand4_ldm.getType(), "Fourth operand should be a register");
                        assertTrue(contains(operand4_ldm.getReg(), ArmReg.R14), "Fourth operand should be r14/lr");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand4_ldm.getAccess(), "lr should be written to");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess_ldm = instruction.getRegAccess();
                        int[] regsRead_ldm = regAccess_ldm.getRegsRead();
                        int[] regsWrite_ldm = regAccess_ldm.getRegsWrite();
                    
                        // Verify registers read
                        assertEquals(1, regsRead_ldm.length, "Should read from one register");
                        assertTrue(contains(regsRead_ldm, ArmReg.R0.getValue()), "r0 should be read");
                    
                        // Verify registers written
                        assertEquals(3, regsWrite_ldm.length, "Should write to three registers");
                        assertTrue(contains(regsWrite_ldm, ArmReg.R0.getValue()), "r0 should be written");
                        assertTrue(contains(regsWrite_ldm, ArmReg.R2.getValue()), "r2 should be written");
                        assertTrue(contains(regsWrite_ldm, ArmReg.R14.getValue()), "r14/lr should be written");
                        break;
                    case 12: // strdeq r8, r9, [r0], -r4
                        assertEquals("strdeq", instruction.getMnemonic());
                        assertEquals("r8, r9, [r0], -r4", instruction.getOpStr());
                    
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                    
                        // Verify condition code
                        assertEquals(ArmCondCodes.EQ, details.getCc(), "Condition code should be EQ");
                    
                        // Verify post-indexed flag
                        assertTrue(details.isPostIndex(), "Should be post-indexed");
                    
                        // Verify writeback
                        assertTrue(instruction.getDetails().isWriteback(), "Should have writeback");
                    
                        // Verify operands
                        assertEquals(3, details.getOpCount(), "Should have 3 operands");
                    
                        // Verify first operand (r8)
                        ArmOperand operand1_strd = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_strd.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_strd.getReg(), ArmReg.R8), "First operand should be r8");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_strd.getAccess(), "r8 should be read");
                    
                        // Verify second operand (r9)
                        ArmOperand operand2_strd = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_strd.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_strd.getReg(), ArmReg.R9), "Second operand should be r9");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_strd.getAccess(), "r9 should be read");
                    
                        // Verify third operand (memory [r0], -r4)
                        ArmOperand operand3_strd = details.getOperands()[2];
                        assertEquals(ArmOperandType.MEM, operand3_strd.getType(), "Third operand should be memory type");
                        assertTrue(contains(operand3_strd.getMem().getBase(), ArmReg.R0), "Base register should be r0");
                        assertTrue(contains(operand3_strd.getMem().getIndex(), ArmReg.R4), "Index register should be r4");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand3_strd.getAccess(), "Memory should be written");
                        assertTrue(operand3_strd.isSubtracted(), "Index should be subtracted");
                    
                        // Verify registers accessed
                        CapstoneRegAccess regAccess_strd = instruction.getRegAccess();
                        int[] regsRead_strd = regAccess_strd.getRegsRead();
                        int[] regsWrite_strd = regAccess_strd.getRegsWrite();
                    
                        // Verify registers read
                        assertEquals(5, regsRead_strd.length, "Should read from five registers");
                        assertTrue(contains(regsRead_strd, ArmReg.CPSR.getValue()), "CPSR should be read");
                        assertTrue(contains(regsRead_strd, ArmReg.R8.getValue()), "r8 should be read");
                        assertTrue(contains(regsRead_strd, ArmReg.R9.getValue()), "r9 should be read");
                        assertTrue(contains(regsRead_strd, ArmReg.R0.getValue()), "r0 should be read");
                        assertTrue(contains(regsRead_strd, ArmReg.R4.getValue()), "r4 should be read");
                    
                        // Verify registers written
                        assertEquals(1, regsWrite_strd.length, "Should write to one register");
                        assertTrue(contains(regsWrite_strd, ArmReg.R0.getValue()), "r0 should be written");
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
            fail("Failed to disassemble instruction");
        }
    }

    byte[] testData2 = new byte[] {
        0x60, (byte)0xf9, 0x1f, 0x04, (byte)0xe0, (byte)0xf9, 0x4f, 0x07, 0x70, 0x47, 
        0x00, (byte)0xf0, 0x10, (byte)0xe8, (byte)0xeb, 0x46, (byte)0x83, (byte)0xb0, (byte)0xc9, 0x68, 
        0x1f, (byte)0xb1, 0x30, (byte)0xbf, (byte)0xaf, (byte)0xf3, 0x20, (byte)0x84, 0x52, (byte)0xf8, 
        0x23, (byte)0xf0
    };

    @Test
    public void test2ArmDisassemble() {
        System.out.println("\ntest2ArmDisassemble\n");
        CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();

        try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.ARM, new CapstoneMode[] {CapstoneMode.THUMB}, options)) {
            // Enable detailed instruction information
            handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);

            long runtimeAddress = 0x80001000L;
            int offset = 0;
            final int length = testData2.length;
            int instructionIndex = 0;
            
            while(offset < length) {
                int maxBytesToRead = Math.min(15, length - offset);
                byte[] subData = Arrays.copyOfRange(testData2, offset, offset + maxBytesToRead);

                CapstoneInstruction<CapstoneArmDetails> instruction = handle.disassembleInstruction(subData, runtimeAddress);

                // Verify instruction is not null
                assertNotNull(instruction, "Failed to disassemble instruction at offset " + offset);

                // Verify instruction details
                assertNotNull(instruction.getDetails(), "Instruction details should not be null");
                CapstoneArmDetails details = instruction.getDetails().getArchDetails();
                assertNotNull(details, "Architecture details should not be null");

                // Print instruction info for debugging
                System.out.printf("Instruction %d: %s %s (size: %d, addr: 0x%x)%n", 
                    instructionIndex, instruction.getMnemonic(), instruction.getOpStr(), 
                    instruction.getSize(), instruction.getAddress());

                switch(instructionIndex) {
                    case 0: // vld3.8 {d16, d17, d18}, [r0:0x40]
                        assertEquals("vld3.8", instruction.getMnemonic());
                        assertEquals("{d16, d17, d18}, [r0:0x40]", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify vector size
                        assertEquals(8, details.getVectorSize(), "Vector size should be 8");

                        // Verify operands
                        assertEquals(4, details.getOpCount(), "Should have 4 operands");

                        // Verify first operand (d16)
                        ArmOperand operand1_vld3 = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_vld3.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_vld3.getReg(), ArmReg.D16), "First operand should be d16");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_vld3.getAccess(), "d16 should be written to");

                        // Verify second operand (d17)
                        ArmOperand operand2_vld3 = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_vld3.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_vld3.getReg(), ArmReg.D17), "Second operand should be d17");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand2_vld3.getAccess(), "d17 should be written to");

                        // Verify third operand (d18)
                        ArmOperand operand3_vld3 = details.getOperands()[2];
                        assertEquals(ArmOperandType.REG, operand3_vld3.getType(), "Third operand should be a register");
                        assertTrue(contains(operand3_vld3.getReg(), ArmReg.D18), "Third operand should be d18");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand3_vld3.getAccess(), "d18 should be written to");

                        // Verify fourth operand (memory [r0:0x40])
                        ArmOperand operand4_vld3 = details.getOperands()[3];
                        assertEquals(ArmOperandType.MEM, operand4_vld3.getType(), "Fourth operand should be memory type");
                        assertTrue(contains(operand4_vld3.getMem().getBase(), ArmReg.R0), "Base register should be r0");
                        assertEquals(0x40, operand4_vld3.getMem().getAlign(), "Alignment should be 0x40");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand4_vld3.getAccess(), "Memory should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_vld3 = instruction.getRegAccess();
                        int[] regsRead_vld3 = regAccess_vld3.getRegsRead();
                        int[] regsWrite_vld3 = regAccess_vld3.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_vld3.length, "Should read from one register");
                        assertTrue(contains(regsRead_vld3, ArmReg.R0.getValue()), "R0 should be read");

                        // Verify registers written
                        assertEquals(3, regsWrite_vld3.length, "Should write to three registers");
                        assertTrue(contains(regsWrite_vld3, ArmReg.D16.getValue()), "d16 should be written");
                        assertTrue(contains(regsWrite_vld3, ArmReg.D17.getValue()), "d17 should be written");
                        assertTrue(contains(regsWrite_vld3, ArmReg.D18.getValue()), "d18 should be written");
                        break;
                    case 1: // vld4.16 {d16[1], d17[1], d18[1], d19[1]}, [r0]
                        assertEquals("vld4.16", instruction.getMnemonic());
                        assertEquals("{d16[1], d17[1], d18[1], d19[1]}, [r0]", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify vector size
                        assertEquals(16, details.getVectorSize(), "Vector size should be 16");

                        // Verify operands
                        assertEquals(5, details.getOpCount(), "Should have 5 operands");

                        // Verify first operand (d16[1])
                        ArmOperand operand1_vld4 = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_vld4.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_vld4.getReg(), ArmReg.D16), "First operand should be d16");
                        assertEquals(1, operand1_vld4.getNeonLane(), "Neon lane should be 1");
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_vld4.getAccess(), "d16 should be read and written");

                        // Verify second operand (d17[1])
                        ArmOperand operand2_vld4 = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_vld4.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_vld4.getReg(), ArmReg.D17), "Second operand should be d17");
                        assertEquals(1, operand2_vld4.getNeonLane(), "Neon lane should be 1");
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand2_vld4.getAccess(), "d17 should be read and written");

                        // Verify third operand (d18[1])
                        ArmOperand operand3_vld4 = details.getOperands()[2];
                        assertEquals(ArmOperandType.REG, operand3_vld4.getType(), "Third operand should be a register");
                        assertTrue(contains(operand3_vld4.getReg(), ArmReg.D18), "Third operand should be d18");
                        assertEquals(1, operand3_vld4.getNeonLane(), "Neon lane should be 1");
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand3_vld4.getAccess(), "d18 should be read and written");

                        // Verify fourth operand (d19[1])
                        ArmOperand operand4_vld4 = details.getOperands()[3];
                        assertEquals(ArmOperandType.REG, operand4_vld4.getType(), "Fourth operand should be a register");
                        assertTrue(contains(operand4_vld4.getReg(), ArmReg.D19), "Fourth operand should be d19");
                        assertEquals(1, operand4_vld4.getNeonLane(), "Neon lane should be 1");
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand4_vld4.getAccess(), "d19 should be read and written");

                        // Verify fifth operand (memory [r0])
                        ArmOperand operand5_vld4 = details.getOperands()[4];
                        assertEquals(ArmOperandType.MEM, operand5_vld4.getType(), "Fifth operand should be memory type");
                        assertTrue(contains(operand5_vld4.getMem().getBase(), ArmReg.R0), "Base register should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand5_vld4.getAccess(), "Memory should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_vld4 = instruction.getRegAccess();
                        int[] regsRead_vld4 = regAccess_vld4.getRegsRead();
                        int[] regsWrite_vld4 = regAccess_vld4.getRegsWrite();

                        // Verify registers read
                        assertEquals(5, regsRead_vld4.length, "Should read from five registers");
                        assertTrue(contains(regsRead_vld4, ArmReg.D16.getValue()), "d16 should be read");
                        assertTrue(contains(regsRead_vld4, ArmReg.D17.getValue()), "d17 should be read");
                        assertTrue(contains(regsRead_vld4, ArmReg.D18.getValue()), "d18 should be read");
                        assertTrue(contains(regsRead_vld4, ArmReg.D19.getValue()), "d19 should be read");
                        assertTrue(contains(regsRead_vld4, ArmReg.R0.getValue()), "r0 should be read");

                        // Verify registers written
                        assertEquals(4, regsWrite_vld4.length, "Should write to four registers");
                        assertTrue(contains(regsWrite_vld4, ArmReg.D16.getValue()), "d16 should be written");
                        assertTrue(contains(regsWrite_vld4, ArmReg.D17.getValue()), "d17 should be written");
                        assertTrue(contains(regsWrite_vld4, ArmReg.D18.getValue()), "d18 should be written");
                        assertTrue(contains(regsWrite_vld4, ArmReg.D19.getValue()), "d19 should be written");
                        break;
                    case 2: // bx lr
                        assertEquals("bx", instruction.getMnemonic());
                        assertEquals("lr", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(1, details.getOpCount(), "Should have 1 operand");

                        // Verify register operand (r14/lr)
                        ArmOperand operand_bx = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand_bx.getType(), "Operand should be a register");
                        assertTrue(contains(operand_bx.getReg(), ArmReg.R14), "Operand should be r14/lr");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand_bx.getAccess(), "lr should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_bx = instruction.getRegAccess();
                        int[] regsRead_bx = regAccess_bx.getRegsRead();

                        // Verify registers read
                        assertEquals(1, regsRead_bx.length, "Should read from one register");
                        assertTrue(contains(regsRead_bx, ArmReg.R14.getValue()), "r14/lr should be read");
                        break;
                    case 3: // blx 0x8000102c
                        assertEquals("blx", instruction.getMnemonic());
                        assertEquals("0x8000102c", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(1, details.getOpCount(), "Should have 1 operand");

                        // Verify immediate operand
                        ArmOperand operand_blx = details.getOperands()[0];
                        assertEquals(ArmOperandType.IMM, operand_blx.getType(), "Operand should be immediate type");
                        assertEquals(0x8000102cL, operand_blx.getImm(), "Immediate value should be 0x8000102c");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand_blx.getAccess(), "Immediate should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_blx = instruction.getRegAccess();
                        int[] regsRead_blx = regAccess_blx.getRegsRead();
                        int[] regsWrite_blx = regAccess_blx.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_blx.length, "Should read from one register");
                        assertTrue(contains(regsRead_blx, ArmReg.R13.getValue()), "r13 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_blx.length, "Should write to one register");
                        assertTrue(contains(regsWrite_blx, ArmReg.R14.getValue()), "r14 should be written");
                        break;
                    case 4: // mov r11, sp
                        assertEquals("mov", instruction.getMnemonic());
                        assertEquals("r11, sp", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r11)
                        ArmOperand operand1_mov = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_mov.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_mov.getReg(), ArmReg.R11), "First operand should be r11");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_mov.getAccess(), "r11 should be written to");

                        // Verify second operand (r13/sp)
                        ArmOperand operand2_mov = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_mov.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_mov.getReg(), ArmReg.R13), "Second operand should be r13/sp");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_mov.getAccess(), "r13 should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_mov = instruction.getRegAccess();
                        int[] regsRead_mov = regAccess_mov.getRegsRead();
                        int[] regsWrite_mov = regAccess_mov.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_mov.length, "Should read from one register");
                        assertTrue(contains(regsRead_mov, ArmReg.R13.getValue()), "r13 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_mov.length, "Should write to one register");
                        assertTrue(contains(regsWrite_mov, ArmReg.R11.getValue()), "r11 should be written");
                        break;
                    case 5: // sub sp, #0xc
                        assertEquals("sub", instruction.getMnemonic());
                        assertEquals("sp, #0xc", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r13/sp)
                        ArmOperand operand1_sub = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_sub.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_sub.getReg(), ArmReg.R13), "First operand should be r13/sp");
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_sub.getAccess(), "r13 should be read and written");

                        // Verify second operand (immediate #0xc)
                        ArmOperand operand2_sub = details.getOperands()[1];
                        assertEquals(ArmOperandType.IMM, operand2_sub.getType(), "Second operand should be immediate");
                        assertEquals(0xc, operand2_sub.getImm(), "Immediate value should be 0xc");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_sub.getAccess(), "Immediate should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_sub = instruction.getRegAccess();
                        int[] regsRead_sub = regAccess_sub.getRegsRead();
                        int[] regsWrite_sub = regAccess_sub.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_sub.length, "Should read from one register");
                        assertTrue(contains(regsRead_sub, ArmReg.R13.getValue()), "r13 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_sub.length, "Should write to one register");
                        assertTrue(contains(regsWrite_sub, ArmReg.R13.getValue()), "r13 should be written");
                        break;
                    case 6: // ldr r1, [r1, #0xc]
                        assertEquals("ldr", instruction.getMnemonic());
                        assertEquals("r1, [r1, #0xc]", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r1)
                        ArmOperand operand1_ldr = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_ldr.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_ldr.getReg(), ArmReg.R1), "First operand should be r1");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_ldr.getAccess(), "r1 should be written to");

                        // Verify second operand (memory [r1, #0xc])
                        ArmOperand operand2_ldr = details.getOperands()[1];
                        assertEquals(ArmOperandType.MEM, operand2_ldr.getType(), "Second operand should be memory type");
                        assertTrue(contains(operand2_ldr.getMem().getBase(), ArmReg.R1), "Base register should be r1");
                        assertEquals(0xc, operand2_ldr.getMem().getDisp(), "Displacement should be 0xc");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_ldr.getAccess(), "Memory should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_ldr = instruction.getRegAccess();
                        int[] regsRead_ldr = regAccess_ldr.getRegsRead();
                        int[] regsWrite_ldr = regAccess_ldr.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_ldr.length, "Should read from one register");
                        assertTrue(contains(regsRead_ldr, ArmReg.R1.getValue()), "r1 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_ldr.length, "Should write to one register");
                        assertTrue(contains(regsWrite_ldr, ArmReg.R1.getValue()), "r1 should be written");
                        break;
                    case 7: // cbz r7, 0x8000101e
                        assertEquals("cbz", instruction.getMnemonic());
                        assertEquals("r7, 0x8000101e", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r7)
                        ArmOperand operand1_cbz = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_cbz.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_cbz.getReg(), ArmReg.R7), "First operand should be r7");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand1_cbz.getAccess(), "r7 should be read");

                        // Verify second operand (immediate 0x8000101e)
                        ArmOperand operand2_cbz = details.getOperands()[1];
                        assertEquals(ArmOperandType.IMM, operand2_cbz.getType(), "Second operand should be immediate");
                        assertEquals(0x8000101eL, operand2_cbz.getImm(), "Immediate value should be 0x8000101e");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_cbz.getAccess(), "Immediate should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_cbz = instruction.getRegAccess();
                        int[] regsRead_cbz = regAccess_cbz.getRegsRead();

                        // Verify registers read
                        assertEquals(1, regsRead_cbz.length, "Should read from one register");
                        assertTrue(contains(regsRead_cbz, ArmReg.R7.getValue()), "r7 should be read");
                        break;
                    case 8: // wfi
                        assertEquals("wfi", instruction.getMnemonic());
                        break;
                    case 9: // cpsie.w f
                        assertEquals("cpsie.w", instruction.getMnemonic());
                        assertEquals("f", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify CPS mode (IE = Interrupt Enable)
                        assertEquals(ArmCpsModeType.IE, details.getCpsMode(), "CPS mode should be IE (1)");

                        // Verify CPS flag (F = FIQ)
                        assertEquals(ArmCpsFlagType.F, details.getCpsFlag(), "CPS flag should be F (2)");
                        break;
                    case 10: // ldr.w pc, [r2, r3, lsl #2]
                        assertEquals("ldr.w", instruction.getMnemonic());
                        assertEquals("pc, [r2, r3, lsl #2]", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r15/pc)
                        ArmOperand operand1_ldr_pc = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_ldr_pc.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_ldr_pc.getReg(), ArmReg.R15), "First operand should be r15/pc");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_ldr_pc.getAccess(), "pc should be written to");

                        // Verify second operand (memory [r2, r3, lsl #2])
                        ArmOperand operand2_ldr_pc = details.getOperands()[1];
                        assertEquals(ArmOperandType.MEM, operand2_ldr_pc.getType(), "Second operand should be memory type");
                        assertTrue(contains(operand2_ldr_pc.getMem().getBase(), ArmReg.R2), "Base register should be r2");
                        assertTrue(contains(operand2_ldr_pc.getMem().getIndex(), ArmReg.R3), "Index register should be r3");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_ldr_pc = instruction.getRegAccess();
                        int[] regsRead_ldr_pc = regAccess_ldr_pc.getRegsRead();
                        int[] regsWrite_ldr_pc = regAccess_ldr_pc.getRegsWrite();

                        // Verify registers read
                        assertEquals(2, regsRead_ldr_pc.length, "Should read from two registers");
                        assertTrue(contains(regsRead_ldr_pc, ArmReg.R2.getValue()), "r2 should be read");
                        assertTrue(contains(regsRead_ldr_pc, ArmReg.R3.getValue()), "r3 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_ldr_pc.length, "Should write to one register");
                        assertTrue(contains(regsWrite_ldr_pc, ArmReg.R15.getValue()), "r15/pc should be written");
                        break;
                }

                // Update for next iteration
                offset += instruction.getSize();
                runtimeAddress += instruction.getSize();
                instructionIndex++;
            }

            // Verify we processed 11 instructions
            assertEquals(11, instructionIndex, "Expected 11 instructions, but processed " + instructionIndex);

        } catch (Exception e) {
            e.printStackTrace();
            fail("Failed to disassemble instruction");
        }
    }

    byte[] testData3 = new byte[] {
        (byte)0xd1, (byte)0xe8, 0x00, (byte)0xf0, (byte)0xf0, 0x24, 0x04, 0x07, 0x1f, 0x3c, 
        (byte)0xf2, (byte)0xc0, 0x00, 0x00, 0x4f, (byte)0xf0, 0x00, 0x01, 0x46, 0x6c
    };

    @Test
    public void test3ArmDisassemble() {
        System.out.println("\ntest3ArmDisassemble\n");
        CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();

        try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.ARM, new CapstoneMode[] {CapstoneMode.THUMB}, options)) {
            // Enable detailed instruction information
            handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);

            long runtimeAddress = 0x80001000L;
            int offset = 0;
            final int length = testData3.length;
            int instructionIndex = 0;
            
            while(offset < length) {
                int maxBytesToRead = Math.min(15, length - offset);
                byte[] subData = Arrays.copyOfRange(testData3, offset, offset + maxBytesToRead);

                CapstoneInstruction<CapstoneArmDetails> instruction = handle.disassembleInstruction(subData, runtimeAddress);

                // Verify instruction is not null
                assertNotNull(instruction, "Failed to disassemble instruction at offset " + offset);

                // Verify instruction details
                assertNotNull(instruction.getDetails(), "Instruction details should not be null");
                CapstoneArmDetails details = instruction.getDetails().getArchDetails();
                assertNotNull(details, "Architecture details should not be null");

                // Print instruction info for debugging
                System.out.printf("Instruction %d: %s %s (size: %d, addr: 0x%x)%n", 
                    instructionIndex, instruction.getMnemonic(), instruction.getOpStr(), 
                    instruction.getSize(), instruction.getAddress());

                switch(instructionIndex) {
                    case 0: // tbb [r1, r0]
                        assertEquals("tbb", instruction.getMnemonic());
                        assertEquals("[r1, r0]", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(1, details.getOpCount(), "Should have 1 operand");

                        // Verify memory operand
                        ArmOperand operand = details.getOperands()[0];
                        assertEquals(ArmOperandType.MEM, operand.getType(), "Operand should be memory type");
                        assertTrue(contains(operand.getMem().getBase(), ArmReg.R1), "Base register should be r1");
                        assertTrue(contains(operand.getMem().getIndex(), ArmReg.R0), "Index register should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand.getAccess(), "Memory should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess = instruction.getRegAccess();
                        int[] regsRead = regAccess.getRegsRead();

                        // Verify registers read
                        assertEquals(2, regsRead.length, "Should read from two registers");
                        assertTrue(contains(regsRead, ArmReg.R1.getValue()), "R1 should be read");
                        assertTrue(contains(regsRead, ArmReg.R0.getValue()), "R0 should be read");
                        break;
                    case 1: // movs r4, #0xf0
                        assertEquals("movs", instruction.getMnemonic());
                        assertEquals("r4, #0xf0", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify update flags
                        assertTrue(details.isUpdateFlags(), "Should update flags");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r4)
                        ArmOperand operand1_movs = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_movs.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_movs.getReg(), ArmReg.R4), "First operand should be r4");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_movs.getAccess(), "R4 should be written to");

                        // Verify second operand (immediate #0xf0)
                        ArmOperand operand2_movs = details.getOperands()[1];
                        assertEquals(ArmOperandType.IMM, operand2_movs.getType(), "Second operand should be immediate");
                        assertEquals(0xf0, operand2_movs.getImm(), "Immediate value should be 0xf0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_movs.getAccess(), "Immediate should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_movs = instruction.getRegAccess();
                        int[] regsWrite_movs = regAccess_movs.getRegsWrite();

                        // Verify registers written
                        assertEquals(2, regsWrite_movs.length, "Should write to two registers");
                        assertTrue(contains(regsWrite_movs, ArmReg.CPSR.getValue()), "CPSR should be written");
                        assertTrue(contains(regsWrite_movs, ArmReg.R4.getValue()), "R4 should be written");
                        break;
                    case 2: // lsls r4, r0, #0x1c
                        assertEquals("lsls", instruction.getMnemonic());
                        assertEquals("r4, r0, #0x1c", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify update flags
                        assertTrue(details.isUpdateFlags(), "Should update flags");

                        // Verify operands
                        assertEquals(3, details.getOpCount(), "Should have 3 operands");

                        // Verify first operand (r4)
                        ArmOperand operand1_lsls = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_lsls.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_lsls.getReg(), ArmReg.R4), "First operand should be r4");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_lsls.getAccess(), "R4 should be written to");

                        // Verify second operand (r0)
                        ArmOperand operand2_lsls = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_lsls.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_lsls.getReg(), ArmReg.R0), "Second operand should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_lsls.getAccess(), "R0 should be read");

                        // Verify third operand (immediate #0x1c)
                        ArmOperand operand3_lsls = details.getOperands()[2];
                        assertEquals(ArmOperandType.IMM, operand3_lsls.getType(), "Third operand should be immediate");
                        assertEquals(0x1c, operand3_lsls.getImm(), "Immediate value should be 0x1c");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand3_lsls.getAccess(), "Immediate should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_lsls = instruction.getRegAccess();
                        int[] regsRead_lsls = regAccess_lsls.getRegsRead();
                        int[] regsWrite_lsls = regAccess_lsls.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_lsls.length, "Should read from one register");
                        assertTrue(contains(regsRead_lsls, ArmReg.R0.getValue()), "R0 should be read");

                        // Verify registers written
                        assertEquals(2, regsWrite_lsls.length, "Should write to two registers");
                        assertTrue(contains(regsWrite_lsls, ArmReg.CPSR.getValue()), "CPSR should be written");
                        assertTrue(contains(regsWrite_lsls, ArmReg.R4.getValue()), "R4 should be written");
                        break;
                    case 3: // subs r4, #0x1f
                        assertEquals("subs", instruction.getMnemonic());
                        assertEquals("r4, #0x1f", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify update flags
                        assertTrue(details.isUpdateFlags(), "Should update flags");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r4)
                        ArmOperand operand1_subs = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_subs.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_subs.getReg(), ArmReg.R4), "First operand should be r4");  
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_subs.getAccess(), "R4 should be read and written");

                        // Verify second operand (immediate #0x1f)
                        ArmOperand operand2_subs = details.getOperands()[1];
                        assertEquals(ArmOperandType.IMM, operand2_subs.getType(), "Second operand should be immediate");
                        assertEquals(0x1f, operand2_subs.getImm(), "Immediate value should be 0x1f");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_subs.getAccess(), "Immediate should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_subs = instruction.getRegAccess();
                        int[] regsRead_subs = regAccess_subs.getRegsRead();
                        int[] regsWrite_subs = regAccess_subs.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_subs.length, "Should read from one register");
                        assertTrue(contains(regsRead_subs, ArmReg.R4.getValue()), "R4 should be read");

                        // Verify registers written
                        assertEquals(2, regsWrite_subs.length, "Should write to two registers");
                        assertTrue(contains(regsWrite_subs, ArmReg.CPSR.getValue()), "CPSR should be written");
                        assertTrue(contains(regsWrite_subs, ArmReg.R4.getValue()), "R4 should be written");
                        break;
                    case 4: // stm r0!, {r1, r4, r5, r6, r7}
                        assertEquals("stm", instruction.getMnemonic());
                        assertEquals("r0!, {r1, r4, r5, r6, r7}", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(6, details.getOpCount(), "Should have 6 operands");

                        // Verify first operand (r0 with writeback)
                        ArmOperand operand1_stm = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_stm.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_stm.getReg(), ArmReg.R0), "First operand should be r0");
                        assertEquals(CapstoneAccessType.READ_WRITE.getValue(), operand1_stm.getAccess(), "R0 should be read and written");

                        // Verify second operand (r1)
                        ArmOperand operand2_stm = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_stm.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_stm.getReg(), ArmReg.R1), "Second operand should be r1");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_stm.getAccess(), "R1 should be read");

                        // Verify third operand (r4)
                        ArmOperand operand3_stm = details.getOperands()[2];
                        assertEquals(ArmOperandType.REG, operand3_stm.getType(), "Third operand should be a register");
                        assertTrue(contains(operand3_stm.getReg(), ArmReg.R4), "Third operand should be r4");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand3_stm.getAccess(), "R4 should be read");

                        // Verify fourth operand (r5)
                        ArmOperand operand4_stm = details.getOperands()[3];
                        assertEquals(ArmOperandType.REG, operand4_stm.getType(), "Fourth operand should be a register");
                        assertTrue(contains(operand4_stm.getReg(), ArmReg.R5), "Fourth operand should be r5");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand4_stm.getAccess(), "R5 should be read");

                        // Verify fifth operand (r6)
                        ArmOperand operand5_stm = details.getOperands()[4];
                        assertEquals(ArmOperandType.REG, operand5_stm.getType(), "Fifth operand should be a register");
                        assertTrue(contains(operand5_stm.getReg(), ArmReg.R6), "Fifth operand should be r6");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand5_stm.getAccess(), "R6 should be read");

                        // Verify sixth operand (r7)
                        ArmOperand operand6_stm = details.getOperands()[5];
                        assertEquals(ArmOperandType.REG, operand6_stm.getType(), "Sixth operand should be a register");
                        assertTrue(contains(operand6_stm.getReg(), ArmReg.R7), "Sixth operand should be r7");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand6_stm.getAccess(), "R7 should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_stm = instruction.getRegAccess();
                        int[] regsRead_stm = regAccess_stm.getRegsRead();
                        int[] regsWrite_stm = regAccess_stm.getRegsWrite();

                        // Verify registers read
                        assertEquals(6, regsRead_stm.length, "Should read from six registers");
                        assertTrue(contains(regsRead_stm, ArmReg.R0.getValue()), "R0 should be read");
                        assertTrue(contains(regsRead_stm, ArmReg.R1.getValue()), "R1 should be read");
                        assertTrue(contains(regsRead_stm, ArmReg.R4.getValue()), "R4 should be read");
                        assertTrue(contains(regsRead_stm, ArmReg.R5.getValue()), "R5 should be read");
                        assertTrue(contains(regsRead_stm, ArmReg.R6.getValue()), "R6 should be read");
                        assertTrue(contains(regsRead_stm, ArmReg.R7.getValue()), "R7 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_stm.length, "Should write to one register");
                        assertTrue(contains(regsWrite_stm, ArmReg.R0.getValue()), "R0 should be written");
                        break;
                    case 5: // movs r0, r0
                        assertEquals("movs", instruction.getMnemonic());
                        assertEquals("r0, r0", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify update flags
                        assertTrue(details.isUpdateFlags(), "Should update flags");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r0)
                        ArmOperand operand1_movs2 = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_movs2.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_movs2.getReg(), ArmReg.R0), "First operand should be r0");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_movs2.getAccess(), "R0 should be written to");

                        // Verify second operand (r0)
                        ArmOperand operand2_movs2 = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_movs2.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_movs2.getReg(), ArmReg.R0), "Second operand should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_movs2.getAccess(), "R0 should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_movs2 = instruction.getRegAccess();
                        int[] regsRead_movs2 = regAccess_movs2.getRegsRead();
                        int[] regsWrite_movs2 = regAccess_movs2.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_movs2.length, "Should read from one register");
                        assertTrue(contains(regsRead_movs2, ArmReg.R0.getValue()), "R0 should be read");

                        // Verify registers written
                        assertEquals(2, regsWrite_movs2.length, "Should write to two registers");
                        assertTrue(contains(regsWrite_movs2, ArmReg.CPSR.getValue()), "CPSR should be written");
                        assertTrue(contains(regsWrite_movs2, ArmReg.R0.getValue()), "R0 should be written");
                        break;
                    case 6: // mov.w r1, #0
                        assertEquals("mov.w", instruction.getMnemonic());
                        assertEquals("r1, #0", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r1)
                        ArmOperand operand1_movw = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_movw.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_movw.getReg(), ArmReg.R1), "First operand should be r1");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_movw.getAccess(), "R1 should be written to");

                        // Verify second operand (immediate #0)
                        ArmOperand operand2_movw = details.getOperands()[1];
                        assertEquals(ArmOperandType.IMM, operand2_movw.getType(), "Second operand should be immediate");
                        assertEquals(0, operand2_movw.getImm(), "Immediate value should be 0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_movw.getAccess(), "Immediate should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_movw = instruction.getRegAccess();
                        int[] regsWrite_movw = regAccess_movw.getRegsWrite();

                        // Verify registers written
                        assertEquals(1, regsWrite_movw.length, "Should write to one register");
                        assertTrue(contains(regsWrite_movw, ArmReg.R1.getValue()), "R1 should be written");
                        break;
                    case 7: // ldr r6, [r0, #0x44]
                        assertEquals("ldr", instruction.getMnemonic());
                        assertEquals("r6, [r0, #0x44]", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r6)
                        ArmOperand operand1_ldr = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_ldr.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_ldr.getReg(), ArmReg.R6), "First operand should be r6");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_ldr.getAccess(), "R6 should be written to");

                        // Verify second operand (memory [r0, #0x44])
                        ArmOperand operand2_ldr = details.getOperands()[1];
                        assertEquals(ArmOperandType.MEM, operand2_ldr.getType(), "Second operand should be memory type");
                        assertTrue(contains(operand2_ldr.getMem().getBase(), ArmReg.R0), "Base register should be r0");
                        assertEquals(0x44, operand2_ldr.getMem().getDisp(), "Displacement should be 0x44");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_ldr.getAccess(), "Memory should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_ldr = instruction.getRegAccess();
                        int[] regsRead_ldr = regAccess_ldr.getRegsRead();
                        int[] regsWrite_ldr = regAccess_ldr.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_ldr.length, "Should read from one register");
                        assertTrue(contains(regsRead_ldr, ArmReg.R0.getValue()), "R0 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_ldr.length, "Should write to one register");
                        assertTrue(contains(regsWrite_ldr, ArmReg.R6.getValue()), "R6 should be written");
                        break;
                }

                // Update for next iteration
                offset += instruction.getSize();
                runtimeAddress += instruction.getSize();
                instructionIndex++;
            }

            // Verify we processed 8 instructions
            assertEquals(8, instructionIndex, "Expected 8 instructions, but processed " + instructionIndex);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    byte[] testData4 = new byte[] {
        0x4f, (byte)0xf0, 0x00, 0x01, (byte)0xbd, (byte)0xe8, 0x00, (byte)0x88, (byte)0xd1, (byte)0xe8, 
        0x00, (byte)0xf0, 0x18, (byte)0xbf, (byte)0xad, (byte)0xbf, (byte)0xf3, (byte)0xff, 0x0b, 0x0c, 
        (byte)0x86, (byte)0xf3, 0x00, (byte)0x89, (byte)0x80, (byte)0xf3, 0x00, (byte)0x8c, 0x4f, (byte)0xfa, 
        (byte)0x99, (byte)0xf6, (byte)0xd0, (byte)0xff, (byte)0xa2, 0x01
    };

    @Test
    public void test4ArmDisassemble() {
        System.out.println("\ntest4ArmDisassemble\n");
        CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();

        try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.ARM, new CapstoneMode[] {CapstoneMode.THUMB}, options)) {
            // Enable detailed instruction information
            handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);

            long runtimeAddress = 0x80001000L;
            int offset = 0;
            final int length = testData4.length;
            int instructionIndex = 0;
            
            while(offset < length) {
                int maxBytesToRead = Math.min(15, length - offset);
                byte[] subData = Arrays.copyOfRange(testData4, offset, offset + maxBytesToRead);

                CapstoneInstruction<CapstoneArmDetails> instruction = handle.disassembleInstruction(subData, runtimeAddress);

                // Verify instruction is not null
                assertNotNull(instruction, "Failed to disassemble instruction at offset " + offset);

                // Verify instruction details
                assertNotNull(instruction.getDetails(), "Instruction details should not be null");
                CapstoneArmDetails details = instruction.getDetails().getArchDetails();
                assertNotNull(details, "Architecture details should not be null");

                // Print instruction info for debugging
                System.out.printf("Instruction %d: %s %s (size: %d, addr: 0x%x)%n", 
                    instructionIndex, instruction.getMnemonic(), instruction.getOpStr(), 
                    instruction.getSize(), instruction.getAddress());

                switch(instructionIndex) {
                    case 0: // mov.w r1, #0
                        assertEquals("mov.w", instruction.getMnemonic());
                        assertEquals("r1, #0", instruction.getOpStr());
                
                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");
                
                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");
                
                        // Verify first operand (r1)
                        ArmOperand operand1 = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1.getType(), "First operand should be a register");
                        assertTrue(contains(operand1.getReg(), ArmReg.R1), "First operand should be r1");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1.getAccess(), "R1 should be written to");
                
                        // Verify second operand (immediate #0)
                        ArmOperand operand2 = details.getOperands()[1];
                        assertEquals(ArmOperandType.IMM, operand2.getType(), "Second operand should be immediate");
                        assertEquals(0, operand2.getImm(), "Immediate value should be 0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2.getAccess(), "Immediate should be read");
                
                        // Verify registers written
                        CapstoneRegAccess regAccess = instruction.getRegAccess();
                        int[] regsWrite = regAccess.getRegsWrite();
                        assertEquals(1, regsWrite.length, "Should write to one register");
                        assertTrue(contains(regsWrite, ArmReg.R1.getValue()), "R1 should be written");
                        break;
                    case 1: // pop.w {r11, pc}
                        assertEquals("pop.w", instruction.getMnemonic());
                        assertEquals("{r11, pc}", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r11)
                        ArmOperand operand1_pop = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_pop.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_pop.getReg(), ArmReg.R11), "First operand should be r11");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_pop.getAccess(), "R11 should be written to");

                        // Verify second operand (pc/r15)
                        ArmOperand operand2_pop = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_pop.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_pop.getReg(), ArmReg.R15), "Second operand should be r15/pc");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand2_pop.getAccess(), "R15 should be written to");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_pop = instruction.getRegAccess();
                        int[] regsRead_pop = regAccess_pop.getRegsRead();
                        int[] regsWrite_pop = regAccess_pop.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_pop.length, "Should read from one register");
                        assertTrue(contains(regsRead_pop, ArmReg.R13.getValue()), "R13 should be read");

                        // Verify registers written
                        assertEquals(3, regsWrite_pop.length, "Should write to three registers");
                        assertTrue(contains(regsWrite_pop, ArmReg.R13.getValue()), "R13 should be written");
                        assertTrue(contains(regsWrite_pop, ArmReg.R11.getValue()), "R11 should be written");
                        assertTrue(contains(regsWrite_pop, ArmReg.R15.getValue()), "R15 should be written");
                        break;
                    case 2: // tbb [r1, r0]
                        assertEquals("tbb", instruction.getMnemonic());
                        assertEquals("[r1, r0]", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify operands
                        assertEquals(1, details.getOpCount(), "Should have 1 operand");

                        // Verify memory operand
                        ArmOperand operand_tbb = details.getOperands()[0];
                        assertEquals(ArmOperandType.MEM, operand_tbb.getType(), "Operand should be memory type");
                        assertTrue(contains(operand_tbb.getMem().getBase(), ArmReg.R1), "Base register should be r1");
                        assertTrue(contains(operand_tbb.getMem().getIndex(), ArmReg.R0), "Index register should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand_tbb.getAccess(), "Memory should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_tbb = instruction.getRegAccess();
                        int[] regsRead_tbb = regAccess_tbb.getRegsRead();

                        // Verify registers read
                        assertEquals(2, regsRead_tbb.length, "Should read from two registers");
                        assertTrue(contains(regsRead_tbb, ArmReg.R1.getValue()), "R1 should be read");
                        assertTrue(contains(regsRead_tbb, ArmReg.R0.getValue()), "R0 should be read");
                        break;
                    case 3: // it ne
                        assertEquals("it", instruction.getMnemonic());
                        assertEquals("ne", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify condition code
                        assertEquals(ArmCondCodes.NE, details.getCc(), "Condition code should be NE");

                        // Verify predicate mask
                        assertEquals(0x1, details.getPredMask(), "Predicate mask should be 0x1");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_it = instruction.getRegAccess();
                        int[] regsRead_it = regAccess_it.getRegsRead();
                        int[] regsWrite_it = regAccess_it.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_it.length, "Should read from one register");
                        assertTrue(contains(regsRead_it, ArmReg.CPSR.getValue()), "CPSR should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_it.length, "Should write to one register");
                        assertTrue(contains(regsWrite_it, ArmReg.ITSTATE.getValue()), "ITSTATE should be written");
                        break;
                    case 4: // iteet ge
                        assertEquals("iteet", instruction.getMnemonic());
                        assertEquals("ge", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify condition code
                        assertEquals(ArmCondCodes.GE, details.getCc(), "Condition code should be GE");

                        // Verify predicate mask (0xd = 1101b, indicating T-T-E-T pattern)
                        assertEquals(0xd, details.getPredMask(), "Predicate mask should be 0xd");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_iteet = instruction.getRegAccess();
                        int[] regsRead_iteet = regAccess_iteet.getRegsRead();
                        int[] regsWrite_iteet = regAccess_iteet.getRegsWrite();

                        // Verify registers read
                        assertEquals(1, regsRead_iteet.length, "Should read from one register");
                        assertTrue(contains(regsRead_iteet, ArmReg.CPSR.getValue()), "CPSR should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_iteet.length, "Should write to one register");
                        assertTrue(contains(regsWrite_iteet, ArmReg.ITSTATE.getValue()), "ITSTATE should be written");
                        break;
                    case 5: // vdupge.8 d16, d11[1]
                        assertEquals("vdupge.8", instruction.getMnemonic());
                        assertEquals("d16, d11[1]", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify condition code
                        assertEquals(ArmCondCodes.GE, details.getCc(), "Condition code should be GE");

                        // Verify vector size
                        assertEquals(8, details.getVectorSize(), "Vector size should be 8");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (d16)
                        ArmOperand operand1_vdup = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_vdup.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_vdup.getReg(), ArmReg.D16), "First operand should be d16");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_vdup.getAccess(), "d16 should be written to");

                        // Verify second operand (d11[1])
                        ArmOperand operand2_vdup = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_vdup.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_vdup.getReg(), ArmReg.D11), "Second operand should be d11");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_vdup.getAccess(), "d11 should be read");
                        assertEquals(1, operand2_vdup.getVectorIndex(), "Vector index should be 1");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_vdup = instruction.getRegAccess();
                        int[] regsRead_vdup = regAccess_vdup.getRegsRead();
                        int[] regsWrite_vdup = regAccess_vdup.getRegsWrite();

                        // Verify registers read
                        assertEquals(2, regsRead_vdup.length, "Should read from two registers");
                        assertTrue(contains(regsRead_vdup, ArmReg.CPSR.getValue()), "CPSR should be read");
                        assertTrue(contains(regsRead_vdup, ArmReg.D11.getValue()), "d11 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_vdup.length, "Should write to one register");
                        assertTrue(contains(regsWrite_vdup, ArmReg.D16.getValue()), "d16 should be written");
                        break;
                    case 6: // msrlt cpsr_fc, r6
                        assertEquals("msrlt", instruction.getMnemonic());
                        assertEquals("cpsr_fc, r6", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify condition code
                        assertEquals(ArmCondCodes.LT, details.getCc(), "Condition code should be LT");

                        // Verify update flags
                        assertTrue(details.isUpdateFlags(), "Should update flags");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (cpsr_fc)
                        ArmOperand operand1_msr = details.getOperands()[0];
                        assertEquals(ArmOperandType.CPSR, operand1_msr.getType(), "First operand should be CPSR type");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_msr.getAccess(), "CPSR should be written to");
                        assertEquals(9, operand1_msr.getSysOp().getMsrMask(), "MSR mask should be 9");

                        // Verify second operand (r6)
                        ArmOperand operand2_msr = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_msr.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_msr.getReg(), ArmReg.R6), "Second operand should be r6");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_msr.getAccess(), "r6 should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_msr = instruction.getRegAccess();
                        int[] regsRead_msr = regAccess_msr.getRegsRead();
                        int[] regsWrite_msr = regAccess_msr.getRegsWrite();

                        // Verify registers read
                        assertEquals(2, regsRead_msr.length, "Should read from two registers");
                        assertTrue(contains(regsRead_msr, ArmReg.CPSR.getValue()), "CPSR should be read");
                        assertTrue(contains(regsRead_msr, ArmReg.R6.getValue()), "r6 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_msr.length, "Should write to one register");
                        assertTrue(contains(regsWrite_msr, ArmReg.CPSR.getValue()), "CPSR should be written");
                        break;
                    case 7: // msrlt apsr_nzcvqg, r0
                        assertEquals("msrlt", instruction.getMnemonic());
                        assertEquals("apsr_nzcvqg, r0", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify condition code
                        assertEquals(ArmCondCodes.LT, details.getCc(), "Condition code should be LT");

                        // Verify update flags
                        assertTrue(details.isUpdateFlags(), "Should update flags");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (apsr_nzcvqg)
                        ArmOperand operand1_msr2 = details.getOperands()[0];
                        assertEquals(ArmOperandType.SYSREG, operand1_msr2.getType(), "First operand should be system register type");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_msr2.getAccess(), "APSR should be written to");
                        assertEquals(12, operand1_msr2.getSysOp().getMsrMask(), "MSR mask should be 12");

                        // Verify second operand (r0)
                        ArmOperand operand2_msr2 = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_msr2.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_msr2.getReg(), ArmReg.R0), "Second operand should be r0");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_msr2.getAccess(), "r0 should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_msr2 = instruction.getRegAccess();
                        int[] regsRead_msr2 = regAccess_msr2.getRegsRead();
                        int[] regsWrite_msr2 = regAccess_msr2.getRegsWrite();

                        // Verify registers read
                        assertEquals(2, regsRead_msr2.length, "Should read from two registers");
                        assertTrue(contains(regsRead_msr2, ArmReg.CPSR.getValue()), "CPSR should be read");
                        assertTrue(contains(regsRead_msr2, ArmReg.R0.getValue()), "r0 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_msr2.length, "Should write to one register");
                        assertTrue(contains(regsWrite_msr2, ArmReg.CPSR.getValue()), "CPSR should be written");
                        break;
                    case 8: // sxtbge.w r6, r9, ror #8
                        assertEquals("sxtbge.w", instruction.getMnemonic());
                        assertEquals("r6, r9, ror #8", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify condition code
                        assertEquals(ArmCondCodes.GE, details.getCc(), "Condition code should be GE");

                        // Verify operands
                        assertEquals(2, details.getOpCount(), "Should have 2 operands");

                        // Verify first operand (r6)
                        ArmOperand operand1_sxtb = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_sxtb.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_sxtb.getReg(), ArmReg.R6), "First operand should be r6");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_sxtb.getAccess(), "r6 should be written to");

                        // Verify second operand (r9 with rotate)
                        ArmOperand operand2_sxtb = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_sxtb.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_sxtb.getReg(), ArmReg.R9), "Second operand should be r9");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_sxtb.getAccess(), "r9 should be read");
                        assertEquals(8, operand2_sxtb.getShift().getValue(), "Shift value should be 8");
                        assertEquals(ArmShifter.ROR, operand2_sxtb.getShift().getType(), "Shift type should be ROR");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_sxtb = instruction.getRegAccess();
                        int[] regsRead_sxtb = regAccess_sxtb.getRegsRead();
                        int[] regsWrite_sxtb = regAccess_sxtb.getRegsWrite();

                        // Verify registers read
                        assertEquals(2, regsRead_sxtb.length, "Should read from two registers");
                        assertTrue(contains(regsRead_sxtb, ArmReg.CPSR.getValue()), "CPSR should be read");
                        assertTrue(contains(regsRead_sxtb, ArmReg.R9.getValue()), "r9 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_sxtb.length, "Should write to one register");
                        assertTrue(contains(regsWrite_sxtb, ArmReg.R6.getValue()), "r6 should be written");
                        break;
                    case 9: // vaddw.u16 q8, q8, d18
                        assertEquals("vaddw.u16", instruction.getMnemonic());
                        assertEquals("q8, q8, d18", instruction.getOpStr());

                        // Verify instruction details
                        assertNotNull(details, "Architecture details should not be null");

                        // Verify vector data type
                        assertEquals(ArmVectorDataType.U16, details.getVectorDataType(), "Vector data type should be U16");

                        // Verify operands
                        assertEquals(3, details.getOpCount(), "Should have 3 operands");

                        // Verify first operand (q8)
                        ArmOperand operand1_vadd = details.getOperands()[0];
                        assertEquals(ArmOperandType.REG, operand1_vadd.getType(), "First operand should be a register");
                        assertTrue(contains(operand1_vadd.getReg(), ArmReg.Q8), "First operand should be q8");
                        assertEquals(CapstoneAccessType.WRITE.getValue(), operand1_vadd.getAccess(), "q8 should be written to");

                        // Verify second operand (q8)
                        ArmOperand operand2_vadd = details.getOperands()[1];
                        assertEquals(ArmOperandType.REG, operand2_vadd.getType(), "Second operand should be a register");
                        assertTrue(contains(operand2_vadd.getReg(), ArmReg.Q8), "Second operand should be q8");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand2_vadd.getAccess(), "q8 should be read");

                        // Verify third operand (d18)
                        ArmOperand operand3_vadd = details.getOperands()[2];
                        assertEquals(ArmOperandType.REG, operand3_vadd.getType(), "Third operand should be a register");
                        assertTrue(contains(operand3_vadd.getReg(), ArmReg.D18), "Third operand should be d18");
                        assertEquals(CapstoneAccessType.READ.getValue(), operand3_vadd.getAccess(), "d18 should be read");

                        // Verify registers accessed
                        CapstoneRegAccess regAccess_vadd = instruction.getRegAccess();
                        int[] regsRead_vadd = regAccess_vadd.getRegsRead();
                        int[] regsWrite_vadd = regAccess_vadd.getRegsWrite();

                        // Verify registers read
                        assertEquals(2, regsRead_vadd.length, "Should read from two registers");
                        assertTrue(contains(regsRead_vadd, ArmReg.Q8.getValue()), "q8 should be read");
                        assertTrue(contains(regsRead_vadd, ArmReg.D18.getValue()), "d18 should be read");

                        // Verify registers written
                        assertEquals(1, regsWrite_vadd.length, "Should write to one register");
                        assertTrue(contains(regsWrite_vadd, ArmReg.Q8.getValue()), "q8 should be written");
                        break;
                }

                // Update for next iteration
                offset += instruction.getSize();
                runtimeAddress += instruction.getSize();
                instructionIndex++;
            }

            // Verify we processed 10 instructions
            assertEquals(10, instructionIndex, "Expected 10 instructions, but processed " + instructionIndex);

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected exception: " + e.getMessage());
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

    private boolean contains(ArmReg[] array, ArmReg value) {
        for (ArmReg item : array) {
            if (item == value) {
                return true;
            }
        }
        return false;
    }
}
