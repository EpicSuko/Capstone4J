package com.suko.capstone4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.suko.capstone4j.Capstone;
import com.suko.capstone4j.CapstoneAArch64Details;
import com.suko.capstone4j.CapstoneArch;
import com.suko.capstone4j.CapstoneHandle;
import com.suko.capstone4j.CapstoneHandleOptions;
import com.suko.capstone4j.CapstoneInstruction;
import com.suko.capstone4j.CapstoneMode;
import com.suko.capstone4j.CapstoneOption;
import com.suko.capstone4j.CapstoneOptionValue;
import com.suko.capstone4j.CapstoneRegAccess;
import com.suko.capstone4j.CapstoneAArch64Details.AArch64CondCode;
import com.suko.capstone4j.CapstoneAArch64Details.AArch64Extender;
import com.suko.capstone4j.CapstoneAArch64Details.AArch64OperandType;
import com.suko.capstone4j.CapstoneAArch64Details.AArch64Reg;
import com.suko.capstone4j.CapstoneAArch64Details.AArch64Shifter;
import com.suko.capstone4j.CapstoneAArch64Details.AArch64VectorLayout;

public class CapstoneAArch64Test {

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
		0x09, 0x00, 0x38, (byte)0xd5, (byte)0xbf, 0x40, 0x00, (byte)0xd5, 0x0c, 0x05, 
		0x13, (byte)0xd5, 0x20, 0x50, 0x02, 0x0e, 0x20, (byte)0xe4, 0x3d, 0x0f, 
		0x00, 0x18, (byte)0xa0, 0x5f, (byte)0xa2, 0x00, (byte)0xae, (byte)0x9e, (byte)0x9f, 0x37, 
		0x03, (byte)0xd5, (byte)0xbf, 0x33, 0x03, (byte)0xd5, (byte)0xdf, 0x3f, 0x03, (byte)0xd5, 
		0x21, 0x7c, 0x02, (byte)0x9b, 0x21, 0x7c, 0x00, 0x53, 0x00, 0x40, 
		0x21, 0x4b, (byte)0xe1, 0x0b, 0x40, (byte)0xb9, 0x20, 0x04, (byte)0x81, (byte)0xda, 
		0x20, 0x08, 0x02, (byte)0x8b, 0x10, 0x5b, (byte)0xe8, 0x3c, (byte)0xfd, 0x7b, 
		(byte)0xba, (byte)0xa9, (byte)0xfd, (byte)0xc7, 0x43, (byte)0xf8
    };

	@Test
	public void test1AArch64Disassemble() {
		System.out.println("\ntest1AArch64Disassemble\n");
		CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();

        try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.AARCH64, new CapstoneMode[] {CapstoneMode.ARM}, options)) {
            // Enable detailed instruction information
            handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);

            long runtimeAddress = 0x2cL;
            int offset = 0;
            final int length = testData1.length;
            int instructionIndex = 0;
            
            while(offset < length) {
                int maxBytesToRead = Math.min(15, length - offset);
                byte[] subData = Arrays.copyOfRange(testData1, offset, offset + maxBytesToRead);

                CapstoneInstruction<CapstoneAArch64Details> instruction = handle.disassembleInstruction(subData, runtimeAddress);

                // Verify instruction is not null
                assertNotNull(instruction, "Failed to disassemble instruction at offset " + offset);

                // Verify instruction details
                assertNotNull(instruction.getDetails(), "Instruction details should not be null");
                CapstoneAArch64Details details = instruction.getDetails().getArchDetails();
                assertNotNull(details, "Architecture details should not be null");

                // Print instruction info for debugging
                System.out.printf("Instruction %d: %s %s (size: %d, addr: 0x%x)%n", 
                    instructionIndex, instruction.getMnemonic(), instruction.getOpStr(), 
                    instruction.getSize(), instruction.getAddress());

				switch(instructionIndex) {
                    case 0: // mrs x9, MIDR_EL1
                        assertEquals("mrs", instruction.getMnemonic(), "Mnemonic should be 'mrs'");
                        assertEquals("x9, MIDR_EL1", instruction.getOpStr(), "Operands should be 'x9, MIDR_EL1'");
                        
                        // Verify operands
                        assertEquals(2, details.getOperands().length, "Should have 2 operands");
                        
                        // First operand (x9)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.X9),"First operand should be x9 register");
                            
                        // Second operand (MIDR_EL1)
                        assertEquals(AArch64OperandType.SYSREG, details.getOperands()[1].getType(),"Second operand should be system register type");
                        assertEquals(AArch64OperandType.REG_MRS, details.getOperands()[1].getSys().getSubType(),"Second operand should be MRS subtype");
                        assertEquals(0xc000L, details.getOperands()[1].getSys().getReg().getRawVal(),"System register raw value should be 0xc000");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        CapstoneRegAccess regAccess = instruction.getRegAccess();
                            
                        // Verify written registers
                        assertNotNull(regAccess.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess.getRegsWrite(), AArch64Reg.X9),"Should write to x9 register");
                        break;
                    case 1: // msr SPSel, #0
                        assertEquals("msr", instruction.getMnemonic(), "Mnemonic should be 'msr'");
                        assertEquals("SPSel, #0", instruction.getOpStr(), "Operands should be 'SPSel, #0'");
                        
                        // Verify operands
                        assertEquals(2, details.getOperands().length, "Should have 2 operands");
                        
                        // First operand (SPSel)
                        assertEquals(AArch64OperandType.SYSALIAS, details.getOperands()[0].getType(),"First operand should be system alias type");
                        assertEquals(AArch64OperandType.PSTATEIMM0_15, details.getOperands()[0].getSys().getSubType(),"First operand should have PSTATEIMM subtype");
                        assertEquals(0x5L, details.getOperands()[0].getSys().getAlias().getRawVal(),"System register raw value should be 0x5");
                            
                        // Second operand (#0)
                        assertEquals(AArch64OperandType.IMM, details.getOperands()[1].getType(),"Second operand should be immediate type");
                        assertEquals(0, details.getOperands()[1].getImm(),"Immediate value should be 0");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");
                        break;
                    case 2: // msr DBGDTRTX_EL0, x12
                        assertEquals("msr", instruction.getMnemonic(), "Mnemonic should be 'msr'");
                        assertEquals("DBGDTRTX_EL0, x12", instruction.getOpStr(), "Operands should be 'DBGDTRTX_EL0, x12'");
                        
                        // Verify operands
                        assertEquals(2, details.getOperands().length, "Should have 2 operands");
                        
                        // First operand (DBGDTRTX_EL0)
                        assertEquals(AArch64OperandType.SYSREG, details.getOperands()[0].getType(),"First operand should be system register type");
                        assertEquals(AArch64OperandType.REG_MSR, details.getOperands()[0].getSys().getSubType(),"First operand should have MSR subtype");
                        assertEquals(0x9828L, details.getOperands()[0].getSys().getReg().getRawVal(),"System register raw value should be 0x9828");
                            
                        // Second operand (x12)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.X12),"Second operand should be x12 register");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify register access
                        CapstoneRegAccess regAccess_2 = instruction.getRegAccess();
                        assertNotNull(regAccess_2.getRegsRead(), "Read registers array should not be null");
                        assertEquals(1, regAccess_2.getRegsRead().length, "Should read from 1 register");
                        assertTrue(contains(regAccess_2.getRegsRead(), AArch64Reg.X12),"Should read from x12 register");
                        break;
                    case 3: // tbx v0.8b, { v1.16b, v2.16b, v3.16b }, v2.8b
                        assertEquals("tbx", instruction.getMnemonic(), "Mnemonic should be 'tbx'");
                        assertEquals("v0.8b, { v1.16b, v2.16b, v3.16b }, v2.8b", instruction.getOpStr(), "Operands should be 'v0.8b, { v1.16b, v2.16b, v3.16b }, v2.8b'");
                        
                        // Verify operands
                        assertEquals(5, details.getOperands().length, "Should have 5 operands");
                        
                        // First operand (v0.8b)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.D0),"First operand should be d0 register");
                        assertTrue(details.getOperands()[0].isVReg(),"First operand should be a vector register");
                        assertEquals(AArch64VectorLayout._8B, details.getOperands()[0].getVas(),"First operand should have 8B vector arrangement");
                            
                        // Second operand (v1.16b)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.Q1),"Second operand should be q1 register");
                        assertTrue(details.getOperands()[1].isVReg(),"Second operand should be a vector register");
                        assertEquals(AArch64VectorLayout._16B, details.getOperands()[1].getVas(),"Second operand should have 16B vector arrangement");
                            
                        // Third operand (v2.16b)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[2].getType(),"Third operand should be register type");
                        assertTrue(contains(details.getOperands()[2].getReg(), AArch64Reg.Q2),"Third operand should be q2 register");
                        assertTrue(details.getOperands()[2].isVReg(),"Third operand should be a vector register");
                        assertEquals(AArch64VectorLayout._16B, details.getOperands()[2].getVas(),"Third operand should have 16B vector arrangement");
                            
                        // Fourth operand (v3.16b)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[3].getType(),"Fourth operand should be register type");
                        assertTrue(contains(details.getOperands()[3].getReg(), AArch64Reg.Q3),"Fourth operand should be q3 register");
                        assertTrue(details.getOperands()[3].isVReg(),"Fourth operand should be a vector register");
                        assertEquals(AArch64VectorLayout._16B, details.getOperands()[3].getVas(),"Fourth operand should have 16B vector arrangement");
                            
                        // Fifth operand (v2.8b)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[4].getType(),
                            "Fifth operand should be register type");
                        assertTrue(contains(details.getOperands()[4].getReg(), AArch64Reg.D2),
                            "Fifth operand should be d2 register");
                        assertTrue(details.getOperands()[4].isVReg(),
                            "Fifth operand should be a vector register");
                        assertEquals(AArch64VectorLayout._8B, details.getOperands()[4].getVas(),
                            "Fifth operand should have 8B vector arrangement");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),
                            "Condition code should be invalid");

                        // Verify writeback
                        assertTrue(instruction.getDetails().isWriteback(), "Instruction should have writeback");

                        // Verify register access
                        CapstoneRegAccess regAccess_3 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_3.getRegsRead(), "Read registers array should not be null");
                        assertEquals(5, regAccess_3.getRegsRead().length, "Should read from 5 registers");
                        assertTrue(contains(regAccess_3.getRegsRead(), AArch64Reg.D0), "Should read from d0 register");
                        assertTrue(contains(regAccess_3.getRegsRead(), AArch64Reg.Q1), "Should read from q1 register");
                        assertTrue(contains(regAccess_3.getRegsRead(), AArch64Reg.Q2), "Should read from q2 register");
                        assertTrue(contains(regAccess_3.getRegsRead(), AArch64Reg.Q3), "Should read from q3 register");
                        assertTrue(contains(regAccess_3.getRegsRead(), AArch64Reg.D2), "Should read from d2 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_3.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_3.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_3.getRegsWrite(), AArch64Reg.D0), "Should write to d0 register");
                        break;
                    case 4: // scvtf v0.2s, v1.2s, #3
                        assertEquals("scvtf", instruction.getMnemonic(), "Mnemonic should be 'scvtf'");
                        assertEquals("v0.2s, v1.2s, #3", instruction.getOpStr(), "Operands should be 'v0.2s, v1.2s, #3'");
                        
                        // Verify operands
                        assertEquals(3, details.getOperands().length, "Should have 3 operands");
                        
                        // First operand (v0.2s)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.D0),"First operand should be d0 register");
                        assertTrue(details.getOperands()[0].isVReg(),"First operand should be a vector register");
                        assertEquals(AArch64VectorLayout._2S, details.getOperands()[0].getVas(),"First operand should have 2S vector arrangement");
                            
                        // Second operand (v1.2s)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.D1),"Second operand should be d1 register");
                        assertTrue(details.getOperands()[1].isVReg(),"Second operand should be a vector register");
                        assertEquals(AArch64VectorLayout._2S, details.getOperands()[1].getVas(),"Second operand should have 2S vector arrangement");
                            
                        // Third operand (#3)
                        assertEquals(AArch64OperandType.IMM, details.getOperands()[2].getType(),"Third operand should be immediate type");
                        assertEquals(3, details.getOperands()[2].getImm(),"Immediate value should be 3");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify register access
                        CapstoneRegAccess regAccess_4 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_4.getRegsRead(), "Read registers array should not be null");
                        assertEquals(1, regAccess_4.getRegsRead().length, "Should read from 1 register");
                        assertTrue(contains(regAccess_4.getRegsRead(), AArch64Reg.D1),"Should read from d1 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_4.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_4.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_4.getRegsWrite(), AArch64Reg.D0),"Should write to d0 register");
                        break;
                    case 5: // fmla s0, s0, v0.s[3]
                        assertEquals("fmla", instruction.getMnemonic(), "Mnemonic should be 'fmla'");
                        assertEquals("s0, s0, v0.s[3]", instruction.getOpStr(), "Operands should be 's0, s0, v0.s[3]'");
                        
                        // Verify operands
                        assertEquals(3, details.getOperands().length, "Should have 3 operands");
                        
                        // First operand (s0)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.S0),"First operand should be s0 register");
                            
                        // Second operand (s0)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.S0),"Second operand should be s0 register");
                            
                        // Third operand (v0.s[3])
                        assertEquals(AArch64OperandType.REG, details.getOperands()[2].getType(),"Third operand should be register type");
                        assertTrue(contains(details.getOperands()[2].getReg(), AArch64Reg.Q0),"Third operand should be q0 register");
                        assertTrue(details.getOperands()[2].isVReg(),"Third operand should be a vector register");
                        assertEquals(AArch64VectorLayout.S, details.getOperands()[2].getVas(),"Third operand should have S vector arrangement");
                        assertTrue(details.getOperands()[2].getVectorIndex() != -1,"Third operand should have vector index set");
                        assertEquals(3, details.getOperands()[2].getVectorIndex(),"Third operand should have vector index 3");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify writeback
                        assertTrue(instruction.getDetails().isWriteback(),"Instruction should have writeback");

                        // Verify register access
                        CapstoneRegAccess regAccess_5 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_5.getRegsRead(), "Read registers array should not be null");
                        assertEquals(3, regAccess_5.getRegsRead().length, "Should read from 3 registers");
                        assertTrue(contains(regAccess_5.getRegsRead(), AArch64Reg.FPCR),"Should read from fpcr register");
                        assertTrue(contains(regAccess_5.getRegsRead(), AArch64Reg.S0),"Should read from s0 register");
                        assertTrue(contains(regAccess_5.getRegsRead(), AArch64Reg.Q0),"Should read from q0 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_5.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_5.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_5.getRegsWrite(), AArch64Reg.S0),"Should write to s0 register");
                        break;
                    case 6: // fmov x2, v5.d[1]
                        assertEquals("fmov", instruction.getMnemonic(), "Mnemonic should be 'fmov'");
                        assertEquals("x2, v5.d[1]", instruction.getOpStr(), "Operands should be 'x2, v5.d[1]'");
                        
                        // Verify operands
                        assertEquals(2, details.getOperands().length, "Should have 2 operands");
                        
                        // First operand (x2)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.X2),"First operand should be x2 register");
                            
                        // Second operand (v5.d[1])
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.Q5),"Second operand should be q5 register");
                        assertTrue(details.getOperands()[1].isVReg(),"Second operand should be a vector register");
                        assertEquals(AArch64VectorLayout.D, details.getOperands()[1].getVas(),"Second operand should have D vector arrangement");
                        assertTrue(details.getOperands()[1].getVectorIndex() != -1,"Second operand should have vector index set");
                        assertEquals(1, details.getOperands()[1].getVectorIndex(),"Second operand should have vector index 1");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify register access
                        CapstoneRegAccess regAccess_6 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_6.getRegsRead(), "Read registers array should not be null");
                        assertEquals(1, regAccess_6.getRegsRead().length, "Should read from 1 register");
                        assertTrue(contains(regAccess_6.getRegsRead(), AArch64Reg.Q5),"Should read from q5 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_6.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_6.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_6.getRegsWrite(), AArch64Reg.X2),"Should write to x2 register");
                        break;
                    case 7: // dsb nsh
                        assertEquals("dsb", instruction.getMnemonic(), "Mnemonic should be 'dsb'");
                        assertEquals("nsh", instruction.getOpStr(), "Operands should be 'nsh'");
                        
                        // Verify operands
                        assertEquals(1, details.getOperands().length, "Should have 1 operand");
                        
                        // First operand (nsh)
                        assertEquals(AArch64OperandType.SYSALIAS, details.getOperands()[0].getType(),"First operand should be system alias type");
                        assertEquals(AArch64OperandType.DB, details.getOperands()[0].getSys().getSubType(),"First operand should have DB subtype");
                        assertEquals(0x7L, details.getOperands()[0].getSys().getAlias().getRawVal(),"System alias raw value should be 0x7");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");
                        break;
                    case 8: // dmb osh
                        assertEquals("dmb", instruction.getMnemonic(), "Mnemonic should be 'dmb'");
                        assertEquals("osh", instruction.getOpStr(), "Operands should be 'osh'");
                        
                        // Verify operands
                        assertEquals(1, details.getOperands().length, "Should have 1 operand");
                        
                        // First operand (osh)
                        assertEquals(AArch64OperandType.SYSALIAS, details.getOperands()[0].getType(),"First operand should be system alias type");
                        assertEquals(AArch64OperandType.DB, details.getOperands()[0].getSys().getSubType(),"First operand should have DB subtype");
                        assertEquals(0x3L, details.getOperands()[0].getSys().getAlias().getRawVal(),"System alias raw value should be 0x3");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");
                        break;
                    case 9: // isb
                        assertEquals("isb", instruction.getMnemonic(), "Mnemonic should be 'isb'");
                        assertEquals("", instruction.getOpStr(), "Should have no operands");
                        
                        // Verify operands
                        assertEquals(0, details.getOperands().length, "Should have 0 operands");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");
                        break;
                    case 10: // mul x1, x1, x2
                        assertEquals("mul", instruction.getMnemonic(), "Mnemonic should be 'mul'");
                        assertEquals("x1, x1, x2", instruction.getOpStr(), "Operands should be 'x1, x1, x2'");
                        
                        // Verify operands
                        assertEquals(3, details.getOperands().length, "Should have 3 operands");
                        
                        // First operand (x1 - write)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.X1),"First operand should be x1 register");
                            
                        // Second operand (x1 - read)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.X1),"Second operand should be x1 register");
                            
                        // Third operand (x2 - read)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[2].getType(),"Third operand should be register type");
                        assertTrue(contains(details.getOperands()[2].getReg(), AArch64Reg.X2),"Third operand should be x2 register");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify register access
                        CapstoneRegAccess regAccess_10 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_10.getRegsRead(), "Read registers array should not be null");
                        assertEquals(2, regAccess_10.getRegsRead().length, "Should read from 2 registers");
                        assertTrue(contains(regAccess_10.getRegsRead(), AArch64Reg.X1),"Should read from x1 register");
                        assertTrue(contains(regAccess_10.getRegsRead(), AArch64Reg.X2),"Should read from x2 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_10.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_10.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_10.getRegsWrite(), AArch64Reg.X1),"Should write to x1 register");
                        break;
                    case 11: // lsr w1, w1, #0
                        assertEquals("lsr", instruction.getMnemonic(), "Mnemonic should be 'lsr'");
                        assertEquals("w1, w1, #0", instruction.getOpStr(), "Operands should be 'w1, w1, #0'");
                        
                        // Verify operands
                        assertEquals(2, details.getOperands().length, "Should have 2 operands");
                        
                        // First operand (w1 - write)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.W1),"First operand should be w1 register");
                            
                        // Second operand (w1 - read)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.W1),"Second operand should be w1 register");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify register access
                        CapstoneRegAccess regAccess_11 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_11.getRegsRead(), "Read registers array should not be null");
                        assertEquals(1, regAccess_11.getRegsRead().length, "Should read from 1 register");
                        assertTrue(contains(regAccess_11.getRegsRead(), AArch64Reg.W1),"Should read from w1 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_11.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_11.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_11.getRegsWrite(), AArch64Reg.W1),"Should write to w1 register");
                        break;
                    case 12: // sub w0, w0, w1, uxtw
                        assertEquals("sub", instruction.getMnemonic(), "Mnemonic should be 'sub'");
                        assertEquals("w0, w0, w1, uxtw", instruction.getOpStr(), "Operands should be 'w0, w0, w1, uxtw'");
                        
                        // Verify operands
                        assertEquals(3, details.getOperands().length, "Should have 3 operands");
                        
                        // First operand (w0 - write)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.W0),"First operand should be w0 register");
                            
                        // Second operand (w0 - read)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.W0),"Second operand should be w0 register");
                            
                        // Third operand (w1 - read with UXTW extension)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[2].getType(),"Third operand should be register type");
                        assertTrue(contains(details.getOperands()[2].getReg(), AArch64Reg.W1),"Third operand should be w1 register");
                        assertEquals(AArch64Extender.UXTW, details.getOperands()[2].getExt(),"Third operand should have UXTW extension");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify register access
                        CapstoneRegAccess regAccess_12 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_12.getRegsRead(), "Read registers array should not be null");
                        assertEquals(2, regAccess_12.getRegsRead().length, "Should read from 2 registers");
                        assertTrue(contains(regAccess_12.getRegsRead(), AArch64Reg.W0),"Should read from w0 register");
                        assertTrue(contains(regAccess_12.getRegsRead(), AArch64Reg.W1),"Should read from w1 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_12.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_12.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_12.getRegsWrite(), AArch64Reg.W0),"Should write to w0 register");
                        break;
                    case 13: // ldr w1, [sp, #8]
                        assertEquals("ldr", instruction.getMnemonic(), "Mnemonic should be 'ldr'");
                        assertEquals("w1, [sp, #8]", instruction.getOpStr(), "Operands should be 'w1, [sp, #8]'");
                        
                        // Verify operands
                        assertEquals(2, details.getOperands().length, "Should have 2 operands");
                        
                        // First operand (w1 - write)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.W1),"First operand should be w1 register");
                            
                        // Second operand (memory)
                        assertEquals(AArch64OperandType.MEM, details.getOperands()[1].getType(),"Second operand should be memory type");
                        assertTrue(contains(details.getOperands()[1].getMem().getBase(), AArch64Reg.SP),"Memory base should be sp register");
                        assertEquals(8, details.getOperands()[1].getMem().getDisp(),"Memory displacement should be 8");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify register access
                        CapstoneRegAccess regAccess_13 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_13.getRegsRead(), "Read registers array should not be null");
                        assertEquals(1, regAccess_13.getRegsRead().length, "Should read from 1 register");
                        assertTrue(contains(regAccess_13.getRegsRead(), AArch64Reg.SP),"Should read from sp register");
                        
                        // Check written registers
                        assertNotNull(regAccess_13.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_13.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_13.getRegsWrite(), AArch64Reg.W1),"Should write to w1 register");
                        break;
                    case 14: // cneg x0, x1, ne
                        assertEquals("cneg", instruction.getMnemonic(), "Mnemonic should be 'cneg'");
                        assertEquals("x0, x1, ne", instruction.getOpStr(), "Operands should be 'x0, x1, ne'");
                        
                        // Verify operands
                        assertEquals(2, details.getOperands().length, "Should have 2 operands");
                        
                        // First operand (x0 - write)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.X0),"First operand should be x0 register");
                            
                        // Second operand (x1 - read)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.X1),"Second operand should be x1 register");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.NE),"Condition code should be NE");

                        // Verify register access
                        CapstoneRegAccess regAccess_14 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_14.getRegsRead(), "Read registers array should not be null");
                        assertEquals(2, regAccess_14.getRegsRead().length, "Should read from 2 registers");
                        assertTrue(contains(regAccess_14.getRegsRead(), AArch64Reg.NZCV),"Should read from nzcv register");
                        assertTrue(contains(regAccess_14.getRegsRead(), AArch64Reg.X1),"Should read from x1 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_14.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_14.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_14.getRegsWrite(), AArch64Reg.X0),"Should write to x0 register");
                        break;
                    case 15: // add x0, x1, x2, lsl #2
                        assertEquals("add", instruction.getMnemonic(), "Mnemonic should be 'add'");
                        assertEquals("x0, x1, x2, lsl #2", instruction.getOpStr(), "Operands should be 'x0, x1, x2, lsl #2'");
                        
                        // Verify operands
                        assertEquals(3, details.getOperands().length, "Should have 3 operands");
                        
                        // First operand (x0 - write)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.X0),"First operand should be x0 register");
                            
                        // Second operand (x1 - read)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.X1),"Second operand should be x1 register");
                            
                        // Third operand (x2 - read with LSL #2)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[2].getType(),"Third operand should be register type");
                        assertTrue(contains(details.getOperands()[2].getReg(), AArch64Reg.X2),"Third operand should be x2 register");
                        assertEquals(AArch64Shifter.LSL, details.getOperands()[2].getShift().getShifter(),"Third operand should have LSL shift type");
                        assertEquals(2L, details.getOperands()[2].getShift().getValue(),"Third operand should have shift value of 2");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify register access
                        CapstoneRegAccess regAccess_15 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_15.getRegsRead(), "Read registers array should not be null");
                        assertEquals(2, regAccess_15.getRegsRead().length, "Should read from 2 registers");
                        assertTrue(contains(regAccess_15.getRegsRead(), AArch64Reg.X1),"Should read from x1 register");
                        assertTrue(contains(regAccess_15.getRegsRead(), AArch64Reg.X2),"Should read from x2 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_15.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_15.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_15.getRegsWrite(), AArch64Reg.X0),"Should write to x0 register");
                        break;
                    case 16: // ldr q16, [x24, w8, uxtw #4]
                        assertEquals("ldr", instruction.getMnemonic(), "Mnemonic should be 'ldr'");
                        assertEquals("q16, [x24, w8, uxtw #4]", instruction.getOpStr(), "Operands should be 'q16, [x24, w8, uxtw #4]'");
                        
                        // Verify operands
                        assertEquals(2, details.getOperands().length, "Should have 2 operands");
                        
                        // First operand (q16 - write)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.Q16),"First operand should be q16 register");
                            
                        // Second operand (memory)
                        assertEquals(AArch64OperandType.MEM, details.getOperands()[1].getType(),"Second operand should be memory type");
                        assertTrue(contains(details.getOperands()[1].getMem().getBase(), AArch64Reg.X24),"Memory base should be x24 register");
                        assertTrue(contains(details.getOperands()[1].getMem().getIndex(), AArch64Reg.W8),"Memory index should be w8 register");
                        assertEquals(AArch64Extender.UXTW, details.getOperands()[1].getExt(),"Memory should have UXTW extension");
                        assertEquals(AArch64Shifter.LSL, details.getOperands()[1].getShift().getShifter(),"Memory should have LSL shift type");
                        assertEquals(4L, details.getOperands()[1].getShift().getValue(),"Memory should have shift value of 4");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify register access
                        CapstoneRegAccess regAccess_16 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_16.getRegsRead(), "Read registers array should not be null");
                        assertEquals(2, regAccess_16.getRegsRead().length, "Should read from 2 registers");
                        assertTrue(contains(regAccess_16.getRegsRead(), AArch64Reg.X24),"Should read from x24 register");
                        assertTrue(contains(regAccess_16.getRegsRead(), AArch64Reg.W8),"Should read from w8 register");
                        
                        // Check written registers
                        assertNotNull(regAccess_16.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_16.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_16.getRegsWrite(), AArch64Reg.Q16),"Should write to q16 register");
                        break;
                    case 17: // stp x29, x30, [sp, #-0x60]!
                        assertEquals("stp", instruction.getMnemonic(), "Mnemonic should be 'stp'");
                        assertEquals("x29, x30, [sp, #-0x60]!", instruction.getOpStr(), "Operands should be 'x29, x30, [sp, #-0x60]!'");
                        
                        // Verify operands
                        assertEquals(3, details.getOperands().length, "Should have 3 operands");
                        
                        // First operand (x29 - read)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.X29),"First operand should be x29 register");
                            
                        // Second operand (x30 - read)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[1].getType(),"Second operand should be register type");
                        assertTrue(contains(details.getOperands()[1].getReg(), AArch64Reg.X30),"Second operand should be x30 register");
                            
                        // Third operand (memory)
                        assertEquals(AArch64OperandType.MEM, details.getOperands()[2].getType(),"Third operand should be memory type");
                        assertTrue(contains(details.getOperands()[2].getMem().getBase(), AArch64Reg.SP),"Memory base should be sp register");
                        assertEquals(-0x60, details.getOperands()[2].getMem().getDisp(),"Memory displacement should be -0x60");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify writeback
                        assertTrue(instruction.getDetails().isWriteback(),"Instruction should have writeback");

                        // Verify register access
                        CapstoneRegAccess regAccess_17 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_17.getRegsRead(), "Read registers array should not be null");
                        assertEquals(3, regAccess_17.getRegsRead().length, "Should read from 3 registers");
                        assertTrue(contains(regAccess_17.getRegsRead(), AArch64Reg.X29),"Should read from x29 register");
                        assertTrue(contains(regAccess_17.getRegsRead(), AArch64Reg.X30),"Should read from x30 register");
                        assertTrue(contains(regAccess_17.getRegsRead(), AArch64Reg.SP),"Should read from sp register");
                        
                        // Check written registers
                        assertNotNull(regAccess_17.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(1, regAccess_17.getRegsWrite().length, "Should write to 1 register");
                        assertTrue(contains(regAccess_17.getRegsWrite(), AArch64Reg.SP),"Should write to sp register");
                        break;
                    case 18: // ldr x29, [sp], #0x3c
                        assertEquals("ldr", instruction.getMnemonic(), "Mnemonic should be 'ldr'");
                        assertEquals("x29, [sp], #0x3c", instruction.getOpStr(), "Operands should be 'x29, [sp], #0x3c'");
                        
                        // Verify operands
                        assertEquals(2, details.getOperands().length, "Should have 2 operands");
                        
                        // First operand (x29 - write)
                        assertEquals(AArch64OperandType.REG, details.getOperands()[0].getType(),"First operand should be register type");
                        assertTrue(contains(details.getOperands()[0].getReg(), AArch64Reg.X29),"First operand should be x29 register");
                            
                        // Second operand (memory)
                        assertEquals(AArch64OperandType.MEM, details.getOperands()[1].getType(),"Second operand should be memory type");
                        assertTrue(contains(details.getOperands()[1].getMem().getBase(), AArch64Reg.SP),"Memory base should be sp register");
                        assertEquals(0x3c, details.getOperands()[1].getMem().getDisp(),"Memory displacement should be 0x3c");
                            
                        // Verify post-indexed addressing
                        assertTrue(details.isPostIndex(),"Instruction should be post-indexed");
                            
                        // Verify condition code
                        assertTrue(contains(details.getCc(), AArch64CondCode.Invalid),"Condition code should be invalid");

                        // Verify writeback
                        assertTrue(instruction.getDetails().isWriteback(),"Instruction should have writeback");

                        // Verify register access
                        CapstoneRegAccess regAccess_18 = instruction.getRegAccess();
                        
                        // Check read registers
                        assertNotNull(regAccess_18.getRegsRead(), "Read registers array should not be null");
                        assertEquals(1, regAccess_18.getRegsRead().length, "Should read from 1 register");
                        assertTrue(contains(regAccess_18.getRegsRead(), AArch64Reg.SP),"Should read from sp register");
                        
                        // Check written registers
                        assertNotNull(regAccess_18.getRegsWrite(), "Written registers array should not be null");
                        assertEquals(2, regAccess_18.getRegsWrite().length, "Should write to 2 registers");
                        assertTrue(contains(regAccess_18.getRegsWrite(), AArch64Reg.SP),"Should write to sp register");
                        assertTrue(contains(regAccess_18.getRegsWrite(), AArch64Reg.X29),"Should write to x29 register");
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
			fail("Failed to disassemble instruction");
		}
	}

    private boolean contains(AArch64Reg[] regs, AArch64Reg reg) {
        for (AArch64Reg item : regs) {
            if (item == reg) {
                return true;
            }
        }
        return false;
    }

    private boolean contains(int[] regs, AArch64Reg reg) {
        for (int item : regs) {
            if (item == reg.getValue()) {
                return true;
            }
        }
        return false;
    }

    private boolean contains(AArch64CondCode[] condCodes, AArch64CondCode condCode) {
        for (AArch64CondCode item : condCodes) {
            if (item == condCode) {
                return true;
            }
        }
        return false;
    }
}
