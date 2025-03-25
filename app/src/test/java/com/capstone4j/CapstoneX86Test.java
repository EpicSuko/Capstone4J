package com.capstone4j;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

import com.capstone4j.CapstoneX86Details.X86EFlags;
import com.capstone4j.CapstoneX86Details.X86OperandType;
import com.capstone4j.CapstoneX86Details.X86Operand;
import com.capstone4j.CapstoneX86Details.X86Reg;
import com.capstone4j.CapstoneX86Details.X86Prefix;

class CapstoneX86Test {

    byte[] testX86Data = new byte[] {
        0x55, 0x48, (byte)0x8b, 0x05, (byte)0xb8, (byte)0x13, 0x00, 0x00, (byte)0xe9, (byte)0xea, 
        (byte)0xbe, (byte)0xad, (byte)0xde, (byte)0xff, 0x25, 0x23, 0x01, 0x00, 0x00, (byte)0xe8, 
        (byte)0xdf, (byte)0xbe, (byte)0xad, (byte)0xde, 0x74, (byte)0xff
    };

    @Test void testX86() {
        try {
            Capstone.initialize();
        } catch (IOException e) {
            e.printStackTrace();
            fail("Failed to initialize Capstone");
        }
        
        CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();

        try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.X86, CapstoneMode.X86_64, options)) {
            // Enable detailed instruction information
            handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);
            
            long runtimeAddress = 0x1000;
            int offset = 0;
            final int length = testX86Data.length;
            int instructionIndex = 0;
            
            while(offset < length) {
                int maxBytesToRead = Math.min(15, length - offset);
                byte[] subData = Arrays.copyOfRange(testX86Data, offset, offset + maxBytesToRead);
                
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
                        CapstoneRegAccess regAccess = instruction.getComprehensiveRegAccess();
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

                        CapstoneRegAccess regAccess2 = instruction.getComprehensiveRegAccess();
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
                        assertEquals(0, details.getModrm());
                        
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
                        CapstoneRegAccess regAccess3 = instruction.getComprehensiveRegAccess();
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
                        assertTrue(contains(instruction.getRegAccess().getRegsRead(), X86Reg.EFLAGS.getValue()), 
                                  "RFLAGS should be read");
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
}
