package com.capstone.examples;

import java.io.IOException;
import java.util.Arrays;

import com.suko.capstone4j.Capstone;
import com.suko.capstone4j.CapstoneArch;
import com.suko.capstone4j.CapstoneHandle;
import com.suko.capstone4j.CapstoneHandleOptions;
import com.suko.capstone4j.CapstoneInstruction;
import com.suko.capstone4j.CapstoneMode;
import com.suko.capstone4j.CapstoneOption;
import com.suko.capstone4j.CapstoneOptionValue;
import com.suko.capstone4j.CapstoneX86Details;
import com.suko.capstone4j.CapstoneX86Details.X86Encoding;

public class SimpleDisassembler {

    public static void main(String[] args) {
        try {
            System.out.println("Initializing Capstone...");
            Capstone.initialize();

            System.out.println("Capstone version: " + Capstone.getVersion());

            byte[] data = new byte[] {
                0x55, 0x48, (byte)0x8b, 0x05, (byte)0xb8, (byte)0x13, 0x00, 0x00, (byte)0xe9, (byte)0xea, 
                (byte)0xbe, (byte)0xad, (byte)0xde, (byte)0xff, 0x25, 0x23, 0x01, 0x00, 0x00, (byte)0xe8, 
                (byte)0xdf, (byte)0xbe, (byte)0xad, (byte)0xde, 0x74, (byte)0xff
            };

            try {
                // Create options with builder pattern
                CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();
                
                // Create handle with custom options
                try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.X86, CapstoneMode.X86_64, options)) {
                    System.out.println("Created handle with custom options");

                    handle.setOption(CapstoneOption.DETAIL, new CapstoneOptionValue[] { CapstoneOptionValue.ON });

                    long runtimeAddress = 0x1000;
                    int offset = 0;
                    final int length = data.length;

                    while(offset < length) {
                        int maxBytesToRead = Math.min(15, length - offset);
                        byte[] subData = Arrays.copyOfRange(data, offset, offset + maxBytesToRead);
                        CapstoneInstruction<CapstoneX86Details> instruction = handle.disassembleInstruction(subData, runtimeAddress);
                        System.out.printf("\n%016X  %s %s\n", instruction.getAddress(), instruction.getMnemonic(), instruction.getOpStr());
                        System.out.println("Instruction size: " + instruction.getSize());
                        System.out.println("Instruction bytes: " + Arrays.toString(instruction.getBytes()));
                        if(instruction.getDetails() != null) {
                            // Access register information through getRegAccess()
                            System.out.println("Registers read count: " + instruction.getRegAccess().getRegsReadCount());
                            System.out.println("Registers read: " + Arrays.toString(instruction.getRegAccess().getRegsRead()));
                            System.out.println("Registers written count: " + instruction.getRegAccess().getRegsWriteCount());
                            System.out.println("Registers written: " + Arrays.toString(instruction.getRegAccess().getRegsWrite()));
                            
                            // Continue accessing other details directly
                            System.out.println("Groups count: " + instruction.getDetails().getGroupsCount());
                            System.out.println("Groups: " + Arrays.toString(instruction.getDetails().getGroups()));
                            System.out.println("Writeback: " + instruction.getDetails().isWriteback());
                            
                            // Use getRegAccess() for register operations
                            for(int regId : instruction.getRegAccess().getRegsRead()) {
                                System.out.println("Reg read: " + handle.getRegName(regId));
                            }
                            for(int regId : instruction.getRegAccess().getRegsWrite()) {
                                System.out.println("Reg write: " + handle.getRegName(regId));
                            }
                            System.out.println("Instruction name: " + handle.getInsnName(instruction.getId()));
                            for(int groupId : instruction.getDetails().getGroups()) {
                                System.out.println("Group: " + handle.getGroupName(groupId));
                            }
                            System.out.println("Prefix: " + Arrays.toString(instruction.getDetails().getArchDetails().getPrefixs()));
                            System.out.println("Opcode: " + Arrays.toString(instruction.getDetails().getArchDetails().getOpcodes()));
                            System.out.println("Rex: " + instruction.getDetails().getArchDetails().getRex());
                            System.out.println("Addr size: " + instruction.getDetails().getArchDetails().getAddrSize());
                            System.out.println("Modrm: " + instruction.getDetails().getArchDetails().getModrm());
                            System.out.println("Sib: " + instruction.getDetails().getArchDetails().getSib());
                            System.out.println("Disp: " + instruction.getDetails().getArchDetails().getDisp());
                            System.out.println("Sib index: " + instruction.getDetails().getArchDetails().getSibIndex());
                            System.out.println("Sib scale: " + instruction.getDetails().getArchDetails().getSibScale());
                            System.out.println("Sib base: " + instruction.getDetails().getArchDetails().getSibBase());
                            System.out.println("Xop CC: " + instruction.getDetails().getArchDetails().getXopCC());
                            System.out.println("Sse CC: " + instruction.getDetails().getArchDetails().getSseCC());
                            System.out.println("Avx CC: " + instruction.getDetails().getArchDetails().getAvxCC());
                            System.out.println("Avx SAE: " + instruction.getDetails().getArchDetails().getAvxSAE());
                            System.out.println("Avx RM: " + instruction.getDetails().getArchDetails().getAvxRm());
                            System.out.println("Eflags: " + Arrays.toString(instruction.getDetails().getArchDetails().getEflags()));
                            System.out.println("Fpu flags: " + Arrays.toString(instruction.getDetails().getArchDetails().getFpuFlags()));
                            System.out.println("OP Count: " + instruction.getDetails().getArchDetails().getOpCount());
                            System.out.println("Operands:");
                            for(int i = 0; i < instruction.getDetails().getArchDetails().getOpCount(); i++) {
                                CapstoneX86Details.X86Operand operand = instruction.getDetails().getArchDetails().getOperands()[i];
                                System.out.println("\tType: " + operand.getType());
                                System.out.println("\tReg: " + operand.getReg());
                                System.out.println("\tImm: " + operand.getImm());
                                if(operand.getMem() != null) {
                                    System.out.println("\tMem:");
                                    CapstoneX86Details.X86OpMem mem = operand.getMem();
                                    System.out.println("\t\tSegment: " + mem.getSegment());
                                    System.out.println("\t\tBase: " + mem.getBase());
                                    System.out.println("\t\tIndex: " + mem.getIndex());
                                    System.out.println("\t\tScale: " + mem.getScale());
                                    System.out.println("\t\tDisp: " + mem.getDisp());
                                } else {
                                    System.out.println("\tMem: null");
                                }
                            }
                            System.out.println("Encoding:");
                            X86Encoding encoding = instruction.getDetails().getArchDetails().getEncoding();
                            System.out.println("\tModrm offset: " + encoding.getModrmOffset());
                            System.out.println("\tDisp offset: " + encoding.getDispOffset());
                            System.out.println("\tDisp size: " + encoding.getDispSize());
                            System.out.println("\tImm offset: " + encoding.getImmOffset());
                            System.out.println("\tImm size: " + encoding.getImmSize());
                        }
                        offset += instruction.getSize();
                        runtimeAddress += instruction.getSize();
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
