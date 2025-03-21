package com.capstone.examples;

import java.io.IOException;
import java.util.Arrays;

import com.capstone4j.Capstone;
import com.capstone4j.CapstoneArch;
import com.capstone4j.CapstoneHandleOptions;
import com.capstone4j.CapstoneInstruction;
import com.capstone4j.CapstoneMode;
import com.capstone4j.CapstoneOption;
import com.capstone4j.CapstoneOptionValue;
import com.capstone4j.CapstoneHandle;

public class SimpleDisassembler {

    public static void main(String[] args) {
        try {
            System.out.println("Initializing Capstone...");
            Capstone.initialize();

            System.out.println("Capstone version: " + Capstone.getVersion());

            byte[] data = new byte[] {
                0x51, (byte)0x8D, 0x45, (byte)0xFF, 0x50, (byte)0xFF, 0x75, 0x0C, (byte)0xFF, 0x75,
                0x08, (byte)0xFF, 0x15, (byte)0xA0, (byte)0xA5, 0x48, 0x76, (byte)0x85, (byte)0xC0, 0x0F,
                (byte)0x88, (byte)0xFC, (byte)0xDA, 0x02, 0x00
            };

            try {
                // Create options with builder pattern
                CapstoneHandleOptions options = CapstoneHandleOptions.getDefault();
                
                // Create handle with custom options
                try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.X86, CapstoneMode.X86_64, options)) {
                    System.out.println("Created handle with custom options");

                    handle.setOption(CapstoneOption.DETAIL, new CapstoneOptionValue[] { CapstoneOptionValue.ON, CapstoneOptionValue.DETAIL_REAL });

                    long runtimeAddress = 0x0L;
                    int offset = 0;
                    final int length = data.length;

                    while(offset < length) {
                        byte[] subData = Arrays.copyOfRange(data, offset, Math.min(15, offset + 15));
                        CapstoneInstruction instruction = handle.disassembleInstruction(subData, runtimeAddress);
                        System.out.printf("%016X  %s %s\n", instruction.getAddress(), instruction.getMnemonic(), instruction.getOpStr());
                        if(instruction.getDetails() != null) {
                            System.out.println("Registers read count: " + instruction.getDetails().getRegsReadCount());
                            System.out.println("Registers read: " + Arrays.toString(instruction.getDetails().getRegsRead()));
                            System.out.println("Registers written count: " + instruction.getDetails().getRegsWriteCount());
                            System.out.println("Registers written: " + Arrays.toString(instruction.getDetails().getRegsWrite()));
                            System.out.println("Groups count: " + instruction.getDetails().getGroupsCount());
                            System.out.println("Groups: " + Arrays.toString(instruction.getDetails().getGroups()));
                            System.out.println("Writeback: " + instruction.getDetails().isWriteback());
                            for(int regId : instruction.getDetails().getRegsRead()) {
                                System.out.println("Reg read: " + handle.getRegName(regId));
                            }
                            for(int regId : instruction.getDetails().getRegsWrite()) {
                                System.out.println("Reg write: " + handle.getRegName(regId));
                            }
                            System.out.println("Instruction name: " + handle.getInsnName(instruction.getId()));
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
