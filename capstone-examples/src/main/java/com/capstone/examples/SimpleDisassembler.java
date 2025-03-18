package com.capstone.examples;

import java.io.IOException;
import java.lang.foreign.Arena;

import com.capstone4j.Capstone;
import com.capstone4j.CapstoneArch;
import com.capstone4j.CapstoneHandleOptions;
import com.capstone4j.CapstoneMode;
import com.capstone4j.CapstoneHandle;
import com.capstone4j.DefaultCapstoneMemoryProvider;

public class SimpleDisassembler {

    public static void main(String[] args) {
        try {
            System.out.println("Initializing Capstone...");
            Capstone.initialize();

            System.out.println("Capstone version: " + Capstone.getVersion());

            try {
                // Create options with builder pattern
                CapstoneHandleOptions options = CapstoneHandleOptions.builder()
                    .handleArena(Arena.ofConfined())
                    .closeHandleArena(true)
                    .memoryProvider(new DefaultCapstoneMemoryProvider())
                    .useHandleArena(true)
                    .build();
                
                // Create handle with custom options
                try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.X86, CapstoneMode.X86_64, options)) {
                    System.out.println("Created handle with custom options");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
