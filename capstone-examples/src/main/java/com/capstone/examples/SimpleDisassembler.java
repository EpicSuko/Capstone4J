package com.capstone.examples;

import java.io.IOException;

import com.capstone4j.Capstone;
import com.capstone4j.CapstoneArch;
import com.capstone4j.CapstoneMode;
import com.capstone4j.CapstoneHandle;
import com.capstone4j.CapstoneOption;
import com.capstone4j.CapstoneOptionValue;

public class SimpleDisassembler {

    public static void main(String[] args) {
        try {
            System.out.println("Initializing Capstone...");
            Capstone.initialize();

            System.out.println("Capstone version: " + Capstone.getVersion());

            try(CapstoneHandle handle = Capstone.createHandle(CapstoneArch.X86, CapstoneMode.X86_64)) {
                handle.setOption(CapstoneOption.SKIPDATA, CapstoneOptionValue.ON);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
