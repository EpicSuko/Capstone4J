package com.capstone4j;

import java.io.IOException;

import static com.capstone4j.internal.capstone_h.*;

import com.capstone4j.internal.capstone_h;
import com.capstone4j.utils.NativeUtils;

public class Capstone {

    private static boolean initialized = false;
    private static boolean initializationAttempted = false;
    private static IOException lastInitializationError = null;

    private Capstone() {}
    
    /**
     * Initializes the Capstone library by loading the native library.
     * This method must be called before using any Capstone functionality.
     * 
     * @throws IOException If the native library cannot be loaded
     */
    public static synchronized void initialize() throws IOException {
        if (!initialized) {
            if (initializationAttempted) {
                if (lastInitializationError != null) {
                    throw new IOException("Capstone initialization previously failed", lastInitializationError);
                }
                return; // Already initialized successfully
            }
            
            initializationAttempted = true;
            try {
                NativeUtils.loadLibraryFromJar("/libs/capstone.dll");
                initialized = true;
            } catch (IOException e) {
                lastInitializationError = e;
                throw new IOException("Failed to initialize Capstone: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Checks if the Capstone library has been initialized.
     * 
     * @return true if initialized, false otherwise
     */
    public static boolean isInitialized() {
        return initialized;
    }

    /**
     * Gets the version of the Capstone library.
     * 
     * @return A string representation of the Capstone version
     */
    public static String getVersion() {
        return String.format("%d.%d.%d Next %d", CS_VERSION_MAJOR(), CS_VERSION_MINOR(), CS_VERSION_EXTRA(), CS_NEXT_VERSION());
    }


    /**
     * Checks if a specific architecture is supported by the Capstone library.
     * 
     * @param arch The CapstoneArch enum value representing the architecture to check
     * @return true if the architecture is supported, false otherwise
     * @throws IllegalStateException if the Capstone library is not initialized
     */
    public static boolean isArchSupported(CapstoneArch arch) {
        if(!isInitialized()) {
            throw new IllegalStateException("Capstone is not initialized");
        }
        return cs_support(arch.getValue());
    }

    /**
     * Creates a new Capstone handle for disassembling code with the specified options.
     * 
     * @param arch The architecture to use for disassembly
     * @param mode The mode to use for disassembly
     * @param options The options to configure the handle
     * @return A new Capstone handle
     * @throws IllegalStateException if the Capstone library is not initialized
     */
    public static CapstoneHandle createHandle(CapstoneArch arch, CapstoneMode mode, CapstoneHandleOptions options) {
        if(!isInitialized()) {
            throw new IllegalStateException("Capstone is not initialized");
        }
        return new CapstoneHandle(arch, mode, options);
    }

    /**
     * Creates a new Capstone handle for disassembling code with the default options.
     * 
     * @param arch The architecture to use for disassembly
     * @param mode The mode to use for disassembly
     * @return A new Capstone handle
     * @throws IllegalStateException if the Capstone library is not initialized
     */
    public static CapstoneHandle createHandle(CapstoneArch arch, CapstoneMode mode) {
        if(!isInitialized()) {
            throw new IllegalStateException("Capstone is not initialized");
        }
        return new CapstoneHandle(arch, mode);
    }
}