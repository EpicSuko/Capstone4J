package com.capstone4j.utils;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import static java.lang.foreign.ValueLayout.*;

public class NativeVsnprintf {
    private static final MethodHandle vsnprintf;
    private static final boolean isAvailable;
    
    static {
        MethodHandle handle = null;
        boolean available = false;
        
        try {
            // Get the native linker
            Linker linker = Linker.nativeLinker();
            
            // Look up the vsnprintf function in the standard library
            SymbolLookup stdlib = linker.defaultLookup();
            // Use find() without orElseThrow() to handle missing function case
            var vsnprintfAddressOpt = stdlib.find("vsnprintf");
            
            if (vsnprintfAddressOpt.isPresent()) {
                // Create function descriptor for vsnprintf
                // int vsnprintf(char *str, size_t size, const char *format, va_list ap);
                FunctionDescriptor descriptor = FunctionDescriptor.of(
                    JAVA_INT,           // return type
                    ADDRESS,            // char *str
                    JAVA_LONG,         // size_t size
                    ADDRESS,           // const char *format
                    ADDRESS            // va_list ap
                );
                
                // Create the method handle
                handle = linker.downcallHandle(vsnprintfAddressOpt.get(), descriptor);
                available = true;
            }
        } catch (Throwable e) {
            // If anything goes wrong during initialization, we'll fall back to Java implementation
            handle = null;
            available = false;
        }
        
        vsnprintf = handle;
        isAvailable = available;
    }
    
    /**
     * Checks if the native vsnprintf function is available on this system.
     *
     * @return true if native vsnprintf is available, false otherwise
     */
    public static boolean isAvailable() {
        return isAvailable;
    }
    
    /**
     * Calls the native vsnprintf function.
     *
     * @param buffer The output buffer
     * @param size The size of the buffer
     * @param format The format string
     * @param args The va_list arguments
     * @return The number of characters that would have been written if size had been sufficiently large
     * @throws UnsupportedOperationException if native vsnprintf is not available
     * @throws RuntimeException if the native call fails
     */
    public static int vsnprintf(MemorySegment buffer, long size, MemorySegment format, MemorySegment args) {
        if (!isAvailable) {
            throw new UnsupportedOperationException("Native vsnprintf is not available on this system");
        }
        
        try {
            return (int) vsnprintf.invokeExact(buffer, size, format, args);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to call native vsnprintf", e);
        }
    }
}
