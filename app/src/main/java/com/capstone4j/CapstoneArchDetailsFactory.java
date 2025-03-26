package com.capstone4j;

import java.lang.foreign.MemorySegment;
import java.lang.reflect.Method;

class CapstoneArchDetailsFactory {

    static CapstoneX86Details createX86Details(MemorySegment segment) {
        return CapstoneX86Details.createFromMemorySegment(segment);
    }
    
    @SuppressWarnings("unchecked")
    static <T extends CapstoneArchDetails<?>> T createDetails(MemorySegment segment, CapstoneArch arch, Class<? extends CapstoneArchDetails<?>> expectedType) {
        try {
            Method createFromMemorySegment = expectedType.getDeclaredMethod("createFromMemorySegment", MemorySegment.class);
            return (T) createFromMemorySegment.invoke(null, segment);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException("Failed to create architecture details for " + arch, e);
        }
    }
}