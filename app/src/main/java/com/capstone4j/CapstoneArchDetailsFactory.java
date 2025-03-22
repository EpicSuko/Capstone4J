package com.capstone4j;

import java.lang.foreign.MemorySegment;

class CapstoneArchDetailsFactory {

    static CapstoneX86Details createX86Details(MemorySegment segment) {
        return CapstoneX86Details.createFromMemorySegment(segment);
    }
    
    @SuppressWarnings("unchecked")
    static <T extends CapstoneArchDetails> T createDetails(MemorySegment segment, CapstoneArch arch, Class<T> expectedType) {
        CapstoneArchDetails result;
        
        switch(arch) {
            case X86:
                if (!CapstoneX86Details.class.isAssignableFrom(expectedType)) {
                    throw new ClassCastException("Expected type " + expectedType.getSimpleName() + 
                                                " is not compatible with X86 architecture");
                }
                result = createX86Details(segment);
                break;
            default:
                throw new IllegalArgumentException("Unsupported architecture: " + arch);
        }
        
        return (T) result;
    }
}