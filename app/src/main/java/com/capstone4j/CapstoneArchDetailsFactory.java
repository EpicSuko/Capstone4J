package com.capstone4j;

import java.lang.foreign.MemorySegment;

class CapstoneArchDetailsFactory {

    static CapstoneX86Details createX86Details(MemorySegment segment) {
        return CapstoneX86Details.createFromMemorySegment(segment);
    }
    
    @SuppressWarnings("unchecked")
    static <A extends CapstoneArchDetails<?>> A createDetails(MemorySegment segment, CapstoneArch arch, Class<A> expectedType) {
        CapstoneArchDetails<?> result;
        
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
        
        return (A) result;
    }
}