// Generated by jextract

package com.suko.capstone4j.internal;

import java.lang.invoke.*;
import java.lang.foreign.*;
import java.nio.ByteOrder;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

import static java.lang.foreign.ValueLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * {@snippet lang=c :
 * typedef void *(*cs_calloc_t)(size_t, size_t) __attribute__((cdecl))
 * }
 */
public class cs_calloc_t {

    cs_calloc_t() {
        // Should not be called directly
    }

    /**
     * The function pointer signature, expressed as a functional interface
     */
    public interface Function {
        MemorySegment apply(long nmemb, long size);
    }

    private static final FunctionDescriptor $DESC = FunctionDescriptor.of(
        capstone_h.C_POINTER,
        capstone_h.C_LONG_LONG,
        capstone_h.C_LONG_LONG
    );

    /**
     * The descriptor of this function pointer
     */
    public static FunctionDescriptor descriptor() {
        return $DESC;
    }

    private static final MethodHandle UP$MH = capstone_h.upcallHandle(cs_calloc_t.Function.class, "apply", $DESC);

    /**
     * Allocates a new upcall stub, whose implementation is defined by {@code fi}.
     * The lifetime of the returned segment is managed by {@code arena}
     */
    public static MemorySegment allocate(cs_calloc_t.Function fi, Arena arena) {
        return Linker.nativeLinker().upcallStub(UP$MH.bindTo(fi), $DESC, arena);
    }

    private static final MethodHandle DOWN$MH = Linker.nativeLinker().downcallHandle($DESC);

    /**
     * Invoke the upcall stub {@code funcPtr}, with given parameters
     */
    public static MemorySegment invoke(MemorySegment funcPtr,long nmemb, long size) {
        try {
            return (MemorySegment) DOWN$MH.invokeExact(funcPtr, nmemb, size);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }
}

