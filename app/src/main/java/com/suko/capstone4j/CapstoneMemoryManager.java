package com.suko.capstone4j;

import java.lang.foreign.MemorySegment;

import com.suko.capstone4j.internal.cs_calloc_t;
import com.suko.capstone4j.internal.cs_free_t;
import com.suko.capstone4j.internal.cs_malloc_t;
import com.suko.capstone4j.internal.cs_opt_mem;
import com.suko.capstone4j.internal.cs_realloc_t;
import com.suko.capstone4j.internal.cs_vsnprintf_t;

/**
 * Manages memory functions for the Capstone library.
 * <p>
 * This class creates and maintains function pointers for memory operations (malloc, calloc, realloc, free, vsnprintf)
 * that are used by the Capstone library. These function pointers delegate to a provided {@link CapstoneMemoryProvider}
 * implementation.
 * </p>
 */
class CapstoneMemoryManager {

    /** The memory provider that handles actual memory operations. */
    private final CapstoneMemoryProvider memoryProvider;

    /** Function pointer for malloc operations. */
    private final MemorySegment mallocFuncPtr;
    
    /** Function pointer for calloc operations. */
    private final MemorySegment callocFuncPtr;
    
    /** Function pointer for realloc operations. */
    private final MemorySegment reallocFuncPtr;
    
    /** Function pointer for free operations. */
    private final MemorySegment freeFuncPtr;
    
    /** Function pointer for vsnprintf operations. */
    private final MemorySegment vsnprintfFuncPtr;

    /**
     * Constructs a new CapstoneMemoryManager with the specified memory provider.
     * <p>
     * Initializes function pointers for all required memory operations.
     * </p>
     *
     * @param memoryProvider The provider that will handle actual memory operations
     */
    CapstoneMemoryManager(CapstoneMemoryProvider memoryProvider) {
        this.memoryProvider = memoryProvider;

        this.mallocFuncPtr = createMallocFunctionPointer();
        this.callocFuncPtr = createCallocFunctionPointer();
        this.reallocFuncPtr = createReallocFunctionPointer();
        this.freeFuncPtr = createFreeFunctionPointer();
        this.vsnprintfFuncPtr = createVsnprintfFunctionPointer();
    }

    /**
     * Creates a function pointer for malloc operations.
     *
     * @return A MemorySegment containing the function pointer
     */
    private MemorySegment createMallocFunctionPointer() {
        return cs_malloc_t.allocate((size) -> memoryProvider.malloc(size), memoryProvider.getArena());
    }

    /**
     * Creates a function pointer for calloc operations.
     *
     * @return A MemorySegment containing the function pointer
     */
    private MemorySegment createCallocFunctionPointer() {
        return cs_calloc_t.allocate((nmemb, size) -> memoryProvider.calloc(nmemb, size), memoryProvider.getArena());
    }

    /**
     * Creates a function pointer for realloc operations.
     *
     * @return A MemorySegment containing the function pointer
     */
    private MemorySegment createReallocFunctionPointer() {
        return cs_realloc_t.allocate((ptr, size) -> memoryProvider.realloc(ptr, size), memoryProvider.getArena());
    }

    /**
     * Creates a function pointer for free operations.
     *
     * @return A MemorySegment containing the function pointer
     */
    private MemorySegment createFreeFunctionPointer() {
        return cs_free_t.allocate((ptr) -> memoryProvider.free(ptr), memoryProvider.getArena());
    }

    /**
     * Creates a function pointer for vsnprintf operations.
     *
     * @return A MemorySegment containing the function pointer
     */
    private MemorySegment createVsnprintfFunctionPointer() {
        return cs_vsnprintf_t.allocate((str, size, format, ap) -> memoryProvider.vsnprintf(str, size, format, ap), memoryProvider.getArena());
    }

    /**
     * Creates a memory options structure that can be passed to the Capstone library.
     * <p>
     * This structure contains pointers to all the memory management functions.
     * </p>
     *
     * @return A MemorySegment containing the memory options structure
     */
    public MemorySegment createMemoryOptions() {
        MemorySegment memOpt = cs_opt_mem.allocate(memoryProvider.getArena());

        cs_opt_mem.malloc(memOpt, mallocFuncPtr);
        cs_opt_mem.calloc(memOpt, callocFuncPtr);
        cs_opt_mem.realloc(memOpt, reallocFuncPtr);
        cs_opt_mem.free(memOpt, freeFuncPtr);
        cs_opt_mem.vsnprintf(memOpt, vsnprintfFuncPtr);

        return memOpt;
    }
}
