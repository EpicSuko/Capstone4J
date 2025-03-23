package com.capstone4j;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * Interface for custom memory allocation in the Capstone engine.
 * <p>
 * This interface allows providing custom memory management strategies for the Capstone
 * disassembly engine. Implementations of this interface can be passed to
 * {@link CapstoneHandleOptions.Builder#memoryProvider(CapstoneMemoryProvider)} to override the
 * default memory management used by Capstone.
 * <p>
 * The methods in this interface correspond to the standard C memory allocation functions
 * and are called by the Capstone engine when it needs to allocate, reallocate, or free memory.
 * <p>
 * An implementation can use the provided Arena for memory allocation and tracking, which allows
 * for automatic cleanup when the Arena is closed.
 */
public interface CapstoneMemoryProvider {

    /**
     * Sets the arena to be used for memory management.
     * <p>
     * This arena will be used for memory allocation and tracking. The implementation
     * should use this arena when allocating memory in the other methods.
     *
     * @param arena the arena to use for memory management
     */
    void setArena(Arena arena);
    
    /**
     * Gets the arena currently being used for memory management.
     *
     * @return the current arena used for memory management
     */
    Arena getArena();

    /**
     * Allocates memory of the specified size.
     * <p>
     * This method corresponds to the C {@code malloc} function.
     *
     * @param size the number of bytes to allocate
     * @return a memory segment of the specified size, or null if allocation fails
     */
    MemorySegment malloc(long size);

    /**
     * Allocates zero-initialized memory for an array.
     * <p>
     * This method corresponds to the C {@code calloc} function.
     *
     * @param nmemb the number of elements to allocate
     * @param size the size of each element in bytes
     * @return a zero-initialized memory segment of size {@code nmemb * size}, 
     *         or null if allocation fails
     */
    MemorySegment calloc(long nmemb, long size);

    /**
     * Changes the size of a previously allocated memory segment.
     * <p>
     * This method corresponds to the C {@code realloc} function.
     *
     * @param ptr the memory segment to resize
     * @param size the new size in bytes
     * @return a memory segment of the specified size containing the data from the original
     *         segment (up to the lesser of the new and old sizes), or null if reallocation fails
     */
    MemorySegment realloc(MemorySegment ptr, long size);

    /**
     * Frees a previously allocated memory segment.
     * <p>
     * This method corresponds to the C {@code free} function.
     *
     * @param ptr the memory segment to free
     */
    void free(MemorySegment ptr);

    /**
     * Formats a string using a format string and variable arguments, and writes it to a buffer.
     * <p>
     * This method corresponds to the C {@code vsnprintf} function. It is used by Capstone
     * for formatting error messages and other output.
     * <p>
     * This method has a default implementation that uses {@link FormatStringParser#vsnprintf}
     * for format string parsing and value formatting. Implementations can override this method
     * to provide custom formatting logic if needed.
     *
     * @param str the buffer to write the formatted string to
     * @param size the size of the buffer in bytes
     * @param format the format string
     * @param ap the variable arguments pointer
     * @return the number of characters that would have been written if {@code size} had been
     *         sufficiently large, not counting the terminating null character
     */
    default int vsnprintf(MemorySegment str, long size, MemorySegment format, MemorySegment ap) {
        return FormatStringParser.vsnprintf(str, size, format, ap);
    }
}
