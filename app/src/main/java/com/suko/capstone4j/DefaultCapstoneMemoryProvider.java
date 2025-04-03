package com.suko.capstone4j;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * A default implementation of {@link CapstoneMemoryProvider} that uses a Java Arena for memory management.
 * <p>
 * This class provides memory allocation, reallocation, and deallocation services using a
 * Java {@link Arena}. The Arena handles the lifecycle of the memory segments, automatically
 * cleaning up when the Arena is closed.
 * <p>
 * The memory provider implements the standard C memory management functions (malloc, calloc, realloc, free)
 * using Java's Arena-based memory management. Since Java's Arena automatically handles memory cleanup,
 * the {@link #free(MemorySegment)} method is effectively a no-op.
 * <p>
 * This implementation is used by default when creating a Capstone handle with the default options.
 * <p>
 * Example usage:
 * <pre>{@code
 * // Using with a custom arena
 * try (Arena arena = Arena.ofConfined()) {
 *     // Create a provider with the arena
 *     DefaultCapstoneMemoryProvider provider = new DefaultCapstoneMemoryProvider(arena);
 *     
 *     // Use the provider with a handle through CapstoneHandleOptions
 *     CapstoneHandleOptions options = CapstoneHandleOptions.builder()
 *         .memoryProvider(provider)
 *         .build();
 *     
 *     CapstoneHandle handle = new CapstoneHandle(CapstoneArch.X86, CapstoneMode.X86_64, options);
 *     
 *     // Use handle...
 * } // arena is closed automatically, releasing all allocated memory
 * }</pre>
 *
 * @see CapstoneMemoryProvider
 * @see Arena
 * @see CapstoneHandleOptions
 */
public class DefaultCapstoneMemoryProvider implements CapstoneMemoryProvider {
    
    private Arena arena;

    /**
     * Creates a new DefaultCapstoneMemoryProvider with the specified arena.
     * <p>
     * This constructor creates a memory provider that will use the specified arena for
     * all memory allocation operations. The arena will be responsible for the lifecycle
     * of all allocated memory segments.
     * 
     * @param arena the arena to use for memory management
     * @throws NullPointerException if the arena is null
     */
    public DefaultCapstoneMemoryProvider(Arena arena) {
        if (arena == null) {
            throw new NullPointerException("Arena cannot be null");
        }
        this.arena = arena;
    }

    /**
     * Creates a new DefaultCapstoneMemoryProvider without an arena.
     * <p>
     * When using this constructor, an arena must be set using {@link #setArena(Arena)}
     * before calling any memory allocation methods. Attempting to allocate memory
     * without setting an arena will result in an {@link IllegalStateException}.
     * <p>
     * This constructor is primarily intended for use with the builder pattern
     * through {@link CapstoneHandleOptions}.
     */
    public DefaultCapstoneMemoryProvider() {
        this.arena = null;
    }

    /**
     * Sets the arena to be used for memory management.
     * <p>
     * This method updates the arena that this memory provider uses for memory allocation.
     * If this provider is already in use, changing the arena will not affect previously
     * allocated memory segments, but all future allocations will use the new arena.
     *
     * @param arena the arena to use for memory management
     * @throws NullPointerException if the arena is null
     */
    @Override
    public void setArena(Arena arena) {
        if (arena == null) {
            throw new NullPointerException("Arena cannot be null");
        }
        this.arena = arena;
    }

    /**
     * Gets the arena currently being used for memory management.
     *
     * @return the current arena used for memory management, or null if no arena has been set
     */
    @Override
    public Arena getArena() {
        return this.arena;
    }

    /**
     * Allocates memory of the specified size.
     * <p>
     * This method corresponds to the C {@code malloc} function. It allocates a block
     * of memory of the specified size using the current arena.
     *
     * @param size the number of bytes to allocate
     * @return a memory segment of the specified size
     * @throws IllegalStateException if no arena has been set
     * @throws IllegalArgumentException if the size is negative
     */
    @Override
    public MemorySegment malloc(long size) {
        if (arena == null) {
            throw new IllegalStateException("Arena not set. Call setArena(Arena) first.");
        }
        
        if (size < 0) {
            throw new IllegalArgumentException("Size cannot be negative");
        }
        return arena.allocate(size);
    }

    /**
     * Allocates zero-initialized memory for an array.
     * <p>
     * This method corresponds to the C {@code calloc} function. It allocates memory
     * for an array of {@code nmemb} elements, each of {@code size} bytes, and initializes
     * all bytes to zero.
     *
     * @param nmemb the number of elements to allocate
     * @param size the size of each element in bytes
     * @return a zero-initialized memory segment of size {@code nmemb * size}
     * @throws IllegalStateException if no arena has been set
     * @throws IllegalArgumentException if the nmemb or size is negative, or if their product would overflow
     */
    @Override
    public MemorySegment calloc(long nmemb, long size) {
        if (arena == null) {
            throw new IllegalStateException("Arena not set. Call setArena(Arena) first.");
        }
        
        if (nmemb < 0 || size < 0) {
            throw new IllegalArgumentException("Number of elements and size cannot be negative");
        }
        
        if (nmemb > 0 && size > Long.MAX_VALUE / nmemb) {
            throw new IllegalArgumentException("Size would overflow: " + nmemb + " * " + size);
        }
        
        // Allocate and zero-initialize the memory
        MemorySegment segment = arena.allocate(nmemb * size);
        segment.fill((byte) 0);
        return segment;
    }

    /**
     * Changes the size of a previously allocated memory segment.
     * <p>
     * This method corresponds to the C {@code realloc} function. It changes the size of the
     * memory segment pointed to by {@code ptr} to {@code size} bytes. The contents of the
     * memory segment will be unchanged up to the minimum of the old and new sizes.
     * <p>
     * If {@code ptr} is null, this function behaves like {@link #malloc(long)}.
     * If {@code size} is 0, this function behaves like {@link #free(MemorySegment)}.
     * <p>
     * Note that unlike C's realloc, this implementation always allocates a new segment
     * and copies the data, as Java's Arena-based memory management doesn't support
     * in-place resizing.
     *
     * @param ptr the memory segment to resize
     * @param size the new size in bytes
     * @return a memory segment of the specified size containing the data from the original
     *         segment (up to the lesser of the new and old sizes), or null if size is 0
     * @throws IllegalStateException if no arena has been set
     * @throws IllegalArgumentException if the size is negative
     */
    @Override
    public MemorySegment realloc(MemorySegment ptr, long size) {
        if (arena == null) {
            throw new IllegalStateException("Arena not set. Call setArena(Arena) first.");
        }
        
        if (size < 0) {
            throw new IllegalArgumentException("Size cannot be negative");
        }
        
        if (ptr == null || ptr.byteSize() == 0) {
            // If ptr is null, realloc behaves like malloc
            return malloc(size);
        }
        
        if (size == 0) {
            // If size is 0, realloc behaves like free
            free(ptr);
            return null;
        }
        
        // Allocate new memory and copy the data
        MemorySegment newPtr = arena.allocate(size);
        long bytesToCopy = Math.min(ptr.byteSize(), size);
        MemorySegment.copy(ptr, 0, newPtr, 0, bytesToCopy);
        
        // Note: We don't need to explicitly free the old memory segment
        // as it will be handled by the Arena when it's closed
        
        return newPtr;
    }

    /**
     * Frees a previously allocated memory segment.
     * <p>
     * This method corresponds to the C {@code free} function. However, since Java's
     * Arena-based memory management automatically handles memory cleanup when the arena
     * is closed, this method is effectively a no-op.
     * <p>
     * The memory will only be truly freed when the associated arena is closed.
     *
     * @param ptr the memory segment to free (may be null, which is a no-op)
     */
    @Override
    public void free(MemorySegment ptr) {
        // No explicit action needed - the Arena will handle memory cleanup when closed
        // This is a no-op because Java's Arena-based memory management doesn't require
        // explicit freeing of individual segments
    }
} 