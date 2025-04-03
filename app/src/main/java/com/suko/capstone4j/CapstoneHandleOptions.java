package com.suko.capstone4j;

import java.lang.foreign.Arena;

/**
 * Configuration options for creating a {@link CapstoneHandle}.
 * <p>
 * This class uses the builder pattern to configure options for the Capstone handle.
 * It allows setting various parameters like the memory arena, arena closing behavior,
 * and memory provider.
 * <p>
 * Example usage:
 * <pre>{@code
 * CapstoneHandleOptions options = CapstoneHandleOptions.builder()
 *     .handleArena(Arena.ofConfined())
 *     .closeHandleArena(true)
 *     .memoryProvider(new DefaultCapstoneMemoryProvider())
 *     .useHandleArena(true)
 *     .build();
 * 
 * CapstoneHandle handle = new CapstoneHandle(CapstoneArch.X86, CapstoneMode.X86_64, options);
 * }</pre>
 */
public class CapstoneHandleOptions {
    private final Arena handleArena;
    private final boolean closeHandleArena;
    private final CapstoneMemoryProvider memoryProvider;
    private final boolean useHandleArena;

    private CapstoneHandleOptions(Builder builder) {
        this.handleArena = builder.handleArena;
        this.closeHandleArena = builder.closeHandleArena;
        this.memoryProvider = builder.memoryProvider;
        this.useHandleArena = builder.useHandleArena;
    }

    /**
     * Returns the memory arena to be used by the Capstone handle.
     * 
     * @return the memory arena
     */
    public Arena getHandleArena() {
        return handleArena;
    }

    /**
     * Returns whether the arena should be closed when the Capstone handle is closed.
     * 
     * @return true if the arena should be closed, false otherwise
     */
    public boolean isCloseHandleArena() {
        return closeHandleArena;
    }

    /**
     * Returns the memory provider to be used by the Capstone handle.
     * 
     * @return the memory provider, or null if not set
     */
    public CapstoneMemoryProvider getMemoryProvider() {
        return memoryProvider;
    }

    /**
     * Returns whether the handle arena should be used by the CapstoneMemoryProvider.
     * 
     * @return true if the handle arena should be used, false otherwise
     */
    public boolean useHandleArena() {
        return useHandleArena;
    }

    /**
     * Creates a new builder for {@link CapstoneHandleOptions}.
     * 
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the default options for a Capstone handle.
     * <p>
     * The default options use a shared arena that is closed when the handle is closed,
     * and a {@link DefaultCapstoneMemoryProvider} that uses the same shared arena.
     * 
     * @return the default options
     */
    public static CapstoneHandleOptions getDefault() {
        return builder().build();
    }

    /**
     * Builder for {@link CapstoneHandleOptions}.
     */
    public static class Builder {
        private Arena handleArena = Arena.ofShared();
        private boolean closeHandleArena = true;
        private CapstoneMemoryProvider memoryProvider = new DefaultCapstoneMemoryProvider();
        private boolean useHandleArena = true;

        private Builder() {
            // Private constructor to enforce the use of builder() method
        }

        /**
         * Sets the memory arena to be used by the Capstone handle.
         * 
         * @param handleArena the handle memory arena
         * @return this builder
         */
        public Builder handleArena(Arena handleArena) {
            if(handleArena == null) {
                throw new IllegalArgumentException("Handle arena cannot be null");
            }
            this.handleArena = handleArena;
            return this;
        }

        /**
         * Sets whether the arena should be closed when the Capstone handle is closed.
         * 
         * @param closeHandleArena true if the handle arena should be closed, false otherwise
         * @return this builder
         */
        public Builder closeHandleArena(boolean closeHandleArena) {
            this.closeHandleArena = closeHandleArena;
            return this;
        }

        /**
         * Sets the memory provider to be used by the Capstone handle.
         * 
         * @param memoryProvider the memory provider
         * @return this builder
         */
        public Builder memoryProvider(CapstoneMemoryProvider memoryProvider) {
            this.memoryProvider = memoryProvider;
            return this;
        }

        /**
         * Sets whether the handle arena should be used by the CapstoneMemoryProvider.
         * 
         * @param useHandleArena true if the handle arena should be used, false otherwise
         * @return this builder
         */
        public Builder useHandleArena(boolean useHandleArena) {
            this.useHandleArena = useHandleArena;
            return this;
        }

        /**
         * Builds the {@link CapstoneHandleOptions} with the configured options.
         * 
         * @return a new {@link CapstoneHandleOptions} instance
         */
        public CapstoneHandleOptions build() {
            if (memoryProvider != null && handleArena != null) {
                if (useHandleArena) {
                    memoryProvider.setArena(handleArena);
                }
            }
            return new CapstoneHandleOptions(this);
        }
    }
} 