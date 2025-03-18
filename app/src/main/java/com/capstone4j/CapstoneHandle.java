package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import com.capstone4j.internal.capstone_h;
import com.capstone4j.CapstoneError;

public class CapstoneHandle implements AutoCloseable {

    private final Arena arena;
    private MemorySegment handle;

    private final CapstoneArch arch;
    private final CapstoneMode mode;

    private final boolean closeArena;

    /**
     * Creates a new Capstone handle with the specified architecture, mode, arena, and arena closing behavior.
     *
     * @param arch the architecture to use for disassembly
     * @param mode the mode to use for disassembly
     * @param arena the memory arena to allocate native resources from
     * @param closeArena whether to close the arena when this handle is closed
     * @throws RuntimeException if the Capstone handle could not be created
     */
    CapstoneHandle(CapstoneArch arch, CapstoneMode mode, Arena arena, boolean closeArena) {
        this.arch = arch;
        this.mode = mode;
        this.closeArena = closeArena;

        this.arena = arena;
        this.handle = arena.allocate(csh.byteSize());

        CapstoneError err = CapstoneError.fromValue(cs_open(arch.getValue(), mode.getValue(), handle));
        if(err != CapstoneError.OK) {
            throw new RuntimeException("Failed to create Capstone handle: " + CapstoneUtils.getErrorMessage(err));
        }
    }

    /**
     * Creates a new Capstone handle with the specified architecture, mode, and arena.
     * <p>
     * The arena will be closed when this handle is closed.
     *
     * @param arch the architecture to use for disassembly
     * @param mode the mode to use for disassembly
     * @param arena the memory arena to allocate native resources from
     * @throws RuntimeException if the Capstone handle could not be created
     */
    CapstoneHandle(CapstoneArch arch, CapstoneMode mode, Arena arena) {
        this(arch, mode, arena, true);
    }

    /**
     * Creates a new Capstone handle with the specified architecture and mode.
     * <p>
     * This constructor uses a shared arena that will be closed when this handle is closed.
     *
     * @param arch the architecture to use for disassembly
     * @param mode the mode to use for disassembly
     * @throws RuntimeException if the Capstone handle could not be created
     */
    CapstoneHandle(CapstoneArch arch, CapstoneMode mode) {
        this(arch, mode, Arena.ofShared());
    }
    
    /**
     * Sets one or more options for the Capstone engine.
     * <p>
     * This method allows configuring the behavior of the Capstone disassembly engine
     * by setting various options. Multiple option values can be combined by passing
     * them as an array, which will be bitwise OR'ed together.
     * <p>
     * <strong>Note:</strong> For memory-related configurations, do not use this method with
     * {@link CapstoneOption#MEM}. Instead, use the {@link #setMemoryProvider(CapstoneMemoryProvider)}
     * method which provides a more appropriate interface for configuring custom memory allocation.
     * 
     * @param option the option to set, must not be {@link CapstoneOption#INVALID} or {@link CapstoneOption#MEM}
     * @param values an array of option values to be applied (combined with bitwise OR)
     * @throws RuntimeException if the Capstone handle is not initialized or if setting the option fails
     * @throws IllegalArgumentException if the option is {@link CapstoneOption#INVALID}
     * @throws UnsupportedOperationException if the option is {@link CapstoneOption#MEM}
     * @see CapstoneOption
     * @see CapstoneOptionValue
     */
    public void setOption(CapstoneOption option, CapstoneOptionValue[] values) {
        if(handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
        if(option == CapstoneOption.INVALID) {
            throw new IllegalArgumentException("Invalid option");
        } else if(option == CapstoneOption.MEM) {
            throw new UnsupportedOperationException("User-defined dynamic memory option is not supported please use setMemoryProvider(CapstoneMemoryProvider) instead");
        }

        int flag = 0;
        for(CapstoneOptionValue value : values) {
            flag |= value.getValue();
        }

        CapstoneError err = CapstoneError.fromValue(cs_option(handle.address(), option.getValue(), flag));
        if(err != CapstoneError.OK) {
            throw new RuntimeException("Failed to set Capstone option: " + CapstoneUtils.getErrorMessage(err));
        }
    }

    /**
     * Sets a single option for the Capstone engine.
     * <p>
     * This is a convenience method that calls {@link #setOption(CapstoneOption, CapstoneOptionValue[])}
     * with a single value.
     * <p>
     * <strong>Note:</strong> For memory-related configurations, do not use this method with
     * {@link CapstoneOption#MEM}. Instead, use the {@link #setMemoryProvider(CapstoneMemoryProvider)}
     * method which provides a more appropriate interface for configuring custom memory allocation.
     *
     * @param option the option to set, must not be {@link CapstoneOption#INVALID} or {@link CapstoneOption#MEM}
     * @param value the option value to be applied
     * @throws RuntimeException if the Capstone handle is not initialized or if setting the option fails
     * @throws IllegalArgumentException if the option is {@link CapstoneOption#INVALID}
     * @throws UnsupportedOperationException if the option is {@link CapstoneOption#MEM}
     * @see #setOption(CapstoneOption, CapstoneOptionValue[])
     * @see CapstoneOption
     * @see CapstoneOptionValue
     */
    public void setOption(CapstoneOption option, CapstoneOptionValue value) {
        setOption(option, new CapstoneOptionValue[] { value });
    }

    /**
     * Sets a custom memory provider for the Capstone engine.
     * <p>
     * This method allows configuring custom memory allocation for the Capstone engine.
     * However, the implementation is currently pending and will throw an
     * {@link UnsupportedOperationException} if called.
     * 
     * @param provider the memory provider to use for custom memory allocation
     * @throws UnsupportedOperationException this feature is not yet implemented
     */
    public void setMemoryProvider(CapstoneMemoryProvider provider) {
        throw new UnsupportedOperationException("Setting a custom memory provider is not yet implemented");
    }

    /**
     * Closes this Capstone handle and releases associated resources.
     * <p>
     * This method closes the underlying Capstone engine instance and, if configured to do so,
     * also closes the associated memory arena. After this method is called, the handle
     * is no longer valid and cannot be used.
     * <p>
     * This method is automatically called when using try-with-resources.
     *
     * @throws Exception if an error occurs while closing the handle or the arena
     * @throws RuntimeException if the Capstone handle could not be closed properly
     */
    @Override
    public void close() throws Exception {
        if(handle != null) {
            CapstoneError err = CapstoneError.fromValue(cs_close(handle));
            if(err != CapstoneError.OK) {
                throw new RuntimeException("Failed to close Capstone handle: " + CapstoneUtils.getErrorMessage(err));
            }
        }
        
        if(closeArena) {
            try {
                arena.close();
            } catch(UnsupportedOperationException e) {
                // we are either an Arena.global() or Arena.ofAuto() and cannot close it
                this.handle = null;
            } catch(Exception e) {
                throw new RuntimeException("Failed to close arena: " + e.getMessage(), e);
            }
        }
    }
}