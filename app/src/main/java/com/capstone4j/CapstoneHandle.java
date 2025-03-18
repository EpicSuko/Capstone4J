package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

public class CapstoneHandle implements AutoCloseable {

    private final Arena handleArena;
    private MemorySegment handle;

    private final CapstoneArch arch;
    private final CapstoneMode mode;

    private CapstoneMemoryProvider memoryProvider;

    private final boolean closeHandleArena;

    /**
     * Creates a new Capstone handle with the specified architecture, mode, and options.
     * <p>
     * This is the primary constructor for creating a Capstone handle. It initializes a new handle
     * for the Capstone disassembly engine with the specified architecture and mode, and applies
     * the configuration options provided in the {@code options} parameter.
     * <p>
     * The options parameter can be used to configure:
     * <ul>
     *   <li>The memory arena to use for allocating native resources</li>
     *   <li>Whether the arena should be closed when the handle is closed</li>
     *   <li>A custom memory provider for memory allocation operations</li>
     *   <li>Whether the handle arena should be used by the memory provider</li>
     * </ul>
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
     * <p>
     * For default options, use {@link CapstoneHandleOptions#getDefault()}.
     *
     * @param arch the architecture to use for disassembly (e.g., {@link CapstoneArch#X86}, {@link CapstoneArch#ARM})
     * @param mode the mode to use for disassembly (e.g., {@link CapstoneMode#X86_64}, {@link CapstoneMode#ARM})
     * @param options the options for configuring the Capstone handle
     * @throws RuntimeException if the Capstone handle could not be created due to initialization errors
     * @throws NullPointerException if any of the parameters is null
     * @see CapstoneHandleOptions
     * @see CapstoneArch
     * @see CapstoneMode
     */
    CapstoneHandle(CapstoneArch arch, CapstoneMode mode, CapstoneHandleOptions options) {
        this.arch = arch;
        this.mode = mode;
        this.handleArena = options.getHandleArena();
        this.closeHandleArena = options.isCloseHandleArena();   
        this.memoryProvider = options.getMemoryProvider();

        this.handle = handleArena.allocate(csh.byteSize());

        if(this.memoryProvider != null) {
            MemorySegment memOpt = new CapstoneMemoryManager(memoryProvider).createMemoryOptions();
            CapstoneError err = CapstoneError.fromValue(cs_option(0, CapstoneOption.MEM.getValue(), memOpt.address()));
            if(err != CapstoneError.OK) {
                throw new RuntimeException("Failed to set Capstone memory option: " + CapstoneUtils.getErrorMessage(err));
            }
        }

        CapstoneError err = CapstoneError.fromValue(cs_open(this.arch.getValue(), this.mode.getValue(), handle));
        if(err != CapstoneError.OK) {
            throw new RuntimeException("Failed to create Capstone handle: " + CapstoneUtils.getErrorMessage(err));
        }
    }

    /**
     * Creates a new Capstone handle with the specified architecture and mode.
     * <p>
     * This constructor uses the default options ({@link CapstoneHandleOptions#getDefault()}).
     *
     * @param arch the architecture to use for disassembly
     * @param mode the mode to use for disassembly
     * @throws RuntimeException if the Capstone handle could not be created
     */
    CapstoneHandle(CapstoneArch arch, CapstoneMode mode) {
        this(arch, mode, CapstoneHandleOptions.getDefault());
    }
    
    /**
     * Sets one or more options for the Capstone engine.
     * <p>
     * This method allows configuring the behavior of the Capstone disassembly engine
     * by setting various options. Multiple option values can be combined by passing
     * them as an array, which will be bitwise OR'ed together.
     * <p>
     * <strong>Note:</strong> For memory-related configurations, do not use this method with
     * {@link CapstoneOption#MEM}. Instead, use the {@link CapstoneHandleOptions.Builder#memoryProvider(CapstoneMemoryProvider)}
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
            throw new UnsupportedOperationException("User-defined dynamic memory option is not supported please use CapstoneHandleOptions.Builder.memoryProvider(CapstoneMemoryProvider) instead");
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
     * {@link CapstoneOption#MEM}. Instead, use the {@link CapstoneHandleOptions.Builder#memoryProvider(CapstoneMemoryProvider)}
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
        
        if(closeHandleArena) {
            try {
                handleArena.close();
            } catch(UnsupportedOperationException e) {
                // we are either an Arena.global() or Arena.ofAuto() and cannot close it
                this.handle = null;
            } catch(Exception e) {
                throw new RuntimeException("Failed to close arena: " + e.getMessage(), e);
            }
        }
    }
}