package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

// TODO: Work on vsnprintf implementation
// TODO: (Optional) Create a new CapstoneMemoryProvider that maps the memory segment address to a Arena so that we can close the arena when the memory is freed instead of waiting for the Arena to be closed

public class CapstoneHandle implements AutoCloseable {

    private final Arena handleArena;
    private MemorySegment handle;

    private final CapstoneArch arch;
    private final CapstoneMode mode;

    private CapstoneMemoryProvider memoryProvider;

    private final boolean closeHandleArena;

    private boolean parseDetails = false;

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

        if(option == CapstoneOption.DETAIL) {
            if((flag & CapstoneOptionValue.ON.getValue()) > 0) {
                this.parseDetails = true;
            } else if((flag & CapstoneOptionValue.OFF.getValue()) > 0) {
                this.parseDetails = false;
            }
        }

        CapstoneError err = CapstoneError.fromValue(cs_option(this.handle.get(csh, 0), option.getValue(), flag));
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
     * Retrieves the error code from the Capstone engine.
     * <p>
     * This method returns the last error encountered by the Capstone engine for this handle.
     * The error code can be used to diagnose issues during disassembly operations.
     * <p>
     * The returned error is an enum value from {@link CapstoneError}, which provides
     * detailed information about the specific error condition.
     *
     * @return the Capstone error code representing the last error
     * @throws RuntimeException if the Capstone handle is not initialized
     * @see CapstoneError
     * @see CapstoneUtils#getErrorMessage(CapstoneError)
     */
    public CapstoneError getErrNo() {
        if(this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
        return CapstoneError.fromValue(cs_errno(this.handle.get(csh, 0)));
    }

    /**
     * Retrieves a human-readable description for a specific Capstone error code.
     * <p>
     * This method provides detailed error messages that can help diagnose issues
     * with the Capstone engine. The messages are obtained directly from the 
     * native Capstone library.
     * <p>
     * Example usage:
     * <pre>{@code
     * CapstoneError err = handle.getErrNo();
     * if (err != CapstoneError.OK) {
     *     String errorMessage = handle.getStrError(err);
     *     System.err.println("Capstone error: " + errorMessage);
     * }
     * }</pre>
     *
     * @param error the Capstone error code to get a description for
     * @return a human-readable string describing the error
     * @throws RuntimeException if the Capstone handle is not initialized
     * @see CapstoneError
     * @see #getErrNo()
     */
    public String getStrError(CapstoneError error) {
        if(this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
        MemorySegment errStr = cs_strerror(error.getValue());
        return errStr.getUtf8String(0);
    }

    /**
     * Disassembles a single instruction from the provided byte array.
     * <p>
     * This method takes a byte array containing machine code and attempts to disassemble
     * the first instruction at the specified virtual address. It uses Capstone's native
     * disassembly functionality to analyze the code and create a Java representation of
     * the instruction.
     * <p>
     * The method allocates temporary memory for the disassembly process and ensures proper
     * cleanup, regardless of whether the disassembly succeeds or fails.
     * <p>
     * Example usage:
     * <pre>{@code
     * byte[] machineCode = new byte[] { (byte)0x55, (byte)0x48, (byte)0x89, (byte)0xe5 }; // x86 "push rbp; mov rbp, rsp"
     * long virtualAddress = 0x1000;
     * CapstoneInstruction instruction = handle.disassembleInstruction(machineCode, virtualAddress);
     * if (instruction != null) {
     *     System.out.println(instruction.getMnemonic() + " " + instruction.getOpStr());
     * }
     * }</pre>
     *
     * @param code the byte array containing the machine code to disassemble
     * @param address the virtual address where the code is located (used for instruction addressing)
     * @return a {@link CapstoneInstruction} object representing the disassembled instruction,
     *         or {@code null} if disassembly failed
     * @throws RuntimeException if the Capstone handle is not initialized or if an error occurs during disassembly
     * @see CapstoneInstruction
     * @see CapstoneInstructionFactory
     */
    public CapstoneInstruction disassembleInstruction(byte[] code, long address) {
        if(this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
        try(Arena arena = Arena.ofConfined()) {
            MemorySegment codeRef = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment codeSegment = arena.allocateArray(ValueLayout.JAVA_BYTE, code);
            codeRef.set(ValueLayout.ADDRESS, 0, codeSegment);
                
            MemorySegment sizeRef = arena.allocate(ValueLayout.JAVA_LONG, code.length);

            MemorySegment addressRef = arena.allocate(ValueLayout.JAVA_LONG, address);
            
            MemorySegment insn = cs_malloc(this.handle.get(csh, 0));

            // Call the native function
            boolean result = cs_disasm_iter(
                this.handle.get(csh, 0),
                codeRef,
                sizeRef,
                addressRef,
                insn
            );

            CapstoneInstruction instruction = null;

            if(result) {
                instruction = CapstoneInstructionFactory.createFromMemorySegment(insn, this.arch, this.parseDetails);
            }
            
            cs_free(insn, 1);
            return instruction;
        } catch(Exception e) {
            throw new RuntimeException("Failed to disassemble code: " + e.getMessage(), e);
        }
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