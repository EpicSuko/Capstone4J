package com.suko.capstone4j;

import static com.suko.capstone4j.internal.capstone_h.*;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

// TODO: (Optional) Create a new CapstoneMemoryProvider that maps the memory segment address to a Arena so that we can close the arena when the memory is freed instead of waiting for the Arena to be closed

public class CapstoneHandle implements AutoCloseable {

    private final Arena handleArena;
    private MemorySegment handle;

    private final CapstoneArch arch;
    private final CapstoneMode[] modes;

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
     * CapstoneHandle handle = new CapstoneHandle(CapstoneArch.X86, new CapstoneMode[] {CapstoneMode.X86_64}, options);
     * }</pre>
     * <p>
     * For default options, use {@link CapstoneHandleOptions#getDefault()}.
     *
     * @param arch the architecture to use for disassembly (e.g., {@link CapstoneArch#X86}, {@link CapstoneArch#ARM})
     * @param modes the modes to use for disassembly (e.g., {@link CapstoneMode#X86_64}, {@link CapstoneMode#ARM})
     * @param options the options for configuring the Capstone handle
     * @throws RuntimeException if the Capstone handle could not be created due to initialization errors
     * @throws NullPointerException if any of the parameters is null
     * @see CapstoneHandleOptions
     * @see CapstoneArch
     * @see CapstoneMode
     */
    CapstoneHandle(CapstoneArch arch, CapstoneMode[] modes, CapstoneHandleOptions options) {
        this.arch = arch;
        this.modes = modes;
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

        CapstoneError err = CapstoneError.fromValue(cs_open(this.arch.getValue(), CapstoneMode.toValue(this.modes), handle));
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
     * @param modes the modes to use for disassembly
     * @throws RuntimeException if the Capstone handle could not be created
     */
    CapstoneHandle(CapstoneArch arch, CapstoneMode[] modes) {
        this(arch, modes, CapstoneHandleOptions.getDefault());
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
        return errStr.getString(0);
    }

    /**
     * Disassembles a chunk of code from a memory segment.
     * <p>
     * This internal method handles the low-level disassembly of a single instruction from a memory segment.
     * It creates the necessary memory references and calls the native Capstone disassembly function.
     * If disassembly fails, it returns a "bad instruction" with the first byte of the chunk.
     * 
     * @param <A> the type of architecture-specific details this instruction will contain
     * @param arena the memory arena used for temporary allocations
     * @param chunkData the memory segment containing the code to disassemble
     * @param chunkSize the size of the code chunk in bytes
     * @param address the virtual address where the code is located
     * @param insn the memory segment for storing the disassembled instruction
     * @return a CapstoneInstruction object representing the disassembled instruction
     * @throws RuntimeException if disassembly fails with an error
     */
    private <A extends CapstoneArchDetails<?> & MemorySegmentCreatable<A>> CapstoneInstruction<A> disassembleChunk(Arena arena, MemorySegment chunkData, long chunkSize, long address, MemorySegment insn) {
        // Create a new segment that points to the current offset
        MemorySegment currentSegment = chunkData.asSlice(0, chunkSize);
        MemorySegment codeRef = arena.allocateFrom(ValueLayout.ADDRESS, currentSegment);
        MemorySegment sizeRef = arena.allocateFrom(ValueLayout.JAVA_LONG, chunkSize);
        MemorySegment addressRef = arena.allocateFrom(ValueLayout.JAVA_LONG, address);
        
        boolean result = cs_disasm_iter(
            this.handle.get(csh, 0),
            codeRef,
            sizeRef,
            addressRef,
            insn
        );
        
        if (!result) {
            CapstoneError error = getErrNo();
            if (error != CapstoneError.OK) {
                throw new RuntimeException("Disassembly failed with error: " + error + " - " + getStrError(error));
            }
            return CapstoneInstructionFactory.createBadInstruction(address, currentSegment.get(ValueLayout.JAVA_BYTE, 0), this.arch);
        }
        
        return CapstoneInstructionFactory.createFromMemorySegment(this.handle, insn, this.arch, this.parseDetails);
    }

    /**
     * Disassembles a single instruction from the provided byte array.
     * <p>
     * This method takes a byte array containing machine code and attempts to disassemble
     * the first instruction at the specified virtual address. It uses Capstone's native
     * disassembly functionality to analyze the code and create a Java representation of
     * the instruction.
     * <p>
     * The generic type parameter {@code A} represents the architecture-specific details
     * that will be included in the disassembled instruction. The actual type of {@code A}
     * depends on the architecture specified when creating the {@link CapstoneHandle}:
     * <ul>
     *   <li>For X86 architecture: {@code CapstoneInstruction<CapstoneX86Details>}</li>
     *   <li>For other architectures: corresponding architecture-specific detail classes</li>
     * </ul>
     * <p>
     * The method allocates temporary memory for the disassembly process and ensures proper
     * cleanup, regardless of whether the disassembly succeeds or fails.
     * <p>
     * Example usage for X86 architecture:
     * <pre>{@code
     * byte[] machineCode = new byte[] { (byte)0x55, (byte)0x48, (byte)0x89, (byte)0xe5 }; // x86 "push rbp; mov rbp, rsp"
     * long virtualAddress = 0x1000;
     * 
     * // Enable instruction details for architecture-specific information
     * handle.setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON);
     * 
     * CapstoneInstruction<CapstoneX86Details> instruction = handle.disassembleInstruction(machineCode, virtualAddress);
     * if (instruction != null) {
     *     System.out.println(instruction.getMnemonic() + " " + instruction.getOpStr());
     *     
     *     // Access architecture-specific details
     *     if (instruction.getDetails() != null) {
     *         CapstoneX86Details x86Details = instruction.getDetails().getArchDetails();
     *         System.out.println("Operand count: " + x86Details.getOpCount());
     *     }
     * }
     * }</pre>
     * <p>
     * To get the full benefit of architecture-specific details, you should cast the returned
     * instruction to the appropriate type based on the architecture you're working with, and
     * enable instruction details using {@code setOption(CapstoneOption.DETAIL, CapstoneOptionValue.ON)}.
     *
     * @param <A> the type of architecture-specific details this instruction will contain,
     *            must extend {@link CapstoneArchDetails}
     * @param code the byte array containing the machine code to disassemble
     * @param address the virtual address where the code is located (used for instruction addressing)
     * @return a {@link CapstoneInstruction} object representing the disassembled instruction with
     *         architecture-specific details of type {@code A}, or {@code null} if disassembly failed
     * @throws RuntimeException if the Capstone handle is not initialized or if an error occurs during disassembly
     * @see CapstoneInstruction
     * @see CapstoneInstructionDetails
     * @see CapstoneArchDetails
     * @see CapstoneOption#DETAIL
     */
    public <A extends CapstoneArchDetails<?> & MemorySegmentCreatable<A>> CapstoneInstruction<A> disassembleInstruction(byte[] code, long address) {
        if (this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
        
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment chunkData = arena.allocateFrom(ValueLayout.JAVA_BYTE, code);
            MemorySegment insn = cs_malloc(this.handle.get(csh, 0));
            try {
                return disassembleChunk(arena, chunkData, code.length, address, insn);
            } finally {
                cs_free(insn, 1);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to disassemble code: " + e.getMessage(), e);
        }
    }

    public <A extends CapstoneArchDetails<?> & MemorySegmentCreatable<A>> List<CapstoneInstruction<A>> disassembleAllInstructions(byte[] code, long startAddress) {
        if (this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
    
        List<CapstoneInstruction<A>> instructions = new ArrayList<>();
        final int CHUNK_SIZE = 1024 * 1024;
        int currentOffset = 0;
        long currentAddress = startAddress;
        
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment insn = cs_malloc(this.handle.get(csh, 0));
            try {
                while (currentOffset < code.length) {
                    int chunkSize = Math.min(CHUNK_SIZE, code.length - currentOffset);
                    MemorySegment chunkData = arena.allocateFrom(
                        ValueLayout.JAVA_BYTE,
                        Arrays.copyOfRange(code, currentOffset, currentOffset + chunkSize)
                    );
                    
                    CapstoneInstruction<A> instruction = disassembleChunk(
                        arena, chunkData, chunkSize, currentAddress, insn
                    );
                    
                    if (instruction != null) {
                        instructions.add(instruction);
                        currentAddress += instruction.getSize();
                        currentOffset += instruction.getSize();
                    } else {
                        currentOffset += chunkSize;
                    }
                }
            } finally {
                cs_free(insn, 1);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to disassemble code: " + e.getMessage(), e);
        }
        
        return instructions;
    }

    /**
     * Disassembles instructions from an input stream and returns them as a list.
     * <p>
     * This method reads the input stream in chunks and disassembles all instructions,
     * maintaining proper instruction boundaries and address tracking. It's particularly
     * useful for processing large files that can't be loaded entirely into memory.
     * <p>
     * Example usage:
     * <pre>{@code
     * try (InputStream inputStream = new FileInputStream("binary.exe")) {
     *     List<CapstoneInstruction<CapstoneX86Details>> instructions = 
     *         handle.disassembleStreamToList(inputStream, 0x1000);
     *     
     *     for (CapstoneInstruction<CapstoneX86Details> instruction : instructions) {
     *         System.out.println(String.format("0x%x: %s %s", 
     *             instruction.getAddress(),
     *             instruction.getMnemonic(),
     *             instruction.getOpStr()));
     *     }
     * }
     * }</pre>
     *
     * @param <A> the type of architecture-specific details this instruction will contain
     * @param inputStream the input stream containing the machine code to disassemble
     * @param startAddress the virtual address where the code starts
     * @return a list of disassembled instructions
     * @throws IOException if an I/O error occurs while reading from the input stream
     * @throws RuntimeException if the Capstone handle is not initialized or if disassembly fails
     */
    public <A extends CapstoneArchDetails<?> & MemorySegmentCreatable<A>> List<CapstoneInstruction<A>> disassembleStreamToList(InputStream inputStream, long startAddress) throws IOException {
        if (this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
    
        List<CapstoneInstruction<A>> instructions = new ArrayList<>();
        final int CHUNK_SIZE = 1024 * 1024; // 1MB chunks
        byte[] buffer = new byte[CHUNK_SIZE];
        long currentAddress = startAddress;
        
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment insn = cs_malloc(this.handle.get(csh, 0));
            try {
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    if (bytesRead == 0) {
                        continue; // Skip empty chunks
                    }
                    
                    MemorySegment chunkData = arena.allocateFrom(
                        ValueLayout.JAVA_BYTE,
                        Arrays.copyOf(buffer, bytesRead)
                    );
                    
                    // Process all instructions in the current chunk
                    while (bytesRead > 0) {
                        CapstoneInstruction<A> instruction = disassembleChunk(
                            arena, chunkData, bytesRead, currentAddress, insn
                        );
                        
                        if (instruction != null) {
                            instructions.add(instruction);
                            currentAddress += instruction.getSize();
                            
                            // Update the chunk data to point to the next instruction
                            int instructionSize = instruction.getSize();
                            if (instructionSize > bytesRead) {
                                break; // Prevent out of bounds access
                            }
                            
                            chunkData = chunkData.asSlice(instructionSize);
                            bytesRead -= instructionSize;
                        } else {
                            break;
                        }
                    }
                }
            } finally {
                cs_free(insn, 1);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to disassemble code: " + e.getMessage(), e);
        }
        
        return instructions;
    }

    /**
     * Returns a stream of disassembled instructions from an input stream.
     * <p>
     * This method provides a streaming interface for disassembling instructions from an input stream.
     * It reads the input stream in chunks and yields instructions one at a time, making it memory-efficient
     * for processing large files. The stream will terminate when the end of the input stream is reached
     * or when disassembly fails.
     * <p>
     * Example usage:
     * <pre>{@code
     * try (InputStream inputStream = new FileInputStream("large_binary.exe")) {
     *     try (Stream<CapstoneInstruction<CapstoneX86Details>> stream = 
     *         handle.disassembleStream(inputStream, 0x1000)) {
     *         stream.forEach(instruction -> {
     *             System.out.println(String.format("0x%x: %s %s", 
     *                 instruction.getAddress(),
     *                 instruction.getMnemonic(),
     *                 instruction.getOpStr()));
     *         });
     *     }
     * }
     * }</pre>
     *
     * @param <A> the type of architecture-specific details this instruction will contain
     * @param inputStream the input stream containing the machine code to disassemble
     * @param startAddress the virtual address where the code starts
     * @return a stream of disassembled instructions
     * @throws IOException if an I/O error occurs while reading from the input stream
     * @throws RuntimeException if the Capstone handle is not initialized or if disassembly fails
     */
    public <A extends CapstoneArchDetails<?> & MemorySegmentCreatable<A>> Stream<CapstoneInstruction<A>> disassembleStream(InputStream inputStream, long startAddress) throws IOException {
        if (this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
    
        final int CHUNK_SIZE = 1024 * 1024; // 1MB chunks
        byte[] buffer = new byte[CHUNK_SIZE];
        final AtomicLong currentAddress = new AtomicLong(startAddress);
        final AtomicInteger currentChunkOffset = new AtomicInteger(0);
        final AtomicInteger currentChunkSize = new AtomicInteger(0);
        final AtomicReference<MemorySegment> currentChunk = new AtomicReference<>();
        
        return Stream.generate(() -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment insn = cs_malloc(this.handle.get(csh, 0));
                try {
                    // If we've processed all instructions in the current chunk, read the next chunk
                    if (currentChunkOffset.get() >= currentChunkSize.get()) {
                        int bytesRead = inputStream.read(buffer);
                        if (bytesRead == -1) {
                            return null;
                        }
                        
                        currentChunk.set(arena.allocateFrom(
                            ValueLayout.JAVA_BYTE,
                            Arrays.copyOf(buffer, bytesRead)
                        ));
                        currentChunkSize.set(bytesRead);
                        currentChunkOffset.set(0);
                    }
                    
                    // Get the current chunk data starting from the current offset
                    MemorySegment chunkData = currentChunk.get().asSlice(currentChunkOffset.get());
                    int remainingSize = currentChunkSize.get() - currentChunkOffset.get();
                    
                    CapstoneInstruction<A> instruction = disassembleChunk(
                        arena, chunkData, remainingSize, currentAddress.get(), insn
                    );
                    
                    if (instruction != null) {
                        currentAddress.addAndGet(instruction.getSize());
                        currentChunkOffset.addAndGet(instruction.getSize());
                    }
                    
                    return instruction;
                } finally {
                    cs_free(insn, 1);
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to disassemble code: " + e.getMessage(), e);
            }
        }).takeWhile(Objects::nonNull);
    }

    /**
     * Disassembles instructions from a memory segment, which is useful for memory-mapped files.
     * <p>
     * This method is particularly efficient for large files as it works directly with the memory segment
     * without copying data. It's ideal for use with memory-mapped files where the data is already
     * mapped into memory.
     * <p>
     * Example usage with memory-mapped files:
     * <pre>{@code
     * try (FileChannel channel = FileChannel.open(Paths.get("large_binary.exe"), StandardOpenOption.READ)) {
     *     MemorySegment mappedSegment = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size(), arena);
     *     List<CapstoneInstruction<CapstoneX86Details>> instructions = 
     *         handle.disassembleMemory(mappedSegment, channel.size(), 0x1000);
     *     // Process instructions...
     * }
     * }</pre>
     *
     * @param <A> the type of architecture-specific details this instruction will contain
     * @param memorySegment the memory segment containing the code to disassemble
     * @param size the size of the code in bytes
     * @param startAddress the virtual address where the code is located
     * @return a list of disassembled instructions
     * @throws RuntimeException if the Capstone handle is not initialized or if disassembly fails
     */
    public <A extends CapstoneArchDetails<?> & MemorySegmentCreatable<A>> List<CapstoneInstruction<A>> disassembleMemory(MemorySegment memorySegment, long size, long startAddress) {
        if (this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }

        List<CapstoneInstruction<A>> instructions = new ArrayList<>();
        long currentAddress = startAddress;
        long currentOffset = 0;
        
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment insn = cs_malloc(this.handle.get(csh, 0));
            try {
                while (currentOffset < size) {
                    CapstoneInstruction<A> instruction = disassembleChunk(
                        arena, 
                        memorySegment.asSlice(currentOffset), 
                        size - currentOffset, 
                        currentAddress, 
                        insn
                    );
                    
                    if (instruction != null) {
                        instructions.add(instruction);
                        int instructionSize = instruction.getSize();
                        if (instructionSize > (size - currentOffset)) {
                            break; // Prevent out of bounds access
                        }
                        currentAddress += instructionSize;
                        currentOffset += instructionSize;
                    } else {
                        break;
                    }
                }
            } finally {
                cs_free(insn, 1);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to disassemble code: " + e.getMessage(), e);
        }
        
        return instructions;
    }

    /**
     * Returns a stream of instructions from a memory segment, which is useful for memory-mapped files.
     * <p>
     * This method provides a streaming interface for disassembling instructions from a memory segment,
     * making it memory-efficient for processing large memory-mapped files.
     * <p>
     * Example usage with memory-mapped files:
     * <pre>{@code
     * try (FileChannel channel = FileChannel.open(Paths.get("large_binary.exe"), StandardOpenOption.READ)) {
     *     MemorySegment mappedSegment = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size(), arena);
     *     try (Stream<CapstoneInstruction<CapstoneX86Details>> stream = 
     *         handle.disassembleMemoryStream(mappedSegment, channel.size(), 0x1000)) {
     *         stream.forEach(instruction -> {
     *             System.out.println(instruction.getMnemonic() + " " + instruction.getOpStr());
     *         });
     *     }
     * }
     * }</pre>
     *
     * @param <A> the type of architecture-specific details this instruction will contain
     * @param memorySegment the memory segment containing the code to disassemble
     * @param size the size of the code in bytes
     * @param startAddress the virtual address where the code is located
     * @return a stream of disassembled instructions
     * @throws RuntimeException if the Capstone handle is not initialized or if disassembly fails
     */
    public <A extends CapstoneArchDetails<?> & MemorySegmentCreatable<A>> Stream<CapstoneInstruction<A>> disassembleMemoryStream(MemorySegment memorySegment, long size, long startAddress) {
        if (this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }

        final AtomicLong currentAddress = new AtomicLong(startAddress);
        final AtomicLong currentOffset = new AtomicLong(0);
        
        return Stream.generate(() -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment insn = cs_malloc(this.handle.get(csh, 0));
                try {
                    if (currentOffset.get() >= size) {
                        return null;
                    }
                    
                    CapstoneInstruction<A> instruction = disassembleChunk(
                        arena, 
                        memorySegment.asSlice(currentOffset.get()), 
                        size - currentOffset.get(), 
                        currentAddress.get(), 
                        insn
                    );
                    
                    if (instruction != null) {
                        int instructionSize = instruction.getSize();
                        if (instructionSize > (size - currentOffset.get())) {
                            return null; // Prevent out of bounds access
                        }
                        currentAddress.addAndGet(instructionSize);
                        currentOffset.addAndGet(instructionSize);
                    }
                    
                    return instruction;
                } finally {
                    cs_free(insn, 1);
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to disassemble code: " + e.getMessage(), e);
            }
        }).takeWhile(Objects::nonNull);
    }

    /**
     * Retrieves the name of a register based on its identifier.
     * <p>
     * This method returns the human-readable name of a register in the current architecture,
     * based on its numeric identifier. The register identifiers are architecture-specific
     * and are defined by the Capstone engine.
     * <p>
     * This is particularly useful when working with instruction details, where registers
     * are represented by their numeric IDs. For example, when examining which registers are
     * read or written by an instruction.
     * <p>
     * Example usage:
     * <pre>{@code
     * // Get instruction details
     * CapstoneInstruction instruction = handle.disassembleInstruction(code, address);
     * CapstoneInstructionDetails details = instruction.getDetails();
     * 
     * // Print names of registers read by this instruction
     * for (int regId : details.getRegsRead()) {
     *     System.out.println("Register read: " + handle.getRegName(regId));
     * }
     * }</pre>
     *
     * @param regId the architecture-specific register identifier
     * @return the human-readable name of the register
     * @throws RuntimeException if the Capstone handle is not initialized or if the register name could not be retrieved
     * @see CapstoneRegAccess#getRegsRead()
     * @see CapstoneRegAccess#getRegsWrite()
     */
    public String getRegName(int regId) {
        if(this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
        MemorySegment regName = cs_reg_name(this.handle.get(csh, 0), regId);
        if(regName == null || regName.byteSize() == 0 || regName == MemorySegment.NULL) {
            throw new RuntimeException("Failed to get register name for id: " + regId);
        }
        return regName.getString(0);
    }

    /**
     * Retrieves the mnemonic name of an instruction based on its identifier.
     * <p>
     * This method returns the standardized mnemonic name of an instruction in the current architecture,
     * based on its numeric identifier. The instruction identifiers are architecture-specific
     * and are defined by the Capstone engine.
     * <p>
     * This is useful for obtaining consistent instruction names, especially when working with
     * raw instruction IDs obtained from {@link CapstoneInstruction#getId()}. The returned
     * name can be used for instruction classification, analysis, or display purposes.
     * <p>
     * Example usage:
     * <pre>{@code
     * // Disassemble an instruction
     * CapstoneInstruction instruction = handle.disassembleInstruction(code, address);
     * 
     * // Get the standardized name based on its ID
     * String insnName = handle.getInsnName(instruction.getId());
     * System.out.println("Instruction name: " + insnName);
     * }</pre>
     *
     * @param insnId the architecture-specific instruction identifier
     * @return the standardized mnemonic name of the instruction
     * @throws RuntimeException if the Capstone handle is not initialized or if the instruction name could not be retrieved
     * @see CapstoneInstruction#getId()
     */
    public String getInsnName(int insnId) {
        if(this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
        MemorySegment insnName = cs_insn_name(this.handle.get(csh, 0), insnId);
        if(insnName == null || insnName.byteSize() == 0 || insnName == MemorySegment.NULL) {
            throw new RuntimeException("Failed to get instruction name for id: " + insnId);
        }
        return insnName.getString(0);
    }

    /**
     * Retrieves the name of an instruction group based on its identifier.
     * <p>
     * This method returns the human-readable name of an instruction group in the current architecture,
     * based on its numeric identifier. Instruction groups are categories that classify instructions
     * by their functionality or behavior (e.g., jump instructions, arithmetic operations, etc.).
     * The group identifiers are architecture-specific and are defined by the Capstone engine.
     * <p>
     * This is particularly useful when working with instruction details, where instruction groups
     * are represented by their numeric IDs. Understanding which groups an instruction belongs to
     * can help with code analysis, optimization, or security assessment.
     * <p>
     * Example usage:
     * <pre>{@code
     * // Get instruction details
     * CapstoneInstruction instruction = handle.disassembleInstruction(code, address);
     * CapstoneInstructionDetails details = instruction.getDetails();
     * 
     * // Print all groups this instruction belongs to
     * for (int groupId : details.getGroups()) {
     *     System.out.println("Group: " + handle.getGroupName(groupId));
     * }
     * }</pre>
     *
     * @param groupId the architecture-specific group identifier
     * @return the human-readable name of the instruction group
     * @throws RuntimeException if the Capstone handle is not initialized or if the group name could not be retrieved
     * @see CapstoneInstructionDetails#getGroups()
     * @see CapstoneInstructionDetails#getGroupsCount()
     */
    public String getGroupName(int groupId) {
        if(this.handle == null) {
            throw new RuntimeException("Capstone handle is not initialized");
        }
        MemorySegment groupName = cs_group_name(this.handle.get(csh, 0), groupId);
        if(groupName == null || groupName.byteSize() == 0 || groupName == MemorySegment.NULL) {
            throw new RuntimeException("Failed to get group name for id: " + groupId);
        }
        return groupName.getString(0);
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