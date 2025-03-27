package com.capstone4j;

import com.capstone4j.internal.cs_x86;
import com.capstone4j.internal.cs_x86_op;
import com.capstone4j.internal.x86_op_mem;
import com.capstone4j.internal.cs_x86_encoding;

import static com.capstone4j.internal.capstone_h.*;

import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Provides x86-specific instruction details for the Capstone disassembly engine.
 * <p>
 * This class contains all the detailed information about x86 architecture instructions
 * that have been disassembled by the Capstone engine. It provides access to instruction
 * prefixes, operands, register details, flags affected, and encoding information.
 * </p>
 */
public class CapstoneX86Details extends CapstoneArchDetails<CapstoneX86Details.X86Operand> implements MemorySegmentCreatable<CapstoneX86Details> {

    /** Instruction prefixes (up to 4) */
    private final X86Prefix[] prefix;
    
    /** Instruction opcodes (up to 4) */
    private final int[] opcode;
    
    /** REX prefix value */
    private final int rex;
    
    /** Address size */
    private final int addrSize;
    
    /** ModR/M byte */
    private final int modrm;
    
    /** SIB value */
    private final int sib;
    
    /** Displacement value */
    private final long disp;
    
    /** SIB index register */
    private final X86Reg sibIndex;
    
    /** SIB scale value */
    private final byte sibScale;
    
    /** SIB base register */
    private final X86Reg sibBase;
    
    /** XOP condition code */
    private final X86XopCC xopCC;
    
    /** SSE condition code */
    private final X86SseCC sseCC;
    
    /** AVX condition code */
    private final X86AvxCC avxCC;
    
    /** AVX Suppress All Exceptions flag */
    private final boolean avxSAE;
    
    /** AVX rounding mode */
    private final X86AvxRm avxRm;
    
    /** EFLAGS updated by the instruction */
    private final X86EFlags[] eflags;
    
    /** FPU flags updated by the instruction */
    private final X86FPUFlags[] fpuFlags;
    
    /** Instruction encoding information */
    private final X86Encoding encoding;

    /**
     * Constructs a new CapstoneX86Details object with the specified details.
     *
     * @param opCount Number of operands
     * @param operands Array of instruction operands
     * @param prefix Array of instruction prefixes
     * @param opcode Array of instruction opcodes
     * @param rex REX prefix value
     * @param addrSize Address size
     * @param modrm ModR/M byte
     * @param sib SIB value
     * @param disp Displacement value
     * @param sibIndex SIB index register
     * @param sibScale SIB scale value
     * @param sibBase SIB base register
     * @param xopCC XOP condition code
     * @param sseCC SSE condition code
     * @param avxCC AVX condition code
     * @param avxSAE AVX Suppress All Exceptions flag
     * @param avxRm AVX rounding mode
     * @param eflags EFLAGS updated by the instruction
     * @param fpuFlags FPU flags updated by the instruction
     * @param encoding Instruction encoding information
     */
    CapstoneX86Details(int opCount, X86Operand[] operands, X86Prefix[] prefix, int[] opcode, int rex, 
            int addrSize, int modrm, int sib, long disp, X86Reg sibIndex, byte sibScale, 
            X86Reg sibBase, X86XopCC xopCC, X86SseCC sseCC, X86AvxCC avxCC, boolean avxSAE, 
            X86AvxRm avxRm, X86EFlags[] eflags, X86FPUFlags[] fpuFlags, X86Encoding encoding) {
        super(opCount, operands);
        this.prefix = prefix;
        this.opcode = opcode;
        this.rex = rex;
        this.addrSize = addrSize;
        this.modrm = modrm;
        this.sib = sib;
        this.disp = disp;
        this.sibIndex = sibIndex;
        this.sibScale = sibScale;
        this.sibBase = sibBase;
        this.xopCC = xopCC;
        this.sseCC = sseCC;
        this.avxCC = avxCC;
        this.avxSAE = avxSAE;
        this.avxRm = avxRm;
        this.eflags = eflags;
        this.fpuFlags = fpuFlags;
        this.encoding = encoding;
    }

    /**
     * Creates a CapstoneX86Details object from a memory segment containing
     * the x86-specific details of a disassembled instruction.
     *
     * @param segment Memory segment containing x86 instruction details
     * @return A new CapstoneX86Details object
     */
    static CapstoneX86Details createFromMemorySegment(MemorySegment segment) {
        X86Prefix[] prefix = new X86Prefix[4];
        MemorySegment prefixSegment = cs_x86.prefix(segment);
        for(int i = 0; i < 4; i++) {
            prefix[i] = X86Prefix.fromValue(prefixSegment.get(C_CHAR, i) & 0xFF);
        }

        int[] opcode = new int[4];
        MemorySegment opcodeSegment = cs_x86.opcode(segment);
        for(int i = 0; i < 4; i++) {
            opcode[i] = opcodeSegment.get(C_CHAR, i) & 0xFF;
        }

        int rex = cs_x86.rex(segment) & 0xFF;
        int addrSize = cs_x86.addr_size(segment) & 0xFF;
        int modrm = cs_x86.modrm(segment) & 0xFF;
        int sib = cs_x86.sib(segment) & 0xFF;

        long disp = cs_x86.disp(segment);

        X86Reg sibIndex = X86Reg.fromValue(cs_x86.sib_index(segment));

        byte sibScale = cs_x86.sib_scale(segment);

        X86Reg sibBase = X86Reg.fromValue(cs_x86.sib_base(segment));

        X86XopCC xopCC = X86XopCC.fromValue(cs_x86.xop_cc(segment));

        X86SseCC sseCC = X86SseCC.fromValue(cs_x86.sse_cc(segment));

        X86AvxCC avxCC = X86AvxCC.fromValue(cs_x86.avx_cc(segment));

        boolean avxSAE = cs_x86.avx_sae(segment);

        X86AvxRm avxRm = X86AvxRm.fromValue(cs_x86.avx_rm(segment));

        X86EFlags[] eflags = X86EFlags.fromValue(cs_x86.eflags(segment));

        X86FPUFlags[] fpuFlags = X86FPUFlags.fromValue(cs_x86.fpu_flags(segment));

        int opCount = cs_x86.op_count(segment) & 0xFF;

        MemorySegment operandsSegment = cs_x86.operands(segment);
        X86Operand[] operands = new X86Operand[opCount];
        for(int i = 0; i < opCount; i++) {
            operands[i] = createOperandFromMemorySegment(operandsSegment.asSlice(i * cs_x86_op.sizeof()));
        }

        MemorySegment encodingSegment = cs_x86.encoding(segment);
        X86Encoding encoding = createEncodingFromMemorySegment(encodingSegment);

        return new CapstoneX86Details(
            opCount,
            operands,
            prefix,
            opcode,
            rex,
            addrSize,
            modrm,
            sib,
            disp,
            sibIndex,
            sibScale,
            sibBase,
            xopCC,
            sseCC,
            avxCC,
            avxSAE,
            avxRm,
            eflags,
            fpuFlags,
            encoding
        );
    }

    /**
     * Creates an X86Encoding object from a memory segment containing encoding information.
     *
     * @param segment Memory segment containing encoding information
     * @return A new X86Encoding object
     */
    static X86Encoding createEncodingFromMemorySegment(MemorySegment segment) {
        int modrmOffset = cs_x86_encoding.modrm_offset(segment) & 0xFF;
        int dispOffset = cs_x86_encoding.disp_offset(segment) & 0xFF;
        int dispSize = cs_x86_encoding.disp_size(segment) & 0xFF;
        int immOffset = cs_x86_encoding.imm_offset(segment) & 0xFF;
        int immSize = cs_x86_encoding.imm_size(segment) & 0xFF;
        return new X86Encoding(modrmOffset, dispOffset, dispSize, immOffset, immSize);
    }

    /**
     * Creates an X86Operand object from a memory segment containing operand information.
     *
     * @param segment Memory segment containing operand information
     * @return A new X86Operand object
     */
    static X86Operand createOperandFromMemorySegment(MemorySegment segment) {
        X86OperandType type = X86OperandType.fromValue(cs_x86_op.type(segment));
        X86Reg reg = null;
        long imm = 0;
        X86OpMem mem = null;
        if(type == X86OperandType.REG) {
            reg = X86Reg.fromValue(cs_x86_op.reg(segment));
        } else if(type == X86OperandType.IMM) {
            imm = cs_x86_op.imm(segment);
        } else if(type == X86OperandType.MEM) {
            mem = createOpMemFromMemorySegment(cs_x86_op.mem(segment));
        }
        int size = cs_x86_op.size(segment) & 0xFF;
        int access = cs_x86_op.access(segment) & 0xFF;
        X86AvxBcast avxBcast = X86AvxBcast.fromValue(cs_x86_op.avx_bcast(segment));
        boolean avxZeroOpmask = cs_x86_op.avx_zero_opmask(segment);
        return new X86Operand(type, reg, imm, mem, size, access, avxBcast, avxZeroOpmask);
    }

    /**
     * Creates an X86OpMem object from a memory segment containing memory operand information.
     *
     * @param segment Memory segment containing memory operand information
     * @return A new X86OpMem object
     */
    static X86OpMem createOpMemFromMemorySegment(MemorySegment segment) {
        X86Reg segmentReg = X86Reg.fromValue(x86_op_mem.segment(segment));
        X86Reg baseReg = X86Reg.fromValue(x86_op_mem.base(segment));
        X86Reg indexReg = X86Reg.fromValue(x86_op_mem.index(segment));
        int scale = x86_op_mem.scale(segment);
        long disp = x86_op_mem.disp(segment);
        return new X86OpMem(segmentReg, baseReg, indexReg, scale, disp);
    }

    /**
     * Checks if the specified operand is of the given type.
     *
     * @param operand The operand to check
     * @param opType The type value to check against
     * @return true if the operand is of the specified type, false otherwise
     */
    @Override
    boolean isOperandOfType(X86Operand operand, int opType) {
        return operand.getType() == X86OperandType.fromValue(opType);
    }

    /**
     * Counts the number of operands of the specified type.
     *
     * @param opType The type of operands to count
     * @return The number of operands of the specified type
     */
    @Override
    int getOpCounOfType(int opType) {
        int count = 0;
        for(X86Operand operand : getOperands()) {
            if(isOperandOfType(operand, opType)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Gets the instruction prefixes.
     *
     * @return Array of instruction prefixes
     */
    public X86Prefix[] getPrefixs() {
        return this.prefix;
    }

    /**
     * Gets the instruction opcodes.
     *
     * @return Array of instruction opcodes
     */
    public int[] getOpcodes() {
        return this.opcode;
    }

    /**
     * Gets the REX prefix value.
     *
     * @return The REX prefix value
     */
    public int getRex() {
        return this.rex;
    }

    /**
     * Gets the address size.
     *
     * @return The address size
     */
    public int getAddrSize() {
        return this.addrSize;
    }

    /**
     * Gets the ModR/M byte.
     *
     * @return The ModR/M byte
     */
    public int getModrm() {
        return this.modrm;
    }

    /**
     * Gets the SIB value.
     *
     * @return The SIB value
     */
    public int getSib() {
        return this.sib;
    }

    /**
     * Gets the displacement value.
     *
     * @return The displacement value
     */
    public long getDisp() {
        return this.disp;
    }

    /**
     * Gets the SIB index register.
     *
     * @return The SIB index register
     */
    public X86Reg getSibIndex() {
        return this.sibIndex;
    }

    /**
     * Gets the SIB scale value.
     *
     * @return The SIB scale value
     */
    public byte getSibScale() {
        return this.sibScale;
    }

    /**
     * Gets the SIB base register.
     *
     * @return The SIB base register
     */
    public X86Reg getSibBase() {
        return this.sibBase;
    }

    /**
     * Gets the XOP condition code.
     *
     * @return The XOP condition code
     */
    public X86XopCC getXopCC() {
        return this.xopCC;
    }

    /**
     * Gets the SSE condition code.
     *
     * @return The SSE condition code
     */
    public X86SseCC getSseCC() {
        return this.sseCC;
    }

    /**
     * Gets the AVX condition code.
     *
     * @return The AVX condition code
     */
    public X86AvxCC getAvxCC() {
        return this.avxCC;
    }

    /**
     * Gets the AVX SAE (Suppress All Exceptions) flag.
     *
     * @return The AVX SAE flag
     */
    public boolean getAvxSAE() {
        return this.avxSAE;
    }

    /**
     * Gets the AVX rounding mode.
     *
     * @return The AVX rounding mode
     */
    public X86AvxRm getAvxRm() {
        return this.avxRm;
    }

    /**
     * Gets the EFLAGS updated by the instruction.
     *
     * @return Array of EFLAGS
     */
    public X86EFlags[] getEflags() {
        return this.eflags;
    }

    /**
     * Gets the FPU flags updated by the instruction.
     *
     * @return Array of FPU flags
     */
    public X86FPUFlags[] getFpuFlags() {
        return this.fpuFlags;
    }

    /**
     * Gets the instruction encoding information.
     *
     * @return The instruction encoding information
     */
    public X86Encoding getEncoding() {
        return this.encoding;
    }

    /**
     * Represents x86 instruction prefixes.
     * <p>
     * X86 instructions may have up to 4 prefixes that modify the operation
     * of an instruction.
     * </p>
     */
    public enum X86Prefix {
        /** No prefix */
        _0(X86_PREFIX_0()),
        /** LOCK prefix */
        LOCK(X86_PREFIX_LOCK()),
        /** REP prefix */
        REP(X86_PREFIX_REP()),
        /** REPE/REPZ prefix */
        REPE(X86_PREFIX_REPE()),
        /** REPNE/REPNZ prefix */
        REPNE(X86_PREFIX_REPNE()),

        /** CS segment override */
        CS(X86_PREFIX_CS()),
        /** SS segment override */
        SS(X86_PREFIX_SS()),
        /** DS segment override */
        DS(X86_PREFIX_DS()),
        /** ES segment override */
        ES(X86_PREFIX_ES()),
        /** FS segment override */
        FS(X86_PREFIX_FS()),
        /** GS segment override */
        GS(X86_PREFIX_GS()),

        /** Operand-size override */
        OPSIZE(X86_PREFIX_OPSIZE()),
        /** Address-size override */
        ADDRSIZE(X86_PREFIX_ADDRSIZE());

        private final int value;

        /**
         * Constructs a new X86Prefix with the specified value.
         *
         * @param value The native prefix value
         */
        X86Prefix(int value) {
            this.value = value;
        }

        /**
         * Gets the native value of the prefix.
         *
         * @return The native prefix value
         */
        public int getValue() {
            return this.value;
        }

        /**
         * Converts a native prefix value to its corresponding enum constant.
         *
         * @param value The native prefix value
         * @return The corresponding X86Prefix enum constant
         * @throws IllegalArgumentException if the value is not a valid prefix
         */
        public static X86Prefix fromValue(int value) {
            for (X86Prefix prefix : X86Prefix.values()) {
                if (prefix.value == value) {
                    return prefix;
                }
            }
            throw new IllegalArgumentException("Invalid prefix value: " + value);
        }
    }

    /**
     * Represents the EFLAGS (x86 status flags) that can be affected by instructions.
     * <p>
     * EFLAGS are status flags that indicate the results of operations and control
     * the behavior of the CPU.
     * </p>
     */
    public enum X86EFlags {
        /** Modify AF flag (Adjust) */
        MODIFY_AF(1 << 0),
        /** Modify CF flag (Carry) */
        MODIFY_CF(1 << 1),
        /** Modify SF flag (Sign) */
        MODIFY_SF(1 << 2),
        /** Modify ZF flag (Zero) */
        MODIFY_ZF(1 << 3),
        /** Modify PF flag (Parity) */
        MODIFY_PF(1 << 4),
        /** Modify OF flag (Overflow) */
        MODIFY_OF(1 << 5),
        /** Modify TF flag (Trap) */
        MODIFY_TF(1 << 6),
        /** Modify IF flag (Interrupt) */
        MODIFY_IF(1 << 7),
        /** Modify DF flag (Direction) */
        MODIFY_DF(1 << 8),
        /** Modify NT flag (Nested Task) */
        MODIFY_NT(1 << 9),
        /** Modify RF flag (Resume) */
        MODIFY_RF(1 << 10),
        /** Prior value of OF flag is required */
        PRIOR_OF(1 << 11),
        /** Prior value of SF flag is required */
        PRIOR_SF(1 << 12),
        /** Prior value of ZF flag is required */
        PRIOR_ZF(1 << 13),
        /** Prior value of AF flag is required */
        PRIOR_AF(1 << 14),
        /** Prior value of PF flag is required */
        PRIOR_PF(1 << 15),
        /** Prior value of CF flag is required */
        PRIOR_CF(1 << 16),
        /** Prior value of TF flag is required */
        PRIOR_TF(1 << 17),
        /** Prior value of IF flag is required */
        PRIOR_IF(1 << 18),
        /** Prior value of DF flag is required */
        PRIOR_DF(1 << 19),
        /** Prior value of NT flag is required */
        PRIOR_NT(1 << 20),
        /** Reset OF flag to 0 */
        RESET_OF(1 << 21),
        /** Reset CF flag to 0 */
        RESET_CF(1 << 22),
        /** Reset DF flag to 0 */
        RESET_DF(1 << 23),
        /** Reset IF flag to 0 */
        RESET_IF(1 << 24),
        /** Reset SF flag to 0 */
        RESET_SF(1 << 25),
        /** Reset AF flag to 0 */
        RESET_AF(1 << 26),
        /** Reset TF flag to 0 */
        RESET_TF(1 << 27),
        /** Reset NT flag to 0 */
        RESET_NT(1 << 28),
        /** Reset PF flag to 0 */
        RESET_PF(1 << 29),
        /** Set CF flag to 1 */
        SET_CF(1 << 30),
        /** Set DF flag to 1 */
        SET_DF(1 << 31),
        /** Set IF flag to 1 */
        SET_IF(1 << 32),
        /** Test OF flag */
        TEST_OF(1 << 33),
        /** Test SF flag */
        TEST_SF(1 << 34),
        /** Test ZF flag */
        TEST_ZF(1 << 35),
        /** Test PF flag */
        TEST_PF(1 << 36),
        /** Test CF flag */
        TEST_CF(1 << 37),
        /** Test NT flag */
        TEST_NT(1 << 38),
        /** Test DF flag */
        TEST_DF(1 << 39),
        /** Undefined OF flag (value undefined after instruction) */
        UNDEFINED_OF(1 << 40),
        /** Undefined SF flag (value undefined after instruction) */
        UNDEFINED_SF(1 << 41),
        /** Undefined ZF flag (value undefined after instruction) */
        UNDEFINED_ZF(1 << 42),
        /** Undefined PF flag (value undefined after instruction) */
        UNDEFINED_PF(1 << 43),
        /** Undefined AF flag (value undefined after instruction) */
        UNDEFINED_AF(1 << 44),
        /** Undefined CF flag (value undefined after instruction) */
        UNDEFINED_CF(1 << 45),
        /** Reset RF flag to 0 */
        RESET_RF(1 << 46),
        /** Test RF flag */
        TEST_RF(1 << 47),
        /** Test IF flag */
        TEST_IF(1 << 48),
        /** Test TF flag */
        TEST_TF(1 << 49),
        /** Test AF flag */
        TEST_AF(1 << 50),
        /** Reset ZF flag to 0 */
        RESET_ZF(1 << 51),
        /** Set OF flag to 1 */
        SET_OF(1 << 52),
        /** Set SF flag to 1 */
        SET_SF(1 << 53),
        /** Set ZF flag to 1 */
        SET_ZF(1 << 54),
        /** Set AF flag to 1 */
        SET_AF(1 << 55),
        /** Set PF flag to 1 */
        SET_PF(1 << 56),
        /** Reset OF flag to 0 (alternate bit) */
        RESET_0F(1 << 57),
        /** Reset AC flag to 0 */
        RESET_AC(1 << 58);

        long value;

        /**
         * Constructs a new X86EFlags with the specified value.
         *
         * @param value The flag bit value
         */
        X86EFlags(long value) {
            this.value = value;
        }

        /**
         * Gets the native value of the flag.
         *
         * @return The native flag value
         */
        public long getValue() {
            return value;
        }

        /**
         * Converts a bitmap of flags to an array of flag enums.
         *
         * @param value The bitmap containing the flags
         * @return Array of flags present in the bitmap
         */
        public static X86EFlags[] fromValue(long value) {
            List<X86EFlags> result = new ArrayList<>();
            BigInteger bigValue = BigInteger.valueOf(value); // because of the ulong we were getting a different value in the resulting array 
            for(X86EFlags flag : X86EFlags.values()) {
                if(bigValue.testBit(flag.ordinal())) {
                    result.add(flag);
                }
            }
            return result.toArray(new X86EFlags[0]);
        }

        /**
         * Converts an array of flag enums to a bitmap.
         *
         * @param flags Array of flags
         * @return Bitmap representation of the flags
         */
        public static long toValue(X86EFlags[] flags) {
            long value = 0;
            for (X86EFlags flag : flags) {
                value |= flag.getValue();
            }
            return value;
        }
    }

    /**
     * Represents the FPU flags (x87 floating-point status word flags) that can be affected by instructions.
     * <p>
     * FPU flags indicate the state of the floating-point unit after operations.
     * </p>
     */
    public enum X86FPUFlags {
        /** Modify C0 flag */
        MODIFY_C0(1 << 0),
        /** Modify C1 flag */
        MODIFY_C1(1 << 1),
        /** Modify C2 flag */
        MODIFY_C2(1 << 2),
        /** Modify C3 flag */
        MODIFY_C3(1 << 3),
        /** Reset C0 flag to 0 */
        RESET_C0(1 << 4),
        /** Reset C1 flag to 0 */
        RESET_C1(1 << 5),
        /** Reset C2 flag to 0 */
        RESET_C2(1 << 6),
        /** Reset C3 flag to 0 */
        RESET_C3(1 << 7),
        /** Set C0 flag to 1 */
        SET_C0(1 << 8),
        /** Set C1 flag to 1 */
        SET_C1(1 << 9),
        /** Set C2 flag to 1 */
        SET_C2(1 << 10),
        /** Set C3 flag to 1 */
        SET_C3(1 << 11),
        /** Undefined C0 flag (value undefined after instruction) */
        UNDEFINED_C0(1 << 12),
        /** Undefined C1 flag (value undefined after instruction) */
        UNDEFINED_C1(1 << 13),
        /** Undefined C2 flag (value undefined after instruction) */
        UNDEFINED_C2(1 << 14),
        /** Undefined C3 flag (value undefined after instruction) */
        UNDEFINED_C3(1 << 15),
        /** Test C0 flag */
        TEST_C0(1<< 16),
        /** Test C1 flag */
        TEST_C1(1<< 17),
        /** Test C2 flag */
        TEST_C2(1<< 18),
        /** Test C3 flag */
        TEST_C3(1<< 19);

        long value;

        /**
         * Constructs a new X86FPUFlags with the specified value.
         *
         * @param value The flag bit value
         */
        X86FPUFlags(long value) {
            this.value = value;
        }

        /**
         * Gets the native value of the flag.
         *
         * @return The native flag value
         */
        public long getValue() {
            return value;
        }

        /**
         * Converts a bitmap of flags to an array of flag enums.
         *
         * @param value The bitmap containing the flags
         * @return Array of flags present in the bitmap
         */
        public static X86FPUFlags[] fromValue(long value) {
            return Arrays.stream(X86FPUFlags.values())
                .filter(flag -> (flag.getValue() & value) != 0)
                .toArray(X86FPUFlags[]::new);
        }

        /**
         * Converts an array of flag enums to a bitmap.
         *
         * @param flags Array of flags
         * @return Bitmap representation of the flags
         */
        public static long toValue(X86FPUFlags[] flags) {
            long value = 0;
            for (X86FPUFlags flag : flags) {
                value |= flag.getValue();
            }
            return value;
        }
    }

    /**
     * Represents x86 registers.
     * <p>
     * This enum contains all the registers available in x86 architecture,
     * including general purpose, segment, control, debug, MMX, SSE, AVX registers, etc.
     * </p>
     */
    public enum X86Reg {
        /** Invalid register */
        INVALID(X86_REG_INVALID()),
        
        /** AH register (high byte of AX) */
        AH(X86_REG_AH()),
        /** AL register (low byte of AX) */
        AL(X86_REG_AL()),
        /** AX register (16-bit) */
        AX(X86_REG_AX()),
        /** BH register (high byte of BX) */
        BH(X86_REG_BH()),
        /** BL register (low byte of BX) */
        BL(X86_REG_BL()),
        /** BP register (base pointer) */
        BP(X86_REG_BP()),
        /** BPL register (low byte of BP) */
        BPL(X86_REG_BPL()),
        /** BX register (16-bit) */
        BX(X86_REG_BX()),
        /** CH register (high byte of CX) */
        CH(X86_REG_CH()),
        /** CL register (low byte of CX) */
        CL(X86_REG_CL()),
        /** CS register (code segment) */
        CS(X86_REG_CS()),
        /** CX register (16-bit) */
        CX(X86_REG_CX()),
        /** DH register (high byte of DX) */
        DH(X86_REG_DH()),
        /** DI register (destination index) */
        DI(X86_REG_DI()),
        /** DIL register (low byte of DI) */
        DIL(X86_REG_DIL()),
        /** DL register (low byte of DX) */
        DL(X86_REG_DL()),
        /** DS register (data segment) */
        DS(X86_REG_DS()),
        /** DX register (16-bit) */
        DX(X86_REG_DX()),
        
        /** EAX register (32-bit) */
        EAX(X86_REG_EAX()),
        /** EBP register (32-bit base pointer) */
        EBP(X86_REG_EBP()),
        /** EBX register (32-bit) */
        EBX(X86_REG_EBX()),
        /** ECX register (32-bit) */
        ECX(X86_REG_ECX()),
        /** EDI register (32-bit destination index) */
        EDI(X86_REG_EDI()),
        /** EDX register (32-bit) */
        EDX(X86_REG_EDX()),
        /** EFLAGS register */
        EFLAGS(X86_REG_EFLAGS()),
        /** EIP register (32-bit instruction pointer) */
        EIP(X86_REG_EIP()),
        /** EIZ register (32-bit implicit zero register) */
        EIZ(X86_REG_EIZ()),
        /** ES register (extra segment) */
        ES(X86_REG_ES()),
        /** ESI register (32-bit source index) */
        ESI(X86_REG_ESI()),
        /** ESP register (32-bit stack pointer) */
        ESP(X86_REG_ESP()),
        /** FPSW register (FPU status word) */
        FPSW(X86_REG_FPSW()),
        /** FS register (segment register) */
        FS(X86_REG_FS()),
        /** GS register (segment register) */
        GS(X86_REG_GS()),
        /** IP register (16-bit instruction pointer) */
        IP(X86_REG_IP()),
        
        /** RAX register (64-bit) */
        RAX(X86_REG_RAX()),
        /** RBP register (64-bit base pointer) */
        RBP(X86_REG_RBP()),
        /** RBX register (64-bit) */
        RBX(X86_REG_RBX()),
        /** RCX register (64-bit) */
        RCX(X86_REG_RCX()),
        /** RDI register (64-bit destination index) */
        RDI(X86_REG_RDI()),
        /** RDX register (64-bit) */
        RDX(X86_REG_RDX()),
        /** RIP register (64-bit instruction pointer) */
        RIP(X86_REG_RIP()),
        /** RIZ register (64-bit implicit zero register) */
        RIZ(X86_REG_RIZ()),
        /** RSI register (64-bit source index) */
        RSI(X86_REG_RSI()),
        /** RSP register (64-bit stack pointer) */
        RSP(X86_REG_RSP()),
        /** SI register (source index, 16-bit) */
        SI(X86_REG_SI()),
        /** SIL register (low byte of SI) */
        SIL(X86_REG_SIL()),
        /** SP register (stack pointer, 16-bit) */
        SP(X86_REG_SP()),
        /** SPL register (low byte of SP) */
        SPL(X86_REG_SPL()),
        /** SS register (stack segment) */
        SS(X86_REG_SS()),
        
        // Control registers
        /** CR0 control register */
        CR0(X86_REG_CR0()),
        /** CR1 control register */
        CR1(X86_REG_CR1()),
        /** CR2 control register */
        CR2(X86_REG_CR2()),
        /** CR3 control register */
        CR3(X86_REG_CR3()),
        /** CR4 control register */
        CR4(X86_REG_CR4()),
        /** CR5 control register */
        CR5(X86_REG_CR5()),
        /** CR6 control register */
        CR6(X86_REG_CR6()),
        /** CR7 control register */
        CR7(X86_REG_CR7()),
        /** CR8 control register */
        CR8(X86_REG_CR8()),
        /** CR9 control register */
        CR9(X86_REG_CR9()),
        /** CR10 control register */
        CR10(X86_REG_CR10()),
        /** CR11 control register */
        CR11(X86_REG_CR11()),
        /** CR12 control register */
        CR12(X86_REG_CR12()),
        /** CR13 control register */
        CR13(X86_REG_CR13()),
        /** CR14 control register */
        CR14(X86_REG_CR14()),
        /** CR15 control register */
        CR15(X86_REG_CR15()),
        
        // Debug registers
        /** DR0 debug register */
        DR0(X86_REG_DR0()),
        /** DR1 debug register */
        DR1(X86_REG_DR1()),
        /** DR2 debug register */
        DR2(X86_REG_DR2()),
        /** DR3 debug register */
        DR3(X86_REG_DR3()),
        /** DR4 debug register */
        DR4(X86_REG_DR4()),
        /** DR5 debug register */
        DR5(X86_REG_DR5()),
        /** DR6 debug register */
        DR6(X86_REG_DR6()),
        /** DR7 debug register */
        DR7(X86_REG_DR7()),
        /** DR8 debug register */
        DR8(X86_REG_DR8()),
        /** DR9 debug register */
        DR9(X86_REG_DR9()),
        /** DR10 debug register */
        DR10(X86_REG_DR10()),
        /** DR11 debug register */
        DR11(X86_REG_DR11()),
        /** DR12 debug register */
        DR12(X86_REG_DR12()),
        /** DR13 debug register */
        DR13(X86_REG_DR13()),
        /** DR14 debug register */
        DR14(X86_REG_DR14()),
        /** DR15 debug register */
        DR15(X86_REG_DR15()),
        
        // Floating point registers
        /** FP0 floating-point register */
        FP0(X86_REG_FP0()),
        /** FP1 floating-point register */
        FP1(X86_REG_FP1()),
        /** FP2 floating-point register */
        FP2(X86_REG_FP2()),
        /** FP3 floating-point register */
        FP3(X86_REG_FP3()),
        /** FP4 floating-point register */
        FP4(X86_REG_FP4()),
        /** FP5 floating-point register */
        FP5(X86_REG_FP5()),
        /** FP6 floating-point register */
        FP6(X86_REG_FP6()),
        /** FP7 floating-point register */
        FP7(X86_REG_FP7()),
        
        // AVX mask registers
        /** K0 opmask register */
        K0(X86_REG_K0()),
        /** K1 opmask register */
        K1(X86_REG_K1()),
        /** K2 opmask register */
        K2(X86_REG_K2()),
        /** K3 opmask register */
        K3(X86_REG_K3()),
        /** K4 opmask register */
        K4(X86_REG_K4()),
        /** K5 opmask register */
        K5(X86_REG_K5()),
        /** K6 opmask register */
        K6(X86_REG_K6()),
        /** K7 opmask register */
        K7(X86_REG_K7()),
        
        // MMX registers
        /** MM0 MMX register */
        MM0(X86_REG_MM0()),
        /** MM1 MMX register */
        MM1(X86_REG_MM1()),
        /** MM2 MMX register */
        MM2(X86_REG_MM2()),
        /** MM3 MMX register */
        MM3(X86_REG_MM3()),
        /** MM4 MMX register */
        MM4(X86_REG_MM4()),
        /** MM5 MMX register */
        MM5(X86_REG_MM5()),
        /** MM6 MMX register */
        MM6(X86_REG_MM6()),
        /** MM7 MMX register */
        MM7(X86_REG_MM7()),
        
        // 64-bit general purpose registers
        /** R8 register (64-bit) */
        R8(X86_REG_R8()),
        /** R9 register (64-bit) */
        R9(X86_REG_R9()),
        /** R10 register (64-bit) */
        R10(X86_REG_R10()),
        /** R11 register (64-bit) */
        R11(X86_REG_R11()),
        /** R12 register (64-bit) */
        R12(X86_REG_R12()),
        /** R13 register (64-bit) */
        R13(X86_REG_R13()),
        /** R14 register (64-bit) */
        R14(X86_REG_R14()),
        /** R15 register (64-bit) */
        R15(X86_REG_R15()),
        
        // x87 FPU registers (same as FPx, but in x87 notation)
        /** ST0 FPU register */
        ST0(X86_REG_ST0()),
        /** ST1 FPU register */
        ST1(X86_REG_ST1()),
        /** ST2 FPU register */
        ST2(X86_REG_ST2()),
        /** ST3 FPU register */
        ST3(X86_REG_ST3()),
        /** ST4 FPU register */
        ST4(X86_REG_ST4()),
        /** ST5 FPU register */
        ST5(X86_REG_ST5()),
        /** ST6 FPU register */
        ST6(X86_REG_ST6()),
        /** ST7 FPU register */
        ST7(X86_REG_ST7()),
        /** XMM0 SSE register */
        XMM0(X86_REG_XMM0()),
        /** XMM1 SSE register */
        XMM1(X86_REG_XMM1()),
        /** XMM2 SSE register */
        XMM2(X86_REG_XMM2()),
        /** XMM3 SSE register */
        XMM3(X86_REG_XMM3()),
        /** XMM4 SSE register */
        XMM4(X86_REG_XMM4()),
        /** XMM5 SSE register */
        XMM5(X86_REG_XMM5()),
        /** XMM6 SSE register */
        XMM6(X86_REG_XMM6()),
        /** XMM7 SSE register */
        XMM7(X86_REG_XMM7()),
        /** XMM8 SSE register (x86-64 only) */
        XMM8(X86_REG_XMM8()),
        /** XMM9 SSE register (x86-64 only) */
        XMM9(X86_REG_XMM9()),
        /** XMM10 SSE register (x86-64 only) */
        XMM10(X86_REG_XMM10()),
        /** XMM11 SSE register (x86-64 only) */
        XMM11(X86_REG_XMM11()),
        /** XMM12 SSE register (x86-64 only) */
        XMM12(X86_REG_XMM12()),
        /** XMM13 SSE register (x86-64 only) */
        XMM13(X86_REG_XMM13()),
        /** XMM14 SSE register (x86-64 only) */
        XMM14(X86_REG_XMM14()),
        /** XMM15 SSE register (x86-64 only) */
        XMM15(X86_REG_XMM15()),
        /** XMM16 SSE register (AVX-512) */
        XMM16(X86_REG_XMM16()),
        /** XMM17 SSE register (AVX-512) */
        XMM17(X86_REG_XMM17()),
        /** XMM18 SSE register (AVX-512) */
        XMM18(X86_REG_XMM18()),
        /** XMM19 SSE register (AVX-512) */
        XMM19(X86_REG_XMM19()),
        /** XMM20 SSE register (AVX-512) */
        XMM20(X86_REG_XMM20()),
        /** XMM21 SSE register (AVX-512) */
        XMM21(X86_REG_XMM21()),
        /** XMM22 SSE register (AVX-512) */
        XMM22(X86_REG_XMM22()),
        /** XMM23 SSE register (AVX-512) */
        XMM23(X86_REG_XMM23()),
        /** XMM24 SSE register (AVX-512) */
        XMM24(X86_REG_XMM24()),
        /** XMM25 SSE register (AVX-512) */
        XMM25(X86_REG_XMM25()),
        /** XMM26 SSE register (AVX-512) */
        XMM26(X86_REG_XMM26()),
        /** XMM27 SSE register (AVX-512) */
        XMM27(X86_REG_XMM27()),
        /** XMM28 SSE register (AVX-512) */
        XMM28(X86_REG_XMM28()),
        /** XMM29 SSE register (AVX-512) */
        XMM29(X86_REG_XMM29()),
        /** XMM30 SSE register (AVX-512) */
        XMM30(X86_REG_XMM30()),
        /** XMM31 SSE register (AVX-512) */
        XMM31(X86_REG_XMM31()),
        /** YMM0 AVX register */
        YMM0(X86_REG_YMM0()),
        /** YMM1 AVX register */
        YMM1(X86_REG_YMM1()),
        /** YMM2 AVX register */
        YMM2(X86_REG_YMM2()),
        /** YMM3 AVX register */
        YMM3(X86_REG_YMM3()),
        /** YMM4 AVX register */
        YMM4(X86_REG_YMM4()),
        /** YMM5 AVX register */
        YMM5(X86_REG_YMM5()),
        /** YMM6 AVX register */
        YMM6(X86_REG_YMM6()),
        /** YMM7 AVX register */
        YMM7(X86_REG_YMM7()),
        /** YMM8 AVX register (x86-64 only) */
        YMM8(X86_REG_YMM8()),
        /** YMM9 AVX register (x86-64 only) */
        YMM9(X86_REG_YMM9()),
        /** YMM10 AVX register (x86-64 only) */
        YMM10(X86_REG_YMM10()),
        /** YMM11 AVX register (x86-64 only) */
        YMM11(X86_REG_YMM11()),
        /** YMM12 AVX register (x86-64 only) */
        YMM12(X86_REG_YMM12()),
        /** YMM13 AVX register (x86-64 only) */
        YMM13(X86_REG_YMM13()),
        /** YMM14 AVX register (x86-64 only) */
        YMM14(X86_REG_YMM14()),
        /** YMM15 AVX register (x86-64 only) */
        YMM15(X86_REG_YMM15()),
        /** YMM16 AVX register (AVX-512) */
        YMM16(X86_REG_YMM16()),
        /** YMM17 AVX register (AVX-512) */
        YMM17(X86_REG_YMM17()),
        /** YMM18 AVX register (AVX-512) */
        YMM18(X86_REG_YMM18()),
        /** YMM19 AVX register (AVX-512) */
        YMM19(X86_REG_YMM19()),
        /** YMM20 AVX register (AVX-512) */
        YMM20(X86_REG_YMM20()),
        /** YMM21 AVX register (AVX-512) */
        YMM21(X86_REG_YMM21()),
        /** YMM22 AVX register (AVX-512) */
        YMM22(X86_REG_YMM22()),
        /** YMM23 AVX register (AVX-512) */
        YMM23(X86_REG_YMM23()),
        /** YMM24 AVX register (AVX-512) */
        YMM24(X86_REG_YMM24()),
        /** YMM25 AVX register (AVX-512) */
        YMM25(X86_REG_YMM25()),
        /** YMM26 AVX register (AVX-512) */
        YMM26(X86_REG_YMM26()),
        /** YMM27 AVX register (AVX-512) */
        YMM27(X86_REG_YMM27()),
        /** YMM28 AVX register (AVX-512) */
        YMM28(X86_REG_YMM28()),
        /** YMM29 AVX register (AVX-512) */
        YMM29(X86_REG_YMM29()),
        /** YMM30 AVX register (AVX-512) */
        YMM30(X86_REG_YMM30()),
        /** YMM31 AVX register (AVX-512) */
        YMM31(X86_REG_YMM31()),
        /** ZMM0 AVX-512 register */
        ZMM0(X86_REG_ZMM0()),
        /** ZMM1 AVX-512 register */
        ZMM1(X86_REG_ZMM1()),
        /** ZMM2 AVX-512 register */
        ZMM2(X86_REG_ZMM2()),
        /** ZMM3 AVX-512 register */
        ZMM3(X86_REG_ZMM3()),
        /** ZMM4 AVX-512 register */
        ZMM4(X86_REG_ZMM4()),
        /** ZMM5 AVX-512 register */
        ZMM5(X86_REG_ZMM5()),
        /** ZMM6 AVX-512 register */
        ZMM6(X86_REG_ZMM6()),
        /** ZMM7 AVX-512 register */
        ZMM7(X86_REG_ZMM7()),
        /** ZMM8 AVX-512 register */
        ZMM8(X86_REG_ZMM8()),
        /** ZMM9 AVX-512 register */
        ZMM9(X86_REG_ZMM9()),
        /** ZMM10 AVX-512 register */
        ZMM10(X86_REG_ZMM10()),
        /** ZMM11 AVX-512 register */
        ZMM11(X86_REG_ZMM11()),
        /** ZMM12 AVX-512 register */
        ZMM12(X86_REG_ZMM12()),
        /** ZMM13 AVX-512 register */
        ZMM13(X86_REG_ZMM13()),
        /** ZMM14 AVX-512 register */
        ZMM14(X86_REG_ZMM14()),
        /** ZMM15 AVX-512 register */
        ZMM15(X86_REG_ZMM15()),
        /** ZMM16 AVX-512 register */
        ZMM16(X86_REG_ZMM16()),
        /** ZMM17 AVX-512 register */
        ZMM17(X86_REG_ZMM17()),
        /** ZMM18 AVX-512 register */
        ZMM18(X86_REG_ZMM18()),
        /** ZMM19 AVX-512 register */
        ZMM19(X86_REG_ZMM19()),
        /** ZMM20 AVX-512 register */
        ZMM20(X86_REG_ZMM20()),
        /** ZMM21 AVX-512 register */
        ZMM21(X86_REG_ZMM21()),
        /** ZMM22 AVX-512 register */
        ZMM22(X86_REG_ZMM22()),
        /** ZMM23 AVX-512 register */
        ZMM23(X86_REG_ZMM23()),
        /** ZMM24 AVX-512 register */
        ZMM24(X86_REG_ZMM24()),
        /** ZMM25 AVX-512 register */
        ZMM25(X86_REG_ZMM25()),
        /** ZMM26 AVX-512 register */
        ZMM26(X86_REG_ZMM26()),
        /** ZMM27 AVX-512 register */
        ZMM27(X86_REG_ZMM27()),
        /** ZMM28 AVX-512 register */
        ZMM28(X86_REG_ZMM28()),
        /** ZMM29 AVX-512 register */
        ZMM29(X86_REG_ZMM29()),
        /** ZMM30 AVX-512 register */
        ZMM30(X86_REG_ZMM30()),
        /** ZMM31 AVX-512 register */
        ZMM31(X86_REG_ZMM31()),
        /** R8 byte register (low byte of R8, x86-64 only) */
        R8B(X86_REG_R8B()),
        /** R9 byte register (low byte of R9, x86-64 only) */
        R9B(X86_REG_R9B()),
        /** R10 byte register (low byte of R10, x86-64 only) */
        R10B(X86_REG_R10B()),
        /** R11 byte register (low byte of R11, x86-64 only) */
        R11B(X86_REG_R11B()),
        /** R12 byte register (low byte of R12, x86-64 only) */
        R12B(X86_REG_R12B()),
        /** R13 byte register (low byte of R13, x86-64 only) */
        R13B(X86_REG_R13B()),
        /** R14 byte register (low byte of R14, x86-64 only) */
        R14B(X86_REG_R14B()),
        /** R15 byte register (low byte of R15, x86-64 only) */
        R15B(X86_REG_R15B()),
        /** R8 doubleword register (low 32 bits of R8, x86-64 only) */
        R8D(X86_REG_R8D()),
        /** R9 doubleword register (low 32 bits of R9, x86-64 only) */
        R9D(X86_REG_R9D()),
        /** R10 doubleword register (low 32 bits of R10, x86-64 only) */
        R10D(X86_REG_R10D()),
        /** R11 doubleword register (low 32 bits of R11, x86-64 only) */
        R11D(X86_REG_R11D()),
        /** R12 doubleword register (low 32 bits of R12, x86-64 only) */
        R12D(X86_REG_R12D()),
        /** R13 doubleword register (low 32 bits of R13, x86-64 only) */
        R13D(X86_REG_R13D()),
        /** R14 doubleword register (low 32 bits of R14, x86-64 only) */
        R14D(X86_REG_R14D()),
        /** R15 doubleword register (low 32 bits of R15, x86-64 only) */
        R15D(X86_REG_R15D()),
        /** R8 word register (low 16 bits of R8, x86-64 only) */
        R8W(X86_REG_R8W()),
        /** R9 word register (low 16 bits of R9, x86-64 only) */
        R9W(X86_REG_R9W()),
        /** R10 word register (low 16 bits of R10, x86-64 only) */
        R10W(X86_REG_R10W()),
        /** R11 word register (low 16 bits of R11, x86-64 only) */
        R11W(X86_REG_R11W()),
        /** R12 word register (low 16 bits of R12, x86-64 only) */
        R12W(X86_REG_R12W()),
        /** R13 word register (low 16 bits of R13, x86-64 only) */
        R13W(X86_REG_R13W()),
        /** R14 word register (low 16 bits of R14, x86-64 only) */
        R14W(X86_REG_R14W()),
        /** R15 word register (low 16 bits of R15, x86-64 only) */
        R15W(X86_REG_R15W()),
        /** BND0 bound register (MPX) */
        BND0(X86_REG_BND0()),
        /** BND1 bound register (MPX) */
        BND1(X86_REG_BND1()),
        /** BND2 bound register (MPX) */
        BND2(X86_REG_BND2()),
        /** BND3 bound register (MPX) */
        BND3(X86_REG_BND3()),
        /** End of register enum */
        ENDING(X86_REG_ENDING());

        private final int value;

        /**
         * Constructs a new X86Reg with the specified value.
         *
         * @param value The native register value
         */
        X86Reg(int value) {
            this.value = value;
        }

        /**
         * Gets the native value of the register.
         *
         * @return The native register value
         */
        public int getValue() {
            return this.value;
        }

        /**
         * Converts a native register value to its corresponding enum constant.
         *
         * @param value The native register value
         * @return The corresponding X86Reg enum constant
         * @throws IllegalArgumentException if the value is not a valid register
         */
        public static X86Reg fromValue(int value) {
            for (X86Reg reg : X86Reg.values()) {
                if (reg.value == value) {
                    return reg;
                }
            }
            throw new IllegalArgumentException("Invalid X86 register value: " + value);
        }
    }

    /**
     * Represents x86 XOP condition codes.
     * <p>
     * XOP is an AMD-specific extension to x86. These are condition codes used in XOP instructions.
     * </p>
     */
    public enum X86XopCC {
        /** Invalid condition code */
        INVALID(X86_XOP_CC_INVALID()),
        /** Less than */
        LT(X86_XOP_CC_LT()),
        /** Less than or equal */
        LE(X86_XOP_CC_LE()),
        /** Greater than */
        GT(X86_XOP_CC_GT()),
        /** Greater than or equal */
        GE(X86_XOP_CC_GE()),
        /** Equal */
        EQ(X86_XOP_CC_EQ()),
        /** Not equal */
        NEQ(X86_XOP_CC_NEQ()),
        /** False (always 0) */
        FALSE(X86_XOP_CC_FALSE()),
        /** True (always 1) */
        TRUE(X86_XOP_CC_TRUE());

        private final int value;

        /**
         * Constructs a new X86XopCC with the specified value.
         *
         * @param value The native condition code value
         */
        X86XopCC(int value) {
            this.value = value;
        }

        /**
         * Gets the native value of the condition code.
         *
         * @return The native condition code value
         */
        public int getValue() {
            return this.value;
        }

        /**
         * Converts a native condition code value to its corresponding enum constant.
         *
         * @param value The native condition code value
         * @return The corresponding X86XopCC enum constant
         * @throws IllegalArgumentException if the value is not a valid condition code
         */
        public static X86XopCC fromValue(int value) {
            for (X86XopCC cc : X86XopCC.values()) {
                if (cc.value == value) {
                    return cc;
                }
            }
            throw new IllegalArgumentException("Invalid X86 XOP CC value: " + value);
        }
    }

    /**
     * Represents x86 SSE condition codes.
     * <p>
     * These are condition codes used in SSE compare instructions.
     * </p>
     */
    public enum X86SseCC {
        /** Invalid condition code */
        INVALID(X86_SSE_CC_INVALID()),
        /** Equal */
        EQ(X86_SSE_CC_EQ()),
        /** Less than */
        LT(X86_SSE_CC_LT()),
        /** Less than or equal */
        LE(X86_SSE_CC_LE()),
        /** Unordered */
        UNORD(X86_SSE_CC_UNORD()),
        /** Not equal */
        NEQ(X86_SSE_CC_NEQ()),
        /** Not less than */
        NLT(X86_SSE_CC_NLT()),
        /** Not less than or equal */
        NLE(X86_SSE_CC_NLE()),
        /** Ordered */
        ORD(X86_SSE_CC_ORD());

        private final int value;

        /**
         * Constructs a new X86SseCC with the specified value.
         *
         * @param value The native condition code value
         */
        X86SseCC(int value) {
            this.value = value;
        }

        /**
         * Gets the native value of the condition code.
         *
         * @return The native condition code value
         */
        public int getValue() {
            return this.value;
        }

        /**
         * Converts a native condition code value to its corresponding enum constant.
         *
         * @param value The native condition code value
         * @return The corresponding X86SseCC enum constant
         * @throws IllegalArgumentException if the value is not a valid condition code
         */
        public static X86SseCC fromValue(int value) {
            for (X86SseCC cc : X86SseCC.values()) {
                if (cc.value == value) {
                    return cc;
                }
            }
            throw new IllegalArgumentException("Invalid X86 SSE CC value: " + value);
        }
    }

    /**
     * Represents x86 AVX condition codes.
     * <p>
     * These are condition codes used in AVX compare instructions.
     * </p>
     */
    public enum X86AvxCC {
        /** Invalid condition code */
        INVALID(X86_AVX_CC_INVALID()),
        /** Equal */
        EQ(X86_AVX_CC_EQ()),
        /** Less than */
        LT(X86_AVX_CC_LT()),
        /** Less than or equal */
        LE(X86_AVX_CC_LE()),
        /** Unordered */
        UNORD(X86_AVX_CC_UNORD()),
        /** Not equal */
        NEQ(X86_AVX_CC_NEQ()),
        /** Not less than */
        NLT(X86_AVX_CC_NLT()),
        /** Not less than or equal */
        NLE(X86_AVX_CC_NLE()),
        /** Ordered */
        ORD(X86_AVX_CC_ORD()),
        /** Equal (unordered, quiet) */
        EQ_UQ(X86_AVX_CC_EQ_UQ()),
        /** Not greater than or equal */
        NGE(X86_AVX_CC_NGE()),
        /** Not greater than */
        NGT(X86_AVX_CC_NGT()),
        /** False (always 0) */
        FALSE(X86_AVX_CC_FALSE()),
        /** Not equal (ordered, quiet) */
        NEQ_OQ(X86_AVX_CC_NEQ_OQ()),
        /** Greater than or equal */
        GE(X86_AVX_CC_GE()),
        /** Greater than */
        GT(X86_AVX_CC_GT()),
        /** True (always 1) */
        TRUE(X86_AVX_CC_TRUE()),
        /** Equal (ordered, signaling) */
        EQ_OS(X86_AVX_CC_EQ_OS()),
        /** Less than (ordered, quiet) */
        LT_OQ(X86_AVX_CC_LT_OQ()),
        /** Less than or equal (ordered, quiet) */
        LE_OQ(X86_AVX_CC_LE_OQ()),
        /** Unordered (signaling) */
        UNORD_S(X86_AVX_CC_UNORD_S()),
        /** Not equal (unordered, signaling) */
        NEQ_US(X86_AVX_CC_NEQ_US()),
        /** Not less than (unordered, quiet) */
        NLT_UQ(X86_AVX_CC_NLT_UQ()),
        /** Not less than or equal (unordered, quiet) */
        NLE_UQ(X86_AVX_CC_NLE_UQ()),
        /** Ordered (signaling) */
        ORD_S(X86_AVX_CC_ORD_S()),
        /** Equal (unordered, signaling) */
        EQ_US(X86_AVX_CC_EQ_US()),
        /** Not greater than or equal (unordered, quiet) */
        NGE_UQ(X86_AVX_CC_NGE_UQ()),
        /** Not greater than (unordered, quiet) */
        NGT_UQ(X86_AVX_CC_NGT_UQ()),
        /** False (ordered, signaling) */
        FALSE_OS(X86_AVX_CC_FALSE_OS()),
        /** Not equal (ordered, signaling) */
        NEQ_OS(X86_AVX_CC_NEQ_OS()),
        /** Greater than or equal (ordered, quiet) */
        GE_OQ(X86_AVX_CC_GE_OQ()),
        /** Greater than (ordered, quiet) */
        GT_OQ(X86_AVX_CC_GT_OQ()),
        /** True (unordered, signaling) */
        TRUE_US(X86_AVX_CC_TRUE_US());

        private final int value;

        /**
         * Constructs a new X86AvxCC with the specified value.
         *
         * @param value The native condition code value
         */
        X86AvxCC(int value) {
            this.value = value;
        }

        /**
         * Gets the native value of the condition code.
         *
         * @return The native condition code value
         */
        public int getValue() {
            return this.value;
        }

        /**
         * Converts a native condition code value to its corresponding enum constant.
         *
         * @param value The native condition code value
         * @return The corresponding X86AvxCC enum constant
         * @throws IllegalArgumentException if the value is not a valid condition code
         */
        public static X86AvxCC fromValue(int value) {
            for (X86AvxCC cc : X86AvxCC.values()) {
                if (cc.value == value) {
                    return cc;
                }
            }
            throw new IllegalArgumentException("Invalid X86 AVX CC value: " + value);
        }
    }

    /**
     * Represents x86 AVX rounding modes.
     * <p>
     * These are rounding modes used in AVX instructions that perform floating-point operations.
     * </p>
     */
    public enum X86AvxRm {
        /** Invalid rounding mode */
        INVALID(X86_AVX_RM_INVALID()),
        /** Round to nearest (even) */
        RN(X86_AVX_RM_RN()),
        /** Round down (toward negative infinity) */
        RD(X86_AVX_RM_RD()),
        /** Round up (toward positive infinity) */
        RU(X86_AVX_RM_RU()),
        /** Round toward zero (truncate) */
        RZ(X86_AVX_RM_RZ());

        private final int value;

        /**
         * Constructs a new X86AvxRm with the specified value.
         *
         * @param value The native rounding mode value
         */
        X86AvxRm(int value) {
            this.value = value;
        }

        /**
         * Gets the native value of the rounding mode.
         *
         * @return The native rounding mode value
         */
        public int getValue() {
            return this.value;
        }

        /**
         * Converts a native rounding mode value to its corresponding enum constant.
         *
         * @param value The native rounding mode value
         * @return The corresponding X86AvxRm enum constant
         * @throws IllegalArgumentException if the value is not a valid rounding mode
         */
        public static X86AvxRm fromValue(int value) {
            for (X86AvxRm rm : X86AvxRm.values()) {
                if (rm.value == value) {
                    return rm;
                }
            }
            throw new IllegalArgumentException("Invalid X86 AVX RM value: " + value);
        }
    }

    /**
     * Represents types of x86 instruction operands.
     * <p>
     * An operand can be a register, immediate value, or memory reference.
     * </p>
     */
    public enum X86OperandType {
        /** Invalid operand type */
        INVALID(CS_OP_INVALID()),
        /** Register operand */
        REG(CS_OP_REG()),
        /** Immediate value operand */
        IMM(CS_OP_IMM()),
        /** Memory reference operand */
        MEM(CS_OP_MEM());

        private final int value;

        /**
         * Constructs a new X86OperandType with the specified value.
         *
         * @param value The native operand type value
         */
        X86OperandType(int value) {
            this.value = value;
        }

        /**
         * Gets the native value of the operand type.
         *
         * @return The native operand type value
         */
        public int getValue() {
            return this.value;
        }

        /**
         * Converts a native operand type value to its corresponding enum constant.
         *
         * @param value The native operand type value
         * @return The corresponding X86OperandType enum constant
         * @throws IllegalArgumentException if the value is not a valid operand type
         */
        public static X86OperandType fromValue(int value) {
            for (X86OperandType type : X86OperandType.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid X86 operand type value: " + value);
        }
    }

    /**
     * Represents a memory operand in an x86 instruction.
     * <p>
     * Memory operands can use segment register, base register, index register with scale factor,
     * and displacement to calculate an effective address.
     * </p>
     */
    public static class X86OpMem {
        /** Segment register */
        private final X86Reg segment;
        /** Base register */
        private final X86Reg base;
        /** Index register */
        private final X86Reg index;
        /** Scale factor for index register (1, 2, 4, or 8) */
        private final int scale;
        /** Displacement value */
        private final long disp;

        /**
         * Constructs a new X86OpMem with the specified parameters.
         *
         * @param segment Segment register
         * @param base Base register
         * @param index Index register
         * @param scale Scale factor (1, 2, 4, or 8)
         * @param disp Displacement value
         */
        X86OpMem(X86Reg segment, X86Reg base, X86Reg index, int scale, long disp) {
            this.segment = segment;
            this.base = base;
            this.index = index;
            this.scale = scale;
            this.disp = disp;
        }

        /**
         * Gets the segment register.
         *
         * @return The segment register
         */
        public X86Reg getSegment() {
            return this.segment;
        }

        /**
         * Gets the base register.
         *
         * @return The base register
         */
        public X86Reg getBase() {
            return this.base;
        }

        /**
         * Gets the index register.
         *
         * @return The index register
         */
        public X86Reg getIndex() {
            return this.index;
        }

        /**
         * Gets the scale factor.
         *
         * @return The scale factor (1, 2, 4, or 8)
         */
        public int getScale() {
            return this.scale;
        }

        /**
         * Gets the displacement value.
         *
         * @return The displacement value
         */
        public long getDisp() {
            return this.disp;
        }
    }

    /**
     * Represents AVX broadcast types used in AVX instructions.
     * <p>
     * Broadcasting allows a single value to be replicated across multiple lanes in a vector register.
     * </p>
     */
    public enum X86AvxBcast {
        /** Invalid broadcast type */
        INVALID(X86_AVX_BCAST_INVALID()),
        /** Broadcast to 2 elements */
        _2(X86_AVX_BCAST_2()),
        /** Broadcast to 4 elements */
        _4(X86_AVX_BCAST_4()),
        /** Broadcast to 8 elements */
        _8(X86_AVX_BCAST_8()),
        /** Broadcast to 16 elements */
        _16(X86_AVX_BCAST_16());

        private final int value;

        /**
         * Constructs a new X86AvxBcast with the specified value.
         *
         * @param value The native broadcast type value
         */
        X86AvxBcast(int value) {
            this.value = value;
        }

        /**
         * Gets the native value of the broadcast type.
         *
         * @return The native broadcast type value
         */
        public int getValue() {
            return this.value;
        }

        /**
         * Converts a native broadcast type value to its corresponding enum constant.
         *
         * @param value The native broadcast type value
         * @return The corresponding X86AvxBcast enum constant
         * @throws IllegalArgumentException if the value is not a valid broadcast type
         */
        public static X86AvxBcast fromValue(int value) {
            for (X86AvxBcast type : X86AvxBcast.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid X86 AVX broadcast type value: " + value);
        }
    }

    /**
     * Represents an operand in an x86 instruction.
     * <p>
     * An operand can be a register, immediate value, or memory reference. It also contains
     * additional information such as size, access type, and AVX-specific attributes.
     * </p>
     */
    public static class X86Operand {
        /** Type of the operand (register, immediate, memory) */
        private final X86OperandType type;
        /** Register value (if type is REG) */
        private final X86Reg reg;
        /** Immediate value (if type is IMM) */
        private final long imm;
        /** Memory reference (if type is MEM) */
        private final X86OpMem mem;
        /** Size of the operand in bytes */
        private final int size;
        /** Access type (read, write, etc.) */
        private final int access;
        /** AVX broadcast type */
        private final X86AvxBcast avxBcast;
        /** Whether the operand uses AVX zero-masking */
        private final boolean avxZeroOpMask;

        /**
         * Constructs a new X86Operand with the specified parameters.
         *
         * @param type Type of the operand
         * @param reg Register value (if type is REG)
         * @param imm Immediate value (if type is IMM)
         * @param mem Memory reference (if type is MEM)
         * @param size Size of the operand in bytes
         * @param access Access type (read, write, etc.)
         * @param avxBcast AVX broadcast type
         * @param avxZeroOpMask Whether the operand uses AVX zero-masking
         */
        X86Operand(X86OperandType type, X86Reg reg, long imm, X86OpMem mem, int size, int access, X86AvxBcast avxBcast, boolean avxZeroOpMask) {
            this.type = type;
            this.reg = reg;
            this.imm = imm;
            this.mem = mem;
            this.size = size;
            this.access = access;
            this.avxBcast = avxBcast;
            this.avxZeroOpMask = avxZeroOpMask;
        }

        /**
         * Gets the type of the operand.
         *
         * @return The operand type
         */
        public X86OperandType getType() {
            return this.type;
        }

        /**
         * Gets the register value (if type is REG).
         *
         * @return The register value
         */
        public X86Reg getReg() {
            return this.reg;
        }

        /**
         * Gets the immediate value (if type is IMM).
         *
         * @return The immediate value
         */
        public long getImm() {
            return this.imm;
        }

        /**
         * Gets the memory reference (if type is MEM).
         *
         * @return The memory reference
         */
        public X86OpMem getMem() {
            return this.mem;
        }

        /**
         * Gets the size of the operand in bytes.
         *
         * @return The size in bytes
         */
        public int getSize() {
            return this.size;
        }

        /**
         * Gets the access type of the operand.
         *
         * @return The access type
         */
        public int getAccess() {
            return this.access;
        }

        /**
         * Gets the AVX broadcast type.
         *
         * @return The AVX broadcast type
         */
        public X86AvxBcast getAvxBcast() {
            return this.avxBcast;
        }

        /**
         * Checks if the operand uses AVX zero-masking.
         *
         * @return true if the operand uses AVX zero-masking, false otherwise
         */
        public boolean isAvxZeroOpMask() {
            return this.avxZeroOpMask;
        }
    }

    /**
     * Represents encoding information for an x86 instruction.
     * <p>
     * This provides information about the location and size of various instruction components
     * within the encoded instruction bytes.
     * </p>
     */
    public static class X86Encoding {
        /** Offset of ModR/M byte within the instruction */
        private final int modrmOffset;
        /** Offset of displacement value within the instruction */
        private final int dispOffset;
        /** Size of displacement value in bytes */
        private final int dispSize;
        /** Offset of immediate value within the instruction */
        private final int immOffset;
        /** Size of immediate value in bytes */
        private final int immSize;

        /**
         * Constructs a new X86Encoding with the specified parameters.
         *
         * @param modrmOffset Offset of ModR/M byte
         * @param dispOffset Offset of displacement value
         * @param dispSize Size of displacement value in bytes
         * @param immOffset Offset of immediate value
         * @param immSize Size of immediate value in bytes
         */
        X86Encoding(int modrmOffset, int dispOffset, int dispSize, int immOffset, int immSize) {
            this.modrmOffset = modrmOffset;
            this.dispOffset = dispOffset;
            this.dispSize = dispSize;
            this.immOffset = immOffset;
            this.immSize = immSize;
        }

        /**
         * Gets the offset of the ModR/M byte within the instruction.
         *
         * @return The ModR/M offset
         */
        public int getModrmOffset() {
            return this.modrmOffset;
        }

        /**
         * Gets the offset of the displacement value within the instruction.
         *
         * @return The displacement offset
         */
        public int getDispOffset() {
            return this.dispOffset;
        }

        /**
         * Gets the size of the displacement value in bytes.
         *
         * @return The displacement size
         */
        public int getDispSize() {
            return this.dispSize;
        }

        /**
         * Gets the offset of the immediate value within the instruction.
         *
         * @return The immediate value offset
         */
        public int getImmOffset() {
            return this.immOffset;
        }

        /**
         * Gets the size of the immediate value in bytes.
         *
         * @return The immediate value size
         */
        public int getImmSize() {
            return this.immSize;
        }
    }

    /**
     * Represents x86 instruction groups.
     * <p>
     * Instruction groups categorize instructions by functionality or extensions they belong to,
     * such as control flow instructions, SIMD extensions, etc.
     * </p>
     */
    public enum X86InsnGroup {
        /** Invalid instruction group */
        X86_GRP_INVALID(X86_GRP_INVALID()),
        
        /** Jump instructions */
        X86_GRP_JUMP(X86_GRP_JUMP()),
        /** Call instructions */
        X86_GRP_CALL(X86_GRP_CALL()),
        /** Return instructions */
        X86_GRP_RET(X86_GRP_RET()),
        /** Interrupt instructions */
        X86_GRP_INT(X86_GRP_INT()),
        /** Interrupt return instructions */
        X86_GRP_IRET(X86_GRP_IRET()),
        /** Privileged instructions */
        X86_GRP_PRIVILEGE(X86_GRP_PRIVILEGE()),
        /** Relative branch instructions */
        X86_GRP_BRANCH_RELATIVE(X86_GRP_BRANCH_RELATIVE()),

        // Architecture-specific groups
        /** Virtualization instructions */
        VM(X86_GRP_VM()),
        /** 3DNow! instructions */
        _3DNOW(X86_GRP_3DNOW()),
        /** AES instructions */
        AES(X86_GRP_AES()),
        /** ADX instructions */
        ADX(X86_GRP_ADX()),
        /** AVX instructions */
        AVX(X86_GRP_AVX()),
        /** AVX2 instructions */
        AVX2(X86_GRP_AVX2()),
        /** AVX-512 instructions */
        AVX512(X86_GRP_AVX512()),
        /** BMI instructions */
        BMI(X86_GRP_BMI()),
        /** BMI2 instructions */
        BMI2(X86_GRP_BMI2()),
        /** CMOV instructions */
        CMOV(X86_GRP_CMOV()),
        /** F16C instructions */
        F16C(X86_GRP_F16C()),
        /** FMA instructions */
        FMA(X86_GRP_FMA()),
        /** FMA4 instructions */
        FMA4(X86_GRP_FMA4()),
        /** FSGSBASE instructions */
        FSGSBASE(X86_GRP_FSGSBASE()),
        /** HLE instructions */
        HLE(X86_GRP_HLE()),
        /** MMX instructions */
        MMX(X86_GRP_MMX()),
        /** 32-bit mode */
        MODE32(X86_GRP_MODE32()),
        /** 64-bit mode */
        MODE64(X86_GRP_MODE64()),
        /** RTM instructions */
        RTM(X86_GRP_RTM()),
        /** SHA instructions */
        SHA(X86_GRP_SHA()),
        /** SSE1 instructions */
        SSE1(X86_GRP_SSE1()),
        /** SSE2 instructions */
        SSE2(X86_GRP_SSE2()),
        /** SSE3 instructions */
        SSE3(X86_GRP_SSE3()),
        /** SSE4.1 instructions */
        SSE41(X86_GRP_SSE41()),
        /** SSE4.2 instructions */
        SSE42(X86_GRP_SSE42()),
        /** SSE4A instructions */
        SSE4A(X86_GRP_SSE4A()),
        /** SSSE3 instructions */
        SSSE3(X86_GRP_SSSE3()),
        /** PCLMUL instructions */
        PCLMUL(X86_GRP_PCLMUL()),
        /** XOP instructions */
        XOP(X86_GRP_XOP()),
        /** CDI instructions */
        CDI(X86_GRP_CDI()),
        /** ERI instructions */
        ERI(X86_GRP_ERI()),
        /** TBM instructions */
        TBM(X86_GRP_TBM()),
        /** 16-bit mode */
        _16BITMODE(X86_GRP_16BITMODE()),
        /** Not in 64-bit mode */
        NOT64BITMODE(X86_GRP_NOT64BITMODE()),
        /** SGX instructions */
        SGX(X86_GRP_SGX()),
        /** DQI instructions */
        DQI(X86_GRP_DQI()),
        /** BWI instructions */
        BWI(X86_GRP_BWI()),
        /** PFI instructions */
        PFI(X86_GRP_PFI()),
        /** VLX instructions */
        VLX(X86_GRP_VLX()),
        /** SMAP instructions */
        SMAP(X86_GRP_SMAP()),
        /** NOVLX instructions */
        NOVLX(X86_GRP_NOVLX()),
        /** FPU instructions */
        FPU(X86_GRP_FPU()),

        /** End of instruction groups */
        ENDING(X86_GRP_ENDING());

        private final int value;

        /**
         * Constructs a new X86InsnGroup with the specified value.
         *
         * @param value The native instruction group value
         */
        X86InsnGroup(int value) {
            this.value = value;
        }

        /**
         * Gets the native value of the instruction group.
         *
         * @return The native instruction group value
         */
        public int getValue() {
            return value;
        }

        /**
         * Converts a native instruction group value to its corresponding enum constant.
         *
         * @param value The native instruction group value
         * @return The corresponding X86InsnGroup enum constant
         * @throws IllegalArgumentException if the value is not a valid instruction group
         */
        public static X86InsnGroup fromValue(int value) {
            for(X86InsnGroup group : X86InsnGroup.values()) {
                if(group.getValue() == value) {
                    return group;
                }
            }
            throw new IllegalArgumentException("Invalid X86 Instruction Group value: " + value);
        }
    }

    public enum X86Insn {
        INVALID(X86_INS_INVALID()),

        AAA(X86_INS_AAA()),
        AAD(X86_INS_AAD()),
        AAM(X86_INS_AAM()),
        AAS(X86_INS_AAS()),
        FABS(X86_INS_FABS()),
        ADC(X86_INS_ADC()),
        ADCX(X86_INS_ADCX()),
        ADD(X86_INS_ADD()),
        ADDPD(X86_INS_ADDPD()),
        ADDPS(X86_INS_ADDPS()),
        ADDSD(X86_INS_ADDSD()),
        ADDSS(X86_INS_ADDSS()),
        ADDSUBPD(X86_INS_ADDSUBPD()),
        ADDSUBPS(X86_INS_ADDSUBPS()),
        FADD(X86_INS_FADD()),
        FIADD(X86_INS_FIADD()),
        ADOX(X86_INS_ADOX()),
        AESDECLAST(X86_INS_AESDECLAST()),
        AESDEC(X86_INS_AESDEC()),
        AESENCLAST(X86_INS_AESENCLAST()),
        AESENC(X86_INS_AESENC()),
        AESIMC(X86_INS_AESIMC()),
        AESKEYGENASSIST(X86_INS_AESKEYGENASSIST()),
        AND(X86_INS_AND()),
        ANDN(X86_INS_ANDN()),
        ANDNPD(X86_INS_ANDNPD()),
        ANDNPS(X86_INS_ANDNPS()),
        ANDPD(X86_INS_ANDPD()),
        ANDPS(X86_INS_ANDPS()),
        ARPL(X86_INS_ARPL()),
        BEXTR(X86_INS_BEXTR()),
        BLCFILL(X86_INS_BLCFILL()),
        BLCI(X86_INS_BLCI()),
        BLCIC(X86_INS_BLCIC()),
        BLCMSK(X86_INS_BLCMSK()),
        BLCS(X86_INS_BLCS()),
        BLENDPD(X86_INS_BLENDPD()),
        BLENDPS(X86_INS_BLENDPS()),
        BLENDVPD(X86_INS_BLENDVPD()),
        BLENDVPS(X86_INS_BLENDVPS()),
        BLSFILL(X86_INS_BLSFILL()),
        BLSI(X86_INS_BLSI()),
        BLSIC(X86_INS_BLSIC()),
        BLSMSK(X86_INS_BLSMSK()),
        BLSR(X86_INS_BLSR()),
        BNDCL(X86_INS_BNDCL()),
        BNDCN(X86_INS_BNDCN()),
        BNDCU(X86_INS_BNDCU()),
        BNDLDX(X86_INS_BNDLDX()),
        BNDMK(X86_INS_BNDMK()),
        BNDMOV(X86_INS_BNDMOV()),
        BNDSTX(X86_INS_BNDSTX()),
        BOUND(X86_INS_BOUND()),
        BSF(X86_INS_BSF()),
        BSR(X86_INS_BSR()),
        BSWAP(X86_INS_BSWAP()),
        BT(X86_INS_BT()),
        BTC(X86_INS_BTC()),
        BTR(X86_INS_BTR()),
        BTS(X86_INS_BTS()),
        BZHI(X86_INS_BZHI()),
        CALL(X86_INS_CALL()),
        CBW(X86_INS_CBW()),
        CDQ(X86_INS_CDQ()),
        CDQE(X86_INS_CDQE()),
        FCHS(X86_INS_FCHS()),
        CLAC(X86_INS_CLAC()),
        CLC(X86_INS_CLC()),
        CLD(X86_INS_CLD()),
        CLDEMOTE(X86_INS_CLDEMOTE()),
        CLFLUSH(X86_INS_CLFLUSH()),
        CLFLUSHOPT(X86_INS_CLFLUSHOPT()),
        CLGI(X86_INS_CLGI()),
        CLI(X86_INS_CLI()),
        CLRSSBSY(X86_INS_CLRSSBSY()),
        CLTS(X86_INS_CLTS()),
        CLWB(X86_INS_CLWB()),
        CLZERO(X86_INS_CLZERO()),
        CMC(X86_INS_CMC()),
        CMOVA(X86_INS_CMOVA()),
        CMOVAE(X86_INS_CMOVAE()),
        CMOVB(X86_INS_CMOVB()),
        CMOVBE(X86_INS_CMOVBE()),
        FCMOVBE(X86_INS_FCMOVBE()),
        FCMOVB(X86_INS_FCMOVB()),
        CMOVE(X86_INS_CMOVE()),
        FCMOVE(X86_INS_FCMOVE()),
        CMOVG(X86_INS_CMOVG()),
        CMOVGE(X86_INS_CMOVGE()),
        CMOVL(X86_INS_CMOVL()),
        CMOVLE(X86_INS_CMOVLE()),
        FCMOVNBE(X86_INS_FCMOVNBE()),
        FCMOVNB(X86_INS_FCMOVNB()),
        CMOVNE(X86_INS_CMOVNE()),
        FCMOVNE(X86_INS_FCMOVNE()),
        CMOVNO(X86_INS_CMOVNO()),
        CMOVNP(X86_INS_CMOVNP()),
        FCMOVNU(X86_INS_FCMOVNU()),
        FCMOVNP(X86_INS_FCMOVNP()),
        CMOVNS(X86_INS_CMOVNS()),
        CMOVO(X86_INS_CMOVO()),
        CMOVP(X86_INS_CMOVP()),
        FCMOVU(X86_INS_FCMOVU()),
        CMOVS(X86_INS_CMOVS()),
        CMP(X86_INS_CMP()),
        CMPPD(X86_INS_CMPPD()),
        CMPPS(X86_INS_CMPPS()),
        CMPSB(X86_INS_CMPSB()),
        CMPSD(X86_INS_CMPSD()),
        CMPSQ(X86_INS_CMPSQ()),
        CMPSS(X86_INS_CMPSS()),
        CMPSW(X86_INS_CMPSW()),
        CMPXCHG16B(X86_INS_CMPXCHG16B()),
        CMPXCHG(X86_INS_CMPXCHG()),
        CMPXCHG8B(X86_INS_CMPXCHG8B()),
        COMISD(X86_INS_COMISD()),
        COMISS(X86_INS_COMISS()),
        FCOMP(X86_INS_FCOMP()),
        FCOMPI(X86_INS_FCOMPI()),
        FCOMI(X86_INS_FCOMI()),
        FCOM(X86_INS_FCOM()),
        FCOS(X86_INS_FCOS()),
        CPUID(X86_INS_CPUID()),
        CQO(X86_INS_CQO()),
        CRC32(X86_INS_CRC32()),
        CVTDQ2PD(X86_INS_CVTDQ2PD()),
        CVTDQ2PS(X86_INS_CVTDQ2PS()),
        CVTPD2DQ(X86_INS_CVTPD2DQ()),
        CVTPD2PS(X86_INS_CVTPD2PS()),
        CVTPS2DQ(X86_INS_CVTPS2DQ()),
        CVTPS2PD(X86_INS_CVTPS2PD()),
        CVTSD2SI(X86_INS_CVTSD2SI()),
        CVTSD2SS(X86_INS_CVTSD2SS()),
        CVTSI2SD(X86_INS_CVTSI2SD()),
        CVTSI2SS(X86_INS_CVTSI2SS()),
        CVTSS2SD(X86_INS_CVTSS2SD()),
        CVTSS2SI(X86_INS_CVTSS2SI()),
        CVTTPD2DQ(X86_INS_CVTTPD2DQ()),
        CVTTPS2DQ(X86_INS_CVTTPS2DQ()),
        CVTTSD2SI(X86_INS_CVTTSD2SI()),
        CVTTSS2SI(X86_INS_CVTTSS2SI()),
        CWD(X86_INS_CWD()),
        CWDE(X86_INS_CWDE()),
        DAA(X86_INS_DAA()),
        DAS(X86_INS_DAS()),
        DATA16(X86_INS_DATA16()),
        DEC(X86_INS_DEC()),
        DIV(X86_INS_DIV()),
        DIVPD(X86_INS_DIVPD()),
        DIVPS(X86_INS_DIVPS()),
        FDIVR(X86_INS_FDIVR()),
        FIDIVR(X86_INS_FIDIVR()),
        FDIVRP(X86_INS_FDIVRP()),
        DIVSD(X86_INS_DIVSD()),
        DIVSS(X86_INS_DIVSS()),
        FDIV(X86_INS_FDIV()),
        FIDIV(X86_INS_FIDIV()),
        FDIVP(X86_INS_FDIVP()),
        DPPD(X86_INS_DPPD()),
        DPPS(X86_INS_DPPS()),
        ENCLS(X86_INS_ENCLS()),
        ENCLU(X86_INS_ENCLU()),
        ENCLV(X86_INS_ENCLV()),
        ENDBR32(X86_INS_ENDBR32()),
        ENDBR64(X86_INS_ENDBR64()),
        ENTER(X86_INS_ENTER()),
        EXTRACTPS(X86_INS_EXTRACTPS()),
        EXTRQ(X86_INS_EXTRQ()),
        F2XM1(X86_INS_F2XM1()),
        LCALL(X86_INS_LCALL()),
        LJMP(X86_INS_LJMP()),
        JMP(X86_INS_JMP()),
        FBLD(X86_INS_FBLD()),
        FBSTP(X86_INS_FBSTP()),
        FCOMPP(X86_INS_FCOMPP()),
        FDECSTP(X86_INS_FDECSTP()),
        FDISI8087_NOP(X86_INS_FDISI8087_NOP()),
        FEMMS(X86_INS_FEMMS()),
        FENI8087_NOP(X86_INS_FENI8087_NOP()),
        FFREE(X86_INS_FFREE()),
        FFREEP(X86_INS_FFREEP()),
        FICOM(X86_INS_FICOM()),
        FICOMP(X86_INS_FICOMP()),
        FINCSTP(X86_INS_FINCSTP()),
        FLDCW(X86_INS_FLDCW()),
        FLDENV(X86_INS_FLDENV()),
        FLDL2E(X86_INS_FLDL2E()),
        FLDL2T(X86_INS_FLDL2T()),
        FLDLG2(X86_INS_FLDLG2()),
        FLDLN2(X86_INS_FLDLN2()),
        FLDPI(X86_INS_FLDPI()),
        FNCLEX(X86_INS_FNCLEX()),
        FNINIT(X86_INS_FNINIT()),
        FNOP(X86_INS_FNOP()),
        FNSTCW(X86_INS_FNSTCW()),
        FNSTSW(X86_INS_FNSTSW()),
        FPATAN(X86_INS_FPATAN()),
        FSTPNCE(X86_INS_FSTPNCE()),
        FPREM(X86_INS_FPREM()),
        FPREM1(X86_INS_FPREM1()),
        FPTAN(X86_INS_FPTAN()),
        FRNDINT(X86_INS_FRNDINT()),
        FRSTOR(X86_INS_FRSTOR()),
        FNSAVE(X86_INS_FNSAVE()),
        FSCALE(X86_INS_FSCALE()),
        FSETPM(X86_INS_FSETPM()),
        FSINCOS(X86_INS_FSINCOS()),
        FNSTENV(X86_INS_FNSTENV()),
        FXAM(X86_INS_FXAM()),
        FXRSTOR(X86_INS_FXRSTOR()),
        FXRSTOR64(X86_INS_FXRSTOR64()),
        FXSAVE(X86_INS_FXSAVE()),
        FXSAVE64(X86_INS_FXSAVE64()),
        FXTRACT(X86_INS_FXTRACT()),
        FYL2X(X86_INS_FYL2X()),
        FYL2XP1(X86_INS_FYL2XP1()),
        GETSEC(X86_INS_GETSEC()),
        GF2P8AFFINEINVQB(X86_INS_GF2P8AFFINEINVQB()),
        GF2P8AFFINEQB(X86_INS_GF2P8AFFINEQB()),
        GF2P8MULB(X86_INS_GF2P8MULB()),
        HADDPD(X86_INS_HADDPD()),
        HADDPS(X86_INS_HADDPS()),
        HLT(X86_INS_HLT()),
        HSUBPD(X86_INS_HSUBPD()),
        HSUBPS(X86_INS_HSUBPS()),
        IDIV(X86_INS_IDIV()),
        FILD(X86_INS_FILD()),
        IMUL(X86_INS_IMUL()),
        IN(X86_INS_IN()),
        INC(X86_INS_INC()),
        INCSSPD(X86_INS_INCSSPD()),
        INCSSPQ(X86_INS_INCSSPQ()),
        INSB(X86_INS_INSB()),
        INSERTPS(X86_INS_INSERTPS()),
        INSERTQ(X86_INS_INSERTQ()),
        INSD(X86_INS_INSD()),
        INSW(X86_INS_INSW()),
        INT(X86_INS_INT()),
        INT1(X86_INS_INT1()),
        INT3(X86_INS_INT3()),
        INTO(X86_INS_INTO()),
        INVD(X86_INS_INVD()),
        INVEPT(X86_INS_INVEPT()),
        INVLPG(X86_INS_INVLPG()),
        INVLPGA(X86_INS_INVLPGA()),
        INVPCID(X86_INS_INVPCID()),
        INVVPID(X86_INS_INVVPID()),
        IRET(X86_INS_IRET()),
        IRETD(X86_INS_IRETD()),
        IRETQ(X86_INS_IRETQ()),
        FISTTP(X86_INS_FISTTP()),
        FIST(X86_INS_FIST()),
        FISTP(X86_INS_FISTP()),
        JAE(X86_INS_JAE()),
        JA(X86_INS_JA()),
        JBE(X86_INS_JBE()),
        JB(X86_INS_JB()),
        JCXZ(X86_INS_JCXZ()),
        JECXZ(X86_INS_JECXZ()),
        JE(X86_INS_JE()),
        JGE(X86_INS_JGE()),
        JG(X86_INS_JG()),
        JLE(X86_INS_JLE()),
        JL(X86_INS_JL()),
        JNE(X86_INS_JNE()),
        JNO(X86_INS_JNO()),
        JNP(X86_INS_JNP()),
        JNS(X86_INS_JNS()),
        JO(X86_INS_JO()),
        JP(X86_INS_JP()),
        JRCXZ(X86_INS_JRCXZ()),
        JS(X86_INS_JS()),
        KADDB(X86_INS_KADDB()),
        KADDD(X86_INS_KADDD()),
        KADDQ(X86_INS_KADDQ()),
        KADDW(X86_INS_KADDW()),
        KANDB(X86_INS_KANDB()),
        KANDD(X86_INS_KANDD()),
        KANDNB(X86_INS_KANDNB()),
        KANDND(X86_INS_KANDND()),
        KANDNQ(X86_INS_KANDNQ()),
        KANDNW(X86_INS_KANDNW()),
        KANDQ(X86_INS_KANDQ()),
        KANDW(X86_INS_KANDW()),
        KMOVB(X86_INS_KMOVB()),
        KMOVD(X86_INS_KMOVD()),
        KMOVQ(X86_INS_KMOVQ()),
        KMOVW(X86_INS_KMOVW()),
        KNOTB(X86_INS_KNOTB()),
        KNOTD(X86_INS_KNOTD()),
        KNOTQ(X86_INS_KNOTQ()),
        KNOTW(X86_INS_KNOTW()),
        KORB(X86_INS_KORB()),
        KORD(X86_INS_KORD()),
        KORQ(X86_INS_KORQ()),
        KORTESTB(X86_INS_KORTESTB()),
        KORTESTD(X86_INS_KORTESTD()),
        KORTESTQ(X86_INS_KORTESTQ()),
        KORTESTW(X86_INS_KORTESTW()),
        KORW(X86_INS_KORW()),
        KSHIFTLB(X86_INS_KSHIFTLB()),
        KSHIFTLD(X86_INS_KSHIFTLD()),
        KSHIFTLQ(X86_INS_KSHIFTLQ()),
        KSHIFTLW(X86_INS_KSHIFTLW()),
        KSHIFTRB(X86_INS_KSHIFTRB()),
        KSHIFTRD(X86_INS_KSHIFTRD()),
        KSHIFTRQ(X86_INS_KSHIFTRQ()),
        KSHIFTRW(X86_INS_KSHIFTRW()),
        KTESTB(X86_INS_KTESTB()),
        KTESTD(X86_INS_KTESTD()),
        KTESTQ(X86_INS_KTESTQ()),
        KTESTW(X86_INS_KTESTW()),
        KUNPCKBW(X86_INS_KUNPCKBW()),
        KUNPCKDQ(X86_INS_KUNPCKDQ()),
        KUNPCKWD(X86_INS_KUNPCKWD()),
        KXNORB(X86_INS_KXNORB()),
        KXNORD(X86_INS_KXNORD()),
        KXNORQ(X86_INS_KXNORQ()),
        KXNORW(X86_INS_KXNORW()),
        KXORB(X86_INS_KXORB()),
        KXORD(X86_INS_KXORD()),
        KXORQ(X86_INS_KXORQ()),
        KXORW(X86_INS_KXORW()),
        LAHF(X86_INS_LAHF()),
        LAR(X86_INS_LAR()),
        LDDQU(X86_INS_LDDQU()),
        LDMXCSR(X86_INS_LDMXCSR()),
        LDS(X86_INS_LDS()),
        FLDZ(X86_INS_FLDZ()),
        FLD1(X86_INS_FLD1()),
        FLD(X86_INS_FLD()),
        LEA(X86_INS_LEA()),
        LEAVE(X86_INS_LEAVE()),
        LES(X86_INS_LES()),
        LFENCE(X86_INS_LFENCE()),
        LFS(X86_INS_LFS()),
        LGDT(X86_INS_LGDT()),
        LGS(X86_INS_LGS()),
        LIDT(X86_INS_LIDT()),
        LLDT(X86_INS_LLDT()),
        LLWPCB(X86_INS_LLWPCB()),
        LMSW(X86_INS_LMSW()),
        LOCK(X86_INS_LOCK()),
        LODSB(X86_INS_LODSB()),
        LODSD(X86_INS_LODSD()),
        LODSQ(X86_INS_LODSQ()),
        LODSW(X86_INS_LODSW()),
        LOOP(X86_INS_LOOP()),
        LOOPE(X86_INS_LOOPE()),
        LOOPNE(X86_INS_LOOPNE()),
        RETF(X86_INS_RETF()),
        RETFQ(X86_INS_RETFQ()),
        LSL(X86_INS_LSL()),
        LSS(X86_INS_LSS()),
        LTR(X86_INS_LTR()),
        LWPINS(X86_INS_LWPINS()),
        LWPVAL(X86_INS_LWPVAL()),
        LZCNT(X86_INS_LZCNT()),
        MASKMOVDQU(X86_INS_MASKMOVDQU()),
        MAXPD(X86_INS_MAXPD()),
        MAXPS(X86_INS_MAXPS()),
        MAXSD(X86_INS_MAXSD()),
        MAXSS(X86_INS_MAXSS()),
        MFENCE(X86_INS_MFENCE()),
        MINPD(X86_INS_MINPD()),
        MINPS(X86_INS_MINPS()),
        MINSD(X86_INS_MINSD()),
        MINSS(X86_INS_MINSS()),
        CVTPD2PI(X86_INS_CVTPD2PI()),
        CVTPI2PD(X86_INS_CVTPI2PD()),
        CVTPI2PS(X86_INS_CVTPI2PS()),
        CVTPS2PI(X86_INS_CVTPS2PI()),
        CVTTPD2PI(X86_INS_CVTTPD2PI()),
        CVTTPS2PI(X86_INS_CVTTPS2PI()),
        EMMS(X86_INS_EMMS()),
        MASKMOVQ(X86_INS_MASKMOVQ()),
        MOVD(X86_INS_MOVD()),
        MOVQ(X86_INS_MOVQ()),
        MOVDQ2Q(X86_INS_MOVDQ2Q()),
        MOVNTQ(X86_INS_MOVNTQ()),
        MOVQ2DQ(X86_INS_MOVQ2DQ()),
        PABSB(X86_INS_PABSB()),
        PABSD(X86_INS_PABSD()),
        PABSW(X86_INS_PABSW()),
        PACKSSDW(X86_INS_PACKSSDW()),
        PACKSSWB(X86_INS_PACKSSWB()),
        PACKUSWB(X86_INS_PACKUSWB()),
        PADDB(X86_INS_PADDB()),
        PADDD(X86_INS_PADDD()),
        PADDQ(X86_INS_PADDQ()),
        PADDSB(X86_INS_PADDSB()),
        PADDSW(X86_INS_PADDSW()),
        PADDUSB(X86_INS_PADDUSB()),
        PADDUSW(X86_INS_PADDUSW()),
        PADDW(X86_INS_PADDW()),
        PALIGNR(X86_INS_PALIGNR()),
        PANDN(X86_INS_PANDN()),
        PAND(X86_INS_PAND()),
        PAVGB(X86_INS_PAVGB()),
        PAVGW(X86_INS_PAVGW()),
        PCMPEQB(X86_INS_PCMPEQB()),
        PCMPEQD(X86_INS_PCMPEQD()),
        PCMPEQW(X86_INS_PCMPEQW()),
        PCMPGTB(X86_INS_PCMPGTB()),
        PCMPGTD(X86_INS_PCMPGTD()),
        PCMPGTW(X86_INS_PCMPGTW()),
        PEXTRW(X86_INS_PEXTRW()),
        PHADDD(X86_INS_PHADDD()),
        PHADDSW(X86_INS_PHADDSW()),
        PHADDW(X86_INS_PHADDW()),
        PHSUBD(X86_INS_PHSUBD()),
        PHSUBSW(X86_INS_PHSUBSW()),
        PHSUBW(X86_INS_PHSUBW()),
        PINSRW(X86_INS_PINSRW()),
        PMADDUBSW(X86_INS_PMADDUBSW()),
        PMADDWD(X86_INS_PMADDWD()),
        PMAXSW(X86_INS_PMAXSW()),
        PMAXUB(X86_INS_PMAXUB()),
        PMINSW(X86_INS_PMINSW()),
        PMINUB(X86_INS_PMINUB()),
        PMOVMSKB(X86_INS_PMOVMSKB()),
        PMULHRSW(X86_INS_PMULHRSW()),
        PMULHUW(X86_INS_PMULHUW()),
        PMULHW(X86_INS_PMULHW()),
        PMULLW(X86_INS_PMULLW()),
        PMULUDQ(X86_INS_PMULUDQ()),
        POR(X86_INS_POR()),
        PSADBW(X86_INS_PSADBW()),
        PSHUFB(X86_INS_PSHUFB()),
        PSHUFW(X86_INS_PSHUFW()),
        PSIGNB(X86_INS_PSIGNB()),
        PSIGND(X86_INS_PSIGND()),
        PSIGNW(X86_INS_PSIGNW()),
        PSLLD(X86_INS_PSLLD()),
        PSLLQ(X86_INS_PSLLQ()),
        PSLLW(X86_INS_PSLLW()),
        PSRAD(X86_INS_PSRAD()),
        PSRAW(X86_INS_PSRAW()),
        PSRLD(X86_INS_PSRLD()),
        PSRLQ(X86_INS_PSRLQ()),
        PSRLW(X86_INS_PSRLW()),
        PSUBB(X86_INS_PSUBB()),
        PSUBD(X86_INS_PSUBD()),
        PSUBQ(X86_INS_PSUBQ()),
        PSUBSB(X86_INS_PSUBSB()),
        PSUBSW(X86_INS_PSUBSW()),
        PSUBUSB(X86_INS_PSUBUSB()),
        PSUBUSW(X86_INS_PSUBUSW()),
        PSUBW(X86_INS_PSUBW()),
        PUNPCKHBW(X86_INS_PUNPCKHBW()),
        PUNPCKHDQ(X86_INS_PUNPCKHDQ()),
        PUNPCKHWD(X86_INS_PUNPCKHWD()),
        PUNPCKLBW(X86_INS_PUNPCKLBW()),
        PUNPCKLDQ(X86_INS_PUNPCKLDQ()),
        PUNPCKLWD(X86_INS_PUNPCKLWD()),
        PXOR(X86_INS_PXOR()),
        MONITORX(X86_INS_MONITORX()),
        MONITOR(X86_INS_MONITOR()),
        MONTMUL(X86_INS_MONTMUL()),
        MOV(X86_INS_MOV()),
        MOVABS(X86_INS_MOVABS()),
        MOVAPD(X86_INS_MOVAPD()),
        MOVAPS(X86_INS_MOVAPS()),
        MOVBE(X86_INS_MOVBE()),
        MOVDDUP(X86_INS_MOVDDUP()),
        MOVDIR64B(X86_INS_MOVDIR64B()),
        MOVDIRI(X86_INS_MOVDIRI()),
        MOVDQA(X86_INS_MOVDQA()),
        MOVDQU(X86_INS_MOVDQU()),
        MOVHLPS(X86_INS_MOVHLPS()),
        MOVHPD(X86_INS_MOVHPD()),
        MOVHPS(X86_INS_MOVHPS()),
        MOVLHPS(X86_INS_MOVLHPS()),
        MOVLPD(X86_INS_MOVLPD()),
        MOVLPS(X86_INS_MOVLPS()),
        MOVMSKPD(X86_INS_MOVMSKPD()),
        MOVMSKPS(X86_INS_MOVMSKPS()),
        MOVNTDQA(X86_INS_MOVNTDQA()),
        MOVNTDQ(X86_INS_MOVNTDQ()),
        MOVNTI(X86_INS_MOVNTI()),
        MOVNTPD(X86_INS_MOVNTPD()),
        MOVNTPS(X86_INS_MOVNTPS()),
        MOVNTSD(X86_INS_MOVNTSD()),
        MOVNTSS(X86_INS_MOVNTSS()),
        MOVSB(X86_INS_MOVSB()),
        MOVSD(X86_INS_MOVSD()),
        MOVSHDUP(X86_INS_MOVSHDUP()),
        MOVSLDUP(X86_INS_MOVSLDUP()),
        MOVSQ(X86_INS_MOVSQ()),
        MOVSS(X86_INS_MOVSS()),
        MOVSW(X86_INS_MOVSW()),
        MOVSX(X86_INS_MOVSX()),
        MOVSXD(X86_INS_MOVSXD()),
        MOVUPD(X86_INS_MOVUPD()),
        MOVUPS(X86_INS_MOVUPS()),
        MOVZX(X86_INS_MOVZX()),
        MPSADBW(X86_INS_MPSADBW()),
        MUL(X86_INS_MUL()),
        MULPD(X86_INS_MULPD()),
        MULPS(X86_INS_MULPS()),
        MULSD(X86_INS_MULSD()),
        MULSS(X86_INS_MULSS()),
        MULX(X86_INS_MULX()),
        FMUL(X86_INS_FMUL()),
        FIMUL(X86_INS_FIMUL()),
        FMULP(X86_INS_FMULP()),
        MWAITX(X86_INS_MWAITX()),
        MWAIT(X86_INS_MWAIT()),
        NEG(X86_INS_NEG()),
        NOP(X86_INS_NOP()),
        NOT(X86_INS_NOT()),
        OR(X86_INS_OR()),
        ORPD(X86_INS_ORPD()),
        ORPS(X86_INS_ORPS()),
        OUT(X86_INS_OUT()),
        OUTSB(X86_INS_OUTSB()),
        OUTSD(X86_INS_OUTSD()),
        OUTSW(X86_INS_OUTSW()),
        PACKUSDW(X86_INS_PACKUSDW()),
        PAUSE(X86_INS_PAUSE()),
        PAVGUSB(X86_INS_PAVGUSB()),
        PBLENDVB(X86_INS_PBLENDVB()),
        PBLENDW(X86_INS_PBLENDW()),
        PCLMULQDQ(X86_INS_PCLMULQDQ()),
        PCMPEQQ(X86_INS_PCMPEQQ()),
        PCMPESTRI(X86_INS_PCMPESTRI()),
        PCMPESTRM(X86_INS_PCMPESTRM()),
        PCMPGTQ(X86_INS_PCMPGTQ()),
        PCMPISTRI(X86_INS_PCMPISTRI()),
        PCMPISTRM(X86_INS_PCMPISTRM()),
        PCONFIG(X86_INS_PCONFIG()),
        PDEP(X86_INS_PDEP()),
        PEXT(X86_INS_PEXT()),
        PEXTRB(X86_INS_PEXTRB()),
        PEXTRD(X86_INS_PEXTRD()),
        PEXTRQ(X86_INS_PEXTRQ()),
        PF2ID(X86_INS_PF2ID()),
        PF2IW(X86_INS_PF2IW()),
        PFACC(X86_INS_PFACC()),
        PFADD(X86_INS_PFADD()),
        PFCMPEQ(X86_INS_PFCMPEQ()),
        PFCMPGE(X86_INS_PFCMPGE()),
        PFCMPGT(X86_INS_PFCMPGT()),
        PFMAX(X86_INS_PFMAX()),
        PFMIN(X86_INS_PFMIN()),
        PFMUL(X86_INS_PFMUL()),
        PFNACC(X86_INS_PFNACC()),
        PFPNACC(X86_INS_PFPNACC()),
        PFRCPIT1(X86_INS_PFRCPIT1()),
        PFRCPIT2(X86_INS_PFRCPIT2()),
        PFRCP(X86_INS_PFRCP()),
        PFRSQIT1(X86_INS_PFRSQIT1()),
        PFRSQRT(X86_INS_PFRSQRT()),
        PFSUBR(X86_INS_PFSUBR()),
        PFSUB(X86_INS_PFSUB()),
        PHMINPOSUW(X86_INS_PHMINPOSUW()),
        PI2FD(X86_INS_PI2FD()),
        PI2FW(X86_INS_PI2FW()),
        PINSRB(X86_INS_PINSRB()),
        PINSRD(X86_INS_PINSRD()),
        PINSRQ(X86_INS_PINSRQ()),
        PMAXSB(X86_INS_PMAXSB()),
        PMAXSD(X86_INS_PMAXSD()),
        PMAXUD(X86_INS_PMAXUD()),
        PMAXUW(X86_INS_PMAXUW()),
        PMINSB(X86_INS_PMINSB()),
        PMINSD(X86_INS_PMINSD()),
        PMINUD(X86_INS_PMINUD()),
        PMINUW(X86_INS_PMINUW()),
        PMOVSXBD(X86_INS_PMOVSXBD()),
        PMOVSXBQ(X86_INS_PMOVSXBQ()),
        PMOVSXBW(X86_INS_PMOVSXBW()),
        PMOVSXDQ(X86_INS_PMOVSXDQ()),
        PMOVSXWD(X86_INS_PMOVSXWD()),
        PMOVSXWQ(X86_INS_PMOVSXWQ()),
        PMOVZXBD(X86_INS_PMOVZXBD()),
        PMOVZXBQ(X86_INS_PMOVZXBQ()),
        PMOVZXBW(X86_INS_PMOVZXBW()),
        PMOVZXDQ(X86_INS_PMOVZXDQ()),
        PMOVZXWD(X86_INS_PMOVZXWD()),
        PMOVZXWQ(X86_INS_PMOVZXWQ()),
        PMULDQ(X86_INS_PMULDQ()),
        PMULHRW(X86_INS_PMULHRW()),
        PMULLD(X86_INS_PMULLD()),
        POP(X86_INS_POP()),
        POPAW(X86_INS_POPAW()),
        POPAL(X86_INS_POPAL()),
        POPCNT(X86_INS_POPCNT()),
        POPF(X86_INS_POPF()),
        POPFD(X86_INS_POPFD()),
        POPFQ(X86_INS_POPFQ()),
        PREFETCH(X86_INS_PREFETCH()),
        PREFETCHNTA(X86_INS_PREFETCHNTA()),
        PREFETCHT0(X86_INS_PREFETCHT0()),
        PREFETCHT1(X86_INS_PREFETCHT1()),
        PREFETCHT2(X86_INS_PREFETCHT2()),
        PREFETCHW(X86_INS_PREFETCHW()),
        PREFETCHWT1(X86_INS_PREFETCHWT1()),
        PSHUFD(X86_INS_PSHUFD()),
        PSHUFHW(X86_INS_PSHUFHW()),
        PSHUFLW(X86_INS_PSHUFLW()),
        PSLLDQ(X86_INS_PSLLDQ()),
        PSRLDQ(X86_INS_PSRLDQ()),
        PSWAPD(X86_INS_PSWAPD()),
        PTEST(X86_INS_PTEST()),
        PTWRITE(X86_INS_PTWRITE()),
        PUNPCKHQDQ(X86_INS_PUNPCKHQDQ()),
        PUNPCKLQDQ(X86_INS_PUNPCKLQDQ()),
        PUSH(X86_INS_PUSH()),
        PUSHAW(X86_INS_PUSHAW()),
        PUSHAL(X86_INS_PUSHAL()),
        PUSHF(X86_INS_PUSHF()),
        PUSHFD(X86_INS_PUSHFD()),
        PUSHFQ(X86_INS_PUSHFQ()),
        RCL(X86_INS_RCL()),
        RCPPS(X86_INS_RCPPS()),
        RCPSS(X86_INS_RCPSS()),
        RCR(X86_INS_RCR()),
        RDFSBASE(X86_INS_RDFSBASE()),
        RDGSBASE(X86_INS_RDGSBASE()),
        RDMSR(X86_INS_RDMSR()),
        RDPID(X86_INS_RDPID()),
        RDPKRU(X86_INS_RDPKRU()),
        RDPMC(X86_INS_RDPMC()),
        RDRAND(X86_INS_RDRAND()),
        RDSEED(X86_INS_RDSEED()),
        RDSSPD(X86_INS_RDSSPD()),
        RDSSPQ(X86_INS_RDSSPQ()),
        RDTSC(X86_INS_RDTSC()),
        RDTSCP(X86_INS_RDTSCP()),
        REPNE(X86_INS_REPNE()),
        REP(X86_INS_REP()),
        RET(X86_INS_RET()),
        REX64(X86_INS_REX64()),
        ROL(X86_INS_ROL()),
        ROR(X86_INS_ROR()),
        RORX(X86_INS_RORX()),
        ROUNDPD(X86_INS_ROUNDPD()),
        ROUNDPS(X86_INS_ROUNDPS()),
        ROUNDSD(X86_INS_ROUNDSD()),
        ROUNDSS(X86_INS_ROUNDSS()),
        RSM(X86_INS_RSM()),
        RSQRTPS(X86_INS_RSQRTPS()),
        RSQRTSS(X86_INS_RSQRTSS()),
        RSTORSSP(X86_INS_RSTORSSP()),
        SAHF(X86_INS_SAHF()),
        SAL(X86_INS_SAL()),
        SALC(X86_INS_SALC()),
        SAR(X86_INS_SAR()),
        SARX(X86_INS_SARX()),
        SAVEPREVSSP(X86_INS_SAVEPREVSSP()),
        SBB(X86_INS_SBB()),
        SCASB(X86_INS_SCASB()),
        SCASD(X86_INS_SCASD()),
        SCASQ(X86_INS_SCASQ()),
        SCASW(X86_INS_SCASW()),
        SETAE(X86_INS_SETAE()),
        SETA(X86_INS_SETA()),
        SETBE(X86_INS_SETBE()),
        SETB(X86_INS_SETB()),
        SETE(X86_INS_SETE()),
        SETGE(X86_INS_SETGE()),
        SETG(X86_INS_SETG()),
        SETLE(X86_INS_SETLE()),
        SETL(X86_INS_SETL()),
        SETNE(X86_INS_SETNE()),
        SETNO(X86_INS_SETNO()),
        SETNP(X86_INS_SETNP()),
        SETNS(X86_INS_SETNS()),
        SETO(X86_INS_SETO()),
        SETP(X86_INS_SETP()),
        SETSSBSY(X86_INS_SETSSBSY()),
        SETS(X86_INS_SETS()),
        SFENCE(X86_INS_SFENCE()),
        SGDT(X86_INS_SGDT()),
        SHA1MSG1(X86_INS_SHA1MSG1()),
        SHA1MSG2(X86_INS_SHA1MSG2()),
        SHA1NEXTE(X86_INS_SHA1NEXTE()),
        SHA1RNDS4(X86_INS_SHA1RNDS4()),
        SHA256MSG1(X86_INS_SHA256MSG1()),
        SHA256MSG2(X86_INS_SHA256MSG2()),
        SHA256RNDS2(X86_INS_SHA256RNDS2()),
        SHL(X86_INS_SHL()),
        SHLD(X86_INS_SHLD()),
        SHLX(X86_INS_SHLX()),
        SHR(X86_INS_SHR()),
        SHRD(X86_INS_SHRD()),
        SHRX(X86_INS_SHRX()),
        SHUFPD(X86_INS_SHUFPD()),
        SHUFPS(X86_INS_SHUFPS()),
        SIDT(X86_INS_SIDT()),
        FSIN(X86_INS_FSIN()),
        SKINIT(X86_INS_SKINIT()),
        SLDT(X86_INS_SLDT()),
        SLWPCB(X86_INS_SLWPCB()),
        SMSW(X86_INS_SMSW()),
        SQRTPD(X86_INS_SQRTPD()),
        SQRTPS(X86_INS_SQRTPS()),
        SQRTSD(X86_INS_SQRTSD()),
        SQRTSS(X86_INS_SQRTSS()),
        FSQRT(X86_INS_FSQRT()),
        STAC(X86_INS_STAC()),
        STC(X86_INS_STC()),
        STD(X86_INS_STD()),
        STGI(X86_INS_STGI()),
        STI(X86_INS_STI()),
        STMXCSR(X86_INS_STMXCSR()),
        STOSB(X86_INS_STOSB()),
        STOSD(X86_INS_STOSD()),
        STOSQ(X86_INS_STOSQ()),
        STOSW(X86_INS_STOSW()),
        STR(X86_INS_STR()),
        FST(X86_INS_FST()),
        FSTP(X86_INS_FSTP()),
        SUB(X86_INS_SUB()),
        SUBPD(X86_INS_SUBPD()),
        SUBPS(X86_INS_SUBPS()),
        FSUBR(X86_INS_FSUBR()),
        FISUBR(X86_INS_FISUBR()),
        FSUBRP(X86_INS_FSUBRP()),
        SUBSD(X86_INS_SUBSD()),
        SUBSS(X86_INS_SUBSS()),
        FSUB(X86_INS_FSUB()),
        FISUB(X86_INS_FISUB()),
        FSUBP(X86_INS_FSUBP()),
        SWAPGS(X86_INS_SWAPGS()),
        SYSCALL(X86_INS_SYSCALL()),
        SYSENTER(X86_INS_SYSENTER()),
        SYSEXIT(X86_INS_SYSEXIT()),
        SYSEXITQ(X86_INS_SYSEXITQ()),
        SYSRET(X86_INS_SYSRET()),
        SYSRETQ(X86_INS_SYSRETQ()),
        T1MSKC(X86_INS_T1MSKC()),
        TEST(X86_INS_TEST()),
        TPAUSE(X86_INS_TPAUSE()),
        FTST(X86_INS_FTST()),
        TZCNT(X86_INS_TZCNT()),
        TZMSK(X86_INS_TZMSK()),
        UCOMISD(X86_INS_UCOMISD()),
        UCOMISS(X86_INS_UCOMISS()),
        FUCOMPI(X86_INS_FUCOMPI()),
        FUCOMI(X86_INS_FUCOMI()),
        FUCOMPP(X86_INS_FUCOMPP()),
        FUCOMP(X86_INS_FUCOMP()),
        FUCOM(X86_INS_FUCOM()),
        UD0(X86_INS_UD0()),
        UD1(X86_INS_UD1()),
        UD2(X86_INS_UD2()),
        UMONITOR(X86_INS_UMONITOR()),
        UMWAIT(X86_INS_UMWAIT()),
        UNPCKHPD(X86_INS_UNPCKHPD()),
        UNPCKHPS(X86_INS_UNPCKHPS()),
        UNPCKLPD(X86_INS_UNPCKLPD()),
        UNPCKLPS(X86_INS_UNPCKLPS()),
        V4FMADDPS(X86_INS_V4FMADDPS()),
        V4FMADDSS(X86_INS_V4FMADDSS()),
        V4FNMADDPS(X86_INS_V4FNMADDPS()),
        V4FNMADDSS(X86_INS_V4FNMADDSS()),
        VADDPD(X86_INS_VADDPD()),
        VADDPS(X86_INS_VADDPS()),
        VADDSD(X86_INS_VADDSD()),
        VADDSS(X86_INS_VADDSS()),
        VADDSUBPD(X86_INS_VADDSUBPD()),
        VADDSUBPS(X86_INS_VADDSUBPS()),
        VAESDECLAST(X86_INS_VAESDECLAST()),
        VAESDEC(X86_INS_VAESDEC()),
        VAESENCLAST(X86_INS_VAESENCLAST()),
        VAESENC(X86_INS_VAESENC()),
        VAESIMC(X86_INS_VAESIMC()),
        VAESKEYGENASSIST(X86_INS_VAESKEYGENASSIST()),
        VALIGND(X86_INS_VALIGND()),
        VALIGNQ(X86_INS_VALIGNQ()),
        VANDNPD(X86_INS_VANDNPD()),
        VANDNPS(X86_INS_VANDNPS()),
        VANDPD(X86_INS_VANDPD()),
        VANDPS(X86_INS_VANDPS()),
        VBLENDMPD(X86_INS_VBLENDMPD()),
        VBLENDMPS(X86_INS_VBLENDMPS()),
        VBLENDPD(X86_INS_VBLENDPD()),
        VBLENDPS(X86_INS_VBLENDPS()),
        VBLENDVPD(X86_INS_VBLENDVPD()),
        VBLENDVPS(X86_INS_VBLENDVPS()),
        VBROADCASTF128(X86_INS_VBROADCASTF128()),
        VBROADCASTF32X2(X86_INS_VBROADCASTF32X2()),
        VBROADCASTF32X4(X86_INS_VBROADCASTF32X4()),
        VBROADCASTF32X8(X86_INS_VBROADCASTF32X8()),
        VBROADCASTF64X2(X86_INS_VBROADCASTF64X2()),
        VBROADCASTF64X4(X86_INS_VBROADCASTF64X4()),
        VBROADCASTI128(X86_INS_VBROADCASTI128()),
        VBROADCASTI32X2(X86_INS_VBROADCASTI32X2()),
        VBROADCASTI32X4(X86_INS_VBROADCASTI32X4()),
        VBROADCASTI32X8(X86_INS_VBROADCASTI32X8()),
        VBROADCASTI64X2(X86_INS_VBROADCASTI64X2()),
        VBROADCASTI64X4(X86_INS_VBROADCASTI64X4()),
        VBROADCASTSD(X86_INS_VBROADCASTSD()),
        VBROADCASTSS(X86_INS_VBROADCASTSS()),
        VCMP(X86_INS_VCMP()),
        VCMPPD(X86_INS_VCMPPD()),
        VCMPPS(X86_INS_VCMPPS()),
        VCMPSD(X86_INS_VCMPSD()),
        VCMPSS(X86_INS_VCMPSS()),
        VCOMISD(X86_INS_VCOMISD()),
        VCOMISS(X86_INS_VCOMISS()),
        VCOMPRESSPD(X86_INS_VCOMPRESSPD()),
        VCOMPRESSPS(X86_INS_VCOMPRESSPS()),
        VCVTDQ2PD(X86_INS_VCVTDQ2PD()),
        VCVTDQ2PS(X86_INS_VCVTDQ2PS()),
        VCVTPD2DQ(X86_INS_VCVTPD2DQ()),
        VCVTPD2PS(X86_INS_VCVTPD2PS()),
        VCVTPD2QQ(X86_INS_VCVTPD2QQ()),
        VCVTPD2UDQ(X86_INS_VCVTPD2UDQ()),
        VCVTPD2UQQ(X86_INS_VCVTPD2UQQ()),
        VCVTPH2PS(X86_INS_VCVTPH2PS()),
        VCVTPS2DQ(X86_INS_VCVTPS2DQ()),
        VCVTPS2PD(X86_INS_VCVTPS2PD()),
        VCVTPS2PH(X86_INS_VCVTPS2PH()),
        VCVTPS2QQ(X86_INS_VCVTPS2QQ()),
        VCVTPS2UDQ(X86_INS_VCVTPS2UDQ()),
        VCVTPS2UQQ(X86_INS_VCVTPS2UQQ()),
        VCVTQQ2PD(X86_INS_VCVTQQ2PD()),
        VCVTQQ2PS(X86_INS_VCVTQQ2PS()),
        VCVTSD2SI(X86_INS_VCVTSD2SI()),
        VCVTSD2SS(X86_INS_VCVTSD2SS()),
        VCVTSD2USI(X86_INS_VCVTSD2USI()),
        VCVTSI2SD(X86_INS_VCVTSI2SD()),
        VCVTSI2SS(X86_INS_VCVTSI2SS()),
        VCVTSS2SD(X86_INS_VCVTSS2SD()),
        VCVTSS2SI(X86_INS_VCVTSS2SI()),
        VCVTSS2USI(X86_INS_VCVTSS2USI()),
        VCVTTPD2DQ(X86_INS_VCVTTPD2DQ()),
        VCVTTPD2QQ(X86_INS_VCVTTPD2QQ()),
        VCVTTPD2UDQ(X86_INS_VCVTTPD2UDQ()),
        VCVTTPD2UQQ(X86_INS_VCVTTPD2UQQ()),
        VCVTTPS2DQ(X86_INS_VCVTTPS2DQ()),
        VCVTTPS2QQ(X86_INS_VCVTTPS2QQ()),
        VCVTTPS2UDQ(X86_INS_VCVTTPS2UDQ()),
        VCVTTPS2UQQ(X86_INS_VCVTTPS2UQQ()),
        VCVTTSD2SI(X86_INS_VCVTTSD2SI()),
        VCVTTSD2USI(X86_INS_VCVTTSD2USI()),
        VCVTTSS2SI(X86_INS_VCVTTSS2SI()),
        VCVTTSS2USI(X86_INS_VCVTTSS2USI()),
        VCVTUDQ2PD(X86_INS_VCVTUDQ2PD()),
        VCVTUDQ2PS(X86_INS_VCVTUDQ2PS()),
        VCVTUQQ2PD(X86_INS_VCVTUQQ2PD()),
        VCVTUQQ2PS(X86_INS_VCVTUQQ2PS()),
        VCVTUSI2SD(X86_INS_VCVTUSI2SD()),
        VCVTUSI2SS(X86_INS_VCVTUSI2SS()),
        VDBPSADBW(X86_INS_VDBPSADBW()),
        VDIVPD(X86_INS_VDIVPD()),
        VDIVPS(X86_INS_VDIVPS()),
        VDIVSD(X86_INS_VDIVSD()),
        VDIVSS(X86_INS_VDIVSS()),
        VDPPD(X86_INS_VDPPD()),
        VDPPS(X86_INS_VDPPS()),
        VERR(X86_INS_VERR()),
        VERW(X86_INS_VERW()),
        VEXP2PD(X86_INS_VEXP2PD()),
        VEXP2PS(X86_INS_VEXP2PS()),
        VEXPANDPD(X86_INS_VEXPANDPD()),
        VEXPANDPS(X86_INS_VEXPANDPS()),
        VEXTRACTF128(X86_INS_VEXTRACTF128()),
        VEXTRACTF32X4(X86_INS_VEXTRACTF32X4()),
        VEXTRACTF32X8(X86_INS_VEXTRACTF32X8()),
        VEXTRACTF64X2(X86_INS_VEXTRACTF64X2()),
        VEXTRACTF64X4(X86_INS_VEXTRACTF64X4()),
        VEXTRACTI128(X86_INS_VEXTRACTI128()),
        VEXTRACTI32X4(X86_INS_VEXTRACTI32X4()),
        VEXTRACTI32X8(X86_INS_VEXTRACTI32X8()),
        VEXTRACTI64X2(X86_INS_VEXTRACTI64X2()),
        VEXTRACTI64X4(X86_INS_VEXTRACTI64X4()),
        VEXTRACTPS(X86_INS_VEXTRACTPS()),
        VFIXUPIMMPD(X86_INS_VFIXUPIMMPD()),
        VFIXUPIMMPS(X86_INS_VFIXUPIMMPS()),
        VFIXUPIMMSD(X86_INS_VFIXUPIMMSD()),
        VFIXUPIMMSS(X86_INS_VFIXUPIMMSS()),
        VFMADD132PD(X86_INS_VFMADD132PD()),
        VFMADD132PS(X86_INS_VFMADD132PS()),
        VFMADD132SD(X86_INS_VFMADD132SD()),
        VFMADD132SS(X86_INS_VFMADD132SS()),
        VFMADD213PD(X86_INS_VFMADD213PD()),
        VFMADD213PS(X86_INS_VFMADD213PS()),
        VFMADD213SD(X86_INS_VFMADD213SD()),
        VFMADD213SS(X86_INS_VFMADD213SS()),
        VFMADD231PD(X86_INS_VFMADD231PD()),
        VFMADD231PS(X86_INS_VFMADD231PS()),
        VFMADD231SD(X86_INS_VFMADD231SD()),
        VFMADD231SS(X86_INS_VFMADD231SS()),
        VFMADDPD(X86_INS_VFMADDPD()),
        VFMADDPS(X86_INS_VFMADDPS()),
        VFMADDSD(X86_INS_VFMADDSD()),
        VFMADDSS(X86_INS_VFMADDSS()),
        VFMADDSUB132PD(X86_INS_VFMADDSUB132PD()),
        VFMADDSUB132PS(X86_INS_VFMADDSUB132PS()),
        VFMADDSUB213PD(X86_INS_VFMADDSUB213PD()),
        VFMADDSUB213PS(X86_INS_VFMADDSUB213PS()),
        VFMADDSUB231PD(X86_INS_VFMADDSUB231PD()),
        VFMADDSUB231PS(X86_INS_VFMADDSUB231PS()),
        VFMADDSUBPD(X86_INS_VFMADDSUBPD()),
        VFMADDSUBPS(X86_INS_VFMADDSUBPS()),
        VFMSUB132PD(X86_INS_VFMSUB132PD()),
        VFMSUB132PS(X86_INS_VFMSUB132PS()),
        VFMSUB132SD(X86_INS_VFMSUB132SD()),
        VFMSUB132SS(X86_INS_VFMSUB132SS()),
        VFMSUB213PD(X86_INS_VFMSUB213PD()),
        VFMSUB213PS(X86_INS_VFMSUB213PS()),
        VFMSUB213SD(X86_INS_VFMSUB213SD()),
        VFMSUB213SS(X86_INS_VFMSUB213SS()),
        VFMSUB231PD(X86_INS_VFMSUB231PD()),
        VFMSUB231PS(X86_INS_VFMSUB231PS()),
        VFMSUB231SD(X86_INS_VFMSUB231SD()),
        VFMSUB231SS(X86_INS_VFMSUB231SS()),
        VFMSUBADD132PD(X86_INS_VFMSUBADD132PD()),
        VFMSUBADD132PS(X86_INS_VFMSUBADD132PS()),
        VFMSUBADD213PD(X86_INS_VFMSUBADD213PD()),
        VFMSUBADD213PS(X86_INS_VFMSUBADD213PS()),
        VFMSUBADD231PD(X86_INS_VFMSUBADD231PD()),
        VFMSUBADD231PS(X86_INS_VFMSUBADD231PS()),
        VFMSUBADDPD(X86_INS_VFMSUBADDPD()),
        VFMSUBADDPS(X86_INS_VFMSUBADDPS()),
        VFMSUBPD(X86_INS_VFMSUBPD()),
        VFMSUBPS(X86_INS_VFMSUBPS()),
        VFMSUBSD(X86_INS_VFMSUBSD()),
        VFMSUBSS(X86_INS_VFMSUBSS()),
        VFNMADD132PD(X86_INS_VFNMADD132PD()),
        VFNMADD132PS(X86_INS_VFNMADD132PS()),
        VFNMADD132SD(X86_INS_VFNMADD132SD()),
        VFNMADD132SS(X86_INS_VFNMADD132SS()),
        VFNMADD213PD(X86_INS_VFNMADD213PD()),
        VFNMADD213PS(X86_INS_VFNMADD213PS()),
        VFNMADD213SD(X86_INS_VFNMADD213SD()),
        VFNMADD213SS(X86_INS_VFNMADD213SS()),
        VFNMADD231PD(X86_INS_VFNMADD231PD()),
        VFNMADD231PS(X86_INS_VFNMADD231PS()),
        VFNMADD231SD(X86_INS_VFNMADD231SD()),
        VFNMADD231SS(X86_INS_VFNMADD231SS()),
        VFNMADDPD(X86_INS_VFNMADDPD()),
        VFNMADDPS(X86_INS_VFNMADDPS()),
        VFNMADDSD(X86_INS_VFNMADDSD()),
        VFNMADDSS(X86_INS_VFNMADDSS()),
        VFNMSUB132PD(X86_INS_VFNMSUB132PD()),
        VFNMSUB132PS(X86_INS_VFNMSUB132PS()),
        VFNMSUB132SD(X86_INS_VFNMSUB132SD()),
        VFNMSUB132SS(X86_INS_VFNMSUB132SS()),
        VFNMSUB213PD(X86_INS_VFNMSUB213PD()),
        VFNMSUB213PS(X86_INS_VFNMSUB213PS()),
        VFNMSUB213SD(X86_INS_VFNMSUB213SD()),
        VFNMSUB213SS(X86_INS_VFNMSUB213SS()),
        VFNMSUB231PD(X86_INS_VFNMSUB231PD()),
        VFNMSUB231PS(X86_INS_VFNMSUB231PS()),
        VFNMSUB231SD(X86_INS_VFNMSUB231SD()),
        VFNMSUB231SS(X86_INS_VFNMSUB231SS()),
        VFNMSUBPD(X86_INS_VFNMSUBPD()),
        VFNMSUBPS(X86_INS_VFNMSUBPS()),
        VFNMSUBSD(X86_INS_VFNMSUBSD()),
        VFNMSUBSS(X86_INS_VFNMSUBSS()),
        VFPCLASSPD(X86_INS_VFPCLASSPD()),
        VFPCLASSPS(X86_INS_VFPCLASSPS()),
        VFPCLASSSD(X86_INS_VFPCLASSSD()),
        VFPCLASSSS(X86_INS_VFPCLASSSS()),
        VFRCZPD(X86_INS_VFRCZPD()),
        VFRCZPS(X86_INS_VFRCZPS()),
        VFRCZSD(X86_INS_VFRCZSD()),
        VFRCZSS(X86_INS_VFRCZSS()),
        VGATHERDPD(X86_INS_VGATHERDPD()),
        VGATHERDPS(X86_INS_VGATHERDPS()),
        VGATHERPF0DPD(X86_INS_VGATHERPF0DPD()),
        VGATHERPF0DPS(X86_INS_VGATHERPF0DPS()),
        VGATHERPF0QPD(X86_INS_VGATHERPF0QPD()),
        VGATHERPF0QPS(X86_INS_VGATHERPF0QPS()),
        VGATHERPF1DPD(X86_INS_VGATHERPF1DPD()),
        VGATHERPF1DPS(X86_INS_VGATHERPF1DPS()),
        VGATHERPF1QPD(X86_INS_VGATHERPF1QPD()),
        VGATHERPF1QPS(X86_INS_VGATHERPF1QPS()),
        VGATHERQPD(X86_INS_VGATHERQPD()),
        VGATHERQPS(X86_INS_VGATHERQPS()),
        VGETEXPPD(X86_INS_VGETEXPPD()),
        VGETEXPPS(X86_INS_VGETEXPPS()),
        VGETEXPSD(X86_INS_VGETEXPSD()),
        VGETEXPSS(X86_INS_VGETEXPSS()),
        VGETMANTPD(X86_INS_VGETMANTPD()),
        VGETMANTPS(X86_INS_VGETMANTPS()),
        VGETMANTSD(X86_INS_VGETMANTSD()),
        VGETMANTSS(X86_INS_VGETMANTSS()),
        VGF2P8AFFINEINVQB(X86_INS_VGF2P8AFFINEINVQB()),
        VGF2P8AFFINEQB(X86_INS_VGF2P8AFFINEQB()),
        VGF2P8MULB(X86_INS_VGF2P8MULB()),
        VHADDPD(X86_INS_VHADDPD()),
        VHADDPS(X86_INS_VHADDPS()),
        VHSUBPD(X86_INS_VHSUBPD()),
        VHSUBPS(X86_INS_VHSUBPS()),
        VINSERTF128(X86_INS_VINSERTF128()),
        VINSERTF32X4(X86_INS_VINSERTF32X4()),
        VINSERTF32X8(X86_INS_VINSERTF32X8()),
        VINSERTF64X2(X86_INS_VINSERTF64X2()),
        VINSERTF64X4(X86_INS_VINSERTF64X4()),
        VINSERTI128(X86_INS_VINSERTI128()),
        VINSERTI32X4(X86_INS_VINSERTI32X4()),
        VINSERTI32X8(X86_INS_VINSERTI32X8()),
        VINSERTI64X2(X86_INS_VINSERTI64X2()),
        VINSERTI64X4(X86_INS_VINSERTI64X4()),
        VINSERTPS(X86_INS_VINSERTPS()),
        VLDDQU(X86_INS_VLDDQU()),
        VLDMXCSR(X86_INS_VLDMXCSR()),
        VMASKMOVDQU(X86_INS_VMASKMOVDQU()),
        VMASKMOVPD(X86_INS_VMASKMOVPD()),
        VMASKMOVPS(X86_INS_VMASKMOVPS()),
        VMAXPD(X86_INS_VMAXPD()),
        VMAXPS(X86_INS_VMAXPS()),
        VMAXSD(X86_INS_VMAXSD()),
        VMAXSS(X86_INS_VMAXSS()),
        VMCALL(X86_INS_VMCALL()),
        VMCLEAR(X86_INS_VMCLEAR()),
        VMFUNC(X86_INS_VMFUNC()),
        VMINPD(X86_INS_VMINPD()),
        VMINPS(X86_INS_VMINPS()),
        VMINSD(X86_INS_VMINSD()),
        VMINSS(X86_INS_VMINSS()),
        VMLAUNCH(X86_INS_VMLAUNCH()),
        VMLOAD(X86_INS_VMLOAD()),
        VMMCALL(X86_INS_VMMCALL()),
        VMOVQ(X86_INS_VMOVQ()),
        VMOVAPD(X86_INS_VMOVAPD()),
        VMOVAPS(X86_INS_VMOVAPS()),
        VMOVDDUP(X86_INS_VMOVDDUP()),
        VMOVD(X86_INS_VMOVD()),
        VMOVDQA32(X86_INS_VMOVDQA32()),
        VMOVDQA64(X86_INS_VMOVDQA64()),
        VMOVDQA(X86_INS_VMOVDQA()),
        VMOVDQU16(X86_INS_VMOVDQU16()),
        VMOVDQU32(X86_INS_VMOVDQU32()),
        VMOVDQU64(X86_INS_VMOVDQU64()),
        VMOVDQU8(X86_INS_VMOVDQU8()),
        VMOVDQU(X86_INS_VMOVDQU()),
        VMOVHLPS(X86_INS_VMOVHLPS()),
        VMOVHPD(X86_INS_VMOVHPD()),
        VMOVHPS(X86_INS_VMOVHPS()),
        VMOVLHPS(X86_INS_VMOVLHPS()),
        VMOVLPD(X86_INS_VMOVLPD()),
        VMOVLPS(X86_INS_VMOVLPS()),
        VMOVMSKPD(X86_INS_VMOVMSKPD()),
        VMOVMSKPS(X86_INS_VMOVMSKPS()),
        VMOVNTDQA(X86_INS_VMOVNTDQA()),
        VMOVNTDQ(X86_INS_VMOVNTDQ()),
        VMOVNTPD(X86_INS_VMOVNTPD()),
        VMOVNTPS(X86_INS_VMOVNTPS()),
        VMOVSD(X86_INS_VMOVSD()),
        VMOVSHDUP(X86_INS_VMOVSHDUP()),
        VMOVSLDUP(X86_INS_VMOVSLDUP()),
        VMOVSS(X86_INS_VMOVSS()),
        VMOVUPD(X86_INS_VMOVUPD()),
        VMOVUPS(X86_INS_VMOVUPS()),
        VMPSADBW(X86_INS_VMPSADBW()),
        VMPTRLD(X86_INS_VMPTRLD()),
        VMPTRST(X86_INS_VMPTRST()),
        VMREAD(X86_INS_VMREAD()),
        VMRESUME(X86_INS_VMRESUME()),
        VMRUN(X86_INS_VMRUN()),
        VMSAVE(X86_INS_VMSAVE()),
        VMULPD(X86_INS_VMULPD()),
        VMULPS(X86_INS_VMULPS()),
        VMULSD(X86_INS_VMULSD()),
        VMULSS(X86_INS_VMULSS()),
        VMWRITE(X86_INS_VMWRITE()),
        VMXOFF(X86_INS_VMXOFF()),
        VMXON(X86_INS_VMXON()),
        VORPD(X86_INS_VORPD()),
        VORPS(X86_INS_VORPS()),
        VP4DPWSSDS(X86_INS_VP4DPWSSDS()),
        VP4DPWSSD(X86_INS_VP4DPWSSD()),
        VPABSB(X86_INS_VPABSB()),
        VPABSD(X86_INS_VPABSD()),
        VPABSQ(X86_INS_VPABSQ()),
        VPABSW(X86_INS_VPABSW()),
        VPACKSSDW(X86_INS_VPACKSSDW()),
        VPACKSSWB(X86_INS_VPACKSSWB()),
        VPACKUSDW(X86_INS_VPACKUSDW()),
        VPACKUSWB(X86_INS_VPACKUSWB()),
        VPADDB(X86_INS_VPADDB()),
        VPADDD(X86_INS_VPADDD()),
        VPADDQ(X86_INS_VPADDQ()),
        VPADDSB(X86_INS_VPADDSB()),
        VPADDSW(X86_INS_VPADDSW()),
        VPADDUSB(X86_INS_VPADDUSB()),
        VPADDUSW(X86_INS_VPADDUSW()),
        VPADDW(X86_INS_VPADDW()),
        VPALIGNR(X86_INS_VPALIGNR()),
        VPANDD(X86_INS_VPANDD()),
        VPANDND(X86_INS_VPANDND()),
        VPANDNQ(X86_INS_VPANDNQ()),
        VPANDN(X86_INS_VPANDN()),
        VPANDQ(X86_INS_VPANDQ()),
        VPAND(X86_INS_VPAND()),
        VPAVGB(X86_INS_VPAVGB()),
        VPAVGW(X86_INS_VPAVGW()),
        VPBLENDD(X86_INS_VPBLENDD()),
        VPBLENDMB(X86_INS_VPBLENDMB()),
        VPBLENDMD(X86_INS_VPBLENDMD()),
        VPBLENDMQ(X86_INS_VPBLENDMQ()),
        VPBLENDMW(X86_INS_VPBLENDMW()),
        VPBLENDVB(X86_INS_VPBLENDVB()),
        VPBLENDW(X86_INS_VPBLENDW()),
        VPBROADCASTB(X86_INS_VPBROADCASTB()),
        VPBROADCASTD(X86_INS_VPBROADCASTD()),
        VPBROADCASTMB2Q(X86_INS_VPBROADCASTMB2Q()),
        VPBROADCASTMW2D(X86_INS_VPBROADCASTMW2D()),
        VPBROADCASTQ(X86_INS_VPBROADCASTQ()),
        VPBROADCASTW(X86_INS_VPBROADCASTW()),
        VPCLMULQDQ(X86_INS_VPCLMULQDQ()),
        VPCMOV(X86_INS_VPCMOV()),
        VPCMP(X86_INS_VPCMP()),
        VPCMPB(X86_INS_VPCMPB()),
        VPCMPD(X86_INS_VPCMPD()),
        VPCMPEQB(X86_INS_VPCMPEQB()),
        VPCMPEQD(X86_INS_VPCMPEQD()),
        VPCMPEQQ(X86_INS_VPCMPEQQ()),
        VPCMPEQW(X86_INS_VPCMPEQW()),
        VPCMPESTRI(X86_INS_VPCMPESTRI()),
        VPCMPESTRM(X86_INS_VPCMPESTRM()),
        VPCMPGTB(X86_INS_VPCMPGTB()),
        VPCMPGTD(X86_INS_VPCMPGTD()),
        VPCMPGTQ(X86_INS_VPCMPGTQ()),
        VPCMPGTW(X86_INS_VPCMPGTW()),
        VPCMPISTRI(X86_INS_VPCMPISTRI()),
        VPCMPISTRM(X86_INS_VPCMPISTRM()),
        VPCMPQ(X86_INS_VPCMPQ()),
        VPCMPUB(X86_INS_VPCMPUB()),
        VPCMPUD(X86_INS_VPCMPUD()),
        VPCMPUQ(X86_INS_VPCMPUQ()),
        VPCMPUW(X86_INS_VPCMPUW()),
        VPCMPW(X86_INS_VPCMPW()),
        VPCOM(X86_INS_VPCOM()),
        VPCOMB(X86_INS_VPCOMB()),
        VPCOMD(X86_INS_VPCOMD()),
        VPCOMPRESSB(X86_INS_VPCOMPRESSB()),
        VPCOMPRESSD(X86_INS_VPCOMPRESSD()),
        VPCOMPRESSQ(X86_INS_VPCOMPRESSQ()),
        VPCOMPRESSW(X86_INS_VPCOMPRESSW()),
        VPCOMQ(X86_INS_VPCOMQ()),
        VPCOMUB(X86_INS_VPCOMUB()),
        VPCOMUD(X86_INS_VPCOMUD()),
        VPCOMUQ(X86_INS_VPCOMUQ()),
        VPCOMUW(X86_INS_VPCOMUW()),
        VPCOMW(X86_INS_VPCOMW()),
        VPCONFLICTD(X86_INS_VPCONFLICTD()),
        VPCONFLICTQ(X86_INS_VPCONFLICTQ()),
        VPDPBUSDS(X86_INS_VPDPBUSDS()),
        VPDPBUSD(X86_INS_VPDPBUSD()),
        VPDPWSSDS(X86_INS_VPDPWSSDS()),
        VPDPWSSD(X86_INS_VPDPWSSD()),
        VPERM2F128(X86_INS_VPERM2F128()),
        VPERM2I128(X86_INS_VPERM2I128()),
        VPERMB(X86_INS_VPERMB()),
        VPERMD(X86_INS_VPERMD()),
        VPERMI2B(X86_INS_VPERMI2B()),
        VPERMI2D(X86_INS_VPERMI2D()),
        VPERMI2PD(X86_INS_VPERMI2PD()),
        VPERMI2PS(X86_INS_VPERMI2PS()),
        VPERMI2Q(X86_INS_VPERMI2Q()),
        VPERMI2W(X86_INS_VPERMI2W()),
        VPERMIL2PD(X86_INS_VPERMIL2PD()),
        VPERMILPD(X86_INS_VPERMILPD()),
        VPERMIL2PS(X86_INS_VPERMIL2PS()),
        VPERMILPS(X86_INS_VPERMILPS()),
        VPERMPD(X86_INS_VPERMPD()),
        VPERMPS(X86_INS_VPERMPS()),
        VPERMQ(X86_INS_VPERMQ()),
        VPERMT2B(X86_INS_VPERMT2B()),
        VPERMT2D(X86_INS_VPERMT2D()),
        VPERMT2PD(X86_INS_VPERMT2PD()),
        VPERMT2PS(X86_INS_VPERMT2PS()),
        VPERMT2Q(X86_INS_VPERMT2Q()),
        VPERMT2W(X86_INS_VPERMT2W()),
        VPERMW(X86_INS_VPERMW()),
        VPEXPANDB(X86_INS_VPEXPANDB()),
        VPEXPANDD(X86_INS_VPEXPANDD()),
        VPEXPANDQ(X86_INS_VPEXPANDQ()),
        VPEXPANDW(X86_INS_VPEXPANDW()),
        VPEXTRB(X86_INS_VPEXTRB()),
        VPEXTRD(X86_INS_VPEXTRD()),
        VPEXTRQ(X86_INS_VPEXTRQ()),
        VPEXTRW(X86_INS_VPEXTRW()),
        VPGATHERDD(X86_INS_VPGATHERDD()),
        VPGATHERDQ(X86_INS_VPGATHERDQ()),
        VPGATHERQD(X86_INS_VPGATHERQD()),
        VPGATHERQQ(X86_INS_VPGATHERQQ()),
        VPHADDBD(X86_INS_VPHADDBD()),
        VPHADDBQ(X86_INS_VPHADDBQ()),
        VPHADDBW(X86_INS_VPHADDBW()),
        VPHADDDQ(X86_INS_VPHADDDQ()),
        VPHADDD(X86_INS_VPHADDD()),
        VPHADDSW(X86_INS_VPHADDSW()),
        VPHADDUBD(X86_INS_VPHADDUBD()),
        VPHADDUBQ(X86_INS_VPHADDUBQ()),
        VPHADDUBW(X86_INS_VPHADDUBW()),
        VPHADDUDQ(X86_INS_VPHADDUDQ()),
        VPHADDUWD(X86_INS_VPHADDUWD()),
        VPHADDUWQ(X86_INS_VPHADDUWQ()),
        VPHADDWD(X86_INS_VPHADDWD()),
        VPHADDWQ(X86_INS_VPHADDWQ()),
        VPHADDW(X86_INS_VPHADDW()),
        VPHMINPOSUW(X86_INS_VPHMINPOSUW()),
        VPHSUBBW(X86_INS_VPHSUBBW()),
        VPHSUBDQ(X86_INS_VPHSUBDQ()),
        VPHSUBD(X86_INS_VPHSUBD()),
        VPHSUBSW(X86_INS_VPHSUBSW()),
        VPHSUBWD(X86_INS_VPHSUBWD()),
        VPHSUBW(X86_INS_VPHSUBW()),
        VPINSRB(X86_INS_VPINSRB()),
        VPINSRD(X86_INS_VPINSRD()),
        VPINSRQ(X86_INS_VPINSRQ()),
        VPINSRW(X86_INS_VPINSRW()),
        VPLZCNTD(X86_INS_VPLZCNTD()),
        VPLZCNTQ(X86_INS_VPLZCNTQ()),
        VPMACSDD(X86_INS_VPMACSDD()),
        VPMACSDQH(X86_INS_VPMACSDQH()),
        VPMACSDQL(X86_INS_VPMACSDQL()),
        VPMACSSDD(X86_INS_VPMACSSDD()),
        VPMACSSDQH(X86_INS_VPMACSSDQH()),
        VPMACSSDQL(X86_INS_VPMACSSDQL()),
        VPMACSSWD(X86_INS_VPMACSSWD()),
        VPMACSSWW(X86_INS_VPMACSSWW()),
        VPMACSWD(X86_INS_VPMACSWD()),
        VPMACSWW(X86_INS_VPMACSWW()),
        VPMADCSSWD(X86_INS_VPMADCSSWD()),
        VPMADCSWD(X86_INS_VPMADCSWD()),
        VPMADD52HUQ(X86_INS_VPMADD52HUQ()),
        VPMADD52LUQ(X86_INS_VPMADD52LUQ()),
        VPMADDUBSW(X86_INS_VPMADDUBSW()),
        VPMADDWD(X86_INS_VPMADDWD()),
        VPMASKMOVD(X86_INS_VPMASKMOVD()),
        VPMASKMOVQ(X86_INS_VPMASKMOVQ()),
        VPMAXSB(X86_INS_VPMAXSB()),
        VPMAXSD(X86_INS_VPMAXSD()),
        VPMAXSQ(X86_INS_VPMAXSQ()),
        VPMAXSW(X86_INS_VPMAXSW()),
        VPMAXUB(X86_INS_VPMAXUB()),
        VPMAXUD(X86_INS_VPMAXUD()),
        VPMAXUQ(X86_INS_VPMAXUQ()),
        VPMAXUW(X86_INS_VPMAXUW()),
        VPMINSB(X86_INS_VPMINSB()),
        VPMINSD(X86_INS_VPMINSD()),
        VPMINSQ(X86_INS_VPMINSQ()),
        VPMINSW(X86_INS_VPMINSW()),
        VPMINUB(X86_INS_VPMINUB()),
        VPMINUD(X86_INS_VPMINUD()),
        VPMINUQ(X86_INS_VPMINUQ()),
        VPMINUW(X86_INS_VPMINUW()),
        VPMOVB2M(X86_INS_VPMOVB2M()),
        VPMOVD2M(X86_INS_VPMOVD2M()),
        VPMOVDB(X86_INS_VPMOVDB()),
        VPMOVDW(X86_INS_VPMOVDW()),
        VPMOVM2B(X86_INS_VPMOVM2B()),
        VPMOVM2D(X86_INS_VPMOVM2D()),
        VPMOVM2Q(X86_INS_VPMOVM2Q()),
        VPMOVM2W(X86_INS_VPMOVM2W()),
        VPMOVMSKB(X86_INS_VPMOVMSKB()),
        VPMOVQ2M(X86_INS_VPMOVQ2M()),
        VPMOVQB(X86_INS_VPMOVQB()),
        VPMOVQD(X86_INS_VPMOVQD()),
        VPMOVQW(X86_INS_VPMOVQW()),
        VPMOVSDB(X86_INS_VPMOVSDB()),
        VPMOVSDW(X86_INS_VPMOVSDW()),
        VPMOVSQB(X86_INS_VPMOVSQB()),
        VPMOVSQD(X86_INS_VPMOVSQD()),
        VPMOVSQW(X86_INS_VPMOVSQW()),
        VPMOVSWB(X86_INS_VPMOVSWB()),
        VPMOVSXBD(X86_INS_VPMOVSXBD()),
        VPMOVSXBQ(X86_INS_VPMOVSXBQ()),
        VPMOVSXBW(X86_INS_VPMOVSXBW()),
        VPMOVSXDQ(X86_INS_VPMOVSXDQ()),
        VPMOVSXWD(X86_INS_VPMOVSXWD()),
        VPMOVSXWQ(X86_INS_VPMOVSXWQ()),
        VPMOVUSDB(X86_INS_VPMOVUSDB()),
        VPMOVUSDW(X86_INS_VPMOVUSDW()),
        VPMOVUSQB(X86_INS_VPMOVUSQB()),
        VPMOVUSQD(X86_INS_VPMOVUSQD()),
        VPMOVUSQW(X86_INS_VPMOVUSQW()),
        VPMOVUSWB(X86_INS_VPMOVUSWB()),
        VPMOVW2M(X86_INS_VPMOVW2M()),
        VPMOVWB(X86_INS_VPMOVWB()),
        VPMOVZXBD(X86_INS_VPMOVZXBD()),
        VPMOVZXBQ(X86_INS_VPMOVZXBQ()),
        VPMOVZXBW(X86_INS_VPMOVZXBW()),
        VPMOVZXDQ(X86_INS_VPMOVZXDQ()),
        VPMOVZXWD(X86_INS_VPMOVZXWD()),
        VPMOVZXWQ(X86_INS_VPMOVZXWQ()),
        VPMULDQ(X86_INS_VPMULDQ()),
        VPMULHRSW(X86_INS_VPMULHRSW()),
        VPMULHUW(X86_INS_VPMULHUW()),
        VPMULHW(X86_INS_VPMULHW()),
        VPMULLD(X86_INS_VPMULLD()),
        VPMULLQ(X86_INS_VPMULLQ()),
        VPMULLW(X86_INS_VPMULLW()),
        VPMULTISHIFTQB(X86_INS_VPMULTISHIFTQB()),
        VPMULUDQ(X86_INS_VPMULUDQ()),
        VPOPCNTB(X86_INS_VPOPCNTB()),
        VPOPCNTD(X86_INS_VPOPCNTD()),
        VPOPCNTQ(X86_INS_VPOPCNTQ()),
        VPOPCNTW(X86_INS_VPOPCNTW()),
        VPORD(X86_INS_VPORD()),
        VPORQ(X86_INS_VPORQ()),
        VPOR(X86_INS_VPOR()),
        VPPERM(X86_INS_VPPERM()),
        VPROLD(X86_INS_VPROLD()),
        VPROLQ(X86_INS_VPROLQ()),
        VPROLVD(X86_INS_VPROLVD()),
        VPROLVQ(X86_INS_VPROLVQ()),
        VPRORD(X86_INS_VPRORD()),
        VPRORQ(X86_INS_VPRORQ()),
        VPRORVD(X86_INS_VPRORVD()),
        VPRORVQ(X86_INS_VPRORVQ()),
        VPROTB(X86_INS_VPROTB()),
        VPROTD(X86_INS_VPROTD()),
        VPROTQ(X86_INS_VPROTQ()),
        VPROTW(X86_INS_VPROTW()),
        VPSADBW(X86_INS_VPSADBW()),
        VPSCATTERDD(X86_INS_VPSCATTERDD()),
        VPSCATTERDQ(X86_INS_VPSCATTERDQ()),
        VPSCATTERQD(X86_INS_VPSCATTERQD()),
        VPSCATTERQQ(X86_INS_VPSCATTERQQ()),
        VPSHAB(X86_INS_VPSHAB()),
        VPSHAD(X86_INS_VPSHAD()),
        VPSHAQ(X86_INS_VPSHAQ()),
        VPSHAW(X86_INS_VPSHAW()),
        VPSHLB(X86_INS_VPSHLB()),
        VPSHLDD(X86_INS_VPSHLDD()),
        VPSHLDQ(X86_INS_VPSHLDQ()),
        VPSHLDVD(X86_INS_VPSHLDVD()),
        VPSHLDVQ(X86_INS_VPSHLDVQ()),
        VPSHLDVW(X86_INS_VPSHLDVW()),
        VPSHLDW(X86_INS_VPSHLDW()),
        VPSHLD(X86_INS_VPSHLD()),
        VPSHLQ(X86_INS_VPSHLQ()),
        VPSHLW(X86_INS_VPSHLW()),
        VPSHRDD(X86_INS_VPSHRDD()),
        VPSHRDQ(X86_INS_VPSHRDQ()),
        VPSHRDVD(X86_INS_VPSHRDVD()),
        VPSHRDVQ(X86_INS_VPSHRDVQ()),
        VPSHRDVW(X86_INS_VPSHRDVW()),
        VPSHRDW(X86_INS_VPSHRDW()),
        VPSHUFBITQMB(X86_INS_VPSHUFBITQMB()),
        VPSHUFB(X86_INS_VPSHUFB()),
        VPSHUFD(X86_INS_VPSHUFD()),
        VPSHUFHW(X86_INS_VPSHUFHW()),
        VPSHUFLW(X86_INS_VPSHUFLW()),
        VPSIGNB(X86_INS_VPSIGNB()),
        VPSIGND(X86_INS_VPSIGND()),
        VPSIGNW(X86_INS_VPSIGNW()),
        VPSLLDQ(X86_INS_VPSLLDQ()),
        VPSLLD(X86_INS_VPSLLD()),
        VPSLLQ(X86_INS_VPSLLQ()),
        VPSLLVD(X86_INS_VPSLLVD()),
        VPSLLVQ(X86_INS_VPSLLVQ()),
        VPSLLVW(X86_INS_VPSLLVW()),
        VPSLLW(X86_INS_VPSLLW()),
        VPSRAD(X86_INS_VPSRAD()),
        VPSRAQ(X86_INS_VPSRAQ()),
        VPSRAVD(X86_INS_VPSRAVD()),
        VPSRAVQ(X86_INS_VPSRAVQ()),
        VPSRAVW(X86_INS_VPSRAVW()),
        VPSRAW(X86_INS_VPSRAW()),
        VPSRLDQ(X86_INS_VPSRLDQ()),
        VPSRLD(X86_INS_VPSRLD()),
        VPSRLQ(X86_INS_VPSRLQ()),
        VPSRLVD(X86_INS_VPSRLVD()),
        VPSRLVQ(X86_INS_VPSRLVQ()),
        VPSRLVW(X86_INS_VPSRLVW()),
        VPSRLW(X86_INS_VPSRLW()),
        VPSUBB(X86_INS_VPSUBB()),
        VPSUBD(X86_INS_VPSUBD()),
        VPSUBQ(X86_INS_VPSUBQ()),
        VPSUBSB(X86_INS_VPSUBSB()),
        VPSUBSW(X86_INS_VPSUBSW()),
        VPSUBUSB(X86_INS_VPSUBUSB()),
        VPSUBUSW(X86_INS_VPSUBUSW()),
        VPSUBW(X86_INS_VPSUBW()),
        VPTERNLOGD(X86_INS_VPTERNLOGD()),
        VPTERNLOGQ(X86_INS_VPTERNLOGQ()),
        VPTESTMB(X86_INS_VPTESTMB()),
        VPTESTMD(X86_INS_VPTESTMD()),
        VPTESTMQ(X86_INS_VPTESTMQ()),
        VPTESTMW(X86_INS_VPTESTMW()),
        VPTESTNMB(X86_INS_VPTESTNMB()),
        VPTESTNMD(X86_INS_VPTESTNMD()),
        VPTESTNMQ(X86_INS_VPTESTNMQ()),
        VPTESTNMW(X86_INS_VPTESTNMW()),
        VPTEST(X86_INS_VPTEST()),
        VPUNPCKHBW(X86_INS_VPUNPCKHBW()),
        VPUNPCKHDQ(X86_INS_VPUNPCKHDQ()),
        VPUNPCKHQDQ(X86_INS_VPUNPCKHQDQ()),
        VPUNPCKHWD(X86_INS_VPUNPCKHWD()),
        VPUNPCKLBW(X86_INS_VPUNPCKLBW()),
        VPUNPCKLDQ(X86_INS_VPUNPCKLDQ()),
        VPUNPCKLQDQ(X86_INS_VPUNPCKLQDQ()),
        VPUNPCKLWD(X86_INS_VPUNPCKLWD()),
        VPXORD(X86_INS_VPXORD()),
        VPXORQ(X86_INS_VPXORQ()),
        VPXOR(X86_INS_VPXOR()),
        VRANGEPD(X86_INS_VRANGEPD()),
        VRANGEPS(X86_INS_VRANGEPS()),
        VRANGESD(X86_INS_VRANGESD()),
        VRANGESS(X86_INS_VRANGESS()),
        VRCP14PD(X86_INS_VRCP14PD()),
        VRCP14PS(X86_INS_VRCP14PS()),
        VRCP14SD(X86_INS_VRCP14SD()),
        VRCP14SS(X86_INS_VRCP14SS()),
        VRCP28PD(X86_INS_VRCP28PD()),
        VRCP28PS(X86_INS_VRCP28PS()),
        VRCP28SD(X86_INS_VRCP28SD()),
        VRCP28SS(X86_INS_VRCP28SS()),
        VRCPPS(X86_INS_VRCPPS()),
        VRCPSS(X86_INS_VRCPSS()),
        VREDUCEPD(X86_INS_VREDUCEPD()),
        VREDUCEPS(X86_INS_VREDUCEPS()),
        VREDUCESD(X86_INS_VREDUCESD()),
        VREDUCESS(X86_INS_VREDUCESS()),
        VRNDSCALEPD(X86_INS_VRNDSCALEPD()),
        VRNDSCALEPS(X86_INS_VRNDSCALEPS()),
        VRNDSCALESD(X86_INS_VRNDSCALESD()),
        VRNDSCALESS(X86_INS_VRNDSCALESS()),
        VROUNDPD(X86_INS_VROUNDPD()),
        VROUNDPS(X86_INS_VROUNDPS()),
        VROUNDSD(X86_INS_VROUNDSD()),
        VROUNDSS(X86_INS_VROUNDSS()),
        VRSQRT14PD(X86_INS_VRSQRT14PD()),
        VRSQRT14PS(X86_INS_VRSQRT14PS()),
        VRSQRT14SD(X86_INS_VRSQRT14SD()),
        VRSQRT14SS(X86_INS_VRSQRT14SS()),
        VRSQRT28PD(X86_INS_VRSQRT28PD()),
        VRSQRT28PS(X86_INS_VRSQRT28PS()),
        VRSQRT28SD(X86_INS_VRSQRT28SD()),
        VRSQRT28SS(X86_INS_VRSQRT28SS()),
        VRSQRTPS(X86_INS_VRSQRTPS()),
        VRSQRTSS(X86_INS_VRSQRTSS()),
        VSCALEFPD(X86_INS_VSCALEFPD()),
        VSCALEFPS(X86_INS_VSCALEFPS()),
        VSCALEFSD(X86_INS_VSCALEFSD()),
        VSCALEFSS(X86_INS_VSCALEFSS()),
        VSCATTERDPD(X86_INS_VSCATTERDPD()),
        VSCATTERDPS(X86_INS_VSCATTERDPS()),
        VSCATTERPF0DPD(X86_INS_VSCATTERPF0DPD()),
        VSCATTERPF0DPS(X86_INS_VSCATTERPF0DPS()),
        VSCATTERPF0QPD(X86_INS_VSCATTERPF0QPD()),
        VSCATTERPF0QPS(X86_INS_VSCATTERPF0QPS()),
        VSCATTERPF1DPD(X86_INS_VSCATTERPF1DPD()),
        VSCATTERPF1DPS(X86_INS_VSCATTERPF1DPS()),
        VSCATTERPF1QPD(X86_INS_VSCATTERPF1QPD()),
        VSCATTERPF1QPS(X86_INS_VSCATTERPF1QPS()),
        VSCATTERQPD(X86_INS_VSCATTERQPD()),
        VSCATTERQPS(X86_INS_VSCATTERQPS()),
        VSHUFF32X4(X86_INS_VSHUFF32X4()),
        VSHUFF64X2(X86_INS_VSHUFF64X2()),
        VSHUFI32X4(X86_INS_VSHUFI32X4()),
        VSHUFI64X2(X86_INS_VSHUFI64X2()),
        VSHUFPD(X86_INS_VSHUFPD()),
        VSHUFPS(X86_INS_VSHUFPS()),
        VSQRTPD(X86_INS_VSQRTPD()),
        VSQRTPS(X86_INS_VSQRTPS()),
        VSQRTSD(X86_INS_VSQRTSD()),
        VSQRTSS(X86_INS_VSQRTSS()),
        VSTMXCSR(X86_INS_VSTMXCSR()),
        VSUBPD(X86_INS_VSUBPD()),
        VSUBPS(X86_INS_VSUBPS()),
        VSUBSD(X86_INS_VSUBSD()),
        VSUBSS(X86_INS_VSUBSS()),
        VTESTPD(X86_INS_VTESTPD()),
        VTESTPS(X86_INS_VTESTPS()),
        VUCOMISD(X86_INS_VUCOMISD()),
        VUCOMISS(X86_INS_VUCOMISS()),
        VUNPCKHPD(X86_INS_VUNPCKHPD()),
        VUNPCKHPS(X86_INS_VUNPCKHPS()),
        VUNPCKLPD(X86_INS_VUNPCKLPD()),
        VUNPCKLPS(X86_INS_VUNPCKLPS()),
        VXORPD(X86_INS_VXORPD()),
        VXORPS(X86_INS_VXORPS()),
        VZEROALL(X86_INS_VZEROALL()),
        VZEROUPPER(X86_INS_VZEROUPPER()),
        WAIT(X86_INS_WAIT()),
        WBINVD(X86_INS_WBINVD()),
        WBNOINVD(X86_INS_WBNOINVD()),
        WRFSBASE(X86_INS_WRFSBASE()),
        WRGSBASE(X86_INS_WRGSBASE()),
        WRMSR(X86_INS_WRMSR()),
        WRPKRU(X86_INS_WRPKRU()),
        WRSSD(X86_INS_WRSSD()),
        WRSSQ(X86_INS_WRSSQ()),
        WRUSSD(X86_INS_WRUSSD()),
        WRUSSQ(X86_INS_WRUSSQ()),
        XABORT(X86_INS_XABORT()),
        XACQUIRE(X86_INS_XACQUIRE()),
        XADD(X86_INS_XADD()),
        XBEGIN(X86_INS_XBEGIN()),
        XCHG(X86_INS_XCHG()),
        FXCH(X86_INS_FXCH()),
        XCRYPTCBC(X86_INS_XCRYPTCBC()),
        XCRYPTCFB(X86_INS_XCRYPTCFB()),
        XCRYPTCTR(X86_INS_XCRYPTCTR()),
        XCRYPTECB(X86_INS_XCRYPTECB()),
        XCRYPTOFB(X86_INS_XCRYPTOFB()),
        XEND(X86_INS_XEND()),
        XGETBV(X86_INS_XGETBV()),
        XLATB(X86_INS_XLATB()),
        XOR(X86_INS_XOR()),
        XORPD(X86_INS_XORPD()),
        XORPS(X86_INS_XORPS()),
        XRELEASE(X86_INS_XRELEASE()),
        XRSTOR(X86_INS_XRSTOR()),
        XRSTOR64(X86_INS_XRSTOR64()),
        XRSTORS(X86_INS_XRSTORS()),
        XRSTORS64(X86_INS_XRSTORS64()),
        XSAVE(X86_INS_XSAVE()),
        XSAVE64(X86_INS_XSAVE64()),
        XSAVEC(X86_INS_XSAVEC()),
        XSAVEC64(X86_INS_XSAVEC64()),
        XSAVEOPT(X86_INS_XSAVEOPT()),
        XSAVEOPT64(X86_INS_XSAVEOPT64()),
        XSAVES(X86_INS_XSAVES()),
        XSAVES64(X86_INS_XSAVES64()),
        XSETBV(X86_INS_XSETBV()),
        XSHA1(X86_INS_XSHA1()),
        XSHA256(X86_INS_XSHA256()),
        XSTORE(X86_INS_XSTORE()),
        XTEST(X86_INS_XTEST()),

        ENDING(X86_INS_ENDING()); // mark the end of the list of insn

        private final int value;

        X86Insn(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static X86Insn fromValue(int value) {
            for (X86Insn insn : X86Insn.values()) {
                if (insn.value == value) {
                    return insn;
                }
            }
            throw new IllegalArgumentException("Invalid X86 Instruction value: " + value);
        }
    }
}
