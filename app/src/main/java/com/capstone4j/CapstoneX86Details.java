package com.capstone4j;

import com.capstone4j.internal.cs_x86;
import com.capstone4j.internal.cs_x86_op;
import com.capstone4j.internal.x86_op_mem;
import com.capstone4j.internal.cs_x86_encoding;

import static com.capstone4j.internal.capstone_h.*;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;

/**
 * Provides x86-specific instruction details for the Capstone disassembly engine.
 * <p>
 * This class contains all the detailed information about x86 architecture instructions
 * that have been disassembled by the Capstone engine. It provides access to instruction
 * prefixes, operands, register details, flags affected, and encoding information.
 * </p>
 */
public class CapstoneX86Details extends CapstoneArchDetails<CapstoneX86Details.X86Operand> {

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
            return Arrays.stream(X86EFlags.values())
                .filter(flag -> (flag.getValue() & value) != 0)
                .toArray(X86EFlags[]::new);
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
}
