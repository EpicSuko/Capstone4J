package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

import com.capstone4j.internal.cs_arm;
import com.capstone4j.internal.cs_arm_op;
import com.capstone4j.internal.arm_op_mem;
import com.capstone4j.internal.arm_sysop_reg;
import com.capstone4j.internal.arm_sysop;

import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;

public class CapstoneArmDetails extends CapstoneArchDetails<CapstoneArmDetails.ArmOperand> implements MemorySegmentCreatable<CapstoneArmDetails> {

    private final boolean usermode;
    private final int vectorSize;
    private final ArmVectorDataType vectorDataType;
    private final ArmCpsModeType cpsMode;
    private final ArmCpsFlagType cpsFlag;
    private final ArmCondCodes cc;
    private final ArmVPTCodes vcc;
    private final boolean updateFlags;
    private final boolean postIndex;
    private final ArmMemBOpt memBarrier;
    private final int predMask;
    
    CapstoneArmDetails(int opCount, ArmOperand[] operands, boolean usermode, int vectorSize, ArmVectorDataType vectorDataType, ArmCpsModeType cpsMode, ArmCpsFlagType cpsFlag, ArmCondCodes cc, ArmVPTCodes vcc, boolean updateFlags, boolean postIndex, ArmMemBOpt memBarrier, int predMask) {
        super(opCount, operands);
        this.usermode = usermode;
        this.vectorSize = vectorSize;
        this.vectorDataType = vectorDataType;
        this.cpsMode = cpsMode;
        this.cpsFlag = cpsFlag;
        this.cc = cc;
        this.vcc = vcc;
        this.updateFlags = updateFlags;
        this.postIndex = postIndex;
        this.memBarrier = memBarrier;
        this.predMask = predMask;
    }

    static CapstoneArmDetails createFromMemorySegment(MemorySegment segment) {
        boolean usermode = cs_arm.usermode(segment);
        int vectorSize = cs_arm.vector_size(segment);
        ArmVectorDataType vectorDataType = ArmVectorDataType.fromValue(cs_arm.vector_data(segment));
        ArmCpsModeType cpsMode = ArmCpsModeType.fromValue(cs_arm.cps_mode(segment));
        ArmCpsFlagType cpsFlag = ArmCpsFlagType.fromValue(cs_arm.cps_flag(segment));
        ArmCondCodes cc = ArmCondCodes.fromValue(cs_arm.cc(segment));
        ArmVPTCodes vcc = ArmVPTCodes.fromValue(cs_arm.vcc(segment));
        boolean updateFlags = cs_arm.update_flags(segment);
        boolean postIndex = cs_arm.post_index(segment);
        ArmMemBOpt memBarrier = ArmMemBOpt.fromValue(cs_arm.mem_barrier(segment));
        int predMask = cs_arm.pred_mask(segment) & 0xFF;
        int opCount = cs_arm.op_count(segment) & 0xFF;

        MemorySegment operandsSegment = cs_arm.operands(segment);
        ArmOperand[] operands = new ArmOperand[opCount];
        for(int i = 0; i < opCount; i++) {
            operands[i] = createOperandFromMemorySegment(operandsSegment.asSlice(i * cs_arm_op.sizeof()));
        }

        return new CapstoneArmDetails(
            opCount,
            operands,
            usermode,
            vectorSize,
            vectorDataType,
            cpsMode,
            cpsFlag,
            cc,
            vcc,
            updateFlags,
            postIndex,
            memBarrier,
            predMask
        );
    }

    private static ArmOperand createOperandFromMemorySegment(MemorySegment segment) {
        int vectorIndex = cs_arm_op.vector_index(segment);
        ArmShift shift = createShiftFromMemorySegment(cs_arm_op.shift(segment));
        ArmOperandType type = ArmOperandType.fromValue(cs_arm_op.type(segment));
        ArmReg[] reg = null;
        ArmSysOp sysOp = null;
        long imm = 0;
        int pred = 0;
        double fp = 0;
        ArmOpMem mem = null;
        ArmSetEndType setEnd = null;
        if(type == ArmOperandType.REG) {
            reg = ArmReg.fromValue(cs_arm_op.reg(segment));
        } else if(type == ArmOperandType.IMM || type == ArmOperandType.PIMM || type == ArmOperandType.CIMM) {
            imm = cs_arm_op.imm(segment);
        } else if(type == ArmOperandType.PRED) {
            pred = cs_arm_op.pred(segment);
        } else if(type == ArmOperandType.FP) {
            fp = cs_arm_op.fp(segment);
        } else if(type == ArmOperandType.MEM) {
            mem = createOpMemFromMemorySegment(cs_arm_op.mem(segment));
        } else if(type == ArmOperandType.SETEND) {
            setEnd = ArmSetEndType.fromValue(cs_arm_op.setend(segment));
        } else if(type == ArmOperandType.SPSR || type == ArmOperandType.CPSR || type == ArmOperandType.SYSREG) { // Maybe this should be the default case?
            sysOp = createSysOpFromMemorySegment(cs_arm_op.sysop(segment), type);
        } else {
            throw new IllegalArgumentException("Invalid operand type: " + type);
        }
        boolean subtracted = cs_arm_op.subtracted(segment);
        int access = cs_arm_op.access(segment);
        byte neonLane = cs_arm_op.neon_lane(segment);
        return new ArmOperand(vectorIndex, shift, type, reg, sysOp, imm, pred, fp, mem, setEnd, subtracted, access, neonLane);
    }

    private static ArmSysOp createSysOpFromMemorySegment(MemorySegment segment, ArmOperandType type) {
        ArmSysOpReg reg = createSysOpRegFromMemorySegment(arm_sysop.reg(segment), type);
        ArmSpsrCsprBits[] psrBits = ArmSpsrCsprBits.fromValue(arm_sysop.psr_bits(segment));
        int sysm = arm_sysop.sysm(segment) & 0xFFFF;
        int msrMask = arm_sysop.msr_mask(segment) & 0xFF;
        return new ArmSysOp(reg, psrBits, sysm, msrMask);
    }

    private static ArmSysOpReg createSysOpRegFromMemorySegment(MemorySegment segment, ArmOperandType type) {
        ArmSysReg mclassysreg = null;
        if(type != ArmOperandType.CPSR) {
            mclassysreg = ArmSysReg.fromValue(arm_sysop_reg.mclasssysreg(segment));
        }
        ArmBankedReg bankedReg = null;
        if(type != ArmOperandType.SYSREG) {
            bankedReg = ArmBankedReg.fromValue(arm_sysop_reg.bankedreg(segment));
        }
        int rawVal = arm_sysop_reg.raw_val(segment);
        return new ArmSysOpReg(mclassysreg, bankedReg, rawVal);
    }

    private static ArmOpMem createOpMemFromMemorySegment(MemorySegment segment) {
        ArmReg[] base = ArmReg.fromValue(arm_op_mem.base(segment));
        ArmReg[] index = ArmReg.fromValue(arm_op_mem.index(segment));
        int scale = arm_op_mem.scale(segment);
        int disp = arm_op_mem.disp(segment);
        long align = arm_op_mem.align(segment);
        return new ArmOpMem(base, index, scale, disp, align);
    }

    private static ArmShift createShiftFromMemorySegment(MemorySegment segment) {
        ArmShifter shiftType = ArmShifter.fromValue(cs_arm_op.shift.type(segment));
        long shiftValue = cs_arm_op.shift.value(segment) & 0xFFFFFFFF;

        return new ArmShift(shiftType, shiftValue);
    }

	@Override
	int getOpCounOfType(int opType) {
		int count = 0;
		for(ArmOperand operand : getOperands()) {
			if(isOperandOfType(operand, opType)) {
				count++;
			}
		}
		return count;
	}

	@Override
	boolean isOperandOfType(ArmOperand operand, int opType) {
		return operand.getType() == ArmOperandType.fromValue(opType);
	}

    public boolean isUsermode() {
        return this.usermode;
    }

    public int getVectorSize() {
        return this.vectorSize;
    }

    public ArmVectorDataType getVectorDataType() {
        return this.vectorDataType;
    }

    public ArmCpsModeType getCpsMode() {
        return this.cpsMode;
    }

    public ArmCpsFlagType getCpsFlag() {
        return this.cpsFlag;
    }

    public ArmCondCodes getCc() {
        return this.cc;
    }

    public ArmVPTCodes getVcc() {
        return this.vcc;
    }

    public boolean isUpdateFlags() {
        return this.updateFlags;
    }

    public boolean isPostIndex() {
        return this.postIndex;
    }

    public ArmMemBOpt getMemBarrier() {
        return this.memBarrier;
    }

    public int getPredMask() {
        return this.predMask;
    }

    public static class ArmSupplyInfo {
        private final CapstoneAccessType memAcc;

        public ArmSupplyInfo(CapstoneAccessType memAcc) {
            this.memAcc = memAcc;
        }

        public CapstoneAccessType getMemAcc() {
            return this.memAcc;
        }
    }

    public enum ArmMemBOpt {
        RESERVED_0(ARM_MB_RESERVED_0()),
        OSHLD(ARM_MB_OSHLD()),
        OSHST(ARM_MB_OSHST()),
        OSH(ARM_MB_OSH()),
        RESERVED_4(ARM_MB_RESERVED_4()),
        NSHLD(ARM_MB_NSHLD()),
        NSHST(ARM_MB_NSHST()),
        NSH(ARM_MB_NSH()),
        RESERVED_8(ARM_MB_RESERVED_8()),
        ISHLD(ARM_MB_ISHLD()),
        ISHST(ARM_MB_ISHST()),
        ISH(ARM_MB_ISH()),
        RESERVED_12(ARM_MB_RESERVED_12()),
        LD(ARM_MB_LD()),
        ST(ARM_MB_ST()),
        SY(ARM_MB_SY());

        private final int value;

        ArmMemBOpt(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static ArmMemBOpt fromValue(int value) {
            for (ArmMemBOpt type : ArmMemBOpt.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid memory barrier option value: " + value);
        }
    }

    public enum ArmVPTCodes {
        NONE(ARMVCC_None()),
        THEN(ARMVCC_Then()),
        ELSE(ARMVCC_Else());

        private final int value;

        ArmVPTCodes(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static ArmVPTCodes fromValue(int value) {
            for (ArmVPTCodes type : ArmVPTCodes.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid vector predicate type codes value: " + value);
        }
    }

    public enum ArmCondCodes {
        EQ(ARMCC_EQ()), // Equal                      Equal
        NE(ARMCC_NE()), // Not equal                  Not equal, or unordered
        HS(ARMCC_HS()), // Carry set                  >, ==, or unordered
        LO(ARMCC_LO()), // Carry clear                Less than
        MI(ARMCC_MI()), // Minus, negative            Less than
        PL(ARMCC_PL()), // Plus, positive or zero     >, ==, or unordered
        VS(ARMCC_VS()), // Overflow                   Unordered
        VC(ARMCC_VC()), // No overflow                Not unordered
        HI(ARMCC_HI()), // Unsigned higher            Greater than, or unordered
        LS(ARMCC_LS()), // Unsigned lower or same     Less than or equal
        GE(ARMCC_GE()), // Greater than or equal      Greater than or equal
        LT(ARMCC_LT()), // Less than                  Less than, or unordered
        GT(ARMCC_GT()), // Greater than               Greater than
        LE(ARMCC_LE()), // Less than or equal         <, ==, or unordered
        AL(ARMCC_AL()), // Always (unconditional)     Always (unconditional)
        UNDEF(ARMCC_UNDEF()), // Undefined
        INVALID(ARMCC_Invalid()); // Invalid

        private final int value;

        ArmCondCodes(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static ArmCondCodes fromValue(int value) {
            for (ArmCondCodes type : ArmCondCodes.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid condition code: " + value);
        }
    }

    public enum ArmCpsFlagType {
        INVALID(ARM_CPSFLAG_INVALID()),
        F(ARM_CPSFLAG_F()),
        I(ARM_CPSFLAG_I()),
        A(ARM_CPSFLAG_A()),
        NONE(ARM_CPSFLAG_NONE());

        private final int value;

        ArmCpsFlagType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static ArmCpsFlagType fromValue(int value) {
            for (ArmCpsFlagType type : ArmCpsFlagType.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid cps flag type value: " + value);
        }
    }

    public enum ArmCpsModeType {
        INVALID(ARM_CPSMODE_INVALID()),
        IE(ARM_CPSMODE_IE()),
        ID(ARM_CPSMODE_ID());

        private final int value;

        ArmCpsModeType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static ArmCpsModeType fromValue(int value) {
            for (ArmCpsModeType type : ArmCpsModeType.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid cps mode type value: " + value);
        }
    }

    public enum ArmVectorDataType {
        INVALID(ARM_VECTORDATA_INVALID()),

        // Integer type
        I8(ARM_VECTORDATA_I8()),
        I16(ARM_VECTORDATA_I16()),
        I32(ARM_VECTORDATA_I32()),
        I64(ARM_VECTORDATA_I64()),

        // Signed integer type
        S8(ARM_VECTORDATA_S8()),
        S16(ARM_VECTORDATA_S16()),
        S32(ARM_VECTORDATA_S32()),
        S64(ARM_VECTORDATA_S64()),

        // Unsigned integer type
        U8(ARM_VECTORDATA_U8()),
        U16(ARM_VECTORDATA_U16()),
        U32(ARM_VECTORDATA_U32()),
        U64(ARM_VECTORDATA_U64()),

        // Data type for VMUL/VMULL
        P8(ARM_VECTORDATA_P8()),
        P16(ARM_VECTORDATA_P16()),

        // Floating type
        F16(ARM_VECTORDATA_F16()),
        F32(ARM_VECTORDATA_F32()),
        F64(ARM_VECTORDATA_F64()),

        // Convert float <-> float
        F16F64(ARM_VECTORDATA_F16F64()), // f16.f64
        F64F16(ARM_VECTORDATA_F64F16()), // f64.f16
        F32F16(ARM_VECTORDATA_F32F16()), // f32.f16
        F16F32(ARM_VECTORDATA_F16F32()), // f32.f16
        F64F32(ARM_VECTORDATA_F64F32()), // f64.f32
        F32F64(ARM_VECTORDATA_F32F64()), // f32.f64

        // Convert integer <-> float
        S32F32(ARM_VECTORDATA_S32F32()), // s32.f32
        U32F32(ARM_VECTORDATA_U32F32()), // u32.f32
        F32S32(ARM_VECTORDATA_F32S32()), // f32.s32
        F32U32(ARM_VECTORDATA_F32U32()), // f32.u32
        F64S16(ARM_VECTORDATA_F64S16()), // f64.s16
        F32S16(ARM_VECTORDATA_F32S16()), // f32.s16
        F64S32(ARM_VECTORDATA_F64S32()), // f64.s32
        S16F64(ARM_VECTORDATA_S16F64()), // s16.f64
        S16F32(ARM_VECTORDATA_S16F32()), // s16.f64
        S32F64(ARM_VECTORDATA_S32F64()), // s32.f64
        U16F64(ARM_VECTORDATA_U16F64()), // u16.f64
        U16F32(ARM_VECTORDATA_U16F32()), // u16.f32
        U32F64(ARM_VECTORDATA_U32F64()), // u32.f64
        F64U16(ARM_VECTORDATA_F64U16()), // f64.u16
        F32U16(ARM_VECTORDATA_F32U16()), // f32.u16
        F64U32(ARM_VECTORDATA_F64U32()), // f64.u32
        F16U16(ARM_VECTORDATA_F16U16()), // f16.u16
        U16F16(ARM_VECTORDATA_U16F16()), // u16.f16
        F16U32(ARM_VECTORDATA_F16U32()), // f16.u32
        U32F16(ARM_VECTORDATA_U32F16()), // u32.f16
        F16S16(ARM_VECTORDATA_F16S16()),
        S16F16(ARM_VECTORDATA_S16F16()),
        F16S32(ARM_VECTORDATA_F16S32()),
        S32F16(ARM_VECTORDATA_S32F16());

        private final int value;

        ArmVectorDataType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static ArmVectorDataType fromValue(int value) {
            for (ArmVectorDataType type : ArmVectorDataType.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid vector data type value: " + value);
        }
    }

    public enum ArmShifter {
        INVALID(ARM_SFT_INVALID()),
        ASR(ARM_SFT_ASR()),
        LSL(ARM_SFT_LSL()),
        LSR(ARM_SFT_LSR()),
        ROR(ARM_SFT_ROR()),
        RRX(ARM_SFT_RRX()),
        UXTW(ARM_SFT_UXTW()),
        // Added by Capstone to signal that the shift amount is stored in a register.
        // shift.val should be interpreted as register id.
        REG(ARM_SFT_REG()),
        ASR_REG(ARM_SFT_ASR_REG()),
        LSL_REG(ARM_SFT_LSL_REG()),
        LSR_REG(ARM_SFT_LSR_REG()),
        ROR_REG(ARM_SFT_ROR_REG());

        private final int value;

        ArmShifter(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static ArmShifter fromValue(int value) {
            for (ArmShifter type : ArmShifter.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid shifter value: " + value);
        }
    }

    public static class ArmShift {
        private final ArmShifter type;
        private final long value;

        ArmShift(ArmShifter type, long value) {
            this.type = type;
            this.value = value;
        }

        public ArmShifter getType() {
            return this.type;
        }

        public long getValue() {
            return this.value;
        }
    }

    public enum ArmOperandType {
        INVALID(CS_OP_INVALID()),
        REG(CS_OP_REG()),
        IMM(CS_OP_IMM()),
        FP(CS_OP_FP()),
        PRED(CS_OP_PRED()),
        CIMM(ARM_OP_CIMM()),
        PIMM(ARM_OP_PIMM()),
        SETEND(ARM_OP_SETEND()),
        SYSREG(ARM_OP_SYSREG()),
        BANKEDREG(ARM_OP_BANKEDREG()),
        SPSR(ARM_OP_SPSR()),
        CPSR(ARM_OP_CPSR()),
        SYSM(ARM_OP_SYSM()),
        VPRED_R(ARM_OP_VPRED_R()),
        VPRED_N(ARM_OP_VPRED_N()),
        MEM(ARM_OP_MEM());

        private final int value;

        ArmOperandType(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static ArmOperandType fromValue(int value) {
            for (ArmOperandType type : ArmOperandType.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid operand type value: " + value);
        }
    }

    public enum ArmSysReg { 
        APSR(ARM_MCLASSSYSREG_APSR()),
        APSR_G(ARM_MCLASSSYSREG_APSR_G()),
        APSR_NZCVQ(ARM_MCLASSSYSREG_APSR_NZCVQ()),
        APSR_NZCVQG(ARM_MCLASSSYSREG_APSR_NZCVQG()),
        BASEPRI(ARM_MCLASSSYSREG_BASEPRI()),
        BASEPRI_MAX(ARM_MCLASSSYSREG_BASEPRI_MAX()),
        BASEPRI_NS(ARM_MCLASSSYSREG_BASEPRI_NS()),
        CONTROL(ARM_MCLASSSYSREG_CONTROL()),
        CONTROL_NS(ARM_MCLASSSYSREG_CONTROL_NS()),
        EAPSR(ARM_MCLASSSYSREG_EAPSR()),
        EAPSR_G(ARM_MCLASSSYSREG_EAPSR_G()),
        EAPSR_NZCVQ(ARM_MCLASSSYSREG_EAPSR_NZCVQ()),
        EAPSR_NZCVQG(ARM_MCLASSSYSREG_EAPSR_NZCVQG()),
        EPSR(ARM_MCLASSSYSREG_EPSR()),
        FAULTMASK(ARM_MCLASSSYSREG_FAULTMASK()),
        FAULTMASK_NS(ARM_MCLASSSYSREG_FAULTMASK_NS()),
        IAPSR(ARM_MCLASSSYSREG_IAPSR()),
        IAPSR_G(ARM_MCLASSSYSREG_IAPSR_G()),
        IAPSR_NZCVQ(ARM_MCLASSSYSREG_IAPSR_NZCVQ()),
        IAPSR_NZCVQG(ARM_MCLASSSYSREG_IAPSR_NZCVQG()),
        IEPSR(ARM_MCLASSSYSREG_IEPSR()),
        IPSR(ARM_MCLASSSYSREG_IPSR()),
        MSP(ARM_MCLASSSYSREG_MSP()),
        MSPLIM(ARM_MCLASSSYSREG_MSPLIM()),
        MSPLIM_NS(ARM_MCLASSSYSREG_MSPLIM_NS()),
        MSP_NS(ARM_MCLASSSYSREG_MSP_NS()),
        PAC_KEY_P_0(ARM_MCLASSSYSREG_PAC_KEY_P_0()),
        PAC_KEY_P_0_NS(ARM_MCLASSSYSREG_PAC_KEY_P_0_NS()),
        PAC_KEY_P_1(ARM_MCLASSSYSREG_PAC_KEY_P_1()),
        PAC_KEY_P_1_NS(ARM_MCLASSSYSREG_PAC_KEY_P_1_NS()),
        PAC_KEY_P_2(ARM_MCLASSSYSREG_PAC_KEY_P_2()),
        PAC_KEY_P_2_NS(ARM_MCLASSSYSREG_PAC_KEY_P_2_NS()),
        PAC_KEY_P_3(ARM_MCLASSSYSREG_PAC_KEY_P_3()),
        PAC_KEY_P_3_NS(ARM_MCLASSSYSREG_PAC_KEY_P_3_NS()),
        PAC_KEY_U_0(ARM_MCLASSSYSREG_PAC_KEY_U_0()),
        PAC_KEY_U_0_NS(ARM_MCLASSSYSREG_PAC_KEY_U_0_NS()),
        PAC_KEY_U_1(ARM_MCLASSSYSREG_PAC_KEY_U_1()),
        PAC_KEY_U_1_NS(ARM_MCLASSSYSREG_PAC_KEY_U_1_NS()),
        PAC_KEY_U_2(ARM_MCLASSSYSREG_PAC_KEY_U_2()),
        PAC_KEY_U_2_NS(ARM_MCLASSSYSREG_PAC_KEY_U_2_NS()),
        PAC_KEY_U_3(ARM_MCLASSSYSREG_PAC_KEY_U_3()),
        PAC_KEY_U_3_NS(ARM_MCLASSSYSREG_PAC_KEY_U_3_NS()),
        PRIMASK(ARM_MCLASSSYSREG_PRIMASK()),
        PRIMASK_NS(ARM_MCLASSSYSREG_PRIMASK_NS()),
        PSP(ARM_MCLASSSYSREG_PSP()),
        PSPLIM(ARM_MCLASSSYSREG_PSPLIM()),
        PSPLIM_NS(ARM_MCLASSSYSREG_PSPLIM_NS()),
        PSP_NS(ARM_MCLASSSYSREG_PSP_NS()),
        SP_NS(ARM_MCLASSSYSREG_SP_NS()),
        XPSR(ARM_MCLASSSYSREG_XPSR()),
        XPSR_G(ARM_MCLASSSYSREG_XPSR_G()),
        XPSR_NZCVQ(ARM_MCLASSSYSREG_XPSR_NZCVQ()),
        XPSR_NZCVQG(ARM_MCLASSSYSREG_XPSR_NZCVQG());

        private final int value;

        ArmSysReg(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static ArmSysReg fromValue(int value) {
            for (ArmSysReg type : ArmSysReg.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid system register value: " + value);
        }
    }

    public enum ArmBankedReg {
        ELR_HYP(ARM_BANKEDREG_ELR_HYP()),
        LR_ABT(ARM_BANKEDREG_LR_ABT()),
        LR_FIQ(ARM_BANKEDREG_LR_FIQ()),
        LR_IRQ(ARM_BANKEDREG_LR_IRQ()),
        LR_MON(ARM_BANKEDREG_LR_MON()),
        LR_SVC(ARM_BANKEDREG_LR_SVC()),
        LR_UND(ARM_BANKEDREG_LR_UND()),
        LR_USR(ARM_BANKEDREG_LR_USR()),
        R10_FIQ(ARM_BANKEDREG_R10_FIQ()),
        R10_USR(ARM_BANKEDREG_R10_USR()),
        R11_FIQ(ARM_BANKEDREG_R11_FIQ()),
        R11_USR(ARM_BANKEDREG_R11_USR()),
        R12_FIQ(ARM_BANKEDREG_R12_FIQ()),
        R12_USR(ARM_BANKEDREG_R12_USR()),
        R8_FIQ(ARM_BANKEDREG_R8_FIQ()),
        R8_USR(ARM_BANKEDREG_R8_USR()),
        R9_FIQ(ARM_BANKEDREG_R9_FIQ()),
        R9_USR(ARM_BANKEDREG_R9_USR()),
        SPSR_ABT(ARM_BANKEDREG_SPSR_ABT()),
        SPSR_FIQ(ARM_BANKEDREG_SPSR_FIQ()),
        SPSR_HYP(ARM_BANKEDREG_SPSR_HYP()),
        SPSR_IRQ(ARM_BANKEDREG_SPSR_IRQ()),
        SPSR_MON(ARM_BANKEDREG_SPSR_MON()),
        SPSR_SVC(ARM_BANKEDREG_SPSR_SVC()),
        SPSR_UND(ARM_BANKEDREG_SPSR_UND()),
        SP_ABT(ARM_BANKEDREG_SP_ABT()),
        SP_FIQ(ARM_BANKEDREG_SP_FIQ()),
        SP_HYP(ARM_BANKEDREG_SP_HYP()),
        SP_IRQ(ARM_BANKEDREG_SP_IRQ()),
        SP_MON(ARM_BANKEDREG_SP_MON()),
        SP_SVC(ARM_BANKEDREG_SP_SVC()),
        SP_UND(ARM_BANKEDREG_SP_UND()),
        SP_USR(ARM_BANKEDREG_SP_USR());

        private final int value;

        ArmBankedReg(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static ArmBankedReg fromValue(int value) {
            for (ArmBankedReg type : ArmBankedReg.values()) {
                if (type.value == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid banked register value: " + value);
        }
    }

    public static class ArmSysOpReg {
        private final ArmSysReg sysReg;
        private final ArmBankedReg bankedReg;
        private final int rawVal;

        ArmSysOpReg(ArmSysReg sysReg, ArmBankedReg bankedReg, int rawVal) {
            this.sysReg = sysReg;
            this.bankedReg = bankedReg;
            this.rawVal = rawVal;
        }

        public ArmSysReg getSysReg() {
            return this.sysReg;
        }

        public ArmBankedReg getBankedReg() {
            return this.bankedReg;
        }

        public int getRawVal() {
            return this.rawVal;
        }
    }

    public enum ArmSpsrCsprBits {
        SPSR_C(ARM_FIELD_SPSR_C()),
        SPSR_X(ARM_FIELD_SPSR_X()),
        SPSR_S(ARM_FIELD_SPSR_S()),
        SPSR_F(ARM_FIELD_SPSR_F()),

        // CPSR* field flags can be OR combined
        CPSR_C(ARM_FIELD_CPSR_C()),
        CPSR_X(ARM_FIELD_CPSR_X()),
        CPSR_S(ARM_FIELD_CPSR_S()),
        CPSR_F(ARM_FIELD_CPSR_F());

        private final int value;

        ArmSpsrCsprBits(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static ArmSpsrCsprBits[] fromValue(int value) {
            List<ArmSpsrCsprBits> result = new ArrayList<>();
            for (ArmSpsrCsprBits type : ArmSpsrCsprBits.values()) {
                if(value > 15) {
                    // CPSR* field flags can be OR combined
                    if((value & type.value) == type.value) {
                        result.add(type);
                    }
                } else {
                    if(value == type.value) {
                        result.add(type);
                    }
                }
            }
            return result.toArray(new ArmSpsrCsprBits[0]);
        }
    }

    public static class ArmSysOp {
        private final ArmSysOpReg reg;
        private final ArmSpsrCsprBits[] psrBits;
        private final int sysm;
        private final int msrMask;

        ArmSysOp(ArmSysOpReg reg, ArmSpsrCsprBits[] psrBits, int sysm, int msrMask) {
            this.reg = reg;
            this.psrBits = psrBits;
            this.sysm = sysm;
            this.msrMask = msrMask;
        }

        public ArmSysOpReg getReg() {
            return this.reg;
        }

        public ArmSpsrCsprBits[] getPsrBits() {
            return this.psrBits;
        }

        public int getSysm() {
            return this.sysm;
        }

        public int getMsrMask() {
            return this.msrMask;
        }
    }

    public enum ArmReg {
        INVALID(ARM_REG_INVALID()),
        APSR(ARM_REG_APSR()),
        APSR_NZCV(ARM_REG_APSR_NZCV()),
        CPSR(ARM_REG_CPSR()),
        FPCXTNS(ARM_REG_FPCXTNS()),
        FPCXTS(ARM_REG_FPCXTS()),
        FPEXC(ARM_REG_FPEXC()),
        FPINST(ARM_REG_FPINST()),
        FPSCR(ARM_REG_FPSCR()),
        FPSCR_NZCV(ARM_REG_FPSCR_NZCV()),
        FPSCR_NZCVQC(ARM_REG_FPSCR_NZCVQC()),
        FPSID(ARM_REG_FPSID()),
        ITSTATE(ARM_REG_ITSTATE()),
        LR(ARM_REG_LR()),
        PC(ARM_REG_PC()),
        RA_AUTH_CODE(ARM_REG_RA_AUTH_CODE()),
        SP(ARM_REG_SP()),
        SPSR(ARM_REG_SPSR()),
        VPR(ARM_REG_VPR()),
        ZR(ARM_REG_ZR()),
        D0(ARM_REG_D0()),
        D1(ARM_REG_D1()),
        D2(ARM_REG_D2()),
        D3(ARM_REG_D3()),
        D4(ARM_REG_D4()),
        D5(ARM_REG_D5()),
        D6(ARM_REG_D6()),
        D7(ARM_REG_D7()),
        D8(ARM_REG_D8()),
        D9(ARM_REG_D9()),
        D10(ARM_REG_D10()),
        D11(ARM_REG_D11()),
        D12(ARM_REG_D12()),
        D13(ARM_REG_D13()),
        D14(ARM_REG_D14()),
        D15(ARM_REG_D15()),
        D16(ARM_REG_D16()),
        D17(ARM_REG_D17()),
        D18(ARM_REG_D18()),
        D19(ARM_REG_D19()),
        D20(ARM_REG_D20()),
        D21(ARM_REG_D21()),
        D22(ARM_REG_D22()),
        D23(ARM_REG_D23()),
        D24(ARM_REG_D24()),
        D25(ARM_REG_D25()),
        D26(ARM_REG_D26()),
        D27(ARM_REG_D27()),
        D28(ARM_REG_D28()),
        D29(ARM_REG_D29()),
        D30(ARM_REG_D30()),
        D31(ARM_REG_D31()),
        FPINST2(ARM_REG_FPINST2()),
        MVFR0(ARM_REG_MVFR0()),
        MVFR1(ARM_REG_MVFR1()),
        MVFR2(ARM_REG_MVFR2()),
        P0(ARM_REG_P0()),
        Q0(ARM_REG_Q0()),
        Q1(ARM_REG_Q1()),
        Q2(ARM_REG_Q2()),
        Q3(ARM_REG_Q3()),
        Q4(ARM_REG_Q4()),
        Q5(ARM_REG_Q5()),
        Q6(ARM_REG_Q6()),
        Q7(ARM_REG_Q7()),
        Q8(ARM_REG_Q8()),
        Q9(ARM_REG_Q9()),
        Q10(ARM_REG_Q10()),
        Q11(ARM_REG_Q11()),
        Q12(ARM_REG_Q12()),
        Q13(ARM_REG_Q13()),
        Q14(ARM_REG_Q14()),
        Q15(ARM_REG_Q15()),
        R0(ARM_REG_R0()),
        R1(ARM_REG_R1()),
        R2(ARM_REG_R2()),
        R3(ARM_REG_R3()),
        R4(ARM_REG_R4()),
        R5(ARM_REG_R5()),
        R6(ARM_REG_R6()),
        R7(ARM_REG_R7()),
        R8(ARM_REG_R8()),
        R9(ARM_REG_R9()),
        R10(ARM_REG_R10()),
        R11(ARM_REG_R11()),
        R12(ARM_REG_R12()),
        S0(ARM_REG_S0()),
        S1(ARM_REG_S1()),
        S2(ARM_REG_S2()),
        S3(ARM_REG_S3()),
        S4(ARM_REG_S4()),
        S5(ARM_REG_S5()),
        S6(ARM_REG_S6()),
        S7(ARM_REG_S7()),
        S8(ARM_REG_S8()),
        S9(ARM_REG_S9()),
        S10(ARM_REG_S10()),
        S11(ARM_REG_S11()),
        S12(ARM_REG_S12()),
        S13(ARM_REG_S13()),
        S14(ARM_REG_S14()),
        S15(ARM_REG_S15()),
        S16(ARM_REG_S16()),
        S17(ARM_REG_S17()),
        S18(ARM_REG_S18()),
        S19(ARM_REG_S19()),
        S20(ARM_REG_S20()),
        S21(ARM_REG_S21()),
        S22(ARM_REG_S22()),
        S23(ARM_REG_S23()),
        S24(ARM_REG_S24()),
        S25(ARM_REG_S25()),
        S26(ARM_REG_S26()),
        S27(ARM_REG_S27()),
        S28(ARM_REG_S28()),
        S29(ARM_REG_S29()),
        S30(ARM_REG_S30()),
        S31(ARM_REG_S31()),
        D0_D2(ARM_REG_D0_D2()),
        D1_D3(ARM_REG_D1_D3()),
        D2_D4(ARM_REG_D2_D4()),
        D3_D5(ARM_REG_D3_D5()),
        D4_D6(ARM_REG_D4_D6()),
        D5_D7(ARM_REG_D5_D7()),
        D6_D8(ARM_REG_D6_D8()),
        D7_D9(ARM_REG_D7_D9()),
        D8_D10(ARM_REG_D8_D10()),
        D9_D11(ARM_REG_D9_D11()),
        D10_D12(ARM_REG_D10_D12()),
        D11_D13(ARM_REG_D11_D13()),
        D12_D14(ARM_REG_D12_D14()),
        D13_D15(ARM_REG_D13_D15()),
        D14_D16(ARM_REG_D14_D16()),
        D15_D17(ARM_REG_D15_D17()),
        D16_D18(ARM_REG_D16_D18()),
        D17_D19(ARM_REG_D17_D19()),
        D18_D20(ARM_REG_D18_D20()),
        D19_D21(ARM_REG_D19_D21()),
        D20_D22(ARM_REG_D20_D22()),
        D21_D23(ARM_REG_D21_D23()),
        D22_D24(ARM_REG_D22_D24()),
        D23_D25(ARM_REG_D23_D25()),
        D24_D26(ARM_REG_D24_D26()),
        D25_D27(ARM_REG_D25_D27()),
        D26_D28(ARM_REG_D26_D28()),
        D27_D29(ARM_REG_D27_D29()),
        D28_D30(ARM_REG_D28_D30()),
        D29_D31(ARM_REG_D29_D31()),
        Q0_Q1(ARM_REG_Q0_Q1()),
        Q1_Q2(ARM_REG_Q1_Q2()),
        Q2_Q3(ARM_REG_Q2_Q3()),
        Q3_Q4(ARM_REG_Q3_Q4()),
        Q4_Q5(ARM_REG_Q4_Q5()),
        Q5_Q6(ARM_REG_Q5_Q6()),
        Q6_Q7(ARM_REG_Q6_Q7()),
        Q7_Q8(ARM_REG_Q7_Q8()),
        Q8_Q9(ARM_REG_Q8_Q9()),
        Q9_Q10(ARM_REG_Q9_Q10()),
        Q10_Q11(ARM_REG_Q10_Q11()),
        Q11_Q12(ARM_REG_Q11_Q12()),
        Q12_Q13(ARM_REG_Q12_Q13()),
        Q13_Q14(ARM_REG_Q13_Q14()),
        Q14_Q15(ARM_REG_Q14_Q15()),
        Q0_Q1_Q2_Q3(ARM_REG_Q0_Q1_Q2_Q3()),
        Q1_Q2_Q3_Q4(ARM_REG_Q1_Q2_Q3_Q4()),
        Q2_Q3_Q4_Q5(ARM_REG_Q2_Q3_Q4_Q5()),
        Q3_Q4_Q5_Q6(ARM_REG_Q3_Q4_Q5_Q6()),
        Q4_Q5_Q6_Q7(ARM_REG_Q4_Q5_Q6_Q7()),
        Q5_Q6_Q7_Q8(ARM_REG_Q5_Q6_Q7_Q8()),
        Q6_Q7_Q8_Q9(ARM_REG_Q6_Q7_Q8_Q9()),
        Q7_Q8_Q9_Q10(ARM_REG_Q7_Q8_Q9_Q10()),
        Q8_Q9_Q10_Q11(ARM_REG_Q8_Q9_Q10_Q11()),
        Q9_Q10_Q11_Q12(ARM_REG_Q9_Q10_Q11_Q12()),
        Q10_Q11_Q12_Q13(ARM_REG_Q10_Q11_Q12_Q13()),
        Q11_Q12_Q13_Q14(ARM_REG_Q11_Q12_Q13_Q14()),
        Q12_Q13_Q14_Q15(ARM_REG_Q12_Q13_Q14_Q15()),
        R0_R1(ARM_REG_R0_R1()),
        R2_R3(ARM_REG_R2_R3()),
        R4_R5(ARM_REG_R4_R5()),
        R6_R7(ARM_REG_R6_R7()),
        R8_R9(ARM_REG_R8_R9()),
        R10_R11(ARM_REG_R10_R11()),
        R12_SP(ARM_REG_R12_SP()),
        D0_D1_D2(ARM_REG_D0_D1_D2()),
        D1_D2_D3(ARM_REG_D1_D2_D3()),
        D2_D3_D4(ARM_REG_D2_D3_D4()),
        D3_D4_D5(ARM_REG_D3_D4_D5()),
        D4_D5_D6(ARM_REG_D4_D5_D6()),
        D5_D6_D7(ARM_REG_D5_D6_D7()),
        D6_D7_D8(ARM_REG_D6_D7_D8()),
        D7_D8_D9(ARM_REG_D7_D8_D9()),
        D8_D9_D10(ARM_REG_D8_D9_D10()),
        D9_D10_D11(ARM_REG_D9_D10_D11()),
        D10_D11_D12(ARM_REG_D10_D11_D12()),
        D11_D12_D13(ARM_REG_D11_D12_D13()),
        D12_D13_D14(ARM_REG_D12_D13_D14()),
        D13_D14_D15(ARM_REG_D13_D14_D15()),
        D14_D15_D16(ARM_REG_D14_D15_D16()),
        D15_D16_D17(ARM_REG_D15_D16_D17()),
        D16_D17_D18(ARM_REG_D16_D17_D18()),
        D17_D18_D19(ARM_REG_D17_D18_D19()),
        D18_D19_D20(ARM_REG_D18_D19_D20()),
        D19_D20_D21(ARM_REG_D19_D20_D21()),
        D20_D21_D22(ARM_REG_D20_D21_D22()),
        D21_D22_D23(ARM_REG_D21_D22_D23()),
        D22_D23_D24(ARM_REG_D22_D23_D24()),
        D23_D24_D25(ARM_REG_D23_D24_D25()),
        D24_D25_D26(ARM_REG_D24_D25_D26()),
        D25_D26_D27(ARM_REG_D25_D26_D27()),
        D26_D27_D28(ARM_REG_D26_D27_D28()),
        D27_D28_D29(ARM_REG_D27_D28_D29()),
        D28_D29_D30(ARM_REG_D28_D29_D30()),
        D29_D30_D31(ARM_REG_D29_D30_D31()),
        D0_D2_D4(ARM_REG_D0_D2_D4()),
        D1_D3_D5(ARM_REG_D1_D3_D5()),
        D2_D4_D6(ARM_REG_D2_D4_D6()),
        D3_D5_D7(ARM_REG_D3_D5_D7()),
        D4_D6_D8(ARM_REG_D4_D6_D8()),
        D5_D7_D9(ARM_REG_D5_D7_D9()),
        D6_D8_D10(ARM_REG_D6_D8_D10()),
        D7_D9_D11(ARM_REG_D7_D9_D11()),
        D8_D10_D12(ARM_REG_D8_D10_D12()),
        D9_D11_D13(ARM_REG_D9_D11_D13()),
        D10_D12_D14(ARM_REG_D10_D12_D14()),
        D11_D13_D15(ARM_REG_D11_D13_D15()),
        D12_D14_D16(ARM_REG_D12_D14_D16()),
        D13_D15_D17(ARM_REG_D13_D15_D17()),
        D14_D16_D18(ARM_REG_D14_D16_D18()),
        D15_D17_D19(ARM_REG_D15_D17_D19()),
        D16_D18_D20(ARM_REG_D16_D18_D20()),
        D17_D19_D21(ARM_REG_D17_D19_D21()),
        D18_D20_D22(ARM_REG_D18_D20_D22()),
        D19_D21_D23(ARM_REG_D19_D21_D23()),
        D20_D22_D24(ARM_REG_D20_D22_D24()),
        D21_D23_D25(ARM_REG_D21_D23_D25()),
        D22_D24_D26(ARM_REG_D22_D24_D26()),
        D23_D25_D27(ARM_REG_D23_D25_D27()),
        D24_D26_D28(ARM_REG_D24_D26_D28()),
        D25_D27_D29(ARM_REG_D25_D27_D29()),
        D26_D28_D30(ARM_REG_D26_D28_D30()),
        D27_D29_D31(ARM_REG_D27_D29_D31()),
        D0_D2_D4_D6(ARM_REG_D0_D2_D4_D6()),
        D1_D3_D5_D7(ARM_REG_D1_D3_D5_D7()),
        D2_D4_D6_D8(ARM_REG_D2_D4_D6_D8()),
        D3_D5_D7_D9(ARM_REG_D3_D5_D7_D9()),
        D4_D6_D8_D10(ARM_REG_D4_D6_D8_D10()),
        D5_D7_D9_D11(ARM_REG_D5_D7_D9_D11()),
        D6_D8_D10_D12(ARM_REG_D6_D8_D10_D12()),
        D7_D9_D11_D13(ARM_REG_D7_D9_D11_D13()),
        D8_D10_D12_D14(ARM_REG_D8_D10_D12_D14()),
        D9_D11_D13_D15(ARM_REG_D9_D11_D13_D15()),
        D10_D12_D14_D16(ARM_REG_D10_D12_D14_D16()),
        D11_D13_D15_D17(ARM_REG_D11_D13_D15_D17()),
        D12_D14_D16_D18(ARM_REG_D12_D14_D16_D18()),
        D13_D15_D17_D19(ARM_REG_D13_D15_D17_D19()),
        D14_D16_D18_D20(ARM_REG_D14_D16_D18_D20()),
        D15_D17_D19_D21(ARM_REG_D15_D17_D19_D21()),
        D16_D18_D20_D22(ARM_REG_D16_D18_D20_D22()),
        D17_D19_D21_D23(ARM_REG_D17_D19_D21_D23()),
        D18_D20_D22_D24(ARM_REG_D18_D20_D22_D24()),
        D19_D21_D23_D25(ARM_REG_D19_D21_D23_D25()),
        D20_D22_D24_D26(ARM_REG_D20_D22_D24_D26()),
        D21_D23_D25_D27(ARM_REG_D21_D23_D25_D27()),
        D22_D24_D26_D28(ARM_REG_D22_D24_D26_D28()),
        D23_D25_D27_D29(ARM_REG_D23_D25_D27_D29()),
        D24_D26_D28_D30(ARM_REG_D24_D26_D28_D30()),
        D25_D27_D29_D31(ARM_REG_D25_D27_D29_D31()),
        D1_D2(ARM_REG_D1_D2()),
        D3_D4(ARM_REG_D3_D4()),
        D5_D6(ARM_REG_D5_D6()),
        D7_D8(ARM_REG_D7_D8()),
        D9_D10(ARM_REG_D9_D10()),
        D11_D12(ARM_REG_D11_D12()),
        D13_D14(ARM_REG_D13_D14()),
        D15_D16(ARM_REG_D15_D16()),
        D17_D18(ARM_REG_D17_D18()),
        D19_D20(ARM_REG_D19_D20()),
        D21_D22(ARM_REG_D21_D22()),
        D23_D24(ARM_REG_D23_D24()),
        D25_D26(ARM_REG_D25_D26()),
        D27_D28(ARM_REG_D27_D28()),
        D29_D30(ARM_REG_D29_D30()),
        D1_D2_D3_D4(ARM_REG_D1_D2_D3_D4()),
        D3_D4_D5_D6(ARM_REG_D3_D4_D5_D6()),
        D5_D6_D7_D8(ARM_REG_D5_D6_D7_D8()),
        D7_D8_D9_D10(ARM_REG_D7_D8_D9_D10()),
        D9_D10_D11_D12(ARM_REG_D9_D10_D11_D12()),
        D11_D12_D13_D14(ARM_REG_D11_D12_D13_D14()),
        D13_D14_D15_D16(ARM_REG_D13_D14_D15_D16()),
        D15_D16_D17_D18(ARM_REG_D15_D16_D17_D18()),
        D17_D18_D19_D20(ARM_REG_D17_D18_D19_D20()),
        D19_D20_D21_D22(ARM_REG_D19_D20_D21_D22()),
        D21_D22_D23_D24(ARM_REG_D21_D22_D23_D24()),
        D23_D24_D25_D26(ARM_REG_D23_D24_D25_D26()),
        D25_D26_D27_D28(ARM_REG_D25_D26_D27_D28()),
        D27_D28_D29_D30(ARM_REG_D27_D28_D29_D30()),
        ENDING(ARM_REG_ENDING()),

        // clang-format on
        // generated content <ARMGenCSRegEnum.inc> end

        // alias registers
        R13(ARM_REG_SP()),
        R14(ARM_REG_LR()),
        R15(ARM_REG_PC()),

        SB(ARM_REG_R9()),
        SL(ARM_REG_R10()),
        FP(ARM_REG_R11()),
        IP(ARM_REG_R12());

        private final int value;

        ArmReg(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static ArmReg[] fromValue(int value) {
            List<ArmReg> result = new ArrayList<>();
            boolean added = false;
            for (ArmReg reg : ArmReg.values()) {
                if (reg.getValue() == value) {
                    result.add(reg);
                    added = true;
                }
            }
            if (!added) {
                result.add(INVALID);
            }
            return result.toArray(new ArmReg[0]);
        }
    }

    public static class ArmOpMem {
        private final ArmReg[] base;
        private final ArmReg[] index;
        private final int scale;
        private final int disp;
        private final long align;

        ArmOpMem(ArmReg[] base, ArmReg[] index, int scale, int disp, long align) {
            this.base = base;
            this.index = index;
            this.scale = scale;
            this.disp = disp;
            this.align = align;
        }

        public ArmReg[] getBase() {
            return this.base;
        }

        public ArmReg[] getIndex() {
            return this.index;
        }

        public int getScale() {
            return this.scale;
        }

        public int getDisp() {
            return this.disp;
        }

        public long getAlign() {
            return this.align;
        }
    }

    public enum ArmSetEndType {
        INVALID(ARM_SETEND_INVALID()),	///< Uninitialized.
        BE(ARM_SETEND_BE()),	///< BE operand.
        LE(ARM_SETEND_LE()); ///< LE operand

        private final int value;

        ArmSetEndType(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static ArmSetEndType fromValue(int value) {
            for (ArmSetEndType type : ArmSetEndType.values()) {
                if (type.getValue() == value) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid ARM setend type value: " + value);
        }
    }

    public static class ArmOperand {
        private final int vectorIndex;
        private final ArmShift shift;
        private final ArmOperandType type;
        private final ArmReg[] reg;
        private final ArmSysOp sysOp;
        private final long imm;
        private final int pred;
        private final double fp;
        private final ArmOpMem mem;
        private final ArmSetEndType setEnd;
        private final boolean subtracted;
        private final int access;
        private final byte neonLane;

        ArmOperand(int vectorIndex, ArmShift shift, ArmOperandType type, ArmReg[] reg, ArmSysOp sysOp, long imm, int pred, double fp, ArmOpMem mem, ArmSetEndType setEnd, boolean subtracted, int access, byte neonLane) {
            this.vectorIndex = vectorIndex;
            this.shift = shift;
            this.type = type;
            this.reg = reg;
            this.sysOp = sysOp;
            this.imm = imm;
            this.pred = pred;
            this.fp = fp;
            this.mem = mem;
            this.setEnd = setEnd;
            this.subtracted = subtracted;
            this.access = access;
            this.neonLane = neonLane;
        }

        public int getVectorIndex() {
            return this.vectorIndex;
        }

        public ArmShift getShift() {
            return this.shift;
        }

        public ArmOperandType getType() {
            return this.type;
        }

        public ArmReg[] getReg() {
            return this.reg;
        }

        public ArmSysOp getSysOp() {
            return this.sysOp;
        }

        public long getImm() {
            return this.imm;
        }

        public int getPred() {
            return this.pred;
        }

        public double getFp() {
            return this.fp;
        }

        public ArmOpMem getMem() {
            return this.mem;
        }

        public ArmSetEndType getSetEnd() {
            return this.setEnd;
        }

        public boolean isSubtracted() {
            return this.subtracted;
        }

        public int getAccess() {
            return this.access;
        }

        public byte getNeonLane() {
            return this.neonLane;
        }
    }

    public enum ArmPredBlockMask {
        PredBlockMaskInvalid(ARM_PredBlockMaskInvalid()),
        T(ARM_T()),
        TT(ARM_TT()),
        TE(ARM_TE()),
        TTT(ARM_TTT()),
        TTE(ARM_TTE()),
        TEE(ARM_TEE()),
        TET(ARM_TET()),
        TTTT(ARM_TTTT()),
        TTTE(ARM_TTTE()),
        TTEE(ARM_TTEE()),
        TTET(ARM_TTET()),
        TEEE(ARM_TEEE()),
        TEET(ARM_TEET()),
        TETT(ARM_TETT()),
        TETE(ARM_TETE());

        private int value;

        ArmPredBlockMask(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static ArmPredBlockMask fromValue(int value) {
            for (ArmPredBlockMask mask : ArmPredBlockMask.values()) {
                if (mask.getValue() == value) {
                    return mask;
                }
            }
            throw new IllegalArgumentException("Invalid ArmPredBlockMask value: " + value);
        }
    }

    public enum ArmInsnGroup {
        INVALID(ARM_GRP_INVALID()), ///< = CS_GRP_INVALID

        // Generic groups
        // all jump instructions (conditional+direct+indirect jumps)
        JUMP(ARM_GRP_JUMP()),	///< = CS_GRP_JUMP
        CALL(ARM_GRP_CALL()),	///< = CS_GRP_CALL
        RET(ARM_GRP_RET()), ///<  = CS_GRP_RET
        INT(ARM_GRP_INT()), ///< = CS_GRP_INT
        PRIVILEGE(ARM_GRP_PRIVILEGE()), ///< = CS_GRP_PRIVILEGE
        BRANCH_RELATIVE(ARM_GRP_BRANCH_RELATIVE()), ///< = CS_GRP_BRANCH_RELATIVE

        HASV4T(ARM_FEATURE_HASV4T()),
        HASV5T(ARM_FEATURE_HASV5T()),
        HASV5TE(ARM_FEATURE_HASV5TE()),
        HASV6(ARM_FEATURE_HASV6()),
        HASV6M(ARM_FEATURE_HASV6M()),
        HASV8MBASELINE(ARM_FEATURE_HASV8MBASELINE()),
        HASV8MMAINLINE(ARM_FEATURE_HASV8MMAINLINE()),
        HASV8_1MMAINLINE(ARM_FEATURE_HASV8_1MMAINLINE()),
        HASMVEINT(ARM_FEATURE_HASMVEINT()),
        HASMVEFLOAT(ARM_FEATURE_HASMVEFLOAT()),
        HASCDE(ARM_FEATURE_HASCDE()),
        HASFPREGS(ARM_FEATURE_HASFPREGS()),
        HASFPREGS16(ARM_FEATURE_HASFPREGS16()),
        HASNOFPREGS16(ARM_FEATURE_HASNOFPREGS16()),
        HASFPREGS64(ARM_FEATURE_HASFPREGS64()),
        HASFPREGSV8_1M(ARM_FEATURE_HASFPREGSV8_1M()),
        HASV6T2(ARM_FEATURE_HASV6T2()),
        HASV6K(ARM_FEATURE_HASV6K()),
        HASV7(ARM_FEATURE_HASV7()),
        HASV8(ARM_FEATURE_HASV8()),
        PREV8(ARM_FEATURE_PREV8()),
        HASV8_1A(ARM_FEATURE_HASV8_1A()),
        HASV8_2A(ARM_FEATURE_HASV8_2A()),
        HASV8_3A(ARM_FEATURE_HASV8_3A()),
        HASV8_4A(ARM_FEATURE_HASV8_4A()),
        HASV8_5A(ARM_FEATURE_HASV8_5A()),
        HASV8_6A(ARM_FEATURE_HASV8_6A()),
        HASV8_7A(ARM_FEATURE_HASV8_7A()),
        HASVFP2(ARM_FEATURE_HASVFP2()),
        HASVFP3(ARM_FEATURE_HASVFP3()),
        HASVFP4(ARM_FEATURE_HASVFP4()),
        HASDPVFP(ARM_FEATURE_HASDPVFP()),
        HASFPARMV8(ARM_FEATURE_HASFPARMV8()),
        HASNEON(ARM_FEATURE_HASNEON()),
        HASSHA2(ARM_FEATURE_HASSHA2()),
        HASAES(ARM_FEATURE_HASAES()),
        HASCRYPTO(ARM_FEATURE_HASCRYPTO()),
        HASDOTPROD(ARM_FEATURE_HASDOTPROD()),
        HASCRC(ARM_FEATURE_HASCRC()),
        HASRAS(ARM_FEATURE_HASRAS()),
        HASLOB(ARM_FEATURE_HASLOB()),
        HASPACBTI(ARM_FEATURE_HASPACBTI()),
        HASFP16(ARM_FEATURE_HASFP16()),
        HASFULLFP16(ARM_FEATURE_HASFULLFP16()),
        HASFP16FML(ARM_FEATURE_HASFP16FML()),
        HASBF16(ARM_FEATURE_HASBF16()),
        HASMATMULINT8(ARM_FEATURE_HASMATMULINT8()),
        HASDIVIDEINTHUMB(ARM_FEATURE_HASDIVIDEINTHUMB()),
        HASDIVIDEINARM(ARM_FEATURE_HASDIVIDEINARM()),
        HASDSP(ARM_FEATURE_HASDSP()),
        HASDB(ARM_FEATURE_HASDB()),
        HASDFB(ARM_FEATURE_HASDFB()),
        HASV7CLREX(ARM_FEATURE_HASV7CLREX()),
        HASACQUIRERELEASE(ARM_FEATURE_HASACQUIRERELEASE()),
        HASMP(ARM_FEATURE_HASMP()),
        HASVIRTUALIZATION(ARM_FEATURE_HASVIRTUALIZATION()),
        HASTRUSTZONE(ARM_FEATURE_HASTRUSTZONE()),
        HAS8MSECEXT(ARM_FEATURE_HAS8MSECEXT()),
        ISTHUMB(ARM_FEATURE_ISTHUMB()),
        ISTHUMB2(ARM_FEATURE_ISTHUMB2()),
        ISMCLASS(ARM_FEATURE_ISMCLASS()),
        ISNOTMCLASS(ARM_FEATURE_ISNOTMCLASS()),
        ISARM(ARM_FEATURE_ISARM()),
        USENACLTRAP(ARM_FEATURE_USENACLTRAP()),
        USENEGATIVEIMMEDIATES(ARM_FEATURE_USENEGATIVEIMMEDIATES()),
        HASSB(ARM_FEATURE_HASSB()),
        HASCLRBHB(ARM_FEATURE_HASCLRBHB()),

        ENDING(ARM_GRP_ENDING());

        private final int value;

        ArmInsnGroup(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static ArmInsnGroup fromValue(int value) {
            for(ArmInsnGroup group : ArmInsnGroup.values()) {
                if(group.getValue() == value) {
                    return group;
                }
            }
            throw new IllegalArgumentException("Invalid Arm Instruction Group value: " + value);
        }
    }

    public enum ArmInsn {
        INVALID(ARM_INS_INVALID()),
        ASR(ARM_INS_ASR()),
        IT(ARM_INS_IT()),
        LDRBT(ARM_INS_LDRBT()),
        LDR(ARM_INS_LDR()),
        LDRHT(ARM_INS_LDRHT()),
        LDRSBT(ARM_INS_LDRSBT()),
        LDRSHT(ARM_INS_LDRSHT()),
        LDRT(ARM_INS_LDRT()),
        LSL(ARM_INS_LSL()),
        LSR(ARM_INS_LSR()),
        ROR(ARM_INS_ROR()),
        RRX(ARM_INS_RRX()),
        STRBT(ARM_INS_STRBT()),
        STRT(ARM_INS_STRT()),
        VLD1(ARM_INS_VLD1()),
        VLD2(ARM_INS_VLD2()),
        VLD3(ARM_INS_VLD3()),
        VLD4(ARM_INS_VLD4()),
        VST1(ARM_INS_VST1()),
        VST2(ARM_INS_VST2()),
        VST3(ARM_INS_VST3()),
        VST4(ARM_INS_VST4()),
        LDRB(ARM_INS_LDRB()),
        LDRH(ARM_INS_LDRH()),
        LDRSB(ARM_INS_LDRSB()),
        LDRSH(ARM_INS_LDRSH()),
        MOVS(ARM_INS_MOVS()),
        MOV(ARM_INS_MOV()),
        STRB(ARM_INS_STRB()),
        STRH(ARM_INS_STRH()),
        STR(ARM_INS_STR()),
        ADC(ARM_INS_ADC()),
        ADD(ARM_INS_ADD()),
        ADR(ARM_INS_ADR()),
        AESD(ARM_INS_AESD()),
        AESE(ARM_INS_AESE()),
        AESIMC(ARM_INS_AESIMC()),
        AESMC(ARM_INS_AESMC()),
        AND(ARM_INS_AND()),
        VDOT(ARM_INS_VDOT()),
        VCVT(ARM_INS_VCVT()),
        VCVTB(ARM_INS_VCVTB()),
        VCVTT(ARM_INS_VCVTT()),
        BFC(ARM_INS_BFC()),
        BFI(ARM_INS_BFI()),
        BIC(ARM_INS_BIC()),
        BKPT(ARM_INS_BKPT()),
        BL(ARM_INS_BL()),
        BLX(ARM_INS_BLX()),
        BX(ARM_INS_BX()),
        BXJ(ARM_INS_BXJ()),
        B(ARM_INS_B()),
        CX1(ARM_INS_CX1()),
        CX1A(ARM_INS_CX1A()),
        CX1D(ARM_INS_CX1D()),
        CX1DA(ARM_INS_CX1DA()),
        CX2(ARM_INS_CX2()),
        CX2A(ARM_INS_CX2A()),
        CX2D(ARM_INS_CX2D()),
        CX2DA(ARM_INS_CX2DA()),
        CX3(ARM_INS_CX3()),
        CX3A(ARM_INS_CX3A()),
        CX3D(ARM_INS_CX3D()),
        CX3DA(ARM_INS_CX3DA()),
        VCX1A(ARM_INS_VCX1A()),
        VCX1(ARM_INS_VCX1()),
        VCX2A(ARM_INS_VCX2A()),
        VCX2(ARM_INS_VCX2()),
        VCX3A(ARM_INS_VCX3A()),
        VCX3(ARM_INS_VCX3()),
        CDP(ARM_INS_CDP()),
        CDP2(ARM_INS_CDP2()),
        CLREX(ARM_INS_CLREX()),
        CLZ(ARM_INS_CLZ()),
        CMN(ARM_INS_CMN()),
        CMP(ARM_INS_CMP()),
        CPS(ARM_INS_CPS()),
        CRC32B(ARM_INS_CRC32B()),
        CRC32CB(ARM_INS_CRC32CB()),
        CRC32CH(ARM_INS_CRC32CH()),
        CRC32CW(ARM_INS_CRC32CW()),
        CRC32H(ARM_INS_CRC32H()),
        CRC32W(ARM_INS_CRC32W()),
        DBG(ARM_INS_DBG()),
        DMB(ARM_INS_DMB()),
        DSB(ARM_INS_DSB()),
        EOR(ARM_INS_EOR()),
        ERET(ARM_INS_ERET()),
        VMOV(ARM_INS_VMOV()),
        FLDMDBX(ARM_INS_FLDMDBX()),
        FLDMIAX(ARM_INS_FLDMIAX()),
        VMRS(ARM_INS_VMRS()),
        FSTMDBX(ARM_INS_FSTMDBX()),
        FSTMIAX(ARM_INS_FSTMIAX()),
        HINT(ARM_INS_HINT()),
        HLT(ARM_INS_HLT()),
        HVC(ARM_INS_HVC()),
        ISB(ARM_INS_ISB()),
        LDA(ARM_INS_LDA()),
        LDAB(ARM_INS_LDAB()),
        LDAEX(ARM_INS_LDAEX()),
        LDAEXB(ARM_INS_LDAEXB()),
        LDAEXD(ARM_INS_LDAEXD()),
        LDAEXH(ARM_INS_LDAEXH()),
        LDAH(ARM_INS_LDAH()),
        LDC2L(ARM_INS_LDC2L()),
        LDC2(ARM_INS_LDC2()),
        LDCL(ARM_INS_LDCL()),
        LDC(ARM_INS_LDC()),
        LDMDA(ARM_INS_LDMDA()),
        LDMDB(ARM_INS_LDMDB()),
        LDM(ARM_INS_LDM()),
        LDMIB(ARM_INS_LDMIB()),
        LDRD(ARM_INS_LDRD()),
        LDREX(ARM_INS_LDREX()),
        LDREXB(ARM_INS_LDREXB()),
        LDREXD(ARM_INS_LDREXD()),
        LDREXH(ARM_INS_LDREXH()),
        MCR(ARM_INS_MCR()),
        MCR2(ARM_INS_MCR2()),
        MCRR(ARM_INS_MCRR()),
        MCRR2(ARM_INS_MCRR2()),
        MLA(ARM_INS_MLA()),
        MLS(ARM_INS_MLS()),
        MOVT(ARM_INS_MOVT()),
        MOVW(ARM_INS_MOVW()),
        MRC(ARM_INS_MRC()),
        MRC2(ARM_INS_MRC2()),
        MRRC(ARM_INS_MRRC()),
        MRRC2(ARM_INS_MRRC2()),
        MRS(ARM_INS_MRS()),
        MSR(ARM_INS_MSR()),
        MUL(ARM_INS_MUL()),
        ASRL(ARM_INS_ASRL()),
        DLSTP(ARM_INS_DLSTP()),
        LCTP(ARM_INS_LCTP()),
        LETP(ARM_INS_LETP()),
        LSLL(ARM_INS_LSLL()),
        LSRL(ARM_INS_LSRL()),
        SQRSHR(ARM_INS_SQRSHR()),
        SQRSHRL(ARM_INS_SQRSHRL()),
        SQSHL(ARM_INS_SQSHL()),
        SQSHLL(ARM_INS_SQSHLL()),
        SRSHR(ARM_INS_SRSHR()),
        SRSHRL(ARM_INS_SRSHRL()),
        UQRSHL(ARM_INS_UQRSHL()),
        UQRSHLL(ARM_INS_UQRSHLL()),
        UQSHL(ARM_INS_UQSHL()),
        UQSHLL(ARM_INS_UQSHLL()),
        URSHR(ARM_INS_URSHR()),
        URSHRL(ARM_INS_URSHRL()),
        VABAV(ARM_INS_VABAV()),
        VABD(ARM_INS_VABD()),
        VABS(ARM_INS_VABS()),
        VADC(ARM_INS_VADC()),
        VADCI(ARM_INS_VADCI()),
        VADDLVA(ARM_INS_VADDLVA()),
        VADDLV(ARM_INS_VADDLV()),
        VADDVA(ARM_INS_VADDVA()),
        VADDV(ARM_INS_VADDV()),
        VADD(ARM_INS_VADD()),
        VAND(ARM_INS_VAND()),
        VBIC(ARM_INS_VBIC()),
        VBRSR(ARM_INS_VBRSR()),
        VCADD(ARM_INS_VCADD()),
        VCLS(ARM_INS_VCLS()),
        VCLZ(ARM_INS_VCLZ()),
        VCMLA(ARM_INS_VCMLA()),
        VCMP(ARM_INS_VCMP()),
        VCMUL(ARM_INS_VCMUL()),
        VCTP(ARM_INS_VCTP()),
        VCVTA(ARM_INS_VCVTA()),
        VCVTM(ARM_INS_VCVTM()),
        VCVTN(ARM_INS_VCVTN()),
        VCVTP(ARM_INS_VCVTP()),
        VDDUP(ARM_INS_VDDUP()),
        VDUP(ARM_INS_VDUP()),
        VDWDUP(ARM_INS_VDWDUP()),
        VEOR(ARM_INS_VEOR()),
        VFMAS(ARM_INS_VFMAS()),
        VFMA(ARM_INS_VFMA()),
        VFMS(ARM_INS_VFMS()),
        VHADD(ARM_INS_VHADD()),
        VHCADD(ARM_INS_VHCADD()),
        VHSUB(ARM_INS_VHSUB()),
        VIDUP(ARM_INS_VIDUP()),
        VIWDUP(ARM_INS_VIWDUP()),
        VLD20(ARM_INS_VLD20()),
        VLD21(ARM_INS_VLD21()),
        VLD40(ARM_INS_VLD40()),
        VLD41(ARM_INS_VLD41()),
        VLD42(ARM_INS_VLD42()),
        VLD43(ARM_INS_VLD43()),
        VLDRB(ARM_INS_VLDRB()),
        VLDRD(ARM_INS_VLDRD()),
        VLDRH(ARM_INS_VLDRH()),
        VLDRW(ARM_INS_VLDRW()),
        VMAXAV(ARM_INS_VMAXAV()),
        VMAXA(ARM_INS_VMAXA()),
        VMAXNMAV(ARM_INS_VMAXNMAV()),
        VMAXNMA(ARM_INS_VMAXNMA()),
        VMAXNMV(ARM_INS_VMAXNMV()),
        VMAXNM(ARM_INS_VMAXNM()),
        VMAXV(ARM_INS_VMAXV()),
        VMAX(ARM_INS_VMAX()),
        VMINAV(ARM_INS_VMINAV()),
        VMINA(ARM_INS_VMINA()),
        VMINNMAV(ARM_INS_VMINNMAV()),
        VMINNMA(ARM_INS_VMINNMA()),
        VMINNMV(ARM_INS_VMINNMV()),
        VMINNM(ARM_INS_VMINNM()),
        VMINV(ARM_INS_VMINV()),
        VMIN(ARM_INS_VMIN()),
        VMLADAVA(ARM_INS_VMLADAVA()),
        VMLADAVAX(ARM_INS_VMLADAVAX()),
        VMLADAV(ARM_INS_VMLADAV()),
        VMLADAVX(ARM_INS_VMLADAVX()),
        VMLALDAVA(ARM_INS_VMLALDAVA()),
        VMLALDAVAX(ARM_INS_VMLALDAVAX()),
        VMLALDAV(ARM_INS_VMLALDAV()),
        VMLALDAVX(ARM_INS_VMLALDAVX()),
        VMLAS(ARM_INS_VMLAS()),
        VMLA(ARM_INS_VMLA()),
        VMLSDAVA(ARM_INS_VMLSDAVA()),
        VMLSDAVAX(ARM_INS_VMLSDAVAX()),
        VMLSDAV(ARM_INS_VMLSDAV()),
        VMLSDAVX(ARM_INS_VMLSDAVX()),
        VMLSLDAVA(ARM_INS_VMLSLDAVA()),
        VMLSLDAVAX(ARM_INS_VMLSLDAVAX()),
        VMLSLDAV(ARM_INS_VMLSLDAV()),
        VMLSLDAVX(ARM_INS_VMLSLDAVX()),
        VMOVLB(ARM_INS_VMOVLB()),
        VMOVLT(ARM_INS_VMOVLT()),
        VMOVNB(ARM_INS_VMOVNB()),
        VMOVNT(ARM_INS_VMOVNT()),
        VMULH(ARM_INS_VMULH()),
        VMULLB(ARM_INS_VMULLB()),
        VMULLT(ARM_INS_VMULLT()),
        VMUL(ARM_INS_VMUL()),
        VMVN(ARM_INS_VMVN()),
        VNEG(ARM_INS_VNEG()),
        VORN(ARM_INS_VORN()),
        VORR(ARM_INS_VORR()),
        VPNOT(ARM_INS_VPNOT()),
        VPSEL(ARM_INS_VPSEL()),
        VPST(ARM_INS_VPST()),
        VPT(ARM_INS_VPT()),
        VQABS(ARM_INS_VQABS()),
        VQADD(ARM_INS_VQADD()),
        VQDMLADHX(ARM_INS_VQDMLADHX()),
        VQDMLADH(ARM_INS_VQDMLADH()),
        VQDMLAH(ARM_INS_VQDMLAH()),
        VQDMLASH(ARM_INS_VQDMLASH()),
        VQDMLSDHX(ARM_INS_VQDMLSDHX()),
        VQDMLSDH(ARM_INS_VQDMLSDH()),
        VQDMULH(ARM_INS_VQDMULH()),
        VQDMULLB(ARM_INS_VQDMULLB()),
        VQDMULLT(ARM_INS_VQDMULLT()),
        VQMOVNB(ARM_INS_VQMOVNB()),
        VQMOVNT(ARM_INS_VQMOVNT()),
        VQMOVUNB(ARM_INS_VQMOVUNB()),
        VQMOVUNT(ARM_INS_VQMOVUNT()),
        VQNEG(ARM_INS_VQNEG()),
        VQRDMLADHX(ARM_INS_VQRDMLADHX()),
        VQRDMLADH(ARM_INS_VQRDMLADH()),
        VQRDMLAH(ARM_INS_VQRDMLAH()),
        VQRDMLASH(ARM_INS_VQRDMLASH()),
        VQRDMLSDHX(ARM_INS_VQRDMLSDHX()),
        VQRDMLSDH(ARM_INS_VQRDMLSDH()),
        VQRDMULH(ARM_INS_VQRDMULH()),
        VQRSHL(ARM_INS_VQRSHL()),
        VQRSHRNB(ARM_INS_VQRSHRNB()),
        VQRSHRNT(ARM_INS_VQRSHRNT()),
        VQRSHRUNB(ARM_INS_VQRSHRUNB()),
        VQRSHRUNT(ARM_INS_VQRSHRUNT()),
        VQSHLU(ARM_INS_VQSHLU()),
        VQSHL(ARM_INS_VQSHL()),
        VQSHRNB(ARM_INS_VQSHRNB()),
        VQSHRNT(ARM_INS_VQSHRNT()),
        VQSHRUNB(ARM_INS_VQSHRUNB()),
        VQSHRUNT(ARM_INS_VQSHRUNT()),
        VQSUB(ARM_INS_VQSUB()),
        VREV16(ARM_INS_VREV16()),
        VREV32(ARM_INS_VREV32()),
        VREV64(ARM_INS_VREV64()),
        VRHADD(ARM_INS_VRHADD()),
        VRINTA(ARM_INS_VRINTA()),
        VRINTM(ARM_INS_VRINTM()),
        VRINTN(ARM_INS_VRINTN()),
        VRINTP(ARM_INS_VRINTP()),
        VRINTX(ARM_INS_VRINTX()),
        VRINTZ(ARM_INS_VRINTZ()),
        VRMLALDAVHA(ARM_INS_VRMLALDAVHA()),
        VRMLALDAVHAX(ARM_INS_VRMLALDAVHAX()),
        VRMLALDAVH(ARM_INS_VRMLALDAVH()),
        VRMLALDAVHX(ARM_INS_VRMLALDAVHX()),
        VRMLSLDAVHA(ARM_INS_VRMLSLDAVHA()),
        VRMLSLDAVHAX(ARM_INS_VRMLSLDAVHAX()),
        VRMLSLDAVH(ARM_INS_VRMLSLDAVH()),
        VRMLSLDAVHX(ARM_INS_VRMLSLDAVHX()),
        VRMULH(ARM_INS_VRMULH()),
        VRSHL(ARM_INS_VRSHL()),
        VRSHRNB(ARM_INS_VRSHRNB()),
        VRSHRNT(ARM_INS_VRSHRNT()),
        VRSHR(ARM_INS_VRSHR()),
        VSBC(ARM_INS_VSBC()),
        VSBCI(ARM_INS_VSBCI()),
        VSHLC(ARM_INS_VSHLC()),
        VSHLLB(ARM_INS_VSHLLB()),
        VSHLLT(ARM_INS_VSHLLT()),
        VSHL(ARM_INS_VSHL()),
        VSHRNB(ARM_INS_VSHRNB()),
        VSHRNT(ARM_INS_VSHRNT()),
        VSHR(ARM_INS_VSHR()),
        VSLI(ARM_INS_VSLI()),
        VSRI(ARM_INS_VSRI()),
        VST20(ARM_INS_VST20()),
        VST21(ARM_INS_VST21()),
        VST40(ARM_INS_VST40()),
        VST41(ARM_INS_VST41()),
        VST42(ARM_INS_VST42()),
        VST43(ARM_INS_VST43()),
        VSTRB(ARM_INS_VSTRB()),
        VSTRD(ARM_INS_VSTRD()),
        VSTRH(ARM_INS_VSTRH()),
        VSTRW(ARM_INS_VSTRW()),
        VSUB(ARM_INS_VSUB()),
        WLSTP(ARM_INS_WLSTP()),
        MVN(ARM_INS_MVN()),
        ORR(ARM_INS_ORR()),
        PKHBT(ARM_INS_PKHBT()),
        PKHTB(ARM_INS_PKHTB()),
        PLDW(ARM_INS_PLDW()),
        PLD(ARM_INS_PLD()),
        PLI(ARM_INS_PLI()),
        QADD(ARM_INS_QADD()),
        QADD16(ARM_INS_QADD16()),
        QADD8(ARM_INS_QADD8()),
        QASX(ARM_INS_QASX()),
        QDADD(ARM_INS_QDADD()),
        QDSUB(ARM_INS_QDSUB()),
        QSAX(ARM_INS_QSAX()),
        QSUB(ARM_INS_QSUB()),
        QSUB16(ARM_INS_QSUB16()),
        QSUB8(ARM_INS_QSUB8()),
        RBIT(ARM_INS_RBIT()),
        REV(ARM_INS_REV()),
        REV16(ARM_INS_REV16()),
        REVSH(ARM_INS_REVSH()),
        RFEDA(ARM_INS_RFEDA()),
        RFEDB(ARM_INS_RFEDB()),
        RFEIA(ARM_INS_RFEIA()),
        RFEIB(ARM_INS_RFEIB()),
        RSB(ARM_INS_RSB()),
        RSC(ARM_INS_RSC()),
        SADD16(ARM_INS_SADD16()),
        SADD8(ARM_INS_SADD8()),
        SASX(ARM_INS_SASX()),
        SB(ARM_INS_SB()),
        SBC(ARM_INS_SBC()),
        SBFX(ARM_INS_SBFX()),
        SDIV(ARM_INS_SDIV()),
        SEL(ARM_INS_SEL()),
        SETEND(ARM_INS_SETEND()),
        SETPAN(ARM_INS_SETPAN()),
        SHA1C(ARM_INS_SHA1C()),
        SHA1H(ARM_INS_SHA1H()),
        SHA1M(ARM_INS_SHA1M()),
        SHA1P(ARM_INS_SHA1P()),
        SHA1SU0(ARM_INS_SHA1SU0()),
        SHA1SU1(ARM_INS_SHA1SU1()),
        SHA256H(ARM_INS_SHA256H()),
        SHA256H2(ARM_INS_SHA256H2()),
        SHA256SU0(ARM_INS_SHA256SU0()),
        SHA256SU1(ARM_INS_SHA256SU1()),
        SHADD16(ARM_INS_SHADD16()),
        SHADD8(ARM_INS_SHADD8()),
        SHASX(ARM_INS_SHASX()),
        SHSAX(ARM_INS_SHSAX()),
        SHSUB16(ARM_INS_SHSUB16()),
        SHSUB8(ARM_INS_SHSUB8()),
        SMC(ARM_INS_SMC()),
        SMLABB(ARM_INS_SMLABB()),
        SMLABT(ARM_INS_SMLABT()),
        SMLAD(ARM_INS_SMLAD()),
        SMLADX(ARM_INS_SMLADX()),
        SMLAL(ARM_INS_SMLAL()),
        SMLALBB(ARM_INS_SMLALBB()),
        SMLALBT(ARM_INS_SMLALBT()),
        SMLALD(ARM_INS_SMLALD()),
        SMLALDX(ARM_INS_SMLALDX()),
        SMLALTB(ARM_INS_SMLALTB()),
        SMLALTT(ARM_INS_SMLALTT()),
        SMLATB(ARM_INS_SMLATB()),
        SMLATT(ARM_INS_SMLATT()),
        SMLAWB(ARM_INS_SMLAWB()),
        SMLAWT(ARM_INS_SMLAWT()),
        SMLSD(ARM_INS_SMLSD()),
        SMLSDX(ARM_INS_SMLSDX()),
        SMLSLD(ARM_INS_SMLSLD()),
        SMLSLDX(ARM_INS_SMLSLDX()),
        SMMLA(ARM_INS_SMMLA()),
        SMMLAR(ARM_INS_SMMLAR()),
        SMMLS(ARM_INS_SMMLS()),
        SMMLSR(ARM_INS_SMMLSR()),
        SMMUL(ARM_INS_SMMUL()),
        SMMULR(ARM_INS_SMMULR()),
        SMUAD(ARM_INS_SMUAD()),
        SMUADX(ARM_INS_SMUADX()),
        SMULBB(ARM_INS_SMULBB()),
        SMULBT(ARM_INS_SMULBT()),
        SMULL(ARM_INS_SMULL()),
        SMULTB(ARM_INS_SMULTB()),
        SMULTT(ARM_INS_SMULTT()),
        SMULWB(ARM_INS_SMULWB()),
        SMULWT(ARM_INS_SMULWT()),
        SMUSD(ARM_INS_SMUSD()),
        SMUSDX(ARM_INS_SMUSDX()),
        SRSDA(ARM_INS_SRSDA()),
        SRSDB(ARM_INS_SRSDB()),
        SRSIA(ARM_INS_SRSIA()),
        SRSIB(ARM_INS_SRSIB()),
        SSAT(ARM_INS_SSAT()),
        SSAT16(ARM_INS_SSAT16()),
        SSAX(ARM_INS_SSAX()),
        SSUB16(ARM_INS_SSUB16()),
        SSUB8(ARM_INS_SSUB8()),
        STC2L(ARM_INS_STC2L()),
        STC2(ARM_INS_STC2()),
        STCL(ARM_INS_STCL()),
        STC(ARM_INS_STC()),
        STL(ARM_INS_STL()),
        STLB(ARM_INS_STLB()),
        STLEX(ARM_INS_STLEX()),
        STLEXB(ARM_INS_STLEXB()),
        STLEXD(ARM_INS_STLEXD()),
        STLEXH(ARM_INS_STLEXH()),
        STLH(ARM_INS_STLH()),
        STMDA(ARM_INS_STMDA()),
        STMDB(ARM_INS_STMDB()),
        STM(ARM_INS_STM()),
        STMIB(ARM_INS_STMIB()),
        STRD(ARM_INS_STRD()),
        STREX(ARM_INS_STREX()),
        STREXB(ARM_INS_STREXB()),
        STREXD(ARM_INS_STREXD()),
        STREXH(ARM_INS_STREXH()),
        STRHT(ARM_INS_STRHT()),
        SUB(ARM_INS_SUB()),
        SVC(ARM_INS_SVC()),
        SWP(ARM_INS_SWP()),
        SWPB(ARM_INS_SWPB()),
        SXTAB(ARM_INS_SXTAB()),
        SXTAB16(ARM_INS_SXTAB16()),
        SXTAH(ARM_INS_SXTAH()),
        SXTB(ARM_INS_SXTB()),
        SXTB16(ARM_INS_SXTB16()),
        SXTH(ARM_INS_SXTH()),
        TEQ(ARM_INS_TEQ()),
        TRAP(ARM_INS_TRAP()),
        TSB(ARM_INS_TSB()),
        TST(ARM_INS_TST()),
        UADD16(ARM_INS_UADD16()),
        UADD8(ARM_INS_UADD8()),
        UASX(ARM_INS_UASX()),
        UBFX(ARM_INS_UBFX()),
        UDF(ARM_INS_UDF()),
        UDIV(ARM_INS_UDIV()),
        UHADD16(ARM_INS_UHADD16()),
        UHADD8(ARM_INS_UHADD8()),
        UHASX(ARM_INS_UHASX()),
        UHSAX(ARM_INS_UHSAX()),
        UHSUB16(ARM_INS_UHSUB16()),
        UHSUB8(ARM_INS_UHSUB8()),
        UMAAL(ARM_INS_UMAAL()),
        UMLAL(ARM_INS_UMLAL()),
        UMULL(ARM_INS_UMULL()),
        UQADD16(ARM_INS_UQADD16()),
        UQADD8(ARM_INS_UQADD8()),
        UQASX(ARM_INS_UQASX()),
        UQSAX(ARM_INS_UQSAX()),
        UQSUB16(ARM_INS_UQSUB16()),
        UQSUB8(ARM_INS_UQSUB8()),
        USAD8(ARM_INS_USAD8()),
        USADA8(ARM_INS_USADA8()),
        USAT(ARM_INS_USAT()),
        USAT16(ARM_INS_USAT16()),
        USAX(ARM_INS_USAX()),
        USUB16(ARM_INS_USUB16()),
        USUB8(ARM_INS_USUB8()),
        UXTAB(ARM_INS_UXTAB()),
        UXTAB16(ARM_INS_UXTAB16()),
        UXTAH(ARM_INS_UXTAH()),
        UXTB(ARM_INS_UXTB()),
        UXTB16(ARM_INS_UXTB16()),
        UXTH(ARM_INS_UXTH()),
        VABAL(ARM_INS_VABAL()),
        VABA(ARM_INS_VABA()),
        VABDL(ARM_INS_VABDL()),
        VACGE(ARM_INS_VACGE()),
        VACGT(ARM_INS_VACGT()),
        VADDHN(ARM_INS_VADDHN()),
        VADDL(ARM_INS_VADDL()),
        VADDW(ARM_INS_VADDW()),
        VFMAB(ARM_INS_VFMAB()),
        VFMAT(ARM_INS_VFMAT()),
        VBIF(ARM_INS_VBIF()),
        VBIT(ARM_INS_VBIT()),
        VBSL(ARM_INS_VBSL()),
        VCEQ(ARM_INS_VCEQ()),
        VCGE(ARM_INS_VCGE()),
        VCGT(ARM_INS_VCGT()),
        VCLE(ARM_INS_VCLE()),
        VCLT(ARM_INS_VCLT()),
        VCMPE(ARM_INS_VCMPE()),
        VCNT(ARM_INS_VCNT()),
        VDIV(ARM_INS_VDIV()),
        VEXT(ARM_INS_VEXT()),
        VFMAL(ARM_INS_VFMAL()),
        VFMSL(ARM_INS_VFMSL()),
        VFNMA(ARM_INS_VFNMA()),
        VFNMS(ARM_INS_VFNMS()),
        VINS(ARM_INS_VINS()),
        VJCVT(ARM_INS_VJCVT()),
        VLDMDB(ARM_INS_VLDMDB()),
        VLDMIA(ARM_INS_VLDMIA()),
        VLDR(ARM_INS_VLDR()),
        VLLDM(ARM_INS_VLLDM()),
        VLSTM(ARM_INS_VLSTM()),
        VMLAL(ARM_INS_VMLAL()),
        VMLS(ARM_INS_VMLS()),
        VMLSL(ARM_INS_VMLSL()),
        VMMLA(ARM_INS_VMMLA()),
        VMOVX(ARM_INS_VMOVX()),
        VMOVL(ARM_INS_VMOVL()),
        VMOVN(ARM_INS_VMOVN()),
        VMSR(ARM_INS_VMSR()),
        VMULL(ARM_INS_VMULL()),
        VNMLA(ARM_INS_VNMLA()),
        VNMLS(ARM_INS_VNMLS()),
        VNMUL(ARM_INS_VNMUL()),
        VPADAL(ARM_INS_VPADAL()),
        VPADDL(ARM_INS_VPADDL()),
        VPADD(ARM_INS_VPADD()),
        VPMAX(ARM_INS_VPMAX()),
        VPMIN(ARM_INS_VPMIN()),
        VQDMLAL(ARM_INS_VQDMLAL()),
        VQDMLSL(ARM_INS_VQDMLSL()),
        VQDMULL(ARM_INS_VQDMULL()),
        VQMOVUN(ARM_INS_VQMOVUN()),
        VQMOVN(ARM_INS_VQMOVN()),
        VQRDMLSH(ARM_INS_VQRDMLSH()),
        VQRSHRN(ARM_INS_VQRSHRN()),
        VQRSHRUN(ARM_INS_VQRSHRUN()),
        VQSHRN(ARM_INS_VQSHRN()),
        VQSHRUN(ARM_INS_VQSHRUN()),
        VRADDHN(ARM_INS_VRADDHN()),
        VRECPE(ARM_INS_VRECPE()),
        VRECPS(ARM_INS_VRECPS()),
        VRINTR(ARM_INS_VRINTR()),
        VRSHRN(ARM_INS_VRSHRN()),
        VRSQRTE(ARM_INS_VRSQRTE()),
        VRSQRTS(ARM_INS_VRSQRTS()),
        VRSRA(ARM_INS_VRSRA()),
        VRSUBHN(ARM_INS_VRSUBHN()),
        VSCCLRM(ARM_INS_VSCCLRM()),
        VSDOT(ARM_INS_VSDOT()),
        VSELEQ(ARM_INS_VSELEQ()),
        VSELGE(ARM_INS_VSELGE()),
        VSELGT(ARM_INS_VSELGT()),
        VSELVS(ARM_INS_VSELVS()),
        VSHLL(ARM_INS_VSHLL()),
        VSHRN(ARM_INS_VSHRN()),
        VSMMLA(ARM_INS_VSMMLA()),
        VSQRT(ARM_INS_VSQRT()),
        VSRA(ARM_INS_VSRA()),
        VSTMDB(ARM_INS_VSTMDB()),
        VSTMIA(ARM_INS_VSTMIA()),
        VSTR(ARM_INS_VSTR()),
        VSUBHN(ARM_INS_VSUBHN()),
        VSUBL(ARM_INS_VSUBL()),
        VSUBW(ARM_INS_VSUBW()),
        VSUDOT(ARM_INS_VSUDOT()),
        VSWP(ARM_INS_VSWP()),
        VTBL(ARM_INS_VTBL()),
        VTBX(ARM_INS_VTBX()),
        VCVTR(ARM_INS_VCVTR()),
        VTRN(ARM_INS_VTRN()),
        VTST(ARM_INS_VTST()),
        VUDOT(ARM_INS_VUDOT()),
        VUMMLA(ARM_INS_VUMMLA()),
        VUSDOT(ARM_INS_VUSDOT()),
        VUSMMLA(ARM_INS_VUSMMLA()),
        VUZP(ARM_INS_VUZP()),
        VZIP(ARM_INS_VZIP()),
        ADDW(ARM_INS_ADDW()),
        AUT(ARM_INS_AUT()),
        AUTG(ARM_INS_AUTG()),
        BFL(ARM_INS_BFL()),
        BFLX(ARM_INS_BFLX()),
        BF(ARM_INS_BF()),
        BFCSEL(ARM_INS_BFCSEL()),
        BFX(ARM_INS_BFX()),
        BTI(ARM_INS_BTI()),
        BXAUT(ARM_INS_BXAUT()),
        CLRM(ARM_INS_CLRM()),
        CSEL(ARM_INS_CSEL()),
        CSINC(ARM_INS_CSINC()),
        CSINV(ARM_INS_CSINV()),
        CSNEG(ARM_INS_CSNEG()),
        DCPS1(ARM_INS_DCPS1()),
        DCPS2(ARM_INS_DCPS2()),
        DCPS3(ARM_INS_DCPS3()),
        DLS(ARM_INS_DLS()),
        LE(ARM_INS_LE()),
        ORN(ARM_INS_ORN()),
        PAC(ARM_INS_PAC()),
        PACBTI(ARM_INS_PACBTI()),
        PACG(ARM_INS_PACG()),
        SG(ARM_INS_SG()),
        SUBS(ARM_INS_SUBS()),
        SUBW(ARM_INS_SUBW()),
        TBB(ARM_INS_TBB()),
        TBH(ARM_INS_TBH()),
        TT(ARM_INS_TT()),
        TTA(ARM_INS_TTA()),
        TTAT(ARM_INS_TTAT()),
        TTT(ARM_INS_TTT()),
        WLS(ARM_INS_WLS()),
        BLXNS(ARM_INS_BLXNS()),
        BXNS(ARM_INS_BXNS()),
        CBNZ(ARM_INS_CBNZ()),
        CBZ(ARM_INS_CBZ()),
        POP(ARM_INS_POP()),
        PUSH(ARM_INS_PUSH()),
        __BRKDIV0(ARM_INS___BRKDIV0()),

        // clang-format on
        // generated content <ARMGenCSInsnEnum.inc> end

        ENDING(ARM_INS_ENDING()),	// <-- mark the end of the list of instructions

        ALIAS_BEGIN(ARM_INS_ALIAS_BEGIN()),
        // generated content <ARMGenCSAliasEnum.inc> begin
        // clang-format off

        ALIAS_VMOV(ARM_INS_ALIAS_VMOV()), // Real instr.: ARM_MVE_VORR
        ALIAS_NOP(ARM_INS_ALIAS_NOP()), // Real instr.: ARM_HINT
        ALIAS_YIELD(ARM_INS_ALIAS_YIELD()), // Real instr.: ARM_HINT
        ALIAS_WFE(ARM_INS_ALIAS_WFE()), // Real instr.: ARM_HINT
        ALIAS_WFI(ARM_INS_ALIAS_WFI()), // Real instr.: ARM_HINT
        ALIAS_SEV(ARM_INS_ALIAS_SEV()), // Real instr.: ARM_HINT
        ALIAS_SEVL(ARM_INS_ALIAS_SEVL()), // Real instr.: ARM_HINT
        ALIAS_ESB(ARM_INS_ALIAS_ESB()), // Real instr.: ARM_HINT
        ALIAS_CSDB(ARM_INS_ALIAS_CSDB()), // Real instr.: ARM_HINT
        ALIAS_CLRBHB(ARM_INS_ALIAS_CLRBHB()), // Real instr.: ARM_HINT
        ALIAS_PACBTI(ARM_INS_ALIAS_PACBTI()), // Real instr.: ARM_t2HINT
        ALIAS_BTI(ARM_INS_ALIAS_BTI()), // Real instr.: ARM_t2HINT
        ALIAS_PAC(ARM_INS_ALIAS_PAC()), // Real instr.: ARM_t2HINT
        ALIAS_AUT(ARM_INS_ALIAS_AUT()), // Real instr.: ARM_t2HINT
        ALIAS_SSBB(ARM_INS_ALIAS_SSBB()), // Real instr.: ARM_t2DSB
        ALIAS_PSSBB(ARM_INS_ALIAS_PSSBB()), // Real instr.: ARM_t2DSB
        ALIAS_DFB(ARM_INS_ALIAS_DFB()), // Real instr.: ARM_t2DSB
        ALIAS_CSETM(ARM_INS_ALIAS_CSETM()), // Real instr.: ARM_t2CSINV
        ALIAS_CSET(ARM_INS_ALIAS_CSET()), // Real instr.: ARM_t2CSINC
        ALIAS_CINC(ARM_INS_ALIAS_CINC()), // Real instr.: ARM_t2CSINC
        ALIAS_CINV(ARM_INS_ALIAS_CINV()), // Real instr.: ARM_t2CSINV
        ALIAS_CNEG(ARM_INS_ALIAS_CNEG()), // Real instr.: ARM_t2CSNEG
        ALIAS_VMLAV(ARM_INS_ALIAS_VMLAV()), // Real instr.: ARM_MVE_VMLADAVs8
        ALIAS_VMLAVA(ARM_INS_ALIAS_VMLAVA()), // Real instr.: ARM_MVE_VMLADAVas8
        ALIAS_VRMLALVH(ARM_INS_ALIAS_VRMLALVH()), // Real instr.: ARM_MVE_VRMLALDAVHs32
        ALIAS_VRMLALVHA(ARM_INS_ALIAS_VRMLALVHA()), // Real instr.: ARM_MVE_VRMLALDAVHas32
        ALIAS_VMLALV(ARM_INS_ALIAS_VMLALV()), // Real instr.: ARM_MVE_VMLALDAVs16
        ALIAS_VMLALVA(ARM_INS_ALIAS_VMLALVA()), // Real instr.: ARM_MVE_VMLALDAVas16
        ALIAS_VBIC(ARM_INS_ALIAS_VBIC()), // Real instr.: ARM_MVE_VBIC
        ALIAS_VEOR(ARM_INS_ALIAS_VEOR()), // Real instr.: ARM_MVE_VEOR
        ALIAS_VORN(ARM_INS_ALIAS_VORN()), // Real instr.: ARM_MVE_VORN
        ALIAS_VORR(ARM_INS_ALIAS_VORR()), // Real instr.: ARM_MVE_VORR
        ALIAS_VAND(ARM_INS_ALIAS_VAND()), // Real instr.: ARM_MVE_VAND
        ALIAS_VPSEL(ARM_INS_ALIAS_VPSEL()), // Real instr.: ARM_MVE_VPSEL
        ALIAS_ERET(ARM_INS_ALIAS_ERET()), // Real instr.: ARM_t2SUBS_PC_LR

        // clang-format on
        // generated content <ARMGenCSAliasEnum.inc> end

        // Hardcoded in LLVM printer
        ALIAS_ASR(ARM_INS_ALIAS_ASR()),
        ALIAS_LSL(ARM_INS_ALIAS_LSL()),
        ALIAS_LSR(ARM_INS_ALIAS_LSR()),
        ALIAS_ROR(ARM_INS_ALIAS_ROR()),
        ALIAS_RRX(ARM_INS_ALIAS_RRX()),
        ALIAS_UXTW(ARM_INS_ALIAS_UXTW()),
        ALIAS_LDM(ARM_INS_ALIAS_LDM()),
        ALIAS_POP(ARM_INS_ALIAS_POP()),
        ALIAS_PUSH(ARM_INS_ALIAS_PUSH()),
        ALIAS_POPW(ARM_INS_ALIAS_POPW()),
        ALIAS_PUSHW(ARM_INS_ALIAS_PUSHW()),
        ALIAS_VPOP(ARM_INS_ALIAS_VPOP()),
        ALIAS_VPUSH(ARM_INS_ALIAS_VPUSH()),

        ALIAS_END(ARM_INS_ALIAS_END());

        private int value;

        private ArmInsn(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static ArmInsn[] fromValue(int value) {
            boolean added = false;
            List<ArmInsn> result = new ArrayList<>();
            for (ArmInsn insn : ArmInsn.values()) {
                if (insn.value == value) {
                    added = true;
                    result.add(insn);
                }
            }
            if (!added) {
                result.add(INVALID);
            }
            return result.toArray(new ArmInsn[0]);
        }
    }
}
