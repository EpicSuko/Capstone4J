package com.capstone4j;

import static com.capstone4j.internal.capstone_h.*;

import com.capstone4j.internal.aarch64_imm_range;
import com.capstone4j.internal.aarch64_op_mem;
import com.capstone4j.internal.aarch64_op_sme;
import com.capstone4j.internal.aarch64_op_pred;
import com.capstone4j.internal.aarch64_sysop_alias;
import com.capstone4j.internal.aarch64_sysop_imm;
import com.capstone4j.internal.aarch64_sysop_reg;
import com.capstone4j.internal.aarch64_sysop;
import com.capstone4j.internal.cs_aarch64_op;
import com.capstone4j.internal.cs_aarch64;


import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;

public class CapstoneAArch64Details extends CapstoneArchDetails<CapstoneAArch64Details.AArch64Operand> implements MemorySegmentCreatable<CapstoneAArch64Details>{

	private final AArch64CondCode[] cc;
	private final boolean updateFlags;
	private final boolean postIndex;
	private final boolean isDoingSme;

	CapstoneAArch64Details(int opCount, AArch64Operand[] operands, AArch64CondCode[] cc, boolean updateFlags, boolean postIndex, boolean isDoingSme) {
		super(opCount, operands);
		this.cc = cc;
		this.updateFlags = updateFlags;
		this.postIndex = postIndex;
		this.isDoingSme = isDoingSme;
	}

	static CapstoneAArch64Details createFromMemorySegment(MemorySegment segment) {
		AArch64CondCode[] cc = AArch64CondCode.fromValue(cs_aarch64.cc(segment));
		boolean updateFlags = cs_aarch64.update_flags(segment);
		boolean postIndex = cs_aarch64.post_index(segment);
		boolean isDoingSme = cs_aarch64.is_doing_sme(segment);
		int opCount = cs_aarch64.op_count(segment);

		AArch64Operand[] operands = new AArch64Operand[opCount];
		MemorySegment operandsSegment = cs_aarch64.operands(segment);
		for (int i = 0; i < opCount; i++) {
			operands[i] = createOperandFromMemorySegment(operandsSegment.asSlice(i * cs_aarch64_op.sizeof()));
		}
		return new CapstoneAArch64Details(opCount, operands, cc, updateFlags, postIndex, isDoingSme);
	}

	private static AArch64Operand createOperandFromMemorySegment(MemorySegment segment) {
		int vectorIndex = cs_aarch64_op.vector_index(segment);
		AArch64VectorLayout vas = AArch64VectorLayout.fromValue(cs_aarch64_op.vas(segment));
		AArch64Shift shift = createShiftFromMemorySegment(cs_aarch64_op.shift(segment));
		AArch64Extender ext = AArch64Extender.fromValue(cs_aarch64_op.ext(segment));
		AArch64OperandType type = AArch64OperandType.fromValue(cs_aarch64_op.type(segment));
		boolean isVReg = cs_aarch64_op.is_vreg(segment);

		AArch64Reg[] reg = null;
		long imm = 0;
		AArch64ImmRange immRange = null;
		double fp = 0;
		AArch64OpMem mem = null;
		AArch64OpSme sme = null;
		AArch64Pred pred = null;
		AArch64SysOp sysop = null;

		if(type == AArch64OperandType.REG || type == AArch64OperandType.MEM_REG) {
			reg = AArch64Reg.fromValue(cs_aarch64_op.reg(segment));
		} else if(type == AArch64OperandType.IMM || type == AArch64OperandType.CIMM || type == AArch64OperandType.MEM_IMM || type == AArch64OperandType.IMPLICIT_IMM_0) {
			imm = cs_aarch64_op.imm(segment);
		} else if(type == AArch64OperandType.IMM_RANGE) {
			immRange = createImmRangeFromMemorySegment(cs_aarch64_op.imm_range(segment));
		} else if(type == AArch64OperandType.FP) {
			fp = cs_aarch64_op.fp(segment);
		} else if(type == AArch64OperandType.MEM) {
			mem = createOpMemFromMemorySegment(cs_aarch64_op.mem(segment));
		} else if(type == AArch64OperandType.SME) {
			sme = createOpSmeFromMemorySegment(cs_aarch64_op.sme(segment));
		} else if(type == AArch64OperandType.PRED) {
			pred = createPredFromMemorySegment(cs_aarch64_op.pred(segment));
		} else if(type == AArch64OperandType.SYSALIAS || type == AArch64OperandType.SYSREG || type == AArch64OperandType.SYSIMM) {
			sysop = createSysOpFromMemorySegment(cs_aarch64_op.sysop(segment), type);
		} else {
			throw new IllegalArgumentException("Invalid operand type: " + type);
		}

		int access = cs_aarch64_op.access(segment);
		boolean isListMember = cs_aarch64_op.is_list_member(segment);

		return new AArch64Operand(vectorIndex, vas, shift, ext, type, isVReg, reg, imm, immRange, fp, mem, sme, pred, sysop, access, isListMember);
	}

	private static AArch64SysOp createSysOpFromMemorySegment(MemorySegment segment, AArch64OperandType type) {
		AArch64OperandType subType = AArch64OperandType.fromValue(aarch64_sysop.sub_type(segment));
		AArch64SysOpReg reg = null;
		AArch64SysOpImm imm = null;
		AArch64SysOpAlias alias = null;
		if(subType == AArch64OperandType.REG_MRS || subType == AArch64OperandType.REG_MSR) {
			reg = createSysOpRegFromMemorySegment(aarch64_sysop.reg(segment), subType);
		} else if(type == AArch64OperandType.SYSALIAS) {
			alias = createSysOpAliasFromMemorySegment(aarch64_sysop.alias(segment), subType);
		} else if(type == AArch64OperandType.SYSIMM) {
			imm = createSysOpImmFromMemorySegment(aarch64_sysop.imm(segment), subType);
		} else {
			throw new IllegalArgumentException("Invalid system operand type: " + type);
		}
		return new AArch64SysOp(reg, imm, alias, subType);
	}

	private static AArch64SysOpAlias createSysOpAliasFromMemorySegment(MemorySegment segment, AArch64OperandType type) {
		AArch64Svcr svcr = null;
		AArch64At at = null;
		AArch64Db db = null;
		AArch64Dc dc = null;
		AArch64Isb isb = null;
		AArch64Tsb tsb = null;
		AArch64Prfm prfm = null;
		AArch64Sveprfm sveprfm = null;
		AArch64Rprfm rprfm = null;
		AArch64PStateImm015 pstateimm015 = null;
		AArch64PStateImm01 pstateimm01 = null;
		AArch64Psb psb = null;
		AArch64Bti bti = null;
		AArch64Svepredpat svepredpat = null;
		AArch64SveveclenSpecifier sveveclenspecifier = null;

		if(type == AArch64OperandType.SVCR) {
			svcr = AArch64Svcr.fromValue(aarch64_sysop_alias.svcr(segment));
		} else if(type == AArch64OperandType.AT) {
			at = AArch64At.fromValue(aarch64_sysop_alias.at(segment));
		} else if(type == AArch64OperandType.DB) {
			db = AArch64Db.fromValue(aarch64_sysop_alias.db(segment));
		} else if(type == AArch64OperandType.DC) {
			dc = AArch64Dc.fromValue(aarch64_sysop_alias.dc(segment));
		} else if(type == AArch64OperandType.ISB) {
			isb = AArch64Isb.fromValue(aarch64_sysop_alias.isb(segment));
		} else if(type == AArch64OperandType.TSB) {
			tsb = AArch64Tsb.fromValue(aarch64_sysop_alias.tsb(segment));
		} else if(type == AArch64OperandType.PRFM) {
			prfm = AArch64Prfm.fromValue(aarch64_sysop_alias.prfm(segment));
		} else if(type == AArch64OperandType.SVEPRFM) {
			sveprfm = AArch64Sveprfm.fromValue(aarch64_sysop_alias.sveprfm(segment));
		} else if(type == AArch64OperandType.RPRFM) {
			rprfm = AArch64Rprfm.fromValue(aarch64_sysop_alias.rprfm(segment));
		} else if(type == AArch64OperandType.PSTATEIMM0_15) {
			pstateimm015 = AArch64PStateImm015.fromValue(aarch64_sysop_alias.pstateimm0_15(segment));
		} else if(type == AArch64OperandType.PSTATEIMM0_1) {
			pstateimm01 = AArch64PStateImm01.fromValue(aarch64_sysop_alias.pstateimm0_1(segment));
		} else if(type == AArch64OperandType.PSB) {
			psb = AArch64Psb.fromValue(aarch64_sysop_alias.psb(segment));
		} else if(type == AArch64OperandType.BTI) {
			bti = AArch64Bti.fromValue(aarch64_sysop_alias.bti(segment));
		} else if(type == AArch64OperandType.SVEPREDPAT) {
			svepredpat = AArch64Svepredpat.fromValue(aarch64_sysop_alias.svepredpat(segment));
		} else if(type == AArch64OperandType.SVEVECLENSPECIFIER) {
			sveveclenspecifier = AArch64SveveclenSpecifier.fromValue(aarch64_sysop_alias.sveveclenspecifier(segment));
		} else {
			throw new IllegalArgumentException("Invalid system operand type: " + type);
		}
		int rawValue = aarch64_sysop_alias.raw_val(segment);
		return new AArch64SysOpAlias(svcr, at, db, dc, isb, tsb, prfm, sveprfm, rprfm, pstateimm015, pstateimm01, psb, bti, svepredpat, sveveclenspecifier, rawValue);
	}

	private static AArch64SysOpImm createSysOpImmFromMemorySegment(MemorySegment segment, AArch64OperandType subType) {
		AArch64Dbnxs dbnxs = null;
		AArch64ExactFpImm exactfpimm = null;
		if(subType == AArch64OperandType.DBNXS) {
			dbnxs = AArch64Dbnxs.fromValue(aarch64_sysop_imm.dbnxs(segment));
		} else if(subType == AArch64OperandType.EXACTFPIMM) {
			exactfpimm = AArch64ExactFpImm.fromValue(aarch64_sysop_imm.exactfpimm(segment));
		} else {
			throw new IllegalArgumentException("Invalid system operand type: " + subType);
		}
		int rawValue = aarch64_sysop_imm.raw_val(segment);
		return new AArch64SysOpImm(dbnxs, exactfpimm, rawValue);
	}

	private static AArch64SysOpReg createSysOpRegFromMemorySegment(MemorySegment segment, AArch64OperandType subType) {
		AArch64SysReg sysreg = null;
		AArch64Tlbi tlbi = null;
		AArch64Ic ic = null;
		if(subType == AArch64OperandType.REG_MRS || subType == AArch64OperandType.REG_MSR) {
			sysreg = AArch64SysReg.fromValue(aarch64_sysop_reg.sysreg(segment));
		} else if(subType == AArch64OperandType.TLBI) {
			tlbi = AArch64Tlbi.fromValue(aarch64_sysop_reg.tlbi(segment));
		} else if(subType == AArch64OperandType.IC) {
			ic = AArch64Ic.fromValue(aarch64_sysop_reg.ic(segment));
		} else {
			throw new IllegalArgumentException("Invalid system operand type: " + subType);
		}
		int rawValue = aarch64_sysop_reg.raw_val(segment);
		return new AArch64SysOpReg(sysreg, tlbi, ic, rawValue);
	}

	private static AArch64Pred createPredFromMemorySegment(MemorySegment segment) {
		AArch64Reg[] reg = AArch64Reg.fromValue(aarch64_op_pred.reg(segment));
		AArch64Reg[] vecSelect = AArch64Reg.fromValue(aarch64_op_pred.vec_select(segment));
		int immIndex = aarch64_op_pred.imm_index(segment);
		return new AArch64Pred(reg, vecSelect, immIndex);
	}

	private static AArch64OpSme createOpSmeFromMemorySegment(MemorySegment segment) {
		AArch64SmeOpType type = AArch64SmeOpType.fromValue(aarch64_op_sme.type(segment));
		AArch64Reg[] tile = AArch64Reg.fromValue(aarch64_op_sme.tile(segment));
		AArch64Reg[] sliceReg = AArch64Reg.fromValue(aarch64_op_sme.slice_reg(segment));
		MemorySegment sliceOffsetSegment = aarch64_op_sme.slice_offset(segment);
		int imm = aarch64_op_sme.slice_offset.imm(sliceOffsetSegment);
		AArch64ImmRange immRange = createImmRangeFromMemorySegment(aarch64_op_sme.slice_offset.imm_range(sliceOffsetSegment));
		boolean hasRangeOffset = aarch64_op_sme.has_range_offset(segment);
		boolean isVertical = aarch64_op_sme.is_vertical(segment);
		return new AArch64OpSme(type, tile, sliceReg, imm, immRange, hasRangeOffset, isVertical);
	}

	private static AArch64OpMem createOpMemFromMemorySegment(MemorySegment segment) {
		AArch64Reg[] base = AArch64Reg.fromValue(aarch64_op_mem.base(segment));
		AArch64Reg[] index = AArch64Reg.fromValue(aarch64_op_mem.index(segment));
		int disp = aarch64_op_mem.disp(segment);
		return new AArch64OpMem(base, index, disp);
	}

	private static AArch64ImmRange createImmRangeFromMemorySegment(MemorySegment segment) {
		int first = aarch64_imm_range.first(segment);
		int offset = aarch64_imm_range.offset(segment);
		return new AArch64ImmRange(first, offset);
	}

	private static AArch64Shift createShiftFromMemorySegment(MemorySegment segment) {
		AArch64Shifter type = AArch64Shifter.fromValue(cs_aarch64_op.shift.type(segment));
		long value = cs_aarch64_op.shift.value(segment);
		return new AArch64Shift(type, value);
	}

	@Override
	int getOpCounOfType(int opType) {
		int count = 0;
		for (AArch64Operand operand : getOperands()) {
			if (isOperandOfType(operand, opType)) {
				count++;
			}
		}
		return count;
	}

	@Override
	boolean isOperandOfType(AArch64Operand operand, int opType) {
		return operand.getType() == AArch64OperandType.fromValue(opType);
	}

	public AArch64CondCode[] getCc() {
		return cc;
	}

	public boolean isUpdateFlags() {
		return updateFlags;
	}

	public boolean isPostIndex() {
		return postIndex;
	}

	public boolean isDoingSme() {
		return isDoingSme;
	}

	public enum AArch64CondCode {
		EQ(AArch64CC_EQ()), // Equal                      Equal
		NE(AArch64CC_NE()), // Not equal                  Not equal, or unordered
		HS(AArch64CC_HS()), // Unsigned higher or same    >, ==, or unordered
		LO(AArch64CC_LO()), // Unsigned lower             Less than
		MI(AArch64CC_MI()), // Minus, negative            Less than
		PL(AArch64CC_PL()), // Plus, positive or zero     >, ==, or unordered
		VS(AArch64CC_VS()), // Overflow                   Unordered
		VC(AArch64CC_VC()), // No overflow                Not unordered
		HI(AArch64CC_HI()), // Unsigned higher            Greater than, or unordered
		LS(AArch64CC_LS()), // Unsigned lower or same     Less than or equal
		GE(AArch64CC_GE()), // Greater than or equal      Greater than or equal
		LT(AArch64CC_LT()), // Less than                  Less than, or unordered
		GT(AArch64CC_GT()), // Greater than               Greater than
		LE(AArch64CC_LE()), // Less than or equal         <, ==, or unordered
		AL(AArch64CC_AL()), // Always (unconditional)     Always (unconditional)
		NV(AArch64CC_NV()), // Always (unconditional)     Always (unconditional)
		// Note the NV exists purely to disassemble 0b1111. Execution is "always".
		Invalid(AArch64CC_Invalid()),

		// Common aliases used for SVE.
		ANY_ACTIVE(AArch64CC_ANY_ACTIVE()),	 // (!Z)
		FIRST_ACTIVE(AArch64CC_FIRST_ACTIVE()), // ( N)
		LAST_ACTIVE(AArch64CC_LAST_ACTIVE()),	 // (!C)
		NONE_ACTIVE(AArch64CC_NONE_ACTIVE());  // ( Z)

		private final int value;

		private AArch64CondCode(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64CondCode[] fromValue(int value) {
			List<AArch64CondCode> condCodes = new ArrayList<>();
			boolean added = false;
			for (AArch64CondCode condCode : AArch64CondCode.values()) {
				if (condCode.value == value) {
					condCodes.add(condCode);
					added = true;
				}
			}
			if (!added) {
				condCodes.add(AArch64CondCode.Invalid);
			}
			return condCodes.toArray(new AArch64CondCode[0]);
		}
	}

	public enum AArch64VectorLayout {
		INVALID(AARCH64LAYOUT_INVALID()),
		// Bare layout for the 128-bit vector
		// (only show ".b", ".h", ".s", ".d" without vector number)
		B(AARCH64LAYOUT_VL_B()),
		H(AARCH64LAYOUT_VL_H()),
		S(AARCH64LAYOUT_VL_S()),
		D(AARCH64LAYOUT_VL_D()),
		Q(AARCH64LAYOUT_VL_Q()),

		_4B(AARCH64LAYOUT_VL_4B()),
		_2H(AARCH64LAYOUT_VL_2H()),
		_1S(AARCH64LAYOUT_VL_1S()),

		_8B(AARCH64LAYOUT_VL_8B()),
		_4H(AARCH64LAYOUT_VL_4H()),
		_2S(AARCH64LAYOUT_VL_2S()),
		_1D(AARCH64LAYOUT_VL_1D()),

		_16B(AARCH64LAYOUT_VL_16B()),
		_8H(AARCH64LAYOUT_VL_8H()),
		_4S(AARCH64LAYOUT_VL_4S()),
		_2D(AARCH64LAYOUT_VL_2D()),
		_1Q(AARCH64LAYOUT_VL_1Q()),

		_64B(AARCH64LAYOUT_VL_64B()),
		_32H(AARCH64LAYOUT_VL_32H()),
		_16S(AARCH64LAYOUT_VL_16S()),
		_8D(AARCH64LAYOUT_VL_8D()),

		COMPLETE(AARCH64LAYOUT_VL_COMPLETE());

		private final int value;

		private AArch64VectorLayout(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64VectorLayout fromValue(int value) {
			for (AArch64VectorLayout layout : AArch64VectorLayout.values()) {
				if (layout.value == value) {
					return layout;
				}
			}
			return INVALID;
		}
	}

	public enum AArch64Extender {
		INVALID(AARCH64_EXT_INVALID()),
		UXTB(AARCH64_EXT_UXTB()),
		UXTH(AARCH64_EXT_UXTH()),
		UXTW(AARCH64_EXT_UXTW()),
		UXTX(AARCH64_EXT_UXTX()),
		SXTB(AARCH64_EXT_SXTB()),
		SXTH(AARCH64_EXT_SXTH()),
		SXTW(AARCH64_EXT_SXTW()),
		SXTX(AARCH64_EXT_SXTX());

		private final int value;

		private AArch64Extender(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Extender fromValue(int value) {
			for (AArch64Extender extender : AArch64Extender.values()) {
				if (extender.value == value) {
					return extender;
				}
			}
			return INVALID;
		}
	}

	public enum AArch64Shifter {
		INVALID(AARCH64_SFT_INVALID()),
		LSL(AARCH64_SFT_LSL()),
		MSL(AARCH64_SFT_MSL()),
		LSR(AARCH64_SFT_LSR()),
		ASR(AARCH64_SFT_ASR()),
		ROR(AARCH64_SFT_ROR()),
		LSL_REG(AARCH64_SFT_LSL_REG()),
		MSL_REG(AARCH64_SFT_MSL_REG()),
		LSR_REG(AARCH64_SFT_LSR_REG()),
		ASR_REG(AARCH64_SFT_ASR_REG()),
		ROR_REG(AARCH64_SFT_ROR_REG());

		private final int value;

		private AArch64Shifter(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Shifter fromValue(int value) {
			for (AArch64Shifter shifter : AArch64Shifter.values()) {
				if (shifter.value == value) {
					return shifter;
				}
			}
			return INVALID;
		}
	}
	
	static class AArch64Shift {
		private final AArch64Shifter shifter;
		private final long value;

		AArch64Shift(AArch64Shifter shifter, long value) {
			this.shifter = shifter;
			this.value = value;
		}

		public AArch64Shifter getShifter() {
			return shifter;
		}

		public long getValue() {
			return value;
		}
	}

	public enum AArch64OperandType {
		INVALID(CS_OP_INVALID()),
		REG(CS_OP_REG()),
		IMM(CS_OP_IMM()),
		MEM_REG(CS_OP_MEM_REG()),		///< Register which references memory.
		MEM_IMM(CS_OP_MEM_IMM()),		///< = Immediate value which references memory.
		MEM(CS_OP_MEM()),		///< = CS_OP_MEM (Memory operand).
		FP(CS_OP_FP()),		///< = CS_OP_FP (Floating-Point operand).
		CIMM(AARCH64_OP_CIMM()),	///< C-Immediate
		REG_MRS(AARCH64_OP_REG_MRS()),	///< MRS register operand.
		REG_MSR(AARCH64_OP_REG_MSR()),	///< MSR register operand.
		IMPLICIT_IMM_0(AARCH64_OP_IMPLICIT_IMM_0()), ///< Implicit immediate operand 0
		// Different system operands.
		SVCR(AARCH64_OP_SVCR()),
		AT(AARCH64_OP_AT()),
		DB(AARCH64_OP_DB()),
		DC(AARCH64_OP_DC()),
		ISB(AARCH64_OP_ISB()),
		TSB(AARCH64_OP_TSB()),
		PRFM(AARCH64_OP_PRFM()),
		SVEPRFM(AARCH64_OP_SVEPRFM()),
		RPRFM(AARCH64_OP_RPRFM()),
		PSTATEIMM0_15(AARCH64_OP_PSTATEIMM0_15()),
		PSTATEIMM0_1(AARCH64_OP_PSTATEIMM0_1()),
		PSB(AARCH64_OP_PSB()),
		BTI(AARCH64_OP_BTI()),
		SVEPREDPAT(AARCH64_OP_SVEPREDPAT()),
		SVEVECLENSPECIFIER(AARCH64_OP_SVEVECLENSPECIFIER()),
		SME(AARCH64_OP_SME()),
		IMM_RANGE(AARCH64_OP_IMM_RANGE()),
		TLBI(AARCH64_OP_TLBI()),
		IC(AARCH64_OP_IC()),
		DBNXS(AARCH64_OP_DBNXS()),
		EXACTFPIMM(AARCH64_OP_EXACTFPIMM()),
		SYSREG(AARCH64_OP_SYSREG()),
		SYSIMM(AARCH64_OP_SYSIMM()),
		SYSALIAS(AARCH64_OP_SYSALIAS()),
		PRED(AARCH64_OP_PRED());

		private final int value;

		private AArch64OperandType(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64OperandType fromValue(int value) {
			for (AArch64OperandType type : AArch64OperandType.values()) {
				if (type.value == value) {
					return type;
				}
			}
			return INVALID;
		}
	}

	public enum AArch64Reg {
		INVALID(AARCH64_REG_INVALID()),
		FFR(AARCH64_REG_FFR()),
		FP(AARCH64_REG_FP()),
		FPCR(AARCH64_REG_FPCR()),
		LR(AARCH64_REG_LR()),
		NZCV(AARCH64_REG_NZCV()),
		SP(AARCH64_REG_SP()),
		VG(AARCH64_REG_VG()),
		WSP(AARCH64_REG_WSP()),
		WZR(AARCH64_REG_WZR()),
		XZR(AARCH64_REG_XZR()),
		ZA(AARCH64_REG_ZA()),
		B0(AARCH64_REG_B0()),
		B1(AARCH64_REG_B1()),
		B2(AARCH64_REG_B2()),
		B3(AARCH64_REG_B3()),
		B4(AARCH64_REG_B4()),
		B5(AARCH64_REG_B5()),
		B6(AARCH64_REG_B6()),
		B7(AARCH64_REG_B7()),
		B8(AARCH64_REG_B8()),
		B9(AARCH64_REG_B9()),
		B10(AARCH64_REG_B10()),
		B11(AARCH64_REG_B11()),
		B12(AARCH64_REG_B12()),
		B13(AARCH64_REG_B13()),
		B14(AARCH64_REG_B14()),
		B15(AARCH64_REG_B15()),
		B16(AARCH64_REG_B16()),
		B17(AARCH64_REG_B17()),
		B18(AARCH64_REG_B18()),
		B19(AARCH64_REG_B19()),
		B20(AARCH64_REG_B20()),
		B21(AARCH64_REG_B21()),
		B22(AARCH64_REG_B22()),
		B23(AARCH64_REG_B23()),
		B24(AARCH64_REG_B24()),
		B25(AARCH64_REG_B25()),
		B26(AARCH64_REG_B26()),
		B27(AARCH64_REG_B27()),
		B28(AARCH64_REG_B28()),
		B29(AARCH64_REG_B29()),
		B30(AARCH64_REG_B30()),
		B31(AARCH64_REG_B31()),
		D0(AARCH64_REG_D0()),
		D1(AARCH64_REG_D1()),
		D2(AARCH64_REG_D2()),
		D3(AARCH64_REG_D3()),
		D4(AARCH64_REG_D4()),
		D5(AARCH64_REG_D5()),
		D6(AARCH64_REG_D6()),
		D7(AARCH64_REG_D7()),
		D8(AARCH64_REG_D8()),
		D9(AARCH64_REG_D9()),
		D10(AARCH64_REG_D10()),
		D11(AARCH64_REG_D11()),
		D12(AARCH64_REG_D12()),
		D13(AARCH64_REG_D13()),
		D14(AARCH64_REG_D14()),
		D15(AARCH64_REG_D15()),
		D16(AARCH64_REG_D16()),
		D17(AARCH64_REG_D17()),
		D18(AARCH64_REG_D18()),
		D19(AARCH64_REG_D19()),
		D20(AARCH64_REG_D20()),
		D21(AARCH64_REG_D21()),
		D22(AARCH64_REG_D22()),
		D23(AARCH64_REG_D23()),
		D24(AARCH64_REG_D24()),
		D25(AARCH64_REG_D25()),
		D26(AARCH64_REG_D26()),
		D27(AARCH64_REG_D27()),
		D28(AARCH64_REG_D28()),
		D29(AARCH64_REG_D29()),
		D30(AARCH64_REG_D30()),
		D31(AARCH64_REG_D31()),
		H0(AARCH64_REG_H0()),
		H1(AARCH64_REG_H1()),
		H2(AARCH64_REG_H2()),
		H3(AARCH64_REG_H3()),
		H4(AARCH64_REG_H4()),
		H5(AARCH64_REG_H5()),
		H6(AARCH64_REG_H6()),
		H7(AARCH64_REG_H7()),
		H8(AARCH64_REG_H8()),
		H9(AARCH64_REG_H9()),
		H10(AARCH64_REG_H10()),
		H11(AARCH64_REG_H11()),
		H12(AARCH64_REG_H12()),
		H13(AARCH64_REG_H13()),
		H14(AARCH64_REG_H14()),
		H15(AARCH64_REG_H15()),
		H16(AARCH64_REG_H16()),
		H17(AARCH64_REG_H17()),
		H18(AARCH64_REG_H18()),
		H19(AARCH64_REG_H19()),
		H20(AARCH64_REG_H20()),
		H21(AARCH64_REG_H21()),
		H22(AARCH64_REG_H22()),
		H23(AARCH64_REG_H23()),
		H24(AARCH64_REG_H24()),
		H25(AARCH64_REG_H25()),
		H26(AARCH64_REG_H26()),
		H27(AARCH64_REG_H27()),
		H28(AARCH64_REG_H28()),
		H29(AARCH64_REG_H29()),
		H30(AARCH64_REG_H30()),
		H31(AARCH64_REG_H31()),
		P0(AARCH64_REG_P0()),
		P1(AARCH64_REG_P1()),
		P2(AARCH64_REG_P2()),
		P3(AARCH64_REG_P3()),
		P4(AARCH64_REG_P4()),
		P5(AARCH64_REG_P5()),
		P6(AARCH64_REG_P6()),
		P7(AARCH64_REG_P7()),
		P8(AARCH64_REG_P8()),
		P9(AARCH64_REG_P9()),
		P10(AARCH64_REG_P10()),
		P11(AARCH64_REG_P11()),
		P12(AARCH64_REG_P12()),
		P13(AARCH64_REG_P13()),
		P14(AARCH64_REG_P14()),
		P15(AARCH64_REG_P15()),
		PN0(AARCH64_REG_PN0()),
		PN1(AARCH64_REG_PN1()),
		PN2(AARCH64_REG_PN2()),
		PN3(AARCH64_REG_PN3()),
		PN4(AARCH64_REG_PN4()),
		PN5(AARCH64_REG_PN5()),
		PN6(AARCH64_REG_PN6()),
		PN7(AARCH64_REG_PN7()),
		PN8(AARCH64_REG_PN8()),
		PN9(AARCH64_REG_PN9()),
		PN10(AARCH64_REG_PN10()),
		PN11(AARCH64_REG_PN11()),
		PN12(AARCH64_REG_PN12()),
		PN13(AARCH64_REG_PN13()),
		PN14(AARCH64_REG_PN14()),
		PN15(AARCH64_REG_PN15()),
		Q0(AARCH64_REG_Q0()),
		Q1(AARCH64_REG_Q1()),
		Q2(AARCH64_REG_Q2()),
		Q3(AARCH64_REG_Q3()),
		Q4(AARCH64_REG_Q4()),
		Q5(AARCH64_REG_Q5()),
		Q6(AARCH64_REG_Q6()),
		Q7(AARCH64_REG_Q7()),
		Q8(AARCH64_REG_Q8()),
		Q9(AARCH64_REG_Q9()),
		Q10(AARCH64_REG_Q10()),
		Q11(AARCH64_REG_Q11()),
		Q12(AARCH64_REG_Q12()),
		Q13(AARCH64_REG_Q13()),
		Q14(AARCH64_REG_Q14()),
		Q15(AARCH64_REG_Q15()),
		Q16(AARCH64_REG_Q16()),
		Q17(AARCH64_REG_Q17()),
		Q18(AARCH64_REG_Q18()),
		Q19(AARCH64_REG_Q19()),
		Q20(AARCH64_REG_Q20()),
		Q21(AARCH64_REG_Q21()),
		Q22(AARCH64_REG_Q22()),
		Q23(AARCH64_REG_Q23()),
		Q24(AARCH64_REG_Q24()),
		Q25(AARCH64_REG_Q25()),
		Q26(AARCH64_REG_Q26()),
		Q27(AARCH64_REG_Q27()),
		Q28(AARCH64_REG_Q28()),
		Q29(AARCH64_REG_Q29()),
		Q30(AARCH64_REG_Q30()),
		Q31(AARCH64_REG_Q31()),
		S0(AARCH64_REG_S0()),
		S1(AARCH64_REG_S1()),
		S2(AARCH64_REG_S2()),
		S3(AARCH64_REG_S3()),
		S4(AARCH64_REG_S4()),
		S5(AARCH64_REG_S5()),
		S6(AARCH64_REG_S6()),
		S7(AARCH64_REG_S7()),
		S8(AARCH64_REG_S8()),
		S9(AARCH64_REG_S9()),
		S10(AARCH64_REG_S10()),
		S11(AARCH64_REG_S11()),
		S12(AARCH64_REG_S12()),
		S13(AARCH64_REG_S13()),
		S14(AARCH64_REG_S14()),
		S15(AARCH64_REG_S15()),
		S16(AARCH64_REG_S16()),
		S17(AARCH64_REG_S17()),
		S18(AARCH64_REG_S18()),
		S19(AARCH64_REG_S19()),
		S20(AARCH64_REG_S20()),
		S21(AARCH64_REG_S21()),
		S22(AARCH64_REG_S22()),
		S23(AARCH64_REG_S23()),
		S24(AARCH64_REG_S24()),
		S25(AARCH64_REG_S25()),
		S26(AARCH64_REG_S26()),
		S27(AARCH64_REG_S27()),
		S28(AARCH64_REG_S28()),
		S29(AARCH64_REG_S29()),
		S30(AARCH64_REG_S30()),
		S31(AARCH64_REG_S31()),
		W0(AARCH64_REG_W0()),
		W1(AARCH64_REG_W1()),
		W2(AARCH64_REG_W2()),
		W3(AARCH64_REG_W3()),
		W4(AARCH64_REG_W4()),
		W5(AARCH64_REG_W5()),
		W6(AARCH64_REG_W6()),
		W7(AARCH64_REG_W7()),
		W8(AARCH64_REG_W8()),
		W9(AARCH64_REG_W9()),
		W10(AARCH64_REG_W10()),
		W11(AARCH64_REG_W11()),
		W12(AARCH64_REG_W12()),
		W13(AARCH64_REG_W13()),
		W14(AARCH64_REG_W14()),
		W15(AARCH64_REG_W15()),
		W16(AARCH64_REG_W16()),
		W17(AARCH64_REG_W17()),
		W18(AARCH64_REG_W18()),
		W19(AARCH64_REG_W19()),
		W20(AARCH64_REG_W20()),
		W21(AARCH64_REG_W21()),
		W22(AARCH64_REG_W22()),
		W23(AARCH64_REG_W23()),
		W24(AARCH64_REG_W24()),
		W25(AARCH64_REG_W25()),
		W26(AARCH64_REG_W26()),
		W27(AARCH64_REG_W27()),
		W28(AARCH64_REG_W28()),
		W29(AARCH64_REG_W29()),
		W30(AARCH64_REG_W30()),
		X0(AARCH64_REG_X0()),
		X1(AARCH64_REG_X1()),
		X2(AARCH64_REG_X2()),
		X3(AARCH64_REG_X3()),
		X4(AARCH64_REG_X4()),
		X5(AARCH64_REG_X5()),
		X6(AARCH64_REG_X6()),
		X7(AARCH64_REG_X7()),
		X8(AARCH64_REG_X8()),
		X9(AARCH64_REG_X9()),
		X10(AARCH64_REG_X10()),
		X11(AARCH64_REG_X11()),
		X12(AARCH64_REG_X12()),
		X13(AARCH64_REG_X13()),
		X14(AARCH64_REG_X14()),
		X15(AARCH64_REG_X15()),
		X16(AARCH64_REG_X16()),
		X17(AARCH64_REG_X17()),
		X18(AARCH64_REG_X18()),
		X19(AARCH64_REG_X19()),
		X20(AARCH64_REG_X20()),
		X21(AARCH64_REG_X21()),
		X22(AARCH64_REG_X22()),
		X23(AARCH64_REG_X23()),
		X24(AARCH64_REG_X24()),
		X25(AARCH64_REG_X25()),
		X26(AARCH64_REG_X26()),
		X27(AARCH64_REG_X27()),
		X28(AARCH64_REG_X28()),
		Z0(AARCH64_REG_Z0()),
		Z1(AARCH64_REG_Z1()),
		Z2(AARCH64_REG_Z2()),
		Z3(AARCH64_REG_Z3()),
		Z4(AARCH64_REG_Z4()),
		Z5(AARCH64_REG_Z5()),
		Z6(AARCH64_REG_Z6()),
		Z7(AARCH64_REG_Z7()),
		Z8(AARCH64_REG_Z8()),
		Z9(AARCH64_REG_Z9()),
		Z10(AARCH64_REG_Z10()),
		Z11(AARCH64_REG_Z11()),
		Z12(AARCH64_REG_Z12()),
		Z13(AARCH64_REG_Z13()),
		Z14(AARCH64_REG_Z14()),
		Z15(AARCH64_REG_Z15()),
		Z16(AARCH64_REG_Z16()),
		Z17(AARCH64_REG_Z17()),
		Z18(AARCH64_REG_Z18()),
		Z19(AARCH64_REG_Z19()),
		Z20(AARCH64_REG_Z20()),
		Z21(AARCH64_REG_Z21()),
		Z22(AARCH64_REG_Z22()),
		Z23(AARCH64_REG_Z23()),
		Z24(AARCH64_REG_Z24()),
		Z25(AARCH64_REG_Z25()),
		Z26(AARCH64_REG_Z26()),
		Z27(AARCH64_REG_Z27()),
		Z28(AARCH64_REG_Z28()),
		Z29(AARCH64_REG_Z29()),
		Z30(AARCH64_REG_Z30()),
		Z31(AARCH64_REG_Z31()),
		ZAB0(AARCH64_REG_ZAB0()),
		ZAD0(AARCH64_REG_ZAD0()),
		ZAD1(AARCH64_REG_ZAD1()),
		ZAD2(AARCH64_REG_ZAD2()),
		ZAD3(AARCH64_REG_ZAD3()),
		ZAD4(AARCH64_REG_ZAD4()),
		ZAD5(AARCH64_REG_ZAD5()),
		ZAD6(AARCH64_REG_ZAD6()),
		ZAD7(AARCH64_REG_ZAD7()),
		ZAH0(AARCH64_REG_ZAH0()),
		ZAH1(AARCH64_REG_ZAH1()),
		ZAQ0(AARCH64_REG_ZAQ0()),
		ZAQ1(AARCH64_REG_ZAQ1()),
		ZAQ2(AARCH64_REG_ZAQ2()),
		ZAQ3(AARCH64_REG_ZAQ3()),
		ZAQ4(AARCH64_REG_ZAQ4()),
		ZAQ5(AARCH64_REG_ZAQ5()),
		ZAQ6(AARCH64_REG_ZAQ6()),
		ZAQ7(AARCH64_REG_ZAQ7()),
		ZAQ8(AARCH64_REG_ZAQ8()),
		ZAQ9(AARCH64_REG_ZAQ9()),
		ZAQ10(AARCH64_REG_ZAQ10()),
		ZAQ11(AARCH64_REG_ZAQ11()),
		ZAQ12(AARCH64_REG_ZAQ12()),
		ZAQ13(AARCH64_REG_ZAQ13()),
		ZAQ14(AARCH64_REG_ZAQ14()),
		ZAQ15(AARCH64_REG_ZAQ15()),
		ZAS0(AARCH64_REG_ZAS0()),
		ZAS1(AARCH64_REG_ZAS1()),
		ZAS2(AARCH64_REG_ZAS2()),
		ZAS3(AARCH64_REG_ZAS3()),
		ZT0(AARCH64_REG_ZT0()),
		D0_D1(AARCH64_REG_D0_D1()),
		D1_D2(AARCH64_REG_D1_D2()),
		D2_D3(AARCH64_REG_D2_D3()),
		D3_D4(AARCH64_REG_D3_D4()),
		D4_D5(AARCH64_REG_D4_D5()),
		D5_D6(AARCH64_REG_D5_D6()),
		D6_D7(AARCH64_REG_D6_D7()),
		D7_D8(AARCH64_REG_D7_D8()),
		D8_D9(AARCH64_REG_D8_D9()),
		D9_D10(AARCH64_REG_D9_D10()),
		D10_D11(AARCH64_REG_D10_D11()),
		D11_D12(AARCH64_REG_D11_D12()),
		D12_D13(AARCH64_REG_D12_D13()),
		D13_D14(AARCH64_REG_D13_D14()),
		D14_D15(AARCH64_REG_D14_D15()),
		D15_D16(AARCH64_REG_D15_D16()),
		D16_D17(AARCH64_REG_D16_D17()),
		D17_D18(AARCH64_REG_D17_D18()),
		D18_D19(AARCH64_REG_D18_D19()),
		D19_D20(AARCH64_REG_D19_D20()),
		D20_D21(AARCH64_REG_D20_D21()),
		D21_D22(AARCH64_REG_D21_D22()),
		D22_D23(AARCH64_REG_D22_D23()),
		D23_D24(AARCH64_REG_D23_D24()),
		D24_D25(AARCH64_REG_D24_D25()),
		D25_D26(AARCH64_REG_D25_D26()),
		D26_D27(AARCH64_REG_D26_D27()),
		D27_D28(AARCH64_REG_D27_D28()),
		D28_D29(AARCH64_REG_D28_D29()),
		D29_D30(AARCH64_REG_D29_D30()),
		D30_D31(AARCH64_REG_D30_D31()),
		D31_D0(AARCH64_REG_D31_D0()),
		D0_D1_D2_D3(AARCH64_REG_D0_D1_D2_D3()),
		D1_D2_D3_D4(AARCH64_REG_D1_D2_D3_D4()),
		D2_D3_D4_D5(AARCH64_REG_D2_D3_D4_D5()),
		D3_D4_D5_D6(AARCH64_REG_D3_D4_D5_D6()),
		D4_D5_D6_D7(AARCH64_REG_D4_D5_D6_D7()),
		D5_D6_D7_D8(AARCH64_REG_D5_D6_D7_D8()),
		D6_D7_D8_D9(AARCH64_REG_D6_D7_D8_D9()),
		D7_D8_D9_D10(AARCH64_REG_D7_D8_D9_D10()),
		D8_D9_D10_D11(AARCH64_REG_D8_D9_D10_D11()),
		D9_D10_D11_D12(AARCH64_REG_D9_D10_D11_D12()),
		D10_D11_D12_D13(AARCH64_REG_D10_D11_D12_D13()),
		D11_D12_D13_D14(AARCH64_REG_D11_D12_D13_D14()),
		D12_D13_D14_D15(AARCH64_REG_D12_D13_D14_D15()),
		D13_D14_D15_D16(AARCH64_REG_D13_D14_D15_D16()),
		D14_D15_D16_D17(AARCH64_REG_D14_D15_D16_D17()),
		D15_D16_D17_D18(AARCH64_REG_D15_D16_D17_D18()),
		D16_D17_D18_D19(AARCH64_REG_D16_D17_D18_D19()),
		D17_D18_D19_D20(AARCH64_REG_D17_D18_D19_D20()),
		D18_D19_D20_D21(AARCH64_REG_D18_D19_D20_D21()),
		D19_D20_D21_D22(AARCH64_REG_D19_D20_D21_D22()),
		D20_D21_D22_D23(AARCH64_REG_D20_D21_D22_D23()),
		D21_D22_D23_D24(AARCH64_REG_D21_D22_D23_D24()),
		D22_D23_D24_D25(AARCH64_REG_D22_D23_D24_D25()),
		D23_D24_D25_D26(AARCH64_REG_D23_D24_D25_D26()),
		D24_D25_D26_D27(AARCH64_REG_D24_D25_D26_D27()),
		D25_D26_D27_D28(AARCH64_REG_D25_D26_D27_D28()),
		D26_D27_D28_D29(AARCH64_REG_D26_D27_D28_D29()),
		D27_D28_D29_D30(AARCH64_REG_D27_D28_D29_D30()),
		D28_D29_D30_D31(AARCH64_REG_D28_D29_D30_D31()),
		D29_D30_D31_D0(AARCH64_REG_D29_D30_D31_D0()),
		D30_D31_D0_D1(AARCH64_REG_D30_D31_D0_D1()),
		D31_D0_D1_D2(AARCH64_REG_D31_D0_D1_D2()),
		D0_D1_D2(AARCH64_REG_D0_D1_D2()),
		D1_D2_D3(AARCH64_REG_D1_D2_D3()),
		D2_D3_D4(AARCH64_REG_D2_D3_D4()),
		D3_D4_D5(AARCH64_REG_D3_D4_D5()),
		D4_D5_D6(AARCH64_REG_D4_D5_D6()),
		D5_D6_D7(AARCH64_REG_D5_D6_D7()),
		D6_D7_D8(AARCH64_REG_D6_D7_D8()),
		D7_D8_D9(AARCH64_REG_D7_D8_D9()),
		D8_D9_D10(AARCH64_REG_D8_D9_D10()),
		D9_D10_D11(AARCH64_REG_D9_D10_D11()),
		D10_D11_D12(AARCH64_REG_D10_D11_D12()),
		D11_D12_D13(AARCH64_REG_D11_D12_D13()),
		D12_D13_D14(AARCH64_REG_D12_D13_D14()),
		D13_D14_D15(AARCH64_REG_D13_D14_D15()),
		D14_D15_D16(AARCH64_REG_D14_D15_D16()),
		D15_D16_D17(AARCH64_REG_D15_D16_D17()),
		D16_D17_D18(AARCH64_REG_D16_D17_D18()),
		D17_D18_D19(AARCH64_REG_D17_D18_D19()),
		D18_D19_D20(AARCH64_REG_D18_D19_D20()),
		D19_D20_D21(AARCH64_REG_D19_D20_D21()),
		D20_D21_D22(AARCH64_REG_D20_D21_D22()),
		D21_D22_D23(AARCH64_REG_D21_D22_D23()),
		D22_D23_D24(AARCH64_REG_D22_D23_D24()),
		D23_D24_D25(AARCH64_REG_D23_D24_D25()),
		D24_D25_D26(AARCH64_REG_D24_D25_D26()),
		D25_D26_D27(AARCH64_REG_D25_D26_D27()),
		D26_D27_D28(AARCH64_REG_D26_D27_D28()),
		D27_D28_D29(AARCH64_REG_D27_D28_D29()),
		D28_D29_D30(AARCH64_REG_D28_D29_D30()),
		D29_D30_D31(AARCH64_REG_D29_D30_D31()),
		D30_D31_D0(AARCH64_REG_D30_D31_D0()),
		D31_D0_D1(AARCH64_REG_D31_D0_D1()),
		P0_P1(AARCH64_REG_P0_P1()),
		P1_P2(AARCH64_REG_P1_P2()),
		P2_P3(AARCH64_REG_P2_P3()),
		P3_P4(AARCH64_REG_P3_P4()),
		P4_P5(AARCH64_REG_P4_P5()),
		P5_P6(AARCH64_REG_P5_P6()),
		P6_P7(AARCH64_REG_P6_P7()),
		P7_P8(AARCH64_REG_P7_P8()),
		P8_P9(AARCH64_REG_P8_P9()),
		P9_P10(AARCH64_REG_P9_P10()),
		P10_P11(AARCH64_REG_P10_P11()),
		P11_P12(AARCH64_REG_P11_P12()),
		P12_P13(AARCH64_REG_P12_P13()),
		P13_P14(AARCH64_REG_P13_P14()),
		P14_P15(AARCH64_REG_P14_P15()),
		P15_P0(AARCH64_REG_P15_P0()),
		Q0_Q1(AARCH64_REG_Q0_Q1()),
		Q1_Q2(AARCH64_REG_Q1_Q2()),
		Q2_Q3(AARCH64_REG_Q2_Q3()),
		Q3_Q4(AARCH64_REG_Q3_Q4()),
		Q4_Q5(AARCH64_REG_Q4_Q5()),
		Q5_Q6(AARCH64_REG_Q5_Q6()),
		Q6_Q7(AARCH64_REG_Q6_Q7()),
		Q7_Q8(AARCH64_REG_Q7_Q8()),
		Q8_Q9(AARCH64_REG_Q8_Q9()),
		Q9_Q10(AARCH64_REG_Q9_Q10()),
		Q10_Q11(AARCH64_REG_Q10_Q11()),
		Q11_Q12(AARCH64_REG_Q11_Q12()),
		Q12_Q13(AARCH64_REG_Q12_Q13()),
		Q13_Q14(AARCH64_REG_Q13_Q14()),
		Q14_Q15(AARCH64_REG_Q14_Q15()),
		Q15_Q16(AARCH64_REG_Q15_Q16()),
		Q16_Q17(AARCH64_REG_Q16_Q17()),
		Q17_Q18(AARCH64_REG_Q17_Q18()),
		Q18_Q19(AARCH64_REG_Q18_Q19()),
		Q19_Q20(AARCH64_REG_Q19_Q20()),
		Q20_Q21(AARCH64_REG_Q20_Q21()),
		Q21_Q22(AARCH64_REG_Q21_Q22()),
		Q22_Q23(AARCH64_REG_Q22_Q23()),
		Q23_Q24(AARCH64_REG_Q23_Q24()),
		Q24_Q25(AARCH64_REG_Q24_Q25()),
		Q25_Q26(AARCH64_REG_Q25_Q26()),
		Q26_Q27(AARCH64_REG_Q26_Q27()),
		Q27_Q28(AARCH64_REG_Q27_Q28()),
		Q28_Q29(AARCH64_REG_Q28_Q29()),
		Q29_Q30(AARCH64_REG_Q29_Q30()),
		Q30_Q31(AARCH64_REG_Q30_Q31()),
		Q31_Q0(AARCH64_REG_Q31_Q0()),
		Q0_Q1_Q2_Q3(AARCH64_REG_Q0_Q1_Q2_Q3()),
		Q1_Q2_Q3_Q4(AARCH64_REG_Q1_Q2_Q3_Q4()),
		Q2_Q3_Q4_Q5(AARCH64_REG_Q2_Q3_Q4_Q5()),
		Q3_Q4_Q5_Q6(AARCH64_REG_Q3_Q4_Q5_Q6()),
		Q4_Q5_Q6_Q7(AARCH64_REG_Q4_Q5_Q6_Q7()),
		Q5_Q6_Q7_Q8(AARCH64_REG_Q5_Q6_Q7_Q8()),
		Q6_Q7_Q8_Q9(AARCH64_REG_Q6_Q7_Q8_Q9()),
		Q7_Q8_Q9_Q10(AARCH64_REG_Q7_Q8_Q9_Q10()),
		Q8_Q9_Q10_Q11(AARCH64_REG_Q8_Q9_Q10_Q11()),
		Q9_Q10_Q11_Q12(AARCH64_REG_Q9_Q10_Q11_Q12()),
		Q10_Q11_Q12_Q13(AARCH64_REG_Q10_Q11_Q12_Q13()),
		Q11_Q12_Q13_Q14(AARCH64_REG_Q11_Q12_Q13_Q14()),
		Q12_Q13_Q14_Q15(AARCH64_REG_Q12_Q13_Q14_Q15()),
		Q13_Q14_Q15_Q16(AARCH64_REG_Q13_Q14_Q15_Q16()),
		Q14_Q15_Q16_Q17(AARCH64_REG_Q14_Q15_Q16_Q17()),
		Q15_Q16_Q17_Q18(AARCH64_REG_Q15_Q16_Q17_Q18()),
		Q16_Q17_Q18_Q19(AARCH64_REG_Q16_Q17_Q18_Q19()),
		Q17_Q18_Q19_Q20(AARCH64_REG_Q17_Q18_Q19_Q20()),
		Q18_Q19_Q20_Q21(AARCH64_REG_Q18_Q19_Q20_Q21()),
		Q19_Q20_Q21_Q22(AARCH64_REG_Q19_Q20_Q21_Q22()),
		Q20_Q21_Q22_Q23(AARCH64_REG_Q20_Q21_Q22_Q23()),
		Q21_Q22_Q23_Q24(AARCH64_REG_Q21_Q22_Q23_Q24()),
		Q22_Q23_Q24_Q25(AARCH64_REG_Q22_Q23_Q24_Q25()),
		Q23_Q24_Q25_Q26(AARCH64_REG_Q23_Q24_Q25_Q26()),
		Q24_Q25_Q26_Q27(AARCH64_REG_Q24_Q25_Q26_Q27()),
		Q25_Q26_Q27_Q28(AARCH64_REG_Q25_Q26_Q27_Q28()),
		Q26_Q27_Q28_Q29(AARCH64_REG_Q26_Q27_Q28_Q29()),
		Q27_Q28_Q29_Q30(AARCH64_REG_Q27_Q28_Q29_Q30()),
		Q28_Q29_Q30_Q31(AARCH64_REG_Q28_Q29_Q30_Q31()),
		Q29_Q30_Q31_Q0(AARCH64_REG_Q29_Q30_Q31_Q0()),
		Q30_Q31_Q0_Q1(AARCH64_REG_Q30_Q31_Q0_Q1()),
		Q31_Q0_Q1_Q2(AARCH64_REG_Q31_Q0_Q1_Q2()),
		Q0_Q1_Q24(AARCH64_REG_Q0_Q1_Q2()),
		Q1_Q2_Q3(AARCH64_REG_Q1_Q2_Q3()),
		Q2_Q3_Q4(AARCH64_REG_Q2_Q3_Q4()),
		Q3_Q4_Q5(AARCH64_REG_Q3_Q4_Q5()),
		Q4_Q5_Q6(AARCH64_REG_Q4_Q5_Q6()),
		Q5_Q6_Q7(AARCH64_REG_Q5_Q6_Q7()),
		Q6_Q7_Q8(AARCH64_REG_Q6_Q7_Q8()),
		Q7_Q8_Q9(AARCH64_REG_Q7_Q8_Q9()),
		Q8_Q9_Q10(AARCH64_REG_Q8_Q9_Q10()),
		Q9_Q10_Q11(AARCH64_REG_Q9_Q10_Q11()),
		Q10_Q11_Q12(AARCH64_REG_Q10_Q11_Q12()),
		Q11_Q12_Q13(AARCH64_REG_Q11_Q12_Q13()),
		Q12_Q13_Q14(AARCH64_REG_Q12_Q13_Q14()),
		Q13_Q14_Q15(AARCH64_REG_Q13_Q14_Q15()),
		Q14_Q15_Q16(AARCH64_REG_Q14_Q15_Q16()),
		Q15_Q16_Q17(AARCH64_REG_Q15_Q16_Q17()),
		Q16_Q17_Q18(AARCH64_REG_Q16_Q17_Q18()),
		Q17_Q18_Q19(AARCH64_REG_Q17_Q18_Q19()),
		Q18_Q19_Q20(AARCH64_REG_Q18_Q19_Q20()),
		Q19_Q20_Q21(AARCH64_REG_Q19_Q20_Q21()),
		Q20_Q21_Q22(AARCH64_REG_Q20_Q21_Q22()),
		Q21_Q22_Q23(AARCH64_REG_Q21_Q22_Q23()),
		Q22_Q23_Q24(AARCH64_REG_Q22_Q23_Q24()),
		Q23_Q24_Q25(AARCH64_REG_Q23_Q24_Q25()),
		Q24_Q25_Q26(AARCH64_REG_Q24_Q25_Q26()),
		Q25_Q26_Q27(AARCH64_REG_Q25_Q26_Q27()),
		Q26_Q27_Q28(AARCH64_REG_Q26_Q27_Q28()),
		Q27_Q28_Q29(AARCH64_REG_Q27_Q28_Q29()),
		Q28_Q29_Q30(AARCH64_REG_Q28_Q29_Q30()),
		Q29_Q30_Q31(AARCH64_REG_Q29_Q30_Q31()),
		Q30_Q31_Q0(AARCH64_REG_Q30_Q31_Q0()),
		Q31_Q0_Q1(AARCH64_REG_Q31_Q0_Q1()),
		X22_X23_X24_X25_X26_X27_X28_FP(AARCH64_REG_X22_X23_X24_X25_X26_X27_X28_FP()),
		X0_X1_X2_X3_X4_X5_X6_X7(AARCH64_REG_X0_X1_X2_X3_X4_X5_X6_X7()),
		X2_X3_X4_X5_X6_X7_X8_X9(AARCH64_REG_X2_X3_X4_X5_X6_X7_X8_X9()),
		X4_X5_X6_X7_X8_X9_X10_X11(AARCH64_REG_X4_X5_X6_X7_X8_X9_X10_X11()),
		X6_X7_X8_X9_X10_X11_X12_X13(AARCH64_REG_X6_X7_X8_X9_X10_X11_X12_X13()),
		X8_X9_X10_X11_X12_X13_X14_X15(AARCH64_REG_X8_X9_X10_X11_X12_X13_X14_X15()),
		X10_X11_X12_X13_X14_X15_X16_X17(AARCH64_REG_X10_X11_X12_X13_X14_X15_X16_X17()),
		X12_X13_X14_X15_X16_X17_X18_X19(AARCH64_REG_X12_X13_X14_X15_X16_X17_X18_X19()),
		X14_X15_X16_X17_X18_X19_X20_X21(AARCH64_REG_X14_X15_X16_X17_X18_X19_X20_X21()),
		X16_X17_X18_X19_X20_X21_X22_X23(AARCH64_REG_X16_X17_X18_X19_X20_X21_X22_X23()),
		X18_X19_X20_X21_X22_X23_X24_X25(AARCH64_REG_X18_X19_X20_X21_X22_X23_X24_X25()),
		X20_X21_X22_X23_X24_X25_X26_X27(AARCH64_REG_X20_X21_X22_X23_X24_X25_X26_X27()),
		W30_WZR(AARCH64_REG_W30_WZR()),
		W0_W1(AARCH64_REG_W0_W1()),
		W2_W3(AARCH64_REG_W2_W3()),
		W4_W5(AARCH64_REG_W4_W5()),
		W6_W7(AARCH64_REG_W6_W7()),
		W8_W9(AARCH64_REG_W8_W9()),
		W10_W11(AARCH64_REG_W10_W11()),
		W12_W13(AARCH64_REG_W12_W13()),
		W14_W15(AARCH64_REG_W14_W15()),
		W16_W17(AARCH64_REG_W16_W17()),
		W18_W19(AARCH64_REG_W18_W19()),
		W20_W21(AARCH64_REG_W20_W21()),
		W22_W23(AARCH64_REG_W22_W23()),
		W24_W25(AARCH64_REG_W24_W25()),
		W26_W27(AARCH64_REG_W26_W27()),
		W28_W29(AARCH64_REG_W28_W29()),
		LR_XZR(AARCH64_REG_LR_XZR()),
		X28_FP(AARCH64_REG_X28_FP()),
		X0_X1(AARCH64_REG_X0_X1()),
		X2_X3(AARCH64_REG_X2_X3()),
		X4_X5(AARCH64_REG_X4_X5()),
		X6_X7(AARCH64_REG_X6_X7()),
		X8_X9(AARCH64_REG_X8_X9()),
		X10_X11(AARCH64_REG_X10_X11()),
		X12_X13(AARCH64_REG_X12_X13()),
		X14_X15(AARCH64_REG_X14_X15()),
		X16_X17(AARCH64_REG_X16_X17()),
		X18_X19(AARCH64_REG_X18_X19()),
		X20_X21(AARCH64_REG_X20_X21()),
		X22_X23(AARCH64_REG_X22_X23()),
		X24_X25(AARCH64_REG_X24_X25()),
		X26_X27(AARCH64_REG_X26_X27()),
		Z0_Z1(AARCH64_REG_Z0_Z1()),
		Z1_Z2(AARCH64_REG_Z1_Z2()),
		Z2_Z3(AARCH64_REG_Z2_Z3()),
		Z3_Z4(AARCH64_REG_Z3_Z4()),
		Z4_Z5(AARCH64_REG_Z4_Z5()),
		Z5_Z6(AARCH64_REG_Z5_Z6()),
		Z6_Z7(AARCH64_REG_Z6_Z7()),
		Z7_Z8(AARCH64_REG_Z7_Z8()),
		Z8_Z9(AARCH64_REG_Z8_Z9()),
		Z9_Z10(AARCH64_REG_Z9_Z10()),
		Z10_Z11(AARCH64_REG_Z10_Z11()),
		Z11_Z12(AARCH64_REG_Z11_Z12()),
		Z12_Z13(AARCH64_REG_Z12_Z13()),
		Z13_Z14(AARCH64_REG_Z13_Z14()),
		Z14_Z15(AARCH64_REG_Z14_Z15()),
		Z15_Z16(AARCH64_REG_Z15_Z16()),
		Z16_Z17(AARCH64_REG_Z16_Z17()),
		Z17_Z18(AARCH64_REG_Z17_Z18()),
		Z18_Z19(AARCH64_REG_Z18_Z19()),
		Z19_Z20(AARCH64_REG_Z19_Z20()),
		Z20_Z21(AARCH64_REG_Z20_Z21()),
		Z21_Z22(AARCH64_REG_Z21_Z22()),
		Z22_Z23(AARCH64_REG_Z22_Z23()),
		Z23_Z24(AARCH64_REG_Z23_Z24()),
		Z24_Z25(AARCH64_REG_Z24_Z25()),
		Z25_Z26(AARCH64_REG_Z25_Z26()),
		Z26_Z27(AARCH64_REG_Z26_Z27()),
		Z27_Z28(AARCH64_REG_Z27_Z28()),
		Z28_Z29(AARCH64_REG_Z28_Z29()),
		Z29_Z30(AARCH64_REG_Z29_Z30()),
		Z30_Z31(AARCH64_REG_Z30_Z31()),
		Z31_Z0(AARCH64_REG_Z31_Z0()),
		Z0_Z1_Z2_Z3(AARCH64_REG_Z0_Z1_Z2_Z3()),
		Z1_Z2_Z3_Z4(AARCH64_REG_Z1_Z2_Z3_Z4()),
		Z2_Z3_Z4_Z5(AARCH64_REG_Z2_Z3_Z4_Z5()),
		Z3_Z4_Z5_Z6(AARCH64_REG_Z3_Z4_Z5_Z6()),
		Z4_Z5_Z6_Z7(AARCH64_REG_Z4_Z5_Z6_Z7()),
		Z5_Z6_Z7_Z8(AARCH64_REG_Z5_Z6_Z7_Z8()),
		Z6_Z7_Z8_Z9(AARCH64_REG_Z6_Z7_Z8_Z9()),
		Z7_Z8_Z9_Z10(AARCH64_REG_Z7_Z8_Z9_Z10()),
		Z8_Z9_Z10_Z11(AARCH64_REG_Z8_Z9_Z10_Z11()),
		Z9_Z10_Z11_Z12(AARCH64_REG_Z9_Z10_Z11_Z12()),
		Z10_Z11_Z12_Z13(AARCH64_REG_Z10_Z11_Z12_Z13()),
		Z11_Z12_Z13_Z14(AARCH64_REG_Z11_Z12_Z13_Z14()),
		Z12_Z13_Z14_Z15(AARCH64_REG_Z12_Z13_Z14_Z15()),
		Z13_Z14_Z15_Z16(AARCH64_REG_Z13_Z14_Z15_Z16()),
		Z14_Z15_Z16_Z17(AARCH64_REG_Z14_Z15_Z16_Z17()),
		Z15_Z16_Z17_Z18(AARCH64_REG_Z15_Z16_Z17_Z18()),
		Z16_Z17_Z18_Z19(AARCH64_REG_Z16_Z17_Z18_Z19()),
		Z17_Z18_Z19_Z20(AARCH64_REG_Z17_Z18_Z19_Z20()),
		Z18_Z19_Z20_Z21(AARCH64_REG_Z18_Z19_Z20_Z21()),
		Z19_Z20_Z21_Z22(AARCH64_REG_Z19_Z20_Z21_Z22()),
		Z20_Z21_Z22_Z23(AARCH64_REG_Z20_Z21_Z22_Z23()),
		Z21_Z22_Z23_Z24(AARCH64_REG_Z21_Z22_Z23_Z24()),
		Z22_Z23_Z24_Z25(AARCH64_REG_Z22_Z23_Z24_Z25()),
		Z23_Z24_Z25_Z26(AARCH64_REG_Z23_Z24_Z25_Z26()),
		Z24_Z25_Z26_Z27(AARCH64_REG_Z24_Z25_Z26_Z27()),
		Z25_Z26_Z27_Z28(AARCH64_REG_Z25_Z26_Z27_Z28()),
		Z26_Z27_Z28_Z29(AARCH64_REG_Z26_Z27_Z28_Z29()),
		Z27_Z28_Z29_Z30(AARCH64_REG_Z27_Z28_Z29_Z30()),
		Z28_Z29_Z30_Z31(AARCH64_REG_Z28_Z29_Z30_Z31()),
		Z29_Z30_Z31_Z0(AARCH64_REG_Z29_Z30_Z31_Z0()),
		Z30_Z31_Z0_Z1(AARCH64_REG_Z30_Z31_Z0_Z1()),
		Z31_Z0_Z1_Z2(AARCH64_REG_Z31_Z0_Z1_Z2()),
		Z0_Z1_Z2(AARCH64_REG_Z0_Z1_Z2()),
		Z1_Z2_Z3(AARCH64_REG_Z1_Z2_Z3()),
		Z2_Z3_Z4(AARCH64_REG_Z2_Z3_Z4()),
		Z3_Z4_Z5(AARCH64_REG_Z3_Z4_Z5()),
		Z4_Z5_Z6(AARCH64_REG_Z4_Z5_Z6()),
		Z5_Z6_Z7(AARCH64_REG_Z5_Z6_Z7()),
		Z6_Z7_Z8(AARCH64_REG_Z6_Z7_Z8()),
		Z7_Z8_Z9(AARCH64_REG_Z7_Z8_Z9()),
		Z8_Z9_Z10(AARCH64_REG_Z8_Z9_Z10()),
		Z9_Z10_Z11(AARCH64_REG_Z9_Z10_Z11()),
		Z10_Z11_Z12(AARCH64_REG_Z10_Z11_Z12()),
		Z11_Z12_Z13(AARCH64_REG_Z11_Z12_Z13()),
		Z12_Z13_Z14(AARCH64_REG_Z12_Z13_Z14()),
		Z13_Z14_Z15(AARCH64_REG_Z13_Z14_Z15()),
		Z14_Z15_Z16(AARCH64_REG_Z14_Z15_Z16()),
		Z15_Z16_Z17(AARCH64_REG_Z15_Z16_Z17()),
		Z16_Z17_Z18(AARCH64_REG_Z16_Z17_Z18()),
		Z17_Z18_Z19(AARCH64_REG_Z17_Z18_Z19()),
		Z18_Z19_Z20(AARCH64_REG_Z18_Z19_Z20()),
		Z19_Z20_Z21(AARCH64_REG_Z19_Z20_Z21()),
		Z20_Z21_Z22(AARCH64_REG_Z20_Z21_Z22()),
		Z21_Z22_Z23(AARCH64_REG_Z21_Z22_Z23()),
		Z22_Z23_Z24(AARCH64_REG_Z22_Z23_Z24()),
		Z23_Z24_Z25(AARCH64_REG_Z23_Z24_Z25()),
		Z24_Z25_Z26(AARCH64_REG_Z24_Z25_Z26()),
		Z25_Z26_Z27(AARCH64_REG_Z25_Z26_Z27()),
		Z26_Z27_Z28(AARCH64_REG_Z26_Z27_Z28()),
		Z27_Z28_Z29(AARCH64_REG_Z27_Z28_Z29()),
		Z28_Z29_Z30(AARCH64_REG_Z28_Z29_Z30()),
		Z29_Z30_Z31(AARCH64_REG_Z29_Z30_Z31()),
		Z30_Z31_Z0(AARCH64_REG_Z30_Z31_Z0()),
		Z31_Z0_Z1(AARCH64_REG_Z31_Z0_Z1()),
		Z16_Z24(AARCH64_REG_Z16_Z24()),
		Z17_Z25(AARCH64_REG_Z17_Z25()),
		Z18_Z26(AARCH64_REG_Z18_Z26()),
		Z19_Z27(AARCH64_REG_Z19_Z27()),
		Z20_Z28(AARCH64_REG_Z20_Z28()),
		Z21_Z29(AARCH64_REG_Z21_Z29()),
		Z22_Z30(AARCH64_REG_Z22_Z30()),
		Z23_Z31(AARCH64_REG_Z23_Z31()),
		Z0_Z8(AARCH64_REG_Z0_Z8()),
		Z1_Z9(AARCH64_REG_Z1_Z9()),
		Z2_Z10(AARCH64_REG_Z2_Z10()),
		Z3_Z11(AARCH64_REG_Z3_Z11()),
		Z4_Z12(AARCH64_REG_Z4_Z12()),
		Z5_Z13(AARCH64_REG_Z5_Z13()),
		Z6_Z14(AARCH64_REG_Z6_Z14()),
		Z7_Z15(AARCH64_REG_Z7_Z15()),
		Z16_Z20_Z24_Z28(AARCH64_REG_Z16_Z20_Z24_Z28()),
		Z17_Z21_Z25_Z29(AARCH64_REG_Z17_Z21_Z25_Z29()),
		Z18_Z22_Z26_Z30(AARCH64_REG_Z18_Z22_Z26_Z30()),
		Z19_Z23_Z27_Z31(AARCH64_REG_Z19_Z23_Z27_Z31()),
		Z0_Z4_Z8_Z12(AARCH64_REG_Z0_Z4_Z8_Z12()),
		Z1_Z5_Z9_Z13(AARCH64_REG_Z1_Z5_Z9_Z13()),
		Z2_Z6_Z10_Z14(AARCH64_REG_Z2_Z6_Z10_Z14()),
		Z3_Z7_Z11_Z15(AARCH64_REG_Z3_Z7_Z11_Z15()),
		ENDING(AARCH64_REG_ENDING()),

		// clang-format on
		// generated content <AArch64GenCSRegEnum.inc> end

		// alias registers
		IP0(AARCH64_REG_IP0()),
		IP1(AARCH64_REG_IP1()),
		X29(AARCH64_REG_X29()),
		X30(AARCH64_REG_X30());

		private final int value;

		private AArch64Reg(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Reg[] fromValue(int value) {
			List<AArch64Reg> regs = new ArrayList<>();
			boolean added = false;
			for (AArch64Reg reg : AArch64Reg.values()) {
				if (reg.value == value) {
					regs.add(reg);
					added = true;
				}
			}
			if (!added) {
				regs.add(AArch64Reg.INVALID);
			}
			return regs.toArray(new AArch64Reg[0]);
		}
	}

	static class AArch64ImmRange {
		private final int first;
		private final int offset;

		AArch64ImmRange(int first, int offset) {
			this.first = first;
			this.offset = offset;
		}

		public int getFirst() {
			return first;
		}

		public int getOffset() {
			return offset;
		}
	}

	static class AArch64OpMem {
		private final AArch64Reg[] base;
		private final AArch64Reg[] index;
		private final int disp;

		AArch64OpMem(AArch64Reg[] base, AArch64Reg[] index, int disp) {
			this.base = base;
			this.index = index;
			this.disp = disp;
		}

		public AArch64Reg[] getBase() {
			return base;
		}

		public AArch64Reg[] getIndex() {
			return index;
		}

		public int getDisp() {
			return disp;
		}
	}

	public enum AArch64SmeOpType {
		INVALID(AARCH64_SME_OP_INVALID()),
		TILE(AARCH64_SME_OP_TILE()),
		TILE_VEC(AARCH64_SME_OP_TILE_VEC());

		private final int value;

		private AArch64SmeOpType(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64SmeOpType fromValue(int value) {
			for (AArch64SmeOpType type : AArch64SmeOpType.values()) {
				if (type.value == value) {
					return type;
				}
			}
			return INVALID;
		}
	}

	static class AArch64OpSme {
		private final AArch64SmeOpType type;
		private final AArch64Reg[] tile;
		private final AArch64Reg[] sliceReg;
		private final int imm;
		private final AArch64ImmRange immRange;
		private final boolean hasRangeOffset;
		private final boolean isVertical;

		AArch64OpSme(AArch64SmeOpType type, AArch64Reg[] tile, AArch64Reg[] sliceReg, int imm, AArch64ImmRange immRange, boolean hasRangeOffset, boolean isVertical) {
			this.type = type;
			this.tile = tile;
			this.sliceReg = sliceReg;
			this.imm = imm;
			this.immRange = immRange;
			this.hasRangeOffset = hasRangeOffset;
			this.isVertical = isVertical;
		}

		public AArch64SmeOpType getType() {
			return type;
		}

		public AArch64Reg[] getTile() {
			return tile;
		}

		public AArch64Reg[] getSliceReg() {
			return sliceReg;
		}

		public int getImm() {
			return imm;
		}

		public AArch64ImmRange getImmRange() {
			return immRange;
		}

		public boolean hasRangeOffset() {
			return hasRangeOffset;
		}

		public boolean isVertical() {
			return isVertical;
		}
	}

	static class AArch64Pred {
		private final AArch64Reg[] reg;
		private final AArch64Reg[] vecSelect;
		private final int immIndex;

		AArch64Pred(AArch64Reg[] reg, AArch64Reg[] vecSelect, int immIndex) {
			this.reg = reg;
			this.vecSelect = vecSelect;
			this.immIndex = immIndex;
		}

		public AArch64Reg[] getReg() {
			return reg;
		}

		public AArch64Reg[] getVecSelect() {
			return vecSelect;
		}

		public int getImmIndex() {
			return immIndex;
		}
	}

	public enum AArch64SysReg {
		INVALID(AARCH64_SYSREG_INVALID()),
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SysReg> begin
		// clang-format off

		ACCDATA_EL1(AARCH64_SYSREG_ACCDATA_EL1()),
		ACTLR_EL1(AARCH64_SYSREG_ACTLR_EL1()),
		ACTLR_EL2(AARCH64_SYSREG_ACTLR_EL2()),
		ACTLR_EL3(AARCH64_SYSREG_ACTLR_EL3()),
		AFSR0_EL1(AARCH64_SYSREG_AFSR0_EL1()),
		AFSR0_EL12(AARCH64_SYSREG_AFSR0_EL12()),
		AFSR0_EL2(AARCH64_SYSREG_AFSR0_EL2()),
		AFSR0_EL3(AARCH64_SYSREG_AFSR0_EL3()),
		AFSR1_EL1(AARCH64_SYSREG_AFSR1_EL1()),
		AFSR1_EL12(AARCH64_SYSREG_AFSR1_EL12()),
		AFSR1_EL2(AARCH64_SYSREG_AFSR1_EL2()),
		AFSR1_EL3(AARCH64_SYSREG_AFSR1_EL3()),
		AIDR_EL1(AARCH64_SYSREG_AIDR_EL1()),
		ALLINT(AARCH64_SYSREG_ALLINT()),
		AMAIR2_EL1(AARCH64_SYSREG_AMAIR2_EL1()),
		AMAIR2_EL12(AARCH64_SYSREG_AMAIR2_EL12()),
		AMAIR2_EL2(AARCH64_SYSREG_AMAIR2_EL2()),
		AMAIR2_EL3(AARCH64_SYSREG_AMAIR2_EL3()),
		AMAIR_EL1(AARCH64_SYSREG_AMAIR_EL1()),
		AMAIR_EL12(AARCH64_SYSREG_AMAIR_EL12()),
		AMAIR_EL2(AARCH64_SYSREG_AMAIR_EL2()),
		AMAIR_EL3(AARCH64_SYSREG_AMAIR_EL3()),
		AMCFGR_EL0(AARCH64_SYSREG_AMCFGR_EL0()),
		AMCG1IDR_EL0(AARCH64_SYSREG_AMCG1IDR_EL0()),
		AMCGCR_EL0(AARCH64_SYSREG_AMCGCR_EL0()),
		AMCNTENCLR0_EL0(AARCH64_SYSREG_AMCNTENCLR0_EL0()),
		AMCNTENCLR1_EL0(AARCH64_SYSREG_AMCNTENCLR1_EL0()),
		AMCNTENSET0_EL0(AARCH64_SYSREG_AMCNTENSET0_EL0()),
		AMCNTENSET1_EL0(AARCH64_SYSREG_AMCNTENSET1_EL0()),
		AMCR_EL0(AARCH64_SYSREG_AMCR_EL0()),
		AMEVCNTR00_EL0(AARCH64_SYSREG_AMEVCNTR00_EL0()),
		AMEVCNTR01_EL0(AARCH64_SYSREG_AMEVCNTR01_EL0()),
		AMEVCNTR02_EL0(AARCH64_SYSREG_AMEVCNTR02_EL0()),
		AMEVCNTR03_EL0(AARCH64_SYSREG_AMEVCNTR03_EL0()),
		AMEVCNTR10_EL0(AARCH64_SYSREG_AMEVCNTR10_EL0()),
		AMEVCNTR110_EL0(AARCH64_SYSREG_AMEVCNTR110_EL0()),
		AMEVCNTR111_EL0(AARCH64_SYSREG_AMEVCNTR111_EL0()),
		AMEVCNTR112_EL0(AARCH64_SYSREG_AMEVCNTR112_EL0()),
		AMEVCNTR113_EL0(AARCH64_SYSREG_AMEVCNTR113_EL0()),
		AMEVCNTR114_EL0(AARCH64_SYSREG_AMEVCNTR114_EL0()),
		AMEVCNTR115_EL0(AARCH64_SYSREG_AMEVCNTR115_EL0()),
		AMEVCNTR11_EL0(AARCH64_SYSREG_AMEVCNTR11_EL0()),
		AMEVCNTR12_EL0(AARCH64_SYSREG_AMEVCNTR12_EL0()),
		AMEVCNTR13_EL0(AARCH64_SYSREG_AMEVCNTR13_EL0()),
		AMEVCNTR14_EL0(AARCH64_SYSREG_AMEVCNTR14_EL0()),
		AMEVCNTR15_EL0(AARCH64_SYSREG_AMEVCNTR15_EL0()),
		AMEVCNTR16_EL0(AARCH64_SYSREG_AMEVCNTR16_EL0()),
		AMEVCNTR17_EL0(AARCH64_SYSREG_AMEVCNTR17_EL0()),
		AMEVCNTR18_EL0(AARCH64_SYSREG_AMEVCNTR18_EL0()),
		AMEVCNTR19_EL0(AARCH64_SYSREG_AMEVCNTR19_EL0()),
		AMEVCNTVOFF00_EL2(AARCH64_SYSREG_AMEVCNTVOFF00_EL2()),
		AMEVCNTVOFF010_EL2(AARCH64_SYSREG_AMEVCNTVOFF010_EL2()),
		AMEVCNTVOFF011_EL2(AARCH64_SYSREG_AMEVCNTVOFF011_EL2()),
		AMEVCNTVOFF012_EL2(AARCH64_SYSREG_AMEVCNTVOFF012_EL2()),
		AMEVCNTVOFF013_EL2(AARCH64_SYSREG_AMEVCNTVOFF013_EL2()),
		AMEVCNTVOFF014_EL2(AARCH64_SYSREG_AMEVCNTVOFF014_EL2()),
		AMEVCNTVOFF015_EL2(AARCH64_SYSREG_AMEVCNTVOFF015_EL2()),
		AMEVCNTVOFF01_EL2(AARCH64_SYSREG_AMEVCNTVOFF01_EL2()),
		AMEVCNTVOFF02_EL2(AARCH64_SYSREG_AMEVCNTVOFF02_EL2()),
		AMEVCNTVOFF03_EL2(AARCH64_SYSREG_AMEVCNTVOFF03_EL2()),
		AMEVCNTVOFF04_EL2(AARCH64_SYSREG_AMEVCNTVOFF04_EL2()),
		AMEVCNTVOFF05_EL2(AARCH64_SYSREG_AMEVCNTVOFF05_EL2()),
		AMEVCNTVOFF06_EL2(AARCH64_SYSREG_AMEVCNTVOFF06_EL2()),
		AMEVCNTVOFF07_EL2(AARCH64_SYSREG_AMEVCNTVOFF07_EL2()),
		AMEVCNTVOFF08_EL2(AARCH64_SYSREG_AMEVCNTVOFF08_EL2()),
		AMEVCNTVOFF09_EL2(AARCH64_SYSREG_AMEVCNTVOFF09_EL2()),
		AMEVCNTVOFF10_EL2(AARCH64_SYSREG_AMEVCNTVOFF10_EL2()),
		AMEVCNTVOFF110_EL2(AARCH64_SYSREG_AMEVCNTVOFF110_EL2()),
		AMEVCNTVOFF111_EL2(AARCH64_SYSREG_AMEVCNTVOFF111_EL2()),
		AMEVCNTVOFF112_EL2(AARCH64_SYSREG_AMEVCNTVOFF112_EL2()),
		AMEVCNTVOFF113_EL2(AARCH64_SYSREG_AMEVCNTVOFF113_EL2()),
		AMEVCNTVOFF114_EL2(AARCH64_SYSREG_AMEVCNTVOFF114_EL2()),
		AMEVCNTVOFF115_EL2(AARCH64_SYSREG_AMEVCNTVOFF115_EL2()),
		AMEVCNTVOFF11_EL2(AARCH64_SYSREG_AMEVCNTVOFF11_EL2()),
		AMEVCNTVOFF12_EL2(AARCH64_SYSREG_AMEVCNTVOFF12_EL2()),
		AMEVCNTVOFF13_EL2(AARCH64_SYSREG_AMEVCNTVOFF13_EL2()),
		AMEVCNTVOFF14_EL2(AARCH64_SYSREG_AMEVCNTVOFF14_EL2()),
		AMEVCNTVOFF15_EL2(AARCH64_SYSREG_AMEVCNTVOFF15_EL2()),
		AMEVCNTVOFF16_EL2(AARCH64_SYSREG_AMEVCNTVOFF16_EL2()),
		AMEVCNTVOFF17_EL2(AARCH64_SYSREG_AMEVCNTVOFF17_EL2()),
		AMEVCNTVOFF18_EL2(AARCH64_SYSREG_AMEVCNTVOFF18_EL2()),
		AMEVCNTVOFF19_EL2(AARCH64_SYSREG_AMEVCNTVOFF19_EL2()),
		AMEVTYPER00_EL0(AARCH64_SYSREG_AMEVTYPER00_EL0()),
		AMEVTYPER01_EL0(AARCH64_SYSREG_AMEVTYPER01_EL0()),
		AMEVTYPER02_EL0(AARCH64_SYSREG_AMEVTYPER02_EL0()),
		AMEVTYPER03_EL0(AARCH64_SYSREG_AMEVTYPER03_EL0()),
		AMEVTYPER10_EL0(AARCH64_SYSREG_AMEVTYPER10_EL0()),
		AMEVTYPER110_EL0(AARCH64_SYSREG_AMEVTYPER110_EL0()),
		AMEVTYPER111_EL0(AARCH64_SYSREG_AMEVTYPER111_EL0()),
		AMEVTYPER112_EL0(AARCH64_SYSREG_AMEVTYPER112_EL0()),
		AMEVTYPER113_EL0(AARCH64_SYSREG_AMEVTYPER113_EL0()),
		AMEVTYPER114_EL0(AARCH64_SYSREG_AMEVTYPER114_EL0()),
		AMEVTYPER115_EL0(AARCH64_SYSREG_AMEVTYPER115_EL0()),
		AMEVTYPER11_EL0(AARCH64_SYSREG_AMEVTYPER11_EL0()),
		AMEVTYPER12_EL0(AARCH64_SYSREG_AMEVTYPER12_EL0()),
		AMEVTYPER13_EL0(AARCH64_SYSREG_AMEVTYPER13_EL0()),
		AMEVTYPER14_EL0(AARCH64_SYSREG_AMEVTYPER14_EL0()),
		AMEVTYPER15_EL0(AARCH64_SYSREG_AMEVTYPER15_EL0()),
		AMEVTYPER16_EL0(AARCH64_SYSREG_AMEVTYPER16_EL0()),
		AMEVTYPER17_EL0(AARCH64_SYSREG_AMEVTYPER17_EL0()),
		AMEVTYPER18_EL0(AARCH64_SYSREG_AMEVTYPER18_EL0()),
		AMEVTYPER19_EL0(AARCH64_SYSREG_AMEVTYPER19_EL0()),
		AMUSERENR_EL0(AARCH64_SYSREG_AMUSERENR_EL0()),
		APDAKEYHI_EL1(AARCH64_SYSREG_APDAKEYHI_EL1()),
		APDAKEYLO_EL1(AARCH64_SYSREG_APDAKEYLO_EL1()),
		APDBKEYHI_EL1(AARCH64_SYSREG_APDBKEYHI_EL1()),
		APDBKEYLO_EL1(AARCH64_SYSREG_APDBKEYLO_EL1()),
		APGAKEYHI_EL1(AARCH64_SYSREG_APGAKEYHI_EL1()),
		APGAKEYLO_EL1(AARCH64_SYSREG_APGAKEYLO_EL1()),
		APIAKEYHI_EL1(AARCH64_SYSREG_APIAKEYHI_EL1()),
		APIAKEYLO_EL1(AARCH64_SYSREG_APIAKEYLO_EL1()),
		APIBKEYHI_EL1(AARCH64_SYSREG_APIBKEYHI_EL1()),
		APIBKEYLO_EL1(AARCH64_SYSREG_APIBKEYLO_EL1()),
		BRBCR_EL1(AARCH64_SYSREG_BRBCR_EL1()),
		BRBCR_EL12(AARCH64_SYSREG_BRBCR_EL12()),
		BRBCR_EL2(AARCH64_SYSREG_BRBCR_EL2()),
		BRBFCR_EL1(AARCH64_SYSREG_BRBFCR_EL1()),
		BRBIDR0_EL1(AARCH64_SYSREG_BRBIDR0_EL1()),
		BRBINF0_EL1(AARCH64_SYSREG_BRBINF0_EL1()),
		BRBINF10_EL1(AARCH64_SYSREG_BRBINF10_EL1()),
		BRBINF11_EL1(AARCH64_SYSREG_BRBINF11_EL1()),
		BRBINF12_EL1(AARCH64_SYSREG_BRBINF12_EL1()),
		BRBINF13_EL1(AARCH64_SYSREG_BRBINF13_EL1()),
		BRBINF14_EL1(AARCH64_SYSREG_BRBINF14_EL1()),
		BRBINF15_EL1(AARCH64_SYSREG_BRBINF15_EL1()),
		BRBINF16_EL1(AARCH64_SYSREG_BRBINF16_EL1()),
		BRBINF17_EL1(AARCH64_SYSREG_BRBINF17_EL1()),
		BRBINF18_EL1(AARCH64_SYSREG_BRBINF18_EL1()),
		BRBINF19_EL1(AARCH64_SYSREG_BRBINF19_EL1()),
		BRBINF1_EL1(AARCH64_SYSREG_BRBINF1_EL1()),
		BRBINF20_EL1(AARCH64_SYSREG_BRBINF20_EL1()),
		BRBINF21_EL1(AARCH64_SYSREG_BRBINF21_EL1()),
		BRBINF22_EL1(AARCH64_SYSREG_BRBINF22_EL1()),
		BRBINF23_EL1(AARCH64_SYSREG_BRBINF23_EL1()),
		BRBINF24_EL1(AARCH64_SYSREG_BRBINF24_EL1()),
		BRBINF25_EL1(AARCH64_SYSREG_BRBINF25_EL1()),
		BRBINF26_EL1(AARCH64_SYSREG_BRBINF26_EL1()),
		BRBINF27_EL1(AARCH64_SYSREG_BRBINF27_EL1()),
		BRBINF28_EL1(AARCH64_SYSREG_BRBINF28_EL1()),
		BRBINF29_EL1(AARCH64_SYSREG_BRBINF29_EL1()),
		BRBINF2_EL1(AARCH64_SYSREG_BRBINF2_EL1()),
		BRBINF30_EL1(AARCH64_SYSREG_BRBINF30_EL1()),
		BRBINF31_EL1(AARCH64_SYSREG_BRBINF31_EL1()),
		BRBINF3_EL1(AARCH64_SYSREG_BRBINF3_EL1()),
		BRBINF4_EL1(AARCH64_SYSREG_BRBINF4_EL1()),
		BRBINF5_EL1(AARCH64_SYSREG_BRBINF5_EL1()),
		BRBINF6_EL1(AARCH64_SYSREG_BRBINF6_EL1()),
		BRBINF7_EL1(AARCH64_SYSREG_BRBINF7_EL1()),
		BRBINF8_EL1(AARCH64_SYSREG_BRBINF8_EL1()),
		BRBINF9_EL1(AARCH64_SYSREG_BRBINF9_EL1()),
		BRBINFINJ_EL1(AARCH64_SYSREG_BRBINFINJ_EL1()),
		BRBSRC0_EL1(AARCH64_SYSREG_BRBSRC0_EL1()),
		BRBSRC10_EL1(AARCH64_SYSREG_BRBSRC10_EL1()),
		BRBSRC11_EL1(AARCH64_SYSREG_BRBSRC11_EL1()),
		BRBSRC12_EL1(AARCH64_SYSREG_BRBSRC12_EL1()),
		BRBSRC13_EL1(AARCH64_SYSREG_BRBSRC13_EL1()),
		BRBSRC14_EL1(AARCH64_SYSREG_BRBSRC14_EL1()),
		BRBSRC15_EL1(AARCH64_SYSREG_BRBSRC15_EL1()),
		BRBSRC16_EL1(AARCH64_SYSREG_BRBSRC16_EL1()),
		BRBSRC17_EL1(AARCH64_SYSREG_BRBSRC17_EL1()),
		BRBSRC18_EL1(AARCH64_SYSREG_BRBSRC18_EL1()),
		BRBSRC19_EL1(AARCH64_SYSREG_BRBSRC19_EL1()),
		BRBSRC1_EL1(AARCH64_SYSREG_BRBSRC1_EL1()),
		BRBSRC20_EL1(AARCH64_SYSREG_BRBSRC20_EL1()),
		BRBSRC21_EL1(AARCH64_SYSREG_BRBSRC21_EL1()),
		BRBSRC22_EL1(AARCH64_SYSREG_BRBSRC22_EL1()),
		BRBSRC23_EL1(AARCH64_SYSREG_BRBSRC23_EL1()),
		BRBSRC24_EL1(AARCH64_SYSREG_BRBSRC24_EL1()),
		BRBSRC25_EL1(AARCH64_SYSREG_BRBSRC25_EL1()),
		BRBSRC26_EL1(AARCH64_SYSREG_BRBSRC26_EL1()),
		BRBSRC27_EL1(AARCH64_SYSREG_BRBSRC27_EL1()),
		BRBSRC28_EL1(AARCH64_SYSREG_BRBSRC28_EL1()),
		BRBSRC29_EL1(AARCH64_SYSREG_BRBSRC29_EL1()),
		BRBSRC2_EL1(AARCH64_SYSREG_BRBSRC2_EL1()),
		BRBSRC30_EL1(AARCH64_SYSREG_BRBSRC30_EL1()),
		BRBSRC31_EL1(AARCH64_SYSREG_BRBSRC31_EL1()),
		BRBSRC3_EL1(AARCH64_SYSREG_BRBSRC3_EL1()),
		BRBSRC4_EL1(AARCH64_SYSREG_BRBSRC4_EL1()),
		BRBSRC5_EL1(AARCH64_SYSREG_BRBSRC5_EL1()),
		BRBSRC6_EL1(AARCH64_SYSREG_BRBSRC6_EL1()),
		BRBSRC7_EL1(AARCH64_SYSREG_BRBSRC7_EL1()),
		BRBSRC8_EL1(AARCH64_SYSREG_BRBSRC8_EL1()),
		BRBSRC9_EL1(AARCH64_SYSREG_BRBSRC9_EL1()),
		BRBSRCINJ_EL1(AARCH64_SYSREG_BRBSRCINJ_EL1()),
		BRBTGT0_EL1(AARCH64_SYSREG_BRBTGT0_EL1()),
		BRBTGT10_EL1(AARCH64_SYSREG_BRBTGT10_EL1()),
		BRBTGT11_EL1(AARCH64_SYSREG_BRBTGT11_EL1()),
		BRBTGT12_EL1(AARCH64_SYSREG_BRBTGT12_EL1()),
		BRBTGT13_EL1(AARCH64_SYSREG_BRBTGT13_EL1()),
		BRBTGT14_EL1(AARCH64_SYSREG_BRBTGT14_EL1()),
		BRBTGT15_EL1(AARCH64_SYSREG_BRBTGT15_EL1()),
		BRBTGT16_EL1(AARCH64_SYSREG_BRBTGT16_EL1()),
		BRBTGT17_EL1(AARCH64_SYSREG_BRBTGT17_EL1()),
		BRBTGT18_EL1(AARCH64_SYSREG_BRBTGT18_EL1()),
		BRBTGT19_EL1(AARCH64_SYSREG_BRBTGT19_EL1()),
		BRBTGT1_EL1(AARCH64_SYSREG_BRBTGT1_EL1()),
		BRBTGT20_EL1(AARCH64_SYSREG_BRBTGT20_EL1()),
		BRBTGT21_EL1(AARCH64_SYSREG_BRBTGT21_EL1()),
		BRBTGT22_EL1(AARCH64_SYSREG_BRBTGT22_EL1()),
		BRBTGT23_EL1(AARCH64_SYSREG_BRBTGT23_EL1()),
		BRBTGT24_EL1(AARCH64_SYSREG_BRBTGT24_EL1()),
		BRBTGT25_EL1(AARCH64_SYSREG_BRBTGT25_EL1()),
		BRBTGT26_EL1(AARCH64_SYSREG_BRBTGT26_EL1()),
		BRBTGT27_EL1(AARCH64_SYSREG_BRBTGT27_EL1()),
		BRBTGT28_EL1(AARCH64_SYSREG_BRBTGT28_EL1()),
		BRBTGT29_EL1(AARCH64_SYSREG_BRBTGT29_EL1()),
		BRBTGT2_EL1(AARCH64_SYSREG_BRBTGT2_EL1()),
		BRBTGT30_EL1(AARCH64_SYSREG_BRBTGT30_EL1()),
		BRBTGT31_EL1(AARCH64_SYSREG_BRBTGT31_EL1()),
		BRBTGT3_EL1(AARCH64_SYSREG_BRBTGT3_EL1()),
		BRBTGT4_EL1(AARCH64_SYSREG_BRBTGT4_EL1()),
		BRBTGT5_EL1(AARCH64_SYSREG_BRBTGT5_EL1()),
		BRBTGT6_EL1(AARCH64_SYSREG_BRBTGT6_EL1()),
		BRBTGT7_EL1(AARCH64_SYSREG_BRBTGT7_EL1()),
		BRBTGT8_EL1(AARCH64_SYSREG_BRBTGT8_EL1()),
		BRBTGT9_EL1(AARCH64_SYSREG_BRBTGT9_EL1()),
		BRBTGTINJ_EL1(AARCH64_SYSREG_BRBTGTINJ_EL1()),
		BRBTS_EL1(AARCH64_SYSREG_BRBTS_EL1()),
		CCSIDR2_EL1(AARCH64_SYSREG_CCSIDR2_EL1()),
		CCSIDR_EL1(AARCH64_SYSREG_CCSIDR_EL1()),
		CLIDR_EL1(AARCH64_SYSREG_CLIDR_EL1()),
		CNTFRQ_EL0(AARCH64_SYSREG_CNTFRQ_EL0()),
		CNTHCTL_EL2(AARCH64_SYSREG_CNTHCTL_EL2()),
		CNTHPS_CTL_EL2(AARCH64_SYSREG_CNTHPS_CTL_EL2()),
		CNTHPS_CVAL_EL2(AARCH64_SYSREG_CNTHPS_CVAL_EL2()),
		CNTHPS_TVAL_EL2(AARCH64_SYSREG_CNTHPS_TVAL_EL2()),
		CNTHP_CTL_EL2(AARCH64_SYSREG_CNTHP_CTL_EL2()),
		CNTHP_CVAL_EL2(AARCH64_SYSREG_CNTHP_CVAL_EL2()),
		CNTHP_TVAL_EL2(AARCH64_SYSREG_CNTHP_TVAL_EL2()),
		CNTHVS_CTL_EL2(AARCH64_SYSREG_CNTHVS_CTL_EL2()),
		CNTHVS_CVAL_EL2(AARCH64_SYSREG_CNTHVS_CVAL_EL2()),
		CNTHVS_TVAL_EL2(AARCH64_SYSREG_CNTHVS_TVAL_EL2()),
		CNTHV_CTL_EL2(AARCH64_SYSREG_CNTHV_CTL_EL2()),
		CNTHV_CVAL_EL2(AARCH64_SYSREG_CNTHV_CVAL_EL2()),
		CNTHV_TVAL_EL2(AARCH64_SYSREG_CNTHV_TVAL_EL2()),
		CNTISCALE_EL2(AARCH64_SYSREG_CNTISCALE_EL2()),
		CNTKCTL_EL1(AARCH64_SYSREG_CNTKCTL_EL1()),
		CNTKCTL_EL12(AARCH64_SYSREG_CNTKCTL_EL12()),
		CNTPCTSS_EL0(AARCH64_SYSREG_CNTPCTSS_EL0()),
		CNTPCT_EL0(AARCH64_SYSREG_CNTPCT_EL0()),
		CNTPOFF_EL2(AARCH64_SYSREG_CNTPOFF_EL2()),
		CNTPS_CTL_EL1(AARCH64_SYSREG_CNTPS_CTL_EL1()),
		CNTPS_CVAL_EL1(AARCH64_SYSREG_CNTPS_CVAL_EL1()),
		CNTPS_TVAL_EL1(AARCH64_SYSREG_CNTPS_TVAL_EL1()),
		CNTP_CTL_EL0(AARCH64_SYSREG_CNTP_CTL_EL0()),
		CNTP_CTL_EL02(AARCH64_SYSREG_CNTP_CTL_EL02()),
		CNTP_CVAL_EL0(AARCH64_SYSREG_CNTP_CVAL_EL0()),
		CNTP_CVAL_EL02(AARCH64_SYSREG_CNTP_CVAL_EL02()),
		CNTP_TVAL_EL0(AARCH64_SYSREG_CNTP_TVAL_EL0()),
		CNTP_TVAL_EL02(AARCH64_SYSREG_CNTP_TVAL_EL02()),
		CNTSCALE_EL2(AARCH64_SYSREG_CNTSCALE_EL2()),
		CNTVCTSS_EL0(AARCH64_SYSREG_CNTVCTSS_EL0()),
		CNTVCT_EL0(AARCH64_SYSREG_CNTVCT_EL0()),
		CNTVFRQ_EL2(AARCH64_SYSREG_CNTVFRQ_EL2()),
		CNTVOFF_EL2(AARCH64_SYSREG_CNTVOFF_EL2()),
		CNTV_CTL_EL0(AARCH64_SYSREG_CNTV_CTL_EL0()),
		CNTV_CTL_EL02(AARCH64_SYSREG_CNTV_CTL_EL02()),
		CNTV_CVAL_EL0(AARCH64_SYSREG_CNTV_CVAL_EL0()),
		CNTV_CVAL_EL02(AARCH64_SYSREG_CNTV_CVAL_EL02()),
		CNTV_TVAL_EL0(AARCH64_SYSREG_CNTV_TVAL_EL0()),
		CNTV_TVAL_EL02(AARCH64_SYSREG_CNTV_TVAL_EL02()),
		CONTEXTIDR_EL1(AARCH64_SYSREG_CONTEXTIDR_EL1()),
		CONTEXTIDR_EL12(AARCH64_SYSREG_CONTEXTIDR_EL12()),
		CONTEXTIDR_EL2(AARCH64_SYSREG_CONTEXTIDR_EL2()),
		CPACR_EL1(AARCH64_SYSREG_CPACR_EL1()),
		CPACR_EL12(AARCH64_SYSREG_CPACR_EL12()),
		CPM_IOACC_CTL_EL3(AARCH64_SYSREG_CPM_IOACC_CTL_EL3()),
		CPTR_EL2(AARCH64_SYSREG_CPTR_EL2()),
		CPTR_EL3(AARCH64_SYSREG_CPTR_EL3()),
		CSSELR_EL1(AARCH64_SYSREG_CSSELR_EL1()),
		CTR_EL0(AARCH64_SYSREG_CTR_EL0()),
		CURRENTEL(AARCH64_SYSREG_CURRENTEL()),
		DACR32_EL2(AARCH64_SYSREG_DACR32_EL2()),
		DAIF(AARCH64_SYSREG_DAIF()),
		DBGAUTHSTATUS_EL1(AARCH64_SYSREG_DBGAUTHSTATUS_EL1()),
		DBGBCR0_EL1(AARCH64_SYSREG_DBGBCR0_EL1()),
		DBGBCR10_EL1(AARCH64_SYSREG_DBGBCR10_EL1()),
		DBGBCR11_EL1(AARCH64_SYSREG_DBGBCR11_EL1()),
		DBGBCR12_EL1(AARCH64_SYSREG_DBGBCR12_EL1()),
		DBGBCR13_EL1(AARCH64_SYSREG_DBGBCR13_EL1()),
		DBGBCR14_EL1(AARCH64_SYSREG_DBGBCR14_EL1()),
		DBGBCR15_EL1(AARCH64_SYSREG_DBGBCR15_EL1()),
		DBGBCR1_EL1(AARCH64_SYSREG_DBGBCR1_EL1()),
		DBGBCR2_EL1(AARCH64_SYSREG_DBGBCR2_EL1()),
		DBGBCR3_EL1(AARCH64_SYSREG_DBGBCR3_EL1()),
		DBGBCR4_EL1(AARCH64_SYSREG_DBGBCR4_EL1()),
		DBGBCR5_EL1(AARCH64_SYSREG_DBGBCR5_EL1()),
		DBGBCR6_EL1(AARCH64_SYSREG_DBGBCR6_EL1()),
		DBGBCR7_EL1(AARCH64_SYSREG_DBGBCR7_EL1()),
		DBGBCR8_EL1(AARCH64_SYSREG_DBGBCR8_EL1()),
		DBGBCR9_EL1(AARCH64_SYSREG_DBGBCR9_EL1()),
		DBGBVR0_EL1(AARCH64_SYSREG_DBGBVR0_EL1()),
		DBGBVR10_EL1(AARCH64_SYSREG_DBGBVR10_EL1()),
		DBGBVR11_EL1(AARCH64_SYSREG_DBGBVR11_EL1()),
		DBGBVR12_EL1(AARCH64_SYSREG_DBGBVR12_EL1()),
		DBGBVR13_EL1(AARCH64_SYSREG_DBGBVR13_EL1()),
		DBGBVR14_EL1(AARCH64_SYSREG_DBGBVR14_EL1()),
		DBGBVR15_EL1(AARCH64_SYSREG_DBGBVR15_EL1()),
		DBGBVR1_EL1(AARCH64_SYSREG_DBGBVR1_EL1()),
		DBGBVR2_EL1(AARCH64_SYSREG_DBGBVR2_EL1()),
		DBGBVR3_EL1(AARCH64_SYSREG_DBGBVR3_EL1()),
		DBGBVR4_EL1(AARCH64_SYSREG_DBGBVR4_EL1()),
		DBGBVR5_EL1(AARCH64_SYSREG_DBGBVR5_EL1()),
		DBGBVR6_EL1(AARCH64_SYSREG_DBGBVR6_EL1()),
		DBGBVR7_EL1(AARCH64_SYSREG_DBGBVR7_EL1()),
		DBGBVR8_EL1(AARCH64_SYSREG_DBGBVR8_EL1()),
		DBGBVR9_EL1(AARCH64_SYSREG_DBGBVR9_EL1()),
		DBGCLAIMCLR_EL1(AARCH64_SYSREG_DBGCLAIMCLR_EL1()),
		DBGCLAIMSET_EL1(AARCH64_SYSREG_DBGCLAIMSET_EL1()),
		DBGDTRRX_EL0(AARCH64_SYSREG_DBGDTRRX_EL0()),
		DBGDTRTX_EL0(AARCH64_SYSREG_DBGDTRTX_EL0()),
		DBGDTR_EL0(AARCH64_SYSREG_DBGDTR_EL0()),
		DBGPRCR_EL1(AARCH64_SYSREG_DBGPRCR_EL1()),
		DBGVCR32_EL2(AARCH64_SYSREG_DBGVCR32_EL2()),
		DBGWCR0_EL1(AARCH64_SYSREG_DBGWCR0_EL1()),
		DBGWCR10_EL1(AARCH64_SYSREG_DBGWCR10_EL1()),
		DBGWCR11_EL1(AARCH64_SYSREG_DBGWCR11_EL1()),
		DBGWCR12_EL1(AARCH64_SYSREG_DBGWCR12_EL1()),
		DBGWCR13_EL1(AARCH64_SYSREG_DBGWCR13_EL1()),
		DBGWCR14_EL1(AARCH64_SYSREG_DBGWCR14_EL1()),
		DBGWCR15_EL1(AARCH64_SYSREG_DBGWCR15_EL1()),
		DBGWCR1_EL1(AARCH64_SYSREG_DBGWCR1_EL1()),
		DBGWCR2_EL1(AARCH64_SYSREG_DBGWCR2_EL1()),
		DBGWCR3_EL1(AARCH64_SYSREG_DBGWCR3_EL1()),
		DBGWCR4_EL1(AARCH64_SYSREG_DBGWCR4_EL1()),
		DBGWCR5_EL1(AARCH64_SYSREG_DBGWCR5_EL1()),
		DBGWCR6_EL1(AARCH64_SYSREG_DBGWCR6_EL1()),
		DBGWCR7_EL1(AARCH64_SYSREG_DBGWCR7_EL1()),
		DBGWCR8_EL1(AARCH64_SYSREG_DBGWCR8_EL1()),
		DBGWCR9_EL1(AARCH64_SYSREG_DBGWCR9_EL1()),
		DBGWVR0_EL1(AARCH64_SYSREG_DBGWVR0_EL1()),
		DBGWVR10_EL1(AARCH64_SYSREG_DBGWVR10_EL1()),
		DBGWVR11_EL1(AARCH64_SYSREG_DBGWVR11_EL1()),
		DBGWVR12_EL1(AARCH64_SYSREG_DBGWVR12_EL1()),
		DBGWVR13_EL1(AARCH64_SYSREG_DBGWVR13_EL1()),
		DBGWVR14_EL1(AARCH64_SYSREG_DBGWVR14_EL1()),
		DBGWVR15_EL1(AARCH64_SYSREG_DBGWVR15_EL1()),
		DBGWVR1_EL1(AARCH64_SYSREG_DBGWVR1_EL1()),
		DBGWVR2_EL1(AARCH64_SYSREG_DBGWVR2_EL1()),
		DBGWVR3_EL1(AARCH64_SYSREG_DBGWVR3_EL1()),
		DBGWVR4_EL1(AARCH64_SYSREG_DBGWVR4_EL1()),
		DBGWVR5_EL1(AARCH64_SYSREG_DBGWVR5_EL1()),
		DBGWVR6_EL1(AARCH64_SYSREG_DBGWVR6_EL1()),
		DBGWVR7_EL1(AARCH64_SYSREG_DBGWVR7_EL1()),
		DBGWVR8_EL1(AARCH64_SYSREG_DBGWVR8_EL1()),
		DBGWVR9_EL1(AARCH64_SYSREG_DBGWVR9_EL1()),
		DCZID_EL0(AARCH64_SYSREG_DCZID_EL0()),
		DISR_EL1(AARCH64_SYSREG_DISR_EL1()),
		DIT(AARCH64_SYSREG_DIT()),
		DLR_EL0(AARCH64_SYSREG_DLR_EL0()),
		DSPSR_EL0(AARCH64_SYSREG_DSPSR_EL0()),
		ELR_EL1(AARCH64_SYSREG_ELR_EL1()),
		ELR_EL12(AARCH64_SYSREG_ELR_EL12()),
		ELR_EL2(AARCH64_SYSREG_ELR_EL2()),
		ELR_EL3(AARCH64_SYSREG_ELR_EL3()),
		ERRIDR_EL1(AARCH64_SYSREG_ERRIDR_EL1()),
		ERRSELR_EL1(AARCH64_SYSREG_ERRSELR_EL1()),
		ERXADDR_EL1(AARCH64_SYSREG_ERXADDR_EL1()),
		ERXCTLR_EL1(AARCH64_SYSREG_ERXCTLR_EL1()),
		ERXFR_EL1(AARCH64_SYSREG_ERXFR_EL1()),
		ERXGSR_EL1(AARCH64_SYSREG_ERXGSR_EL1()),
		ERXMISC0_EL1(AARCH64_SYSREG_ERXMISC0_EL1()),
		ERXMISC1_EL1(AARCH64_SYSREG_ERXMISC1_EL1()),
		ERXMISC2_EL1(AARCH64_SYSREG_ERXMISC2_EL1()),
		ERXMISC3_EL1(AARCH64_SYSREG_ERXMISC3_EL1()),
		ERXPFGCDN_EL1(AARCH64_SYSREG_ERXPFGCDN_EL1()),
		ERXPFGCTL_EL1(AARCH64_SYSREG_ERXPFGCTL_EL1()),
		ERXPFGF_EL1(AARCH64_SYSREG_ERXPFGF_EL1()),
		ERXSTATUS_EL1(AARCH64_SYSREG_ERXSTATUS_EL1()),
		ESR_EL1(AARCH64_SYSREG_ESR_EL1()),
		ESR_EL12(AARCH64_SYSREG_ESR_EL12()),
		ESR_EL2(AARCH64_SYSREG_ESR_EL2()),
		ESR_EL3(AARCH64_SYSREG_ESR_EL3()),
		FAR_EL1(AARCH64_SYSREG_FAR_EL1()),
		FAR_EL12(AARCH64_SYSREG_FAR_EL12()),
		FAR_EL2(AARCH64_SYSREG_FAR_EL2()),
		FAR_EL3(AARCH64_SYSREG_FAR_EL3()),
		FGWTE3_EL3(AARCH64_SYSREG_FGWTE3_EL3()),
		FPCR(AARCH64_SYSREG_FPCR()),
		FPEXC32_EL2(AARCH64_SYSREG_FPEXC32_EL2()),
		FPMR(AARCH64_SYSREG_FPMR()),
		FPSR(AARCH64_SYSREG_FPSR()),
		GCR_EL1(AARCH64_SYSREG_GCR_EL1()),
		GCSCRE0_EL1(AARCH64_SYSREG_GCSCRE0_EL1()),
		GCSCR_EL1(AARCH64_SYSREG_GCSCR_EL1()),
		GCSCR_EL12(AARCH64_SYSREG_GCSCR_EL12()),
		GCSCR_EL2(AARCH64_SYSREG_GCSCR_EL2()),
		GCSCR_EL3(AARCH64_SYSREG_GCSCR_EL3()),
		GCSPR_EL0(AARCH64_SYSREG_GCSPR_EL0()),
		GCSPR_EL1(AARCH64_SYSREG_GCSPR_EL1()),
		GCSPR_EL12(AARCH64_SYSREG_GCSPR_EL12()),
		GCSPR_EL2(AARCH64_SYSREG_GCSPR_EL2()),
		GCSPR_EL3(AARCH64_SYSREG_GCSPR_EL3()),
		GMID_EL1(AARCH64_SYSREG_GMID_EL1()),
		GPCCR_EL3(AARCH64_SYSREG_GPCCR_EL3()),
		GPTBR_EL3(AARCH64_SYSREG_GPTBR_EL3()),
		HACDBSBR_EL2(AARCH64_SYSREG_HACDBSBR_EL2()),
		HACDBSCONS_EL2(AARCH64_SYSREG_HACDBSCONS_EL2()),
		HACR_EL2(AARCH64_SYSREG_HACR_EL2()),
		HAFGRTR_EL2(AARCH64_SYSREG_HAFGRTR_EL2()),
		HCRX_EL2(AARCH64_SYSREG_HCRX_EL2()),
		HCR_EL2(AARCH64_SYSREG_HCR_EL2()),
		HDBSSBR_EL2(AARCH64_SYSREG_HDBSSBR_EL2()),
		HDBSSPROD_EL2(AARCH64_SYSREG_HDBSSPROD_EL2()),
		HDFGRTR2_EL2(AARCH64_SYSREG_HDFGRTR2_EL2()),
		HDFGRTR_EL2(AARCH64_SYSREG_HDFGRTR_EL2()),
		HDFGWTR2_EL2(AARCH64_SYSREG_HDFGWTR2_EL2()),
		HDFGWTR_EL2(AARCH64_SYSREG_HDFGWTR_EL2()),
		HFGITR2_EL2(AARCH64_SYSREG_HFGITR2_EL2()),
		HFGITR_EL2(AARCH64_SYSREG_HFGITR_EL2()),
		HFGRTR2_EL2(AARCH64_SYSREG_HFGRTR2_EL2()),
		HFGRTR_EL2(AARCH64_SYSREG_HFGRTR_EL2()),
		HFGWTR2_EL2(AARCH64_SYSREG_HFGWTR2_EL2()),
		HFGWTR_EL2(AARCH64_SYSREG_HFGWTR_EL2()),
		HPFAR_EL2(AARCH64_SYSREG_HPFAR_EL2()),
		HSTR_EL2(AARCH64_SYSREG_HSTR_EL2()),
		ICC_AP0R0_EL1(AARCH64_SYSREG_ICC_AP0R0_EL1()),
		ICC_AP0R1_EL1(AARCH64_SYSREG_ICC_AP0R1_EL1()),
		ICC_AP0R2_EL1(AARCH64_SYSREG_ICC_AP0R2_EL1()),
		ICC_AP0R3_EL1(AARCH64_SYSREG_ICC_AP0R3_EL1()),
		ICC_AP1R0_EL1(AARCH64_SYSREG_ICC_AP1R0_EL1()),
		ICC_AP1R1_EL1(AARCH64_SYSREG_ICC_AP1R1_EL1()),
		ICC_AP1R2_EL1(AARCH64_SYSREG_ICC_AP1R2_EL1()),
		ICC_AP1R3_EL1(AARCH64_SYSREG_ICC_AP1R3_EL1()),
		ICC_ASGI1R_EL1(AARCH64_SYSREG_ICC_ASGI1R_EL1()),
		ICC_BPR0_EL1(AARCH64_SYSREG_ICC_BPR0_EL1()),
		ICC_BPR1_EL1(AARCH64_SYSREG_ICC_BPR1_EL1()),
		ICC_CTLR_EL1(AARCH64_SYSREG_ICC_CTLR_EL1()),
		ICC_CTLR_EL3(AARCH64_SYSREG_ICC_CTLR_EL3()),
		ICC_DIR_EL1(AARCH64_SYSREG_ICC_DIR_EL1()),
		ICC_EOIR0_EL1(AARCH64_SYSREG_ICC_EOIR0_EL1()),
		ICC_EOIR1_EL1(AARCH64_SYSREG_ICC_EOIR1_EL1()),
		ICC_HPPIR0_EL1(AARCH64_SYSREG_ICC_HPPIR0_EL1()),
		ICC_HPPIR1_EL1(AARCH64_SYSREG_ICC_HPPIR1_EL1()),
		ICC_IAR0_EL1(AARCH64_SYSREG_ICC_IAR0_EL1()),
		ICC_IAR1_EL1(AARCH64_SYSREG_ICC_IAR1_EL1()),
		ICC_IGRPEN0_EL1(AARCH64_SYSREG_ICC_IGRPEN0_EL1()),
		ICC_IGRPEN1_EL1(AARCH64_SYSREG_ICC_IGRPEN1_EL1()),
		ICC_IGRPEN1_EL3(AARCH64_SYSREG_ICC_IGRPEN1_EL3()),
		ICC_NMIAR1_EL1(AARCH64_SYSREG_ICC_NMIAR1_EL1()),
		ICC_PMR_EL1(AARCH64_SYSREG_ICC_PMR_EL1()),
		ICC_RPR_EL1(AARCH64_SYSREG_ICC_RPR_EL1()),
		ICC_SGI0R_EL1(AARCH64_SYSREG_ICC_SGI0R_EL1()),
		ICC_SGI1R_EL1(AARCH64_SYSREG_ICC_SGI1R_EL1()),
		ICC_SRE_EL1(AARCH64_SYSREG_ICC_SRE_EL1()),
		ICC_SRE_EL2(AARCH64_SYSREG_ICC_SRE_EL2()),
		ICC_SRE_EL3(AARCH64_SYSREG_ICC_SRE_EL3()),
		ICH_AP0R0_EL2(AARCH64_SYSREG_ICH_AP0R0_EL2()),
		ICH_AP0R1_EL2(AARCH64_SYSREG_ICH_AP0R1_EL2()),
		ICH_AP0R2_EL2(AARCH64_SYSREG_ICH_AP0R2_EL2()),
		ICH_AP0R3_EL2(AARCH64_SYSREG_ICH_AP0R3_EL2()),
		ICH_AP1R0_EL2(AARCH64_SYSREG_ICH_AP1R0_EL2()),
		ICH_AP1R1_EL2(AARCH64_SYSREG_ICH_AP1R1_EL2()),
		ICH_AP1R2_EL2(AARCH64_SYSREG_ICH_AP1R2_EL2()),
		ICH_AP1R3_EL2(AARCH64_SYSREG_ICH_AP1R3_EL2()),
		ICH_EISR_EL2(AARCH64_SYSREG_ICH_EISR_EL2()),
		ICH_ELRSR_EL2(AARCH64_SYSREG_ICH_ELRSR_EL2()),
		ICH_HCR_EL2(AARCH64_SYSREG_ICH_HCR_EL2()),
		ICH_LR0_EL2(AARCH64_SYSREG_ICH_LR0_EL2()),
		ICH_LR10_EL2(AARCH64_SYSREG_ICH_LR10_EL2()),
		ICH_LR11_EL2(AARCH64_SYSREG_ICH_LR11_EL2()),
		ICH_LR12_EL2(AARCH64_SYSREG_ICH_LR12_EL2()),
		ICH_LR13_EL2(AARCH64_SYSREG_ICH_LR13_EL2()),
		ICH_LR14_EL2(AARCH64_SYSREG_ICH_LR14_EL2()),
		ICH_LR15_EL2(AARCH64_SYSREG_ICH_LR15_EL2()),
		ICH_LR1_EL2(AARCH64_SYSREG_ICH_LR1_EL2()),
		ICH_LR2_EL2(AARCH64_SYSREG_ICH_LR2_EL2()),
		ICH_LR3_EL2(AARCH64_SYSREG_ICH_LR3_EL2()),
		ICH_LR4_EL2(AARCH64_SYSREG_ICH_LR4_EL2()),
		ICH_LR5_EL2(AARCH64_SYSREG_ICH_LR5_EL2()),
		ICH_LR6_EL2(AARCH64_SYSREG_ICH_LR6_EL2()),
		ICH_LR7_EL2(AARCH64_SYSREG_ICH_LR7_EL2()),
		ICH_LR8_EL2(AARCH64_SYSREG_ICH_LR8_EL2()),
		ICH_LR9_EL2(AARCH64_SYSREG_ICH_LR9_EL2()),
		ICH_MISR_EL2(AARCH64_SYSREG_ICH_MISR_EL2()),
		ICH_VMCR_EL2(AARCH64_SYSREG_ICH_VMCR_EL2()),
		ICH_VTR_EL2(AARCH64_SYSREG_ICH_VTR_EL2()),
		ID_AA64AFR0_EL1(AARCH64_SYSREG_ID_AA64AFR0_EL1()),
		ID_AA64AFR1_EL1(AARCH64_SYSREG_ID_AA64AFR1_EL1()),
		ID_AA64DFR0_EL1(AARCH64_SYSREG_ID_AA64DFR0_EL1()),
		ID_AA64DFR1_EL1(AARCH64_SYSREG_ID_AA64DFR1_EL1()),
		ID_AA64DFR2_EL1(AARCH64_SYSREG_ID_AA64DFR2_EL1()),
		ID_AA64FPFR0_EL1(AARCH64_SYSREG_ID_AA64FPFR0_EL1()),
		ID_AA64ISAR0_EL1(AARCH64_SYSREG_ID_AA64ISAR0_EL1()),
		ID_AA64ISAR1_EL1(AARCH64_SYSREG_ID_AA64ISAR1_EL1()),
		ID_AA64ISAR2_EL1(AARCH64_SYSREG_ID_AA64ISAR2_EL1()),
		ID_AA64ISAR3_EL1(AARCH64_SYSREG_ID_AA64ISAR3_EL1()),
		ID_AA64MMFR0_EL1(AARCH64_SYSREG_ID_AA64MMFR0_EL1()),
		ID_AA64MMFR1_EL1(AARCH64_SYSREG_ID_AA64MMFR1_EL1()),
		ID_AA64MMFR2_EL1(AARCH64_SYSREG_ID_AA64MMFR2_EL1()),
		ID_AA64MMFR3_EL1(AARCH64_SYSREG_ID_AA64MMFR3_EL1()),
		ID_AA64MMFR4_EL1(AARCH64_SYSREG_ID_AA64MMFR4_EL1()),
		ID_AA64PFR0_EL1(AARCH64_SYSREG_ID_AA64PFR0_EL1()),
		ID_AA64PFR1_EL1(AARCH64_SYSREG_ID_AA64PFR1_EL1()),
		ID_AA64PFR2_EL1(AARCH64_SYSREG_ID_AA64PFR2_EL1()),
		ID_AA64SMFR0_EL1(AARCH64_SYSREG_ID_AA64SMFR0_EL1()),
		ID_AA64ZFR0_EL1(AARCH64_SYSREG_ID_AA64ZFR0_EL1()),
		ID_AFR0_EL1(AARCH64_SYSREG_ID_AFR0_EL1()),
		ID_DFR0_EL1(AARCH64_SYSREG_ID_DFR0_EL1()),
		ID_DFR1_EL1(AARCH64_SYSREG_ID_DFR1_EL1()),
		ID_ISAR0_EL1(AARCH64_SYSREG_ID_ISAR0_EL1()),
		ID_ISAR1_EL1(AARCH64_SYSREG_ID_ISAR1_EL1()),
		ID_ISAR2_EL1(AARCH64_SYSREG_ID_ISAR2_EL1()),
		ID_ISAR3_EL1(AARCH64_SYSREG_ID_ISAR3_EL1()),
		ID_ISAR4_EL1(AARCH64_SYSREG_ID_ISAR4_EL1()),
		ID_ISAR5_EL1(AARCH64_SYSREG_ID_ISAR5_EL1()),
		ID_ISAR6_EL1(AARCH64_SYSREG_ID_ISAR6_EL1()),
		ID_MMFR0_EL1(AARCH64_SYSREG_ID_MMFR0_EL1()),
		ID_MMFR1_EL1(AARCH64_SYSREG_ID_MMFR1_EL1()),
		ID_MMFR2_EL1(AARCH64_SYSREG_ID_MMFR2_EL1()),
		ID_MMFR3_EL1(AARCH64_SYSREG_ID_MMFR3_EL1()),
		ID_MMFR4_EL1(AARCH64_SYSREG_ID_MMFR4_EL1()),
		ID_MMFR5_EL1(AARCH64_SYSREG_ID_MMFR5_EL1()),
		ID_PFR0_EL1(AARCH64_SYSREG_ID_PFR0_EL1()),
		ID_PFR1_EL1(AARCH64_SYSREG_ID_PFR1_EL1()),
		ID_PFR2_EL1(AARCH64_SYSREG_ID_PFR2_EL1()),
		IFSR32_EL2(AARCH64_SYSREG_IFSR32_EL2()),
		ISR_EL1(AARCH64_SYSREG_ISR_EL1()),
		LORC_EL1(AARCH64_SYSREG_LORC_EL1()),
		LOREA_EL1(AARCH64_SYSREG_LOREA_EL1()),
		LORID_EL1(AARCH64_SYSREG_LORID_EL1()),
		LORN_EL1(AARCH64_SYSREG_LORN_EL1()),
		LORSA_EL1(AARCH64_SYSREG_LORSA_EL1()),
		MAIR2_EL1(AARCH64_SYSREG_MAIR2_EL1()),
		MAIR2_EL12(AARCH64_SYSREG_MAIR2_EL12()),
		MAIR2_EL2(AARCH64_SYSREG_MAIR2_EL2()),
		MAIR2_EL3(AARCH64_SYSREG_MAIR2_EL3()),
		MAIR_EL1(AARCH64_SYSREG_MAIR_EL1()),
		MAIR_EL12(AARCH64_SYSREG_MAIR_EL12()),
		MAIR_EL2(AARCH64_SYSREG_MAIR_EL2()),
		MAIR_EL3(AARCH64_SYSREG_MAIR_EL3()),
		MDCCINT_EL1(AARCH64_SYSREG_MDCCINT_EL1()),
		MDCCSR_EL0(AARCH64_SYSREG_MDCCSR_EL0()),
		MDCR_EL2(AARCH64_SYSREG_MDCR_EL2()),
		MDCR_EL3(AARCH64_SYSREG_MDCR_EL3()),
		MDRAR_EL1(AARCH64_SYSREG_MDRAR_EL1()),
		MDSCR_EL1(AARCH64_SYSREG_MDSCR_EL1()),
		MDSELR_EL1(AARCH64_SYSREG_MDSELR_EL1()),
		MDSTEPOP_EL1(AARCH64_SYSREG_MDSTEPOP_EL1()),
		MECIDR_EL2(AARCH64_SYSREG_MECIDR_EL2()),
		MECID_A0_EL2(AARCH64_SYSREG_MECID_A0_EL2()),
		MECID_A1_EL2(AARCH64_SYSREG_MECID_A1_EL2()),
		MECID_P0_EL2(AARCH64_SYSREG_MECID_P0_EL2()),
		MECID_P1_EL2(AARCH64_SYSREG_MECID_P1_EL2()),
		MECID_RL_A_EL3(AARCH64_SYSREG_MECID_RL_A_EL3()),
		MFAR_EL3(AARCH64_SYSREG_MFAR_EL3()),
		MIDR_EL1(AARCH64_SYSREG_MIDR_EL1()),
		MPAM0_EL1(AARCH64_SYSREG_MPAM0_EL1()),
		MPAM1_EL1(AARCH64_SYSREG_MPAM1_EL1()),
		MPAM1_EL12(AARCH64_SYSREG_MPAM1_EL12()),
		MPAM2_EL2(AARCH64_SYSREG_MPAM2_EL2()),
		MPAM3_EL3(AARCH64_SYSREG_MPAM3_EL3()),
		MPAMHCR_EL2(AARCH64_SYSREG_MPAMHCR_EL2()),
		MPAMIDR_EL1(AARCH64_SYSREG_MPAMIDR_EL1()),
		MPAMSM_EL1(AARCH64_SYSREG_MPAMSM_EL1()),
		MPAMVPM0_EL2(AARCH64_SYSREG_MPAMVPM0_EL2()),
		MPAMVPM1_EL2(AARCH64_SYSREG_MPAMVPM1_EL2()),
		MPAMVPM2_EL2(AARCH64_SYSREG_MPAMVPM2_EL2()),
		MPAMVPM3_EL2(AARCH64_SYSREG_MPAMVPM3_EL2()),
		MPAMVPM4_EL2(AARCH64_SYSREG_MPAMVPM4_EL2()),
		MPAMVPM5_EL2(AARCH64_SYSREG_MPAMVPM5_EL2()),
		MPAMVPM6_EL2(AARCH64_SYSREG_MPAMVPM6_EL2()),
		MPAMVPM7_EL2(AARCH64_SYSREG_MPAMVPM7_EL2()),
		MPAMVPMV_EL2(AARCH64_SYSREG_MPAMVPMV_EL2()),
		MPIDR_EL1(AARCH64_SYSREG_MPIDR_EL1()),
		MPUIR_EL1(AARCH64_SYSREG_MPUIR_EL1()),
		MPUIR_EL2(AARCH64_SYSREG_MPUIR_EL2()),
		MVFR0_EL1(AARCH64_SYSREG_MVFR0_EL1()),
		MVFR1_EL1(AARCH64_SYSREG_MVFR1_EL1()),
		MVFR2_EL1(AARCH64_SYSREG_MVFR2_EL1()),
		NZCV(AARCH64_SYSREG_NZCV()),
		OSDLR_EL1(AARCH64_SYSREG_OSDLR_EL1()),
		OSDTRRX_EL1(AARCH64_SYSREG_OSDTRRX_EL1()),
		OSDTRTX_EL1(AARCH64_SYSREG_OSDTRTX_EL1()),
		OSECCR_EL1(AARCH64_SYSREG_OSECCR_EL1()),
		OSLAR_EL1(AARCH64_SYSREG_OSLAR_EL1()),
		OSLSR_EL1(AARCH64_SYSREG_OSLSR_EL1()),
		PAN(AARCH64_SYSREG_PAN()),
		PAR_EL1(AARCH64_SYSREG_PAR_EL1()),
		PFAR_EL1(AARCH64_SYSREG_PFAR_EL1()),
		PFAR_EL12(AARCH64_SYSREG_PFAR_EL12()),
		PFAR_EL2(AARCH64_SYSREG_PFAR_EL2()),
		PIRE0_EL1(AARCH64_SYSREG_PIRE0_EL1()),
		PIRE0_EL12(AARCH64_SYSREG_PIRE0_EL12()),
		PIRE0_EL2(AARCH64_SYSREG_PIRE0_EL2()),
		PIR_EL1(AARCH64_SYSREG_PIR_EL1()),
		PIR_EL12(AARCH64_SYSREG_PIR_EL12()),
		PIR_EL2(AARCH64_SYSREG_PIR_EL2()),
		PIR_EL3(AARCH64_SYSREG_PIR_EL3()),
		PM(AARCH64_SYSREG_PM()),
		PMBIDR_EL1(AARCH64_SYSREG_PMBIDR_EL1()),
		PMBLIMITR_EL1(AARCH64_SYSREG_PMBLIMITR_EL1()),
		PMBPTR_EL1(AARCH64_SYSREG_PMBPTR_EL1()),
		PMBSR_EL1(AARCH64_SYSREG_PMBSR_EL1()),
		PMCCFILTR_EL0(AARCH64_SYSREG_PMCCFILTR_EL0()),
		PMCCNTR_EL0(AARCH64_SYSREG_PMCCNTR_EL0()),
		PMCCNTSVR_EL1(AARCH64_SYSREG_PMCCNTSVR_EL1()),
		PMCEID0_EL0(AARCH64_SYSREG_PMCEID0_EL0()),
		PMCEID1_EL0(AARCH64_SYSREG_PMCEID1_EL0()),
		PMCNTENCLR_EL0(AARCH64_SYSREG_PMCNTENCLR_EL0()),
		PMCNTENSET_EL0(AARCH64_SYSREG_PMCNTENSET_EL0()),
		PMCR_EL0(AARCH64_SYSREG_PMCR_EL0()),
		PMECR_EL1(AARCH64_SYSREG_PMECR_EL1()),
		PMEVCNTR0_EL0(AARCH64_SYSREG_PMEVCNTR0_EL0()),
		PMEVCNTR10_EL0(AARCH64_SYSREG_PMEVCNTR10_EL0()),
		PMEVCNTR11_EL0(AARCH64_SYSREG_PMEVCNTR11_EL0()),
		PMEVCNTR12_EL0(AARCH64_SYSREG_PMEVCNTR12_EL0()),
		PMEVCNTR13_EL0(AARCH64_SYSREG_PMEVCNTR13_EL0()),
		PMEVCNTR14_EL0(AARCH64_SYSREG_PMEVCNTR14_EL0()),
		PMEVCNTR15_EL0(AARCH64_SYSREG_PMEVCNTR15_EL0()),
		PMEVCNTR16_EL0(AARCH64_SYSREG_PMEVCNTR16_EL0()),
		PMEVCNTR17_EL0(AARCH64_SYSREG_PMEVCNTR17_EL0()),
		PMEVCNTR18_EL0(AARCH64_SYSREG_PMEVCNTR18_EL0()),
		PMEVCNTR19_EL0(AARCH64_SYSREG_PMEVCNTR19_EL0()),
		PMEVCNTR1_EL0(AARCH64_SYSREG_PMEVCNTR1_EL0()),
		PMEVCNTR20_EL0(AARCH64_SYSREG_PMEVCNTR20_EL0()),
		PMEVCNTR21_EL0(AARCH64_SYSREG_PMEVCNTR21_EL0()),
		PMEVCNTR22_EL0(AARCH64_SYSREG_PMEVCNTR22_EL0()),
		PMEVCNTR23_EL0(AARCH64_SYSREG_PMEVCNTR23_EL0()),
		PMEVCNTR24_EL0(AARCH64_SYSREG_PMEVCNTR24_EL0()),
		PMEVCNTR25_EL0(AARCH64_SYSREG_PMEVCNTR25_EL0()),
		PMEVCNTR26_EL0(AARCH64_SYSREG_PMEVCNTR26_EL0()),
		PMEVCNTR27_EL0(AARCH64_SYSREG_PMEVCNTR27_EL0()),
		PMEVCNTR28_EL0(AARCH64_SYSREG_PMEVCNTR28_EL0()),
		PMEVCNTR29_EL0(AARCH64_SYSREG_PMEVCNTR29_EL0()),
		PMEVCNTR2_EL0(AARCH64_SYSREG_PMEVCNTR2_EL0()),
		PMEVCNTR30_EL0(AARCH64_SYSREG_PMEVCNTR30_EL0()),
		PMEVCNTR3_EL0(AARCH64_SYSREG_PMEVCNTR3_EL0()),
		PMEVCNTR4_EL0(AARCH64_SYSREG_PMEVCNTR4_EL0()),
		PMEVCNTR5_EL0(AARCH64_SYSREG_PMEVCNTR5_EL0()),
		PMEVCNTR6_EL0(AARCH64_SYSREG_PMEVCNTR6_EL0()),
		PMEVCNTR7_EL0(AARCH64_SYSREG_PMEVCNTR7_EL0()),
		PMEVCNTR8_EL0(AARCH64_SYSREG_PMEVCNTR8_EL0()),
		PMEVCNTR9_EL0(AARCH64_SYSREG_PMEVCNTR9_EL0()),
		PMEVCNTSVR0_EL1(AARCH64_SYSREG_PMEVCNTSVR0_EL1()),
		PMEVCNTSVR10_EL1(AARCH64_SYSREG_PMEVCNTSVR10_EL1()),
		PMEVCNTSVR11_EL1(AARCH64_SYSREG_PMEVCNTSVR11_EL1()),
		PMEVCNTSVR12_EL1(AARCH64_SYSREG_PMEVCNTSVR12_EL1()),
		PMEVCNTSVR13_EL1(AARCH64_SYSREG_PMEVCNTSVR13_EL1()),
		PMEVCNTSVR14_EL1(AARCH64_SYSREG_PMEVCNTSVR14_EL1()),
		PMEVCNTSVR15_EL1(AARCH64_SYSREG_PMEVCNTSVR15_EL1()),
		PMEVCNTSVR16_EL1(AARCH64_SYSREG_PMEVCNTSVR16_EL1()),
		PMEVCNTSVR17_EL1(AARCH64_SYSREG_PMEVCNTSVR17_EL1()),
		PMEVCNTSVR18_EL1(AARCH64_SYSREG_PMEVCNTSVR18_EL1()),
		PMEVCNTSVR19_EL1(AARCH64_SYSREG_PMEVCNTSVR19_EL1()),
		PMEVCNTSVR1_EL1(AARCH64_SYSREG_PMEVCNTSVR1_EL1()),
		PMEVCNTSVR20_EL1(AARCH64_SYSREG_PMEVCNTSVR20_EL1()),
		PMEVCNTSVR21_EL1(AARCH64_SYSREG_PMEVCNTSVR21_EL1()),
		PMEVCNTSVR22_EL1(AARCH64_SYSREG_PMEVCNTSVR22_EL1()),
		PMEVCNTSVR23_EL1(AARCH64_SYSREG_PMEVCNTSVR23_EL1()),
		PMEVCNTSVR24_EL1(AARCH64_SYSREG_PMEVCNTSVR24_EL1()),
		PMEVCNTSVR25_EL1(AARCH64_SYSREG_PMEVCNTSVR25_EL1()),
		PMEVCNTSVR26_EL1(AARCH64_SYSREG_PMEVCNTSVR26_EL1()),
		PMEVCNTSVR27_EL1(AARCH64_SYSREG_PMEVCNTSVR27_EL1()),
		PMEVCNTSVR28_EL1(AARCH64_SYSREG_PMEVCNTSVR28_EL1()),
		PMEVCNTSVR29_EL1(AARCH64_SYSREG_PMEVCNTSVR29_EL1()),
		PMEVCNTSVR2_EL1(AARCH64_SYSREG_PMEVCNTSVR2_EL1()),
		PMEVCNTSVR30_EL1(AARCH64_SYSREG_PMEVCNTSVR30_EL1()),
		PMEVCNTSVR3_EL1(AARCH64_SYSREG_PMEVCNTSVR3_EL1()),
		PMEVCNTSVR4_EL1(AARCH64_SYSREG_PMEVCNTSVR4_EL1()),
		PMEVCNTSVR5_EL1(AARCH64_SYSREG_PMEVCNTSVR5_EL1()),
		PMEVCNTSVR6_EL1(AARCH64_SYSREG_PMEVCNTSVR6_EL1()),
		PMEVCNTSVR7_EL1(AARCH64_SYSREG_PMEVCNTSVR7_EL1()),
		PMEVCNTSVR8_EL1(AARCH64_SYSREG_PMEVCNTSVR8_EL1()),
		PMEVCNTSVR9_EL1(AARCH64_SYSREG_PMEVCNTSVR9_EL1()),
		PMEVTYPER0_EL0(AARCH64_SYSREG_PMEVTYPER0_EL0()),
		PMEVTYPER10_EL0(AARCH64_SYSREG_PMEVTYPER10_EL0()),
		PMEVTYPER11_EL0(AARCH64_SYSREG_PMEVTYPER11_EL0()),
		PMEVTYPER12_EL0(AARCH64_SYSREG_PMEVTYPER12_EL0()),
		PMEVTYPER13_EL0(AARCH64_SYSREG_PMEVTYPER13_EL0()),
		PMEVTYPER14_EL0(AARCH64_SYSREG_PMEVTYPER14_EL0()),
		PMEVTYPER15_EL0(AARCH64_SYSREG_PMEVTYPER15_EL0()),
		PMEVTYPER16_EL0(AARCH64_SYSREG_PMEVTYPER16_EL0()),
		PMEVTYPER17_EL0(AARCH64_SYSREG_PMEVTYPER17_EL0()),
		PMEVTYPER18_EL0(AARCH64_SYSREG_PMEVTYPER18_EL0()),
		PMEVTYPER19_EL0(AARCH64_SYSREG_PMEVTYPER19_EL0()),
		PMEVTYPER1_EL0(AARCH64_SYSREG_PMEVTYPER1_EL0()),
		PMEVTYPER20_EL0(AARCH64_SYSREG_PMEVTYPER20_EL0()),
		PMEVTYPER21_EL0(AARCH64_SYSREG_PMEVTYPER21_EL0()),
		PMEVTYPER22_EL0(AARCH64_SYSREG_PMEVTYPER22_EL0()),
		PMEVTYPER23_EL0(AARCH64_SYSREG_PMEVTYPER23_EL0()),
		PMEVTYPER24_EL0(AARCH64_SYSREG_PMEVTYPER24_EL0()),
		PMEVTYPER25_EL0(AARCH64_SYSREG_PMEVTYPER25_EL0()),
		PMEVTYPER26_EL0(AARCH64_SYSREG_PMEVTYPER26_EL0()),
		PMEVTYPER27_EL0(AARCH64_SYSREG_PMEVTYPER27_EL0()),
		PMEVTYPER28_EL0(AARCH64_SYSREG_PMEVTYPER28_EL0()),
		PMEVTYPER29_EL0(AARCH64_SYSREG_PMEVTYPER29_EL0()),
		PMEVTYPER2_EL0(AARCH64_SYSREG_PMEVTYPER2_EL0()),
		PMEVTYPER30_EL0(AARCH64_SYSREG_PMEVTYPER30_EL0()),
		PMEVTYPER3_EL0(AARCH64_SYSREG_PMEVTYPER3_EL0()),
		PMEVTYPER4_EL0(AARCH64_SYSREG_PMEVTYPER4_EL0()),
		PMEVTYPER5_EL0(AARCH64_SYSREG_PMEVTYPER5_EL0()),
		PMEVTYPER6_EL0(AARCH64_SYSREG_PMEVTYPER6_EL0()),
		PMEVTYPER7_EL0(AARCH64_SYSREG_PMEVTYPER7_EL0()),
		PMEVTYPER8_EL0(AARCH64_SYSREG_PMEVTYPER8_EL0()),
		PMEVTYPER9_EL0(AARCH64_SYSREG_PMEVTYPER9_EL0()),
		PMIAR_EL1(AARCH64_SYSREG_PMIAR_EL1()),
		PMICFILTR_EL0(AARCH64_SYSREG_PMICFILTR_EL0()),
		PMICNTR_EL0(AARCH64_SYSREG_PMICNTR_EL0()),
		PMICNTSVR_EL1(AARCH64_SYSREG_PMICNTSVR_EL1()),
		PMINTENCLR_EL1(AARCH64_SYSREG_PMINTENCLR_EL1()),
		PMINTENSET_EL1(AARCH64_SYSREG_PMINTENSET_EL1()),
		PMMIR_EL1(AARCH64_SYSREG_PMMIR_EL1()),
		PMOVSCLR_EL0(AARCH64_SYSREG_PMOVSCLR_EL0()),
		PMOVSSET_EL0(AARCH64_SYSREG_PMOVSSET_EL0()),
		PMSCR_EL1(AARCH64_SYSREG_PMSCR_EL1()),
		PMSCR_EL12(AARCH64_SYSREG_PMSCR_EL12()),
		PMSCR_EL2(AARCH64_SYSREG_PMSCR_EL2()),
		PMSDSFR_EL1(AARCH64_SYSREG_PMSDSFR_EL1()),
		PMSELR_EL0(AARCH64_SYSREG_PMSELR_EL0()),
		PMSEVFR_EL1(AARCH64_SYSREG_PMSEVFR_EL1()),
		PMSFCR_EL1(AARCH64_SYSREG_PMSFCR_EL1()),
		PMSICR_EL1(AARCH64_SYSREG_PMSICR_EL1()),
		PMSIDR_EL1(AARCH64_SYSREG_PMSIDR_EL1()),
		PMSIRR_EL1(AARCH64_SYSREG_PMSIRR_EL1()),
		PMSLATFR_EL1(AARCH64_SYSREG_PMSLATFR_EL1()),
		PMSNEVFR_EL1(AARCH64_SYSREG_PMSNEVFR_EL1()),
		PMSSCR_EL1(AARCH64_SYSREG_PMSSCR_EL1()),
		PMSWINC_EL0(AARCH64_SYSREG_PMSWINC_EL0()),
		PMUACR_EL1(AARCH64_SYSREG_PMUACR_EL1()),
		PMUSERENR_EL0(AARCH64_SYSREG_PMUSERENR_EL0()),
		PMXEVCNTR_EL0(AARCH64_SYSREG_PMXEVCNTR_EL0()),
		PMXEVTYPER_EL0(AARCH64_SYSREG_PMXEVTYPER_EL0()),
		PMZR_EL0(AARCH64_SYSREG_PMZR_EL0()),
		POR_EL0(AARCH64_SYSREG_POR_EL0()),
		POR_EL1(AARCH64_SYSREG_POR_EL1()),
		POR_EL12(AARCH64_SYSREG_POR_EL12()),
		POR_EL2(AARCH64_SYSREG_POR_EL2()),
		POR_EL3(AARCH64_SYSREG_POR_EL3()),
		PRBAR10_EL1(AARCH64_SYSREG_PRBAR10_EL1()),
		PRBAR10_EL2(AARCH64_SYSREG_PRBAR10_EL2()),
		PRBAR11_EL1(AARCH64_SYSREG_PRBAR11_EL1()),
		PRBAR11_EL2(AARCH64_SYSREG_PRBAR11_EL2()),
		PRBAR12_EL1(AARCH64_SYSREG_PRBAR12_EL1()),
		PRBAR12_EL2(AARCH64_SYSREG_PRBAR12_EL2()),
		PRBAR13_EL1(AARCH64_SYSREG_PRBAR13_EL1()),
		PRBAR13_EL2(AARCH64_SYSREG_PRBAR13_EL2()),
		PRBAR14_EL1(AARCH64_SYSREG_PRBAR14_EL1()),
		PRBAR14_EL2(AARCH64_SYSREG_PRBAR14_EL2()),
		PRBAR15_EL1(AARCH64_SYSREG_PRBAR15_EL1()),
		PRBAR15_EL2(AARCH64_SYSREG_PRBAR15_EL2()),
		PRBAR1_EL1(AARCH64_SYSREG_PRBAR1_EL1()),
		PRBAR1_EL2(AARCH64_SYSREG_PRBAR1_EL2()),
		PRBAR2_EL1(AARCH64_SYSREG_PRBAR2_EL1()),
		PRBAR2_EL2(AARCH64_SYSREG_PRBAR2_EL2()),
		PRBAR3_EL1(AARCH64_SYSREG_PRBAR3_EL1()),
		PRBAR3_EL2(AARCH64_SYSREG_PRBAR3_EL2()),
		PRBAR4_EL1(AARCH64_SYSREG_PRBAR4_EL1()),
		PRBAR4_EL2(AARCH64_SYSREG_PRBAR4_EL2()),
		PRBAR5_EL1(AARCH64_SYSREG_PRBAR5_EL1()),
		PRBAR5_EL2(AARCH64_SYSREG_PRBAR5_EL2()),
		PRBAR6_EL1(AARCH64_SYSREG_PRBAR6_EL1()),
		PRBAR6_EL2(AARCH64_SYSREG_PRBAR6_EL2()),
		PRBAR7_EL1(AARCH64_SYSREG_PRBAR7_EL1()),
		PRBAR7_EL2(AARCH64_SYSREG_PRBAR7_EL2()),
		PRBAR8_EL1(AARCH64_SYSREG_PRBAR8_EL1()),
		PRBAR8_EL2(AARCH64_SYSREG_PRBAR8_EL2()),
		PRBAR9_EL1(AARCH64_SYSREG_PRBAR9_EL1()),
		PRBAR9_EL2(AARCH64_SYSREG_PRBAR9_EL2()),
		PRBAR_EL1(AARCH64_SYSREG_PRBAR_EL1()),
		PRBAR_EL2(AARCH64_SYSREG_PRBAR_EL2()),
		PRENR_EL1(AARCH64_SYSREG_PRENR_EL1()),
		PRENR_EL2(AARCH64_SYSREG_PRENR_EL2()),
		PRLAR10_EL1(AARCH64_SYSREG_PRLAR10_EL1()),
		PRLAR10_EL2(AARCH64_SYSREG_PRLAR10_EL2()),
		PRLAR11_EL1(AARCH64_SYSREG_PRLAR11_EL1()),
		PRLAR11_EL2(AARCH64_SYSREG_PRLAR11_EL2()),
		PRLAR12_EL1(AARCH64_SYSREG_PRLAR12_EL1()),
		PRLAR12_EL2(AARCH64_SYSREG_PRLAR12_EL2()),
		PRLAR13_EL1(AARCH64_SYSREG_PRLAR13_EL1()),
		PRLAR13_EL2(AARCH64_SYSREG_PRLAR13_EL2()),
		PRLAR14_EL1(AARCH64_SYSREG_PRLAR14_EL1()),
		PRLAR14_EL2(AARCH64_SYSREG_PRLAR14_EL2()),
		PRLAR15_EL1(AARCH64_SYSREG_PRLAR15_EL1()),
		PRLAR15_EL2(AARCH64_SYSREG_PRLAR15_EL2()),
		PRLAR1_EL1(AARCH64_SYSREG_PRLAR1_EL1()),
		PRLAR1_EL2(AARCH64_SYSREG_PRLAR1_EL2()),
		PRLAR2_EL1(AARCH64_SYSREG_PRLAR2_EL1()),
		PRLAR2_EL2(AARCH64_SYSREG_PRLAR2_EL2()),
		PRLAR3_EL1(AARCH64_SYSREG_PRLAR3_EL1()),
		PRLAR3_EL2(AARCH64_SYSREG_PRLAR3_EL2()),
		PRLAR4_EL1(AARCH64_SYSREG_PRLAR4_EL1()),
		PRLAR4_EL2(AARCH64_SYSREG_PRLAR4_EL2()),
		PRLAR5_EL1(AARCH64_SYSREG_PRLAR5_EL1()),
		PRLAR5_EL2(AARCH64_SYSREG_PRLAR5_EL2()),
		PRLAR6_EL1(AARCH64_SYSREG_PRLAR6_EL1()),
		PRLAR6_EL2(AARCH64_SYSREG_PRLAR6_EL2()),
		PRLAR7_EL1(AARCH64_SYSREG_PRLAR7_EL1()),
		PRLAR7_EL2(AARCH64_SYSREG_PRLAR7_EL2()),
		PRLAR8_EL1(AARCH64_SYSREG_PRLAR8_EL1()),
		PRLAR8_EL2(AARCH64_SYSREG_PRLAR8_EL2()),
		PRLAR9_EL1(AARCH64_SYSREG_PRLAR9_EL1()),
		PRLAR9_EL2(AARCH64_SYSREG_PRLAR9_EL2()),
		PRLAR_EL1(AARCH64_SYSREG_PRLAR_EL1()),
		PRLAR_EL2(AARCH64_SYSREG_PRLAR_EL2()),
		PRSELR_EL1(AARCH64_SYSREG_PRSELR_EL1()),
		PRSELR_EL2(AARCH64_SYSREG_PRSELR_EL2()),
		RCWMASK_EL1(AARCH64_SYSREG_RCWMASK_EL1()),
		RCWSMASK_EL1(AARCH64_SYSREG_RCWSMASK_EL1()),
		REVIDR_EL1(AARCH64_SYSREG_REVIDR_EL1()),
		RGSR_EL1(AARCH64_SYSREG_RGSR_EL1()),
		RMR_EL1(AARCH64_SYSREG_RMR_EL1()),
		RMR_EL2(AARCH64_SYSREG_RMR_EL2()),
		RMR_EL3(AARCH64_SYSREG_RMR_EL3()),
		RNDR(AARCH64_SYSREG_RNDR()),
		RNDRRS(AARCH64_SYSREG_RNDRRS()),
		RVBAR_EL1(AARCH64_SYSREG_RVBAR_EL1()),
		RVBAR_EL2(AARCH64_SYSREG_RVBAR_EL2()),
		RVBAR_EL3(AARCH64_SYSREG_RVBAR_EL3()),
		S2PIR_EL2(AARCH64_SYSREG_S2PIR_EL2()),
		S2POR_EL1(AARCH64_SYSREG_S2POR_EL1()),
		SCR_EL3(AARCH64_SYSREG_SCR_EL3()),
		SCTLR2_EL1(AARCH64_SYSREG_SCTLR2_EL1()),
		SCTLR2_EL12(AARCH64_SYSREG_SCTLR2_EL12()),
		SCTLR2_EL2(AARCH64_SYSREG_SCTLR2_EL2()),
		SCTLR2_EL3(AARCH64_SYSREG_SCTLR2_EL3()),
		SCTLR_EL1(AARCH64_SYSREG_SCTLR_EL1()),
		SCTLR_EL12(AARCH64_SYSREG_SCTLR_EL12()),
		SCTLR_EL2(AARCH64_SYSREG_SCTLR_EL2()),
		SCTLR_EL3(AARCH64_SYSREG_SCTLR_EL3()),
		SCXTNUM_EL0(AARCH64_SYSREG_SCXTNUM_EL0()),
		SCXTNUM_EL1(AARCH64_SYSREG_SCXTNUM_EL1()),
		SCXTNUM_EL12(AARCH64_SYSREG_SCXTNUM_EL12()),
		SCXTNUM_EL2(AARCH64_SYSREG_SCXTNUM_EL2()),
		SCXTNUM_EL3(AARCH64_SYSREG_SCXTNUM_EL3()),
		SDER32_EL2(AARCH64_SYSREG_SDER32_EL2()),
		SDER32_EL3(AARCH64_SYSREG_SDER32_EL3()),
		SMCR_EL1(AARCH64_SYSREG_SMCR_EL1()),
		SMCR_EL12(AARCH64_SYSREG_SMCR_EL12()),
		SMCR_EL2(AARCH64_SYSREG_SMCR_EL2()),
		SMCR_EL3(AARCH64_SYSREG_SMCR_EL3()),
		SMIDR_EL1(AARCH64_SYSREG_SMIDR_EL1()),
		SMPRIMAP_EL2(AARCH64_SYSREG_SMPRIMAP_EL2()),
		SMPRI_EL1(AARCH64_SYSREG_SMPRI_EL1()),
		SPMACCESSR_EL1(AARCH64_SYSREG_SPMACCESSR_EL1()),
		SPMACCESSR_EL12(AARCH64_SYSREG_SPMACCESSR_EL12()),
		SPMACCESSR_EL2(AARCH64_SYSREG_SPMACCESSR_EL2()),
		SPMACCESSR_EL3(AARCH64_SYSREG_SPMACCESSR_EL3()),
		SPMCFGR_EL1(AARCH64_SYSREG_SPMCFGR_EL1()),
		SPMCGCR0_EL1(AARCH64_SYSREG_SPMCGCR0_EL1()),
		SPMCGCR1_EL1(AARCH64_SYSREG_SPMCGCR1_EL1()),
		SPMCNTENCLR_EL0(AARCH64_SYSREG_SPMCNTENCLR_EL0()),
		SPMCNTENSET_EL0(AARCH64_SYSREG_SPMCNTENSET_EL0()),
		SPMCR_EL0(AARCH64_SYSREG_SPMCR_EL0()),
		SPMDEVAFF_EL1(AARCH64_SYSREG_SPMDEVAFF_EL1()),
		SPMDEVARCH_EL1(AARCH64_SYSREG_SPMDEVARCH_EL1()),
		SPMEVCNTR0_EL0(AARCH64_SYSREG_SPMEVCNTR0_EL0()),
		SPMEVCNTR10_EL0(AARCH64_SYSREG_SPMEVCNTR10_EL0()),
		SPMEVCNTR11_EL0(AARCH64_SYSREG_SPMEVCNTR11_EL0()),
		SPMEVCNTR12_EL0(AARCH64_SYSREG_SPMEVCNTR12_EL0()),
		SPMEVCNTR13_EL0(AARCH64_SYSREG_SPMEVCNTR13_EL0()),
		SPMEVCNTR14_EL0(AARCH64_SYSREG_SPMEVCNTR14_EL0()),
		SPMEVCNTR15_EL0(AARCH64_SYSREG_SPMEVCNTR15_EL0()),
		SPMEVCNTR1_EL0(AARCH64_SYSREG_SPMEVCNTR1_EL0()),
		SPMEVCNTR2_EL0(AARCH64_SYSREG_SPMEVCNTR2_EL0()),
		SPMEVCNTR3_EL0(AARCH64_SYSREG_SPMEVCNTR3_EL0()),
		SPMEVCNTR4_EL0(AARCH64_SYSREG_SPMEVCNTR4_EL0()),
		SPMEVCNTR5_EL0(AARCH64_SYSREG_SPMEVCNTR5_EL0()),
		SPMEVCNTR6_EL0(AARCH64_SYSREG_SPMEVCNTR6_EL0()),
		SPMEVCNTR7_EL0(AARCH64_SYSREG_SPMEVCNTR7_EL0()),
		SPMEVCNTR8_EL0(AARCH64_SYSREG_SPMEVCNTR8_EL0()),
		SPMEVCNTR9_EL0(AARCH64_SYSREG_SPMEVCNTR9_EL0()),
		SPMEVFILT2R0_EL0(AARCH64_SYSREG_SPMEVFILT2R0_EL0()),
		SPMEVFILT2R10_EL0(AARCH64_SYSREG_SPMEVFILT2R10_EL0()),
		SPMEVFILT2R11_EL0(AARCH64_SYSREG_SPMEVFILT2R11_EL0()),
		SPMEVFILT2R12_EL0(AARCH64_SYSREG_SPMEVFILT2R12_EL0()),
		SPMEVFILT2R13_EL0(AARCH64_SYSREG_SPMEVFILT2R13_EL0()),
		SPMEVFILT2R14_EL0(AARCH64_SYSREG_SPMEVFILT2R14_EL0()),
		SPMEVFILT2R15_EL0(AARCH64_SYSREG_SPMEVFILT2R15_EL0()),
		SPMEVFILT2R1_EL0(AARCH64_SYSREG_SPMEVFILT2R1_EL0()),
		SPMEVFILT2R2_EL0(AARCH64_SYSREG_SPMEVFILT2R2_EL0()),
		SPMEVFILT2R3_EL0(AARCH64_SYSREG_SPMEVFILT2R3_EL0()),
		SPMEVFILT2R4_EL0(AARCH64_SYSREG_SPMEVFILT2R4_EL0()),
		SPMEVFILT2R5_EL0(AARCH64_SYSREG_SPMEVFILT2R5_EL0()),
		SPMEVFILT2R6_EL0(AARCH64_SYSREG_SPMEVFILT2R6_EL0()),
		SPMEVFILT2R7_EL0(AARCH64_SYSREG_SPMEVFILT2R7_EL0()),
		SPMEVFILT2R8_EL0(AARCH64_SYSREG_SPMEVFILT2R8_EL0()),
		SPMEVFILT2R9_EL0(AARCH64_SYSREG_SPMEVFILT2R9_EL0()),
		SPMEVFILTR0_EL0(AARCH64_SYSREG_SPMEVFILTR0_EL0()),
		SPMEVFILTR10_EL0(AARCH64_SYSREG_SPMEVFILTR10_EL0()),
		SPMEVFILTR11_EL0(AARCH64_SYSREG_SPMEVFILTR11_EL0()),
		SPMEVFILTR12_EL0(AARCH64_SYSREG_SPMEVFILTR12_EL0()),
		SPMEVFILTR13_EL0(AARCH64_SYSREG_SPMEVFILTR13_EL0()),
		SPMEVFILTR14_EL0(AARCH64_SYSREG_SPMEVFILTR14_EL0()),
		SPMEVFILTR15_EL0(AARCH64_SYSREG_SPMEVFILTR15_EL0()),
		SPMEVFILTR1_EL0(AARCH64_SYSREG_SPMEVFILTR1_EL0()),
		SPMEVFILTR2_EL0(AARCH64_SYSREG_SPMEVFILTR2_EL0()),
		SPMEVFILTR3_EL0(AARCH64_SYSREG_SPMEVFILTR3_EL0()),
		SPMEVFILTR4_EL0(AARCH64_SYSREG_SPMEVFILTR4_EL0()),
		SPMEVFILTR5_EL0(AARCH64_SYSREG_SPMEVFILTR5_EL0()),
		SPMEVFILTR6_EL0(AARCH64_SYSREG_SPMEVFILTR6_EL0()),
		SPMEVFILTR7_EL0(AARCH64_SYSREG_SPMEVFILTR7_EL0()),
		SPMEVFILTR8_EL0(AARCH64_SYSREG_SPMEVFILTR8_EL0()),
		SPMEVFILTR9_EL0(AARCH64_SYSREG_SPMEVFILTR9_EL0()),
		SPMEVTYPER0_EL0(AARCH64_SYSREG_SPMEVTYPER0_EL0()),
		SPMEVTYPER10_EL0(AARCH64_SYSREG_SPMEVTYPER10_EL0()),
		SPMEVTYPER11_EL0(AARCH64_SYSREG_SPMEVTYPER11_EL0()),
		SPMEVTYPER12_EL0(AARCH64_SYSREG_SPMEVTYPER12_EL0()),
		SPMEVTYPER13_EL0(AARCH64_SYSREG_SPMEVTYPER13_EL0()),
		SPMEVTYPER14_EL0(AARCH64_SYSREG_SPMEVTYPER14_EL0()),
		SPMEVTYPER15_EL0(AARCH64_SYSREG_SPMEVTYPER15_EL0()),
		SPMEVTYPER1_EL0(AARCH64_SYSREG_SPMEVTYPER1_EL0()),
		SPMEVTYPER2_EL0(AARCH64_SYSREG_SPMEVTYPER2_EL0()),
		SPMEVTYPER3_EL0(AARCH64_SYSREG_SPMEVTYPER3_EL0()),
		SPMEVTYPER4_EL0(AARCH64_SYSREG_SPMEVTYPER4_EL0()),
		SPMEVTYPER5_EL0(AARCH64_SYSREG_SPMEVTYPER5_EL0()),
		SPMEVTYPER6_EL0(AARCH64_SYSREG_SPMEVTYPER6_EL0()),
		SPMEVTYPER7_EL0(AARCH64_SYSREG_SPMEVTYPER7_EL0()),
		SPMEVTYPER8_EL0(AARCH64_SYSREG_SPMEVTYPER8_EL0()),
		SPMEVTYPER9_EL0(AARCH64_SYSREG_SPMEVTYPER9_EL0()),
		SPMIIDR_EL1(AARCH64_SYSREG_SPMIIDR_EL1()),
		SPMINTENCLR_EL1(AARCH64_SYSREG_SPMINTENCLR_EL1()),
		SPMINTENSET_EL1(AARCH64_SYSREG_SPMINTENSET_EL1()),
		SPMOVSCLR_EL0(AARCH64_SYSREG_SPMOVSCLR_EL0()),
		SPMOVSSET_EL0(AARCH64_SYSREG_SPMOVSSET_EL0()),
		SPMROOTCR_EL3(AARCH64_SYSREG_SPMROOTCR_EL3()),
		SPMSCR_EL1(AARCH64_SYSREG_SPMSCR_EL1()),
		SPMSELR_EL0(AARCH64_SYSREG_SPMSELR_EL0()),
		SPMZR_EL0(AARCH64_SYSREG_SPMZR_EL0()),
		SPSEL(AARCH64_SYSREG_SPSEL()),
		SPSR_ABT(AARCH64_SYSREG_SPSR_ABT()),
		SPSR_EL1(AARCH64_SYSREG_SPSR_EL1()),
		SPSR_EL12(AARCH64_SYSREG_SPSR_EL12()),
		SPSR_EL2(AARCH64_SYSREG_SPSR_EL2()),
		SPSR_EL3(AARCH64_SYSREG_SPSR_EL3()),
		SPSR_FIQ(AARCH64_SYSREG_SPSR_FIQ()),
		SPSR_IRQ(AARCH64_SYSREG_SPSR_IRQ()),
		SPSR_UND(AARCH64_SYSREG_SPSR_UND()),
		SP_EL0(AARCH64_SYSREG_SP_EL0()),
		SP_EL1(AARCH64_SYSREG_SP_EL1()),
		SP_EL2(AARCH64_SYSREG_SP_EL2()),
		SSBS(AARCH64_SYSREG_SSBS()),
		SVCR(AARCH64_SYSREG_SVCR()),
		TCO(AARCH64_SYSREG_TCO()),
		TCR2_EL1(AARCH64_SYSREG_TCR2_EL1()),
		TCR2_EL12(AARCH64_SYSREG_TCR2_EL12()),
		TCR2_EL2(AARCH64_SYSREG_TCR2_EL2()),
		TCR_EL1(AARCH64_SYSREG_TCR_EL1()),
		TCR_EL12(AARCH64_SYSREG_TCR_EL12()),
		TCR_EL2(AARCH64_SYSREG_TCR_EL2()),
		TCR_EL3(AARCH64_SYSREG_TCR_EL3()),
		TEECR32_EL1(AARCH64_SYSREG_TEECR32_EL1()),
		TEEHBR32_EL1(AARCH64_SYSREG_TEEHBR32_EL1()),
		TFSRE0_EL1(AARCH64_SYSREG_TFSRE0_EL1()),
		TFSR_EL1(AARCH64_SYSREG_TFSR_EL1()),
		TFSR_EL12(AARCH64_SYSREG_TFSR_EL12()),
		TFSR_EL2(AARCH64_SYSREG_TFSR_EL2()),
		TFSR_EL3(AARCH64_SYSREG_TFSR_EL3()),
		TPIDR2_EL0(AARCH64_SYSREG_TPIDR2_EL0()),
		TPIDRRO_EL0(AARCH64_SYSREG_TPIDRRO_EL0()),
		TPIDR_EL0(AARCH64_SYSREG_TPIDR_EL0()),
		TPIDR_EL1(AARCH64_SYSREG_TPIDR_EL1()),
		TPIDR_EL2(AARCH64_SYSREG_TPIDR_EL2()),
		TPIDR_EL3(AARCH64_SYSREG_TPIDR_EL3()),
		TRBBASER_EL1(AARCH64_SYSREG_TRBBASER_EL1()),
		TRBIDR_EL1(AARCH64_SYSREG_TRBIDR_EL1()),
		TRBLIMITR_EL1(AARCH64_SYSREG_TRBLIMITR_EL1()),
		TRBMAR_EL1(AARCH64_SYSREG_TRBMAR_EL1()),
		TRBPTR_EL1(AARCH64_SYSREG_TRBPTR_EL1()),
		TRBSR_EL1(AARCH64_SYSREG_TRBSR_EL1()),
		TRBTRG_EL1(AARCH64_SYSREG_TRBTRG_EL1()),
		TRCACATR0(AARCH64_SYSREG_TRCACATR0()),
		TRCACATR1(AARCH64_SYSREG_TRCACATR1()),
		TRCACATR10(AARCH64_SYSREG_TRCACATR10()),
		TRCACATR11(AARCH64_SYSREG_TRCACATR11()),
		TRCACATR12(AARCH64_SYSREG_TRCACATR12()),
		TRCACATR13(AARCH64_SYSREG_TRCACATR13()),
		TRCACATR14(AARCH64_SYSREG_TRCACATR14()),
		TRCACATR15(AARCH64_SYSREG_TRCACATR15()),
		TRCACATR2(AARCH64_SYSREG_TRCACATR2()),
		TRCACATR3(AARCH64_SYSREG_TRCACATR3()),
		TRCACATR4(AARCH64_SYSREG_TRCACATR4()),
		TRCACATR5(AARCH64_SYSREG_TRCACATR5()),
		TRCACATR6(AARCH64_SYSREG_TRCACATR6()),
		TRCACATR7(AARCH64_SYSREG_TRCACATR7()),
		TRCACATR8(AARCH64_SYSREG_TRCACATR8()),
		TRCACATR9(AARCH64_SYSREG_TRCACATR9()),
		TRCACVR0(AARCH64_SYSREG_TRCACVR0()),
		TRCACVR1(AARCH64_SYSREG_TRCACVR1()),
		TRCACVR10(AARCH64_SYSREG_TRCACVR10()),
		TRCACVR11(AARCH64_SYSREG_TRCACVR11()),
		TRCACVR12(AARCH64_SYSREG_TRCACVR12()),
		TRCACVR13(AARCH64_SYSREG_TRCACVR13()),
		TRCACVR14(AARCH64_SYSREG_TRCACVR14()),
		TRCACVR15(AARCH64_SYSREG_TRCACVR15()),
		TRCACVR2(AARCH64_SYSREG_TRCACVR2()),
		TRCACVR3(AARCH64_SYSREG_TRCACVR3()),
		TRCACVR4(AARCH64_SYSREG_TRCACVR4()),
		TRCACVR5(AARCH64_SYSREG_TRCACVR5()),
		TRCACVR6(AARCH64_SYSREG_TRCACVR6()),
		TRCACVR7(AARCH64_SYSREG_TRCACVR7()),
		TRCACVR8(AARCH64_SYSREG_TRCACVR8()),
		TRCACVR9(AARCH64_SYSREG_TRCACVR9()),
		TRCAUTHSTATUS(AARCH64_SYSREG_TRCAUTHSTATUS()),
		TRCAUXCTLR(AARCH64_SYSREG_TRCAUXCTLR()),
		TRCBBCTLR(AARCH64_SYSREG_TRCBBCTLR()),
		TRCCCCTLR(AARCH64_SYSREG_TRCCCCTLR()),
		TRCCIDCCTLR0(AARCH64_SYSREG_TRCCIDCCTLR0()),
		TRCCIDCCTLR1(AARCH64_SYSREG_TRCCIDCCTLR1()),
		TRCCIDCVR0(AARCH64_SYSREG_TRCCIDCVR0()),
		TRCCIDCVR1(AARCH64_SYSREG_TRCCIDCVR1()),
		TRCCIDCVR2(AARCH64_SYSREG_TRCCIDCVR2()),
		TRCCIDCVR3(AARCH64_SYSREG_TRCCIDCVR3()),
		TRCCIDCVR4(AARCH64_SYSREG_TRCCIDCVR4()),
		TRCCIDCVR5(AARCH64_SYSREG_TRCCIDCVR5()),
		TRCCIDCVR6(AARCH64_SYSREG_TRCCIDCVR6()),
		TRCCIDCVR7(AARCH64_SYSREG_TRCCIDCVR7()),
		TRCCIDR0(AARCH64_SYSREG_TRCCIDR0()),
		TRCCIDR1(AARCH64_SYSREG_TRCCIDR1()),
		TRCCIDR2(AARCH64_SYSREG_TRCCIDR2()),
		TRCCIDR3(AARCH64_SYSREG_TRCCIDR3()),
		TRCCLAIMCLR(AARCH64_SYSREG_TRCCLAIMCLR()),
		TRCCLAIMSET(AARCH64_SYSREG_TRCCLAIMSET()),
		TRCCNTCTLR0(AARCH64_SYSREG_TRCCNTCTLR0()),
		TRCCNTCTLR1(AARCH64_SYSREG_TRCCNTCTLR1()),
		TRCCNTCTLR2(AARCH64_SYSREG_TRCCNTCTLR2()),
		TRCCNTCTLR3(AARCH64_SYSREG_TRCCNTCTLR3()),
		TRCCNTRLDVR0(AARCH64_SYSREG_TRCCNTRLDVR0()),
		TRCCNTRLDVR1(AARCH64_SYSREG_TRCCNTRLDVR1()),
		TRCCNTRLDVR2(AARCH64_SYSREG_TRCCNTRLDVR2()),
		TRCCNTRLDVR3(AARCH64_SYSREG_TRCCNTRLDVR3()),
		TRCCNTVR0(AARCH64_SYSREG_TRCCNTVR0()),
		TRCCNTVR1(AARCH64_SYSREG_TRCCNTVR1()),
		TRCCNTVR2(AARCH64_SYSREG_TRCCNTVR2()),
		TRCCNTVR3(AARCH64_SYSREG_TRCCNTVR3()),
		TRCCONFIGR(AARCH64_SYSREG_TRCCONFIGR()),
		TRCDEVAFF0(AARCH64_SYSREG_TRCDEVAFF0()),
		TRCDEVAFF1(AARCH64_SYSREG_TRCDEVAFF1()),
		TRCDEVARCH(AARCH64_SYSREG_TRCDEVARCH()),
		TRCDEVID(AARCH64_SYSREG_TRCDEVID()),
		TRCDEVTYPE(AARCH64_SYSREG_TRCDEVTYPE()),
		TRCDVCMR0(AARCH64_SYSREG_TRCDVCMR0()),
		TRCDVCMR1(AARCH64_SYSREG_TRCDVCMR1()),
		TRCDVCMR2(AARCH64_SYSREG_TRCDVCMR2()),
		TRCDVCMR3(AARCH64_SYSREG_TRCDVCMR3()),
		TRCDVCMR4(AARCH64_SYSREG_TRCDVCMR4()),
		TRCDVCMR5(AARCH64_SYSREG_TRCDVCMR5()),
		TRCDVCMR6(AARCH64_SYSREG_TRCDVCMR6()),
		TRCDVCMR7(AARCH64_SYSREG_TRCDVCMR7()),
		TRCDVCVR0(AARCH64_SYSREG_TRCDVCVR0()),
		TRCDVCVR1(AARCH64_SYSREG_TRCDVCVR1()),
		TRCDVCVR2(AARCH64_SYSREG_TRCDVCVR2()),
		TRCDVCVR3(AARCH64_SYSREG_TRCDVCVR3()),
		TRCDVCVR4(AARCH64_SYSREG_TRCDVCVR4()),
		TRCDVCVR5(AARCH64_SYSREG_TRCDVCVR5()),
		TRCDVCVR6(AARCH64_SYSREG_TRCDVCVR6()),
		TRCDVCVR7(AARCH64_SYSREG_TRCDVCVR7()),
		TRCEVENTCTL0R(AARCH64_SYSREG_TRCEVENTCTL0R()),
		TRCEVENTCTL1R(AARCH64_SYSREG_TRCEVENTCTL1R()),
		TRCEXTINSELR(AARCH64_SYSREG_TRCEXTINSELR()),
		TRCEXTINSELR0(AARCH64_SYSREG_TRCEXTINSELR0()),
		TRCEXTINSELR1(AARCH64_SYSREG_TRCEXTINSELR1()),
		TRCEXTINSELR2(AARCH64_SYSREG_TRCEXTINSELR2()),
		TRCEXTINSELR3(AARCH64_SYSREG_TRCEXTINSELR3()),
		TRCIDR0(AARCH64_SYSREG_TRCIDR0()),
		TRCIDR1(AARCH64_SYSREG_TRCIDR1()),
		TRCIDR10(AARCH64_SYSREG_TRCIDR10()),
		TRCIDR11(AARCH64_SYSREG_TRCIDR11()),
		TRCIDR12(AARCH64_SYSREG_TRCIDR12()),
		TRCIDR13(AARCH64_SYSREG_TRCIDR13()),
		TRCIDR2(AARCH64_SYSREG_TRCIDR2()),
		TRCIDR3(AARCH64_SYSREG_TRCIDR3()),
		TRCIDR4(AARCH64_SYSREG_TRCIDR4()),
		TRCIDR5(AARCH64_SYSREG_TRCIDR5()),
		TRCIDR6(AARCH64_SYSREG_TRCIDR6()),
		TRCIDR7(AARCH64_SYSREG_TRCIDR7()),
		TRCIDR8(AARCH64_SYSREG_TRCIDR8()),
		TRCIDR9(AARCH64_SYSREG_TRCIDR9()),
		TRCIMSPEC0(AARCH64_SYSREG_TRCIMSPEC0()),
		TRCIMSPEC1(AARCH64_SYSREG_TRCIMSPEC1()),
		TRCIMSPEC2(AARCH64_SYSREG_TRCIMSPEC2()),
		TRCIMSPEC3(AARCH64_SYSREG_TRCIMSPEC3()),
		TRCIMSPEC4(AARCH64_SYSREG_TRCIMSPEC4()),
		TRCIMSPEC5(AARCH64_SYSREG_TRCIMSPEC5()),
		TRCIMSPEC6(AARCH64_SYSREG_TRCIMSPEC6()),
		TRCIMSPEC7(AARCH64_SYSREG_TRCIMSPEC7()),
		TRCITCTRL(AARCH64_SYSREG_TRCITCTRL()),
		TRCITECR_EL1(AARCH64_SYSREG_TRCITECR_EL1()),
		TRCITECR_EL12(AARCH64_SYSREG_TRCITECR_EL12()),
		TRCITECR_EL2(AARCH64_SYSREG_TRCITECR_EL2()),
		TRCITEEDCR(AARCH64_SYSREG_TRCITEEDCR()),
		TRCLAR(AARCH64_SYSREG_TRCLAR()),
		TRCLSR(AARCH64_SYSREG_TRCLSR()),
		TRCOSLAR(AARCH64_SYSREG_TRCOSLAR()),
		TRCOSLSR(AARCH64_SYSREG_TRCOSLSR()),
		TRCPDCR(AARCH64_SYSREG_TRCPDCR()),
		TRCPDSR(AARCH64_SYSREG_TRCPDSR()),
		TRCPIDR0(AARCH64_SYSREG_TRCPIDR0()),
		TRCPIDR1(AARCH64_SYSREG_TRCPIDR1()),
		TRCPIDR2(AARCH64_SYSREG_TRCPIDR2()),
		TRCPIDR3(AARCH64_SYSREG_TRCPIDR3()),
		TRCPIDR4(AARCH64_SYSREG_TRCPIDR4()),
		TRCPIDR5(AARCH64_SYSREG_TRCPIDR5()),
		TRCPIDR6(AARCH64_SYSREG_TRCPIDR6()),
		TRCPIDR7(AARCH64_SYSREG_TRCPIDR7()),
		TRCPRGCTLR(AARCH64_SYSREG_TRCPRGCTLR()),
		TRCPROCSELR(AARCH64_SYSREG_TRCPROCSELR()),
		TRCQCTLR(AARCH64_SYSREG_TRCQCTLR()),
		TRCRSCTLR10(AARCH64_SYSREG_TRCRSCTLR10()),
		TRCRSCTLR11(AARCH64_SYSREG_TRCRSCTLR11()),
		TRCRSCTLR12(AARCH64_SYSREG_TRCRSCTLR12()),
		TRCRSCTLR13(AARCH64_SYSREG_TRCRSCTLR13()),
		TRCRSCTLR14(AARCH64_SYSREG_TRCRSCTLR14()),
		TRCRSCTLR15(AARCH64_SYSREG_TRCRSCTLR15()),
		TRCRSCTLR16(AARCH64_SYSREG_TRCRSCTLR16()),
		TRCRSCTLR17(AARCH64_SYSREG_TRCRSCTLR17()),
		TRCRSCTLR18(AARCH64_SYSREG_TRCRSCTLR18()),
		TRCRSCTLR19(AARCH64_SYSREG_TRCRSCTLR19()),
		TRCRSCTLR2(AARCH64_SYSREG_TRCRSCTLR2()),
		TRCRSCTLR20(AARCH64_SYSREG_TRCRSCTLR20()),
		TRCRSCTLR21(AARCH64_SYSREG_TRCRSCTLR21()),
		TRCRSCTLR22(AARCH64_SYSREG_TRCRSCTLR22()),
		TRCRSCTLR23(AARCH64_SYSREG_TRCRSCTLR23()),
		TRCRSCTLR24(AARCH64_SYSREG_TRCRSCTLR24()),
		TRCRSCTLR25(AARCH64_SYSREG_TRCRSCTLR25()),
		TRCRSCTLR26(AARCH64_SYSREG_TRCRSCTLR26()),
		TRCRSCTLR27(AARCH64_SYSREG_TRCRSCTLR27()),
		TRCRSCTLR28(AARCH64_SYSREG_TRCRSCTLR28()),
		TRCRSCTLR29(AARCH64_SYSREG_TRCRSCTLR29()),
		TRCRSCTLR3(AARCH64_SYSREG_TRCRSCTLR3()),
		TRCRSCTLR30(AARCH64_SYSREG_TRCRSCTLR30()),
		TRCRSCTLR31(AARCH64_SYSREG_TRCRSCTLR31()),
		TRCRSCTLR4(AARCH64_SYSREG_TRCRSCTLR4()),
		TRCRSCTLR5(AARCH64_SYSREG_TRCRSCTLR5()),
		TRCRSCTLR6(AARCH64_SYSREG_TRCRSCTLR6()),
		TRCRSCTLR7(AARCH64_SYSREG_TRCRSCTLR7()),
		TRCRSCTLR8(AARCH64_SYSREG_TRCRSCTLR8()),
		TRCRSCTLR9(AARCH64_SYSREG_TRCRSCTLR9()),
		TRCRSR(AARCH64_SYSREG_TRCRSR()),
		TRCSEQEVR0(AARCH64_SYSREG_TRCSEQEVR0()),
		TRCSEQEVR1(AARCH64_SYSREG_TRCSEQEVR1()),
		TRCSEQEVR2(AARCH64_SYSREG_TRCSEQEVR2()),
		TRCSEQRSTEVR(AARCH64_SYSREG_TRCSEQRSTEVR()),
		TRCSEQSTR(AARCH64_SYSREG_TRCSEQSTR()),
		TRCSSCCR0(AARCH64_SYSREG_TRCSSCCR0()),
		TRCSSCCR1(AARCH64_SYSREG_TRCSSCCR1()),
		TRCSSCCR2(AARCH64_SYSREG_TRCSSCCR2()),
		TRCSSCCR3(AARCH64_SYSREG_TRCSSCCR3()),
		TRCSSCCR4(AARCH64_SYSREG_TRCSSCCR4()),
		TRCSSCCR5(AARCH64_SYSREG_TRCSSCCR5()),
		TRCSSCCR6(AARCH64_SYSREG_TRCSSCCR6()),
		TRCSSCCR7(AARCH64_SYSREG_TRCSSCCR7()),
		TRCSSCSR0(AARCH64_SYSREG_TRCSSCSR0()),
		TRCSSCSR1(AARCH64_SYSREG_TRCSSCSR1()),
		TRCSSCSR2(AARCH64_SYSREG_TRCSSCSR2()),
		TRCSSCSR3(AARCH64_SYSREG_TRCSSCSR3()),
		TRCSSCSR4(AARCH64_SYSREG_TRCSSCSR4()),
		TRCSSCSR5(AARCH64_SYSREG_TRCSSCSR5()),
		TRCSSCSR6(AARCH64_SYSREG_TRCSSCSR6()),
		TRCSSCSR7(AARCH64_SYSREG_TRCSSCSR7()),
		TRCSSPCICR0(AARCH64_SYSREG_TRCSSPCICR0()),
		TRCSSPCICR1(AARCH64_SYSREG_TRCSSPCICR1()),
		TRCSSPCICR2(AARCH64_SYSREG_TRCSSPCICR2()),
		TRCSSPCICR3(AARCH64_SYSREG_TRCSSPCICR3()),
		TRCSSPCICR4(AARCH64_SYSREG_TRCSSPCICR4()),
		TRCSSPCICR5(AARCH64_SYSREG_TRCSSPCICR5()),
		TRCSSPCICR6(AARCH64_SYSREG_TRCSSPCICR6()),
		TRCSSPCICR7(AARCH64_SYSREG_TRCSSPCICR7()),
		TRCSTALLCTLR(AARCH64_SYSREG_TRCSTALLCTLR()),
		TRCSTATR(AARCH64_SYSREG_TRCSTATR()),
		TRCSYNCPR(AARCH64_SYSREG_TRCSYNCPR()),
		TRCTRACEIDR(AARCH64_SYSREG_TRCTRACEIDR()),
		TRCTSCTLR(AARCH64_SYSREG_TRCTSCTLR()),
		TRCVDARCCTLR(AARCH64_SYSREG_TRCVDARCCTLR()),
		TRCVDCTLR(AARCH64_SYSREG_TRCVDCTLR()),
		TRCVDSACCTLR(AARCH64_SYSREG_TRCVDSACCTLR()),
		TRCVICTLR(AARCH64_SYSREG_TRCVICTLR()),
		TRCVIIECTLR(AARCH64_SYSREG_TRCVIIECTLR()),
		TRCVIPCSSCTLR(AARCH64_SYSREG_TRCVIPCSSCTLR()),
		TRCVISSCTLR(AARCH64_SYSREG_TRCVISSCTLR()),
		TRCVMIDCCTLR0(AARCH64_SYSREG_TRCVMIDCCTLR0()),
		TRCVMIDCCTLR1(AARCH64_SYSREG_TRCVMIDCCTLR1()),
		TRCVMIDCVR0(AARCH64_SYSREG_TRCVMIDCVR0()),
		TRCVMIDCVR1(AARCH64_SYSREG_TRCVMIDCVR1()),
		TRCVMIDCVR2(AARCH64_SYSREG_TRCVMIDCVR2()),
		TRCVMIDCVR3(AARCH64_SYSREG_TRCVMIDCVR3()),
		TRCVMIDCVR4(AARCH64_SYSREG_TRCVMIDCVR4()),
		TRCVMIDCVR5(AARCH64_SYSREG_TRCVMIDCVR5()),
		TRCVMIDCVR6(AARCH64_SYSREG_TRCVMIDCVR6()),
		TRCVMIDCVR7(AARCH64_SYSREG_TRCVMIDCVR7()),
		TRFCR_EL1(AARCH64_SYSREG_TRFCR_EL1()),
		TRFCR_EL12(AARCH64_SYSREG_TRFCR_EL12()),
		TRFCR_EL2(AARCH64_SYSREG_TRFCR_EL2()),
		TTBR0_EL1(AARCH64_SYSREG_TTBR0_EL1()),
		TTBR0_EL12(AARCH64_SYSREG_TTBR0_EL12()),
		TTBR0_EL2(AARCH64_SYSREG_TTBR0_EL2()),
		VSCTLR_EL2(AARCH64_SYSREG_VSCTLR_EL2()),
		TTBR0_EL3(AARCH64_SYSREG_TTBR0_EL3()),
		TTBR1_EL1(AARCH64_SYSREG_TTBR1_EL1()),
		TTBR1_EL12(AARCH64_SYSREG_TTBR1_EL12()),
		TTBR1_EL2(AARCH64_SYSREG_TTBR1_EL2()),
		UAO(AARCH64_SYSREG_UAO()),
		VBAR_EL1(AARCH64_SYSREG_VBAR_EL1()),
		VBAR_EL12(AARCH64_SYSREG_VBAR_EL12()),
		VBAR_EL2(AARCH64_SYSREG_VBAR_EL2()),
		VBAR_EL3(AARCH64_SYSREG_VBAR_EL3()),
		VDISR_EL2(AARCH64_SYSREG_VDISR_EL2()),
		VDISR_EL3(AARCH64_SYSREG_VDISR_EL3()),
		VMECID_A_EL2(AARCH64_SYSREG_VMECID_A_EL2()),
		VMECID_P_EL2(AARCH64_SYSREG_VMECID_P_EL2()),
		VMPIDR_EL2(AARCH64_SYSREG_VMPIDR_EL2()),
		VNCR_EL2(AARCH64_SYSREG_VNCR_EL2()),
		VPIDR_EL2(AARCH64_SYSREG_VPIDR_EL2()),
		VSESR_EL2(AARCH64_SYSREG_VSESR_EL2()),
		VSESR_EL3(AARCH64_SYSREG_VSESR_EL3()),
		VSTCR_EL2(AARCH64_SYSREG_VSTCR_EL2()),
		VSTTBR_EL2(AARCH64_SYSREG_VSTTBR_EL2()),
		VTCR_EL2(AARCH64_SYSREG_VTCR_EL2()),
		VTTBR_EL2(AARCH64_SYSREG_VTTBR_EL2()),
		ZCR_EL1(AARCH64_SYSREG_ZCR_EL1()),
		ZCR_EL12(AARCH64_SYSREG_ZCR_EL12()),
		ZCR_EL2(AARCH64_SYSREG_ZCR_EL2()),
		ZCR_EL3(AARCH64_SYSREG_ZCR_EL3()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SysReg> end
		AARCH64_SYSREG_ENDING(AARCH64_SYSREG_ENDING());

		private final int value;

		private AArch64SysReg(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64SysReg fromValue(int value) {
			for (AArch64SysReg reg : AArch64SysReg.values()) {
				if (reg.value == value) {
					return reg;
				}
			}
			return INVALID;
		}
	}

	static class AArch64SysOpReg {
		private final AArch64SysReg sysReg;
		private final AArch64Tlbi tlbi;
		private final AArch64Ic ic;
		private final int rawVal;

		AArch64SysOpReg(AArch64SysReg sysReg, AArch64Tlbi tlbi, AArch64Ic ic, int rawVal) {
			this.sysReg = sysReg;
			this.tlbi = tlbi;
			this.ic = ic;
			this.rawVal = rawVal;
		}

		public AArch64SysReg getSysReg() {
			return sysReg;
		}

		public AArch64Tlbi getTlbi() {
			return tlbi;
		}

		public AArch64Ic getIc() {
			return ic;
		}

		public int getRawVal() {
			return rawVal;
		}
	}

	static class AArch64SysOpImm {
		private final AArch64Dbnxs dbnxs;
		private final AArch64ExactFpImm exactFpImm;
		private final int rawVal;

		AArch64SysOpImm(AArch64Dbnxs dbnxs, AArch64ExactFpImm exactFpImm, int rawVal) {
			this.dbnxs = dbnxs;
			this.exactFpImm = exactFpImm;
			this.rawVal = rawVal;
		}

		public AArch64Dbnxs getDbnxs() {
			return dbnxs;
		}

		public AArch64ExactFpImm getExactFpImm() {
			return exactFpImm;
		}

		public int getRawVal() {
			return rawVal;
		}
	}

	static class AArch64SysOpAlias {
		private final AArch64Svcr svcr;
		private final AArch64At at;
		private final AArch64Db db;
		private final AArch64Dc dc;
		private final AArch64Isb isb;
		private final AArch64Tsb tsb;
		private final AArch64Prfm prfm;
		private final AArch64Sveprfm sveprfm;
		private final AArch64Rprfm rprfm;
		private final AArch64PStateImm015 pStateImm015;
		private final AArch64PStateImm01 pStateImm01;
		private final AArch64Psb psb;
		private final AArch64Bti bti;
		private final AArch64Svepredpat svepredpat;
		private final AArch64SveveclenSpecifier sveveclenSpecifier;
		private final int rawVal;

		AArch64SysOpAlias(AArch64Svcr svcr, AArch64At at, AArch64Db db, AArch64Dc dc, AArch64Isb isb, AArch64Tsb tsb, AArch64Prfm prfm, AArch64Sveprfm sveprfm, AArch64Rprfm rprfm, AArch64PStateImm015 pStateImm015, AArch64PStateImm01 pStateImm01, AArch64Psb psb, AArch64Bti bti, AArch64Svepredpat svepredpat, AArch64SveveclenSpecifier sveveclenSpecifier, int rawVal) {
			this.svcr = svcr;
			this.at = at;
			this.db = db;
			this.dc = dc;
			this.isb = isb;
			this.tsb = tsb;
			this.prfm = prfm;
			this.sveprfm = sveprfm;
			this.rprfm = rprfm;
			this.pStateImm015 = pStateImm015;
			this.pStateImm01 = pStateImm01;
			this.psb = psb;
			this.bti = bti;
			this.svepredpat = svepredpat;
			this.sveveclenSpecifier = sveveclenSpecifier;
			this.rawVal = rawVal;
		}

		public AArch64Svcr getSvcr() {
			return svcr;
		}

		public AArch64At getAt() {
			return at;
		}

		public AArch64Db getDb() {
			return db;
		}

		public AArch64Dc getDc() {
			return dc;
		}

		public AArch64Isb getIsb() {
			return isb;
		}

		public AArch64Tsb getTsb() {
			return tsb;
		}

		public AArch64Prfm getPrfm() {
			return prfm;
		}

		public AArch64Sveprfm getSveprfm() {
			return sveprfm;
		}

		public AArch64Rprfm getRprfm() {
			return rprfm;
		}

		public AArch64PStateImm015 getPStateImm015() {
			return pStateImm015;
		}

		public AArch64PStateImm01 getPStateImm01() {
			return pStateImm01;
		}

		public AArch64Psb getPsb() {
			return psb;
		}

		public AArch64Bti getBti() {
			return bti;
		}

		public AArch64Svepredpat getSvepredpat() {
			return svepredpat;
		}

		public AArch64SveveclenSpecifier getSveveclenSpecifier() {
			return sveveclenSpecifier;
		}

		public int getRawVal() {
			return rawVal;
		}
	}

	public enum AArch64Tsb {
		CSYNC(AARCH64_TSB_CSYNC()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_TSB> end
		ENDING(AARCH64_TSB_ENDING());

		private final int value;

		private AArch64Tsb(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Tsb fromValue(int value) {
			for (AArch64Tsb tsb : AArch64Tsb.values()) {
				if (tsb.value == value) {
					return tsb;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64SveveclenSpecifier {
		VLX2(AARCH64_SVEVECLENSPECIFIER_VLX2()),
		VLX4(AARCH64_SVEVECLENSPECIFIER_VLX4()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVEVECLENSPECIFIER> end
		ENDING(AARCH64_SVEVECLENSPECIFIER_ENDING());

		private final int value;

		private AArch64SveveclenSpecifier(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64SveveclenSpecifier fromValue(int value) {
			for (AArch64SveveclenSpecifier sveveclenSpecifier : AArch64SveveclenSpecifier.values()) {
				if (sveveclenSpecifier.value == value) {
					return sveveclenSpecifier;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Sveprfm {
		PLDL1KEEP(AARCH64_SVEPRFM_PLDL1KEEP()),
		PLDL1STRM(AARCH64_SVEPRFM_PLDL1STRM()),
		PLDL2KEEP(AARCH64_SVEPRFM_PLDL2KEEP()),
		PLDL2STRM(AARCH64_SVEPRFM_PLDL2STRM()),
		PLDL3KEEP(AARCH64_SVEPRFM_PLDL3KEEP()),
		PLDL3STRM(AARCH64_SVEPRFM_PLDL3STRM()),
		PSTL1KEEP(AARCH64_SVEPRFM_PSTL1KEEP()),
		PSTL1STRM(AARCH64_SVEPRFM_PSTL1STRM()),
		PSTL2KEEP(AARCH64_SVEPRFM_PSTL2KEEP()),
		PSTL2STRM(AARCH64_SVEPRFM_PSTL2STRM()),
		PSTL3KEEP(AARCH64_SVEPRFM_PSTL3KEEP()),
		PSTL3STRM(AARCH64_SVEPRFM_PSTL3STRM()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVEPRFM> end
		ENDING(AARCH64_SVEPRFM_ENDING());

		private final int value;

		private AArch64Sveprfm(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Sveprfm fromValue(int value) {
			for (AArch64Sveprfm sveprfm : AArch64Sveprfm.values()) {
				if (sveprfm.value == value) {
					return sveprfm;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Svepredpat {
		ALL(AARCH64_SVEPREDPAT_ALL()),
		MUL3(AARCH64_SVEPREDPAT_MUL3()),
		MUL4(AARCH64_SVEPREDPAT_MUL4()),
		POW2(AARCH64_SVEPREDPAT_POW2()),
		VL1(AARCH64_SVEPREDPAT_VL1()),
		VL128(AARCH64_SVEPREDPAT_VL128()),
		VL16(AARCH64_SVEPREDPAT_VL16()),
		VL2(AARCH64_SVEPREDPAT_VL2()),
		VL256(AARCH64_SVEPREDPAT_VL256()),
		VL3(AARCH64_SVEPREDPAT_VL3()),
		VL32(AARCH64_SVEPREDPAT_VL32()),
		VL4(AARCH64_SVEPREDPAT_VL4()),
		VL5(AARCH64_SVEPREDPAT_VL5()),
		VL6(AARCH64_SVEPREDPAT_VL6()),
		VL64(AARCH64_SVEPREDPAT_VL64()),
		VL7(AARCH64_SVEPREDPAT_VL7()),
		VL8(AARCH64_SVEPREDPAT_VL8()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVEPREDPAT> end
		ENDING(AARCH64_SVEPREDPAT_ENDING());

		private final int value;

		private AArch64Svepredpat(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Svepredpat fromValue(int value) {
			for (AArch64Svepredpat svepredpat : AArch64Svepredpat.values()) {
				if (svepredpat.value == value) {
					return svepredpat;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Prfm {
		PLDL1KEEP(AARCH64_PRFM_PLDL1KEEP()),
		PLDL1STRM(AARCH64_PRFM_PLDL1STRM()),
		PLDL2KEEP(AARCH64_PRFM_PLDL2KEEP()),
		PLDL2STRM(AARCH64_PRFM_PLDL2STRM()),
		PLDL3KEEP(AARCH64_PRFM_PLDL3KEEP()),
		PLDL3STRM(AARCH64_PRFM_PLDL3STRM()),
		PLDSLCKEEP(AARCH64_PRFM_PLDSLCKEEP()),
		PLDSLCSTRM(AARCH64_PRFM_PLDSLCSTRM()),
		PLIL1KEEP(AARCH64_PRFM_PLIL1KEEP()),
		PLIL1STRM(AARCH64_PRFM_PLIL1STRM()),
		PLIL2KEEP(AARCH64_PRFM_PLIL2KEEP()),
		PLIL2STRM(AARCH64_PRFM_PLIL2STRM()),
		PLIL3KEEP(AARCH64_PRFM_PLIL3KEEP()),
		PLIL3STRM(AARCH64_PRFM_PLIL3STRM()),
		PLISLCKEEP(AARCH64_PRFM_PLISLCKEEP()),
		PLISLCSTRM(AARCH64_PRFM_PLISLCSTRM()),
		PSTL1KEEP(AARCH64_PRFM_PSTL1KEEP()),
		PSTL1STRM(AARCH64_PRFM_PSTL1STRM()),
		PSTL2KEEP(AARCH64_PRFM_PSTL2KEEP()),
		PSTL2STRM(AARCH64_PRFM_PSTL2STRM()),
		PSTL3KEEP(AARCH64_PRFM_PSTL3KEEP()),
		PSTL3STRM(AARCH64_PRFM_PSTL3STRM()),
		PSTSLCKEEP(AARCH64_PRFM_PSTSLCKEEP()),
		PSTSLCSTRM(AARCH64_PRFM_PSTSLCSTRM()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PRFM> end
		ENDING(AARCH64_PRFM_ENDING());

		private final int value;

		private AArch64Prfm(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Prfm fromValue(int value) {
			for (AArch64Prfm prfm : AArch64Prfm.values()) {
				if (prfm.value == value) {
					return prfm;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Isb {
		SY(AARCH64_ISB_SY()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_ISB> end
		ENDING(AARCH64_ISB_ENDING());

		private final int value;

		private AArch64Isb(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Isb fromValue(int value) {
			for (AArch64Isb isb : AArch64Isb.values()) {
				if (isb.value == value) {
					return isb;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Dc {
		CGDSW(AARCH64_DC_CGDSW()),
		CGDVAC(AARCH64_DC_CGDVAC()),
		CGDVADP(AARCH64_DC_CGDVADP()),
		CGDVAP(AARCH64_DC_CGDVAP()),
		CGSW(AARCH64_DC_CGSW()),
		CGVAC(AARCH64_DC_CGVAC()),
		CGVADP(AARCH64_DC_CGVADP()),
		CGVAP(AARCH64_DC_CGVAP()),
		CIGDPAE(AARCH64_DC_CIGDPAE()),
		CIGDSW(AARCH64_DC_CIGDSW()),
		CIGDVAC(AARCH64_DC_CIGDVAC()),
		CIGSW(AARCH64_DC_CIGSW()),
		CIGVAC(AARCH64_DC_CIGVAC()),
		CIPAE(AARCH64_DC_CIPAE()),
		CISW(AARCH64_DC_CISW()),
		CIVAC(AARCH64_DC_CIVAC()),
		CSW(AARCH64_DC_CSW()),
		CVAC(AARCH64_DC_CVAC()),
		CVADP(AARCH64_DC_CVADP()),
		CVAP(AARCH64_DC_CVAP()),
		CVAU(AARCH64_DC_CVAU()),
		GVA(AARCH64_DC_GVA()),
		GZVA(AARCH64_DC_GZVA()),
		IGDSW(AARCH64_DC_IGDSW()),
		IGDVAC(AARCH64_DC_IGDVAC()),
		IGSW(AARCH64_DC_IGSW()),
		IGVAC(AARCH64_DC_IGVAC()),
		ISW(AARCH64_DC_ISW()),
		IVAC(AARCH64_DC_IVAC()),
		ZVA(AARCH64_DC_ZVA()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_DC> end
		ENDING(AARCH64_DC_ENDING());

		private final int value;

		private AArch64Dc(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Dc fromValue(int value) {
			for (AArch64Dc dc : AArch64Dc.values()) {
				if (dc.value == value) {
					return dc;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Db {
		ISH(AARCH64_DB_ISH()),
		ISHLD(AARCH64_DB_ISHLD()),
		ISHST(AARCH64_DB_ISHST()),
		LD(AARCH64_DB_LD()),
		NSH(AARCH64_DB_NSH()),
		NSHLD(AARCH64_DB_NSHLD()),
		NSHST(AARCH64_DB_NSHST()),
		OSH(AARCH64_DB_OSH()),
		OSHLD(AARCH64_DB_OSHLD()),
		OSHST(AARCH64_DB_OSHST()),
		ST(AARCH64_DB_ST()),
		SY(AARCH64_DB_SY()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_DB> end
		ENDING(AARCH64_DB_ENDING());

		private final int value;

		private AArch64Db(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Db fromValue(int value) {
			for (AArch64Db db : AArch64Db.values()) {
				if (db.value == value) {
					return db;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Bti {
		C(AARCH64_BTI_C()),
		J(AARCH64_BTI_J()),
		JC(AARCH64_BTI_JC()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_BTI> end
		ENDING(AARCH64_BTI_ENDING());

		private final int value;

		private AArch64Bti(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Bti fromValue(int value) {
			for (AArch64Bti bti : AArch64Bti.values()) {
				if (bti.value == value) {
					return bti;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64At {
		S12E0R(AARCH64_AT_S12E0R()),
		S12E0W(AARCH64_AT_S12E0W()),
		S12E1R(AARCH64_AT_S12E1R()),
		S12E1W(AARCH64_AT_S12E1W()),
		S1E0R(AARCH64_AT_S1E0R()),
		S1E0W(AARCH64_AT_S1E0W()),
		S1E1A(AARCH64_AT_S1E1A()),
		S1E1R(AARCH64_AT_S1E1R()),
		S1E1RP(AARCH64_AT_S1E1RP()),
		S1E1W(AARCH64_AT_S1E1W()),
		S1E1WP(AARCH64_AT_S1E1WP()),
		S1E2A(AARCH64_AT_S1E2A()),
		S1E2R(AARCH64_AT_S1E2R()),
		S1E2W(AARCH64_AT_S1E2W()),
		S1E3A(AARCH64_AT_S1E3A()),
		S1E3R(AARCH64_AT_S1E3R()),
		S1E3W(AARCH64_AT_S1E3W()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_AT> end
		ENDING(AARCH64_AT_ENDING());

		private final int value;

		private AArch64At(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64At fromValue(int value) {
			for (AArch64At at : AArch64At.values()) {
				if (at.value == value) {
					return at;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Psb {
		CSYNC(AARCH64_PSB_CSYNC()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PSB> end
		ENDING(AARCH64_PSB_ENDING());

		private final int value;

		private AArch64Psb(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Psb fromValue(int value) {
			for (AArch64Psb psb : AArch64Psb.values()) {
				if (psb.value == value) {
					return psb;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64PStateImm01 {
		ALLINT(AARCH64_PSTATEIMM0_1_ALLINT()),
		PM(AARCH64_PSTATEIMM0_1_PM()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PStateImm0_1> end
		ENDING(AARCH64_PSTATEIMM0_1_ENDING());

		private final int value;

		private AArch64PStateImm01(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64PStateImm01 fromValue(int value) {
			for (AArch64PStateImm01 pStateImm01 : AArch64PStateImm01.values()) {
				if (pStateImm01.value == value) {
					return pStateImm01;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64PStateImm015 {
		DAIFCLR(AARCH64_PSTATEIMM0_15_DAIFCLR()),
		DAIFSET(AARCH64_PSTATEIMM0_15_DAIFSET()),
		DIT(AARCH64_PSTATEIMM0_15_DIT()),
		PAN(AARCH64_PSTATEIMM0_15_PAN()),
		SPSEL(AARCH64_PSTATEIMM0_15_SPSEL()),
		SSBS(AARCH64_PSTATEIMM0_15_SSBS()),
		TCO(AARCH64_PSTATEIMM0_15_TCO()),
		UAO(AARCH64_PSTATEIMM0_15_UAO()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PStateImm0_15> end
		ENDING(AARCH64_PSTATEIMM0_15_ENDING());

		private final int value;

		private AArch64PStateImm015(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64PStateImm015 fromValue(int value) {
			for (AArch64PStateImm015 pStateImm015 : AArch64PStateImm015.values()) {
				if (pStateImm015.value == value) {
					return pStateImm015;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Rprfm {
		PLDKEEP(AARCH64_RPRFM_PLDKEEP()),
		PLDSTRM(AARCH64_RPRFM_PLDSTRM()),
		PSTKEEP(AARCH64_RPRFM_PSTKEEP()),
		PSTSTRM(AARCH64_RPRFM_PSTSTRM()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_RPRFM> end
		ENDING(AARCH64_RPRFM_ENDING());

		private final int value;

		private AArch64Rprfm(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Rprfm fromValue(int value) {
			for (AArch64Rprfm rprfm : AArch64Rprfm.values()) {
				if (rprfm.value == value) {
					return rprfm;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Svcr {
		SVCRSM(AARCH64_SVCR_SVCRSM()),
		SVCRSMZA(AARCH64_SVCR_SVCRSMZA()),
		SVCRZA(AARCH64_SVCR_SVCRZA()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVCR> end
		ENDING(AARCH64_SVCR_ENDING());

		private final int value;

		private AArch64Svcr(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Svcr fromValue(int value) {
			for (AArch64Svcr svcr : AArch64Svcr.values()) {
				if (svcr.value == value) {
					return svcr;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	static class AArch64SysOp {
		private final AArch64SysOpReg reg;
		private final AArch64SysOpImm imm;
		private final AArch64SysOpAlias alias;
		private final AArch64OperandType subType;

		AArch64SysOp(AArch64SysOpReg reg, AArch64SysOpImm imm, AArch64SysOpAlias alias, AArch64OperandType subType) {
			this.reg = reg;
			this.imm = imm;
			this.alias = alias;
			this.subType = subType;
		}

		public AArch64SysOpReg getReg() {
			return reg;
		}

		public AArch64SysOpImm getImm() {
			return imm;
		}

		public AArch64SysOpAlias getAlias() {
			return alias;
		}

		public AArch64OperandType getSubType() {
			return subType;
		}
	}

	public enum AArch64ExactFpImm {
		HALF(AARCH64_EXACTFPIMM_HALF()),
		ONE(AARCH64_EXACTFPIMM_ONE()),
		TWO(AARCH64_EXACTFPIMM_TWO()),
		ZERO(AARCH64_EXACTFPIMM_ZERO()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_ExactFPImm> end
		INVALID(AARCH64_EXACTFPIMM_INVALID()),

		ENDING(AARCH64_EXACTFPIMM_ENDING());

		private final int value;

		private AArch64ExactFpImm(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64ExactFpImm fromValue(int value) {
			for (AArch64ExactFpImm exactFpImm : AArch64ExactFpImm.values()) {
				if (exactFpImm.value == value) {
					return exactFpImm;
				}
			}
			return INVALID;
		}
	}

	public enum AArch64Dbnxs {
		ISHNXS(AARCH64_DBNXS_ISHNXS()),
		NSHNXS(AARCH64_DBNXS_NSHNXS()),
		OSHNXS(AARCH64_DBNXS_OSHNXS()),
		SYNXS(AARCH64_DBNXS_SYNXS()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_DBnXS> end
		ENDING(AARCH64_DBNXS_ENDING());

		private final int value;

		private AArch64Dbnxs(int value) {
			this.value = value;
		}	

		public int getValue() {
			return value;
		}

		public static AArch64Dbnxs fromValue(int value) {
			for (AArch64Dbnxs dbnxs : AArch64Dbnxs.values()) {
				if (dbnxs.value == value) {
					return dbnxs;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Ic {
		IALLU(AARCH64_IC_IALLU()),
		IALLUIS(AARCH64_IC_IALLUIS()),
		IVAU(AARCH64_IC_IVAU()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_IC> end
		ENDING(AARCH64_IC_ENDING());

		private final int value;

		private AArch64Ic(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Ic fromValue(int value) {
			for (AArch64Ic ic : AArch64Ic.values()) {
				if (ic.value == value) {
					return ic;
				}
			}
			throw new IllegalArgumentException("Invalid value: " + value);
		}
	}

	public enum AArch64Tlbi {
		ALLE1(AARCH64_TLBI_ALLE1()),
		ALLE1IS(AARCH64_TLBI_ALLE1IS()),
		ALLE1ISNXS(AARCH64_TLBI_ALLE1ISNXS()),
		ALLE1NXS(AARCH64_TLBI_ALLE1NXS()),
		ALLE1OS(AARCH64_TLBI_ALLE1OS()),
		ALLE1OSNXS(AARCH64_TLBI_ALLE1OSNXS()),
		ALLE2(AARCH64_TLBI_ALLE2()),
		ALLE2IS(AARCH64_TLBI_ALLE2IS()),
		ALLE2ISNXS(AARCH64_TLBI_ALLE2ISNXS()),
		ALLE2NXS(AARCH64_TLBI_ALLE2NXS()),
		ALLE2OS(AARCH64_TLBI_ALLE2OS()),
		ALLE2OSNXS(AARCH64_TLBI_ALLE2OSNXS()),
		ALLE3(AARCH64_TLBI_ALLE3()),
		ALLE3IS(AARCH64_TLBI_ALLE3IS()),
		ALLE3ISNXS(AARCH64_TLBI_ALLE3ISNXS()),
		ALLE3NXS(AARCH64_TLBI_ALLE3NXS()),
		ALLE3OS(AARCH64_TLBI_ALLE3OS()),
		ALLE3OSNXS(AARCH64_TLBI_ALLE3OSNXS()),
		ASIDE1(AARCH64_TLBI_ASIDE1()),
		ASIDE1IS(AARCH64_TLBI_ASIDE1IS()),
		ASIDE1ISNXS(AARCH64_TLBI_ASIDE1ISNXS()),
		ASIDE1NXS(AARCH64_TLBI_ASIDE1NXS()),
		ASIDE1OS(AARCH64_TLBI_ASIDE1OS()),
		ASIDE1OSNXS(AARCH64_TLBI_ASIDE1OSNXS()),
		IPAS2E1(AARCH64_TLBI_IPAS2E1()),
		IPAS2E1IS(AARCH64_TLBI_IPAS2E1IS()),
		IPAS2E1ISNXS(AARCH64_TLBI_IPAS2E1ISNXS()),
		IPAS2E1NXS(AARCH64_TLBI_IPAS2E1NXS()),
		IPAS2E1OS(AARCH64_TLBI_IPAS2E1OS()),
		IPAS2E1OSNXS(AARCH64_TLBI_IPAS2E1OSNXS()),
		IPAS2LE1(AARCH64_TLBI_IPAS2LE1()),
		IPAS2LE1IS(AARCH64_TLBI_IPAS2LE1IS()),
		IPAS2LE1ISNXS(AARCH64_TLBI_IPAS2LE1ISNXS()),
		IPAS2LE1NXS(AARCH64_TLBI_IPAS2LE1NXS()),
		IPAS2LE1OS(AARCH64_TLBI_IPAS2LE1OS()),
		IPAS2LE1OSNXS(AARCH64_TLBI_IPAS2LE1OSNXS()),
		PAALL(AARCH64_TLBI_PAALL()),
		PAALLNXS(AARCH64_TLBI_PAALLNXS()),
		PAALLOS(AARCH64_TLBI_PAALLOS()),
		PAALLOSNXS(AARCH64_TLBI_PAALLOSNXS()),
		RIPAS2E1(AARCH64_TLBI_RIPAS2E1()),
		RIPAS2E1IS(AARCH64_TLBI_RIPAS2E1IS()),
		RIPAS2E1ISNXS(AARCH64_TLBI_RIPAS2E1ISNXS()),
		RIPAS2E1NXS(AARCH64_TLBI_RIPAS2E1NXS()),
		RIPAS2E1OS(AARCH64_TLBI_RIPAS2E1OS()),
		RIPAS2E1OSNXS(AARCH64_TLBI_RIPAS2E1OSNXS()),
		RIPAS2LE1(AARCH64_TLBI_RIPAS2LE1()),
		RIPAS2LE1IS(AARCH64_TLBI_RIPAS2LE1IS()),
		RIPAS2LE1ISNXS(AARCH64_TLBI_RIPAS2LE1ISNXS()),
		RIPAS2LE1NXS(AARCH64_TLBI_RIPAS2LE1NXS()),
		RIPAS2LE1OS(AARCH64_TLBI_RIPAS2LE1OS()),
		RIPAS2LE1OSNXS(AARCH64_TLBI_RIPAS2LE1OSNXS()),
		RPALOS(AARCH64_TLBI_RPALOS()),
		RPALOSNXS(AARCH64_TLBI_RPALOSNXS()),
		RPAOS(AARCH64_TLBI_RPAOS()),
		RPAOSNXS(AARCH64_TLBI_RPAOSNXS()),
		RVAAE1(AARCH64_TLBI_RVAAE1()),
		RVAAE1IS(AARCH64_TLBI_RVAAE1IS()),
		RVAAE1ISNXS(AARCH64_TLBI_RVAAE1ISNXS()),
		RVAAE1NXS(AARCH64_TLBI_RVAAE1NXS()),
		RVAAE1OS(AARCH64_TLBI_RVAAE1OS()),
		RVAAE1OSNXS(AARCH64_TLBI_RVAAE1OSNXS()),
		RVAALE1(AARCH64_TLBI_RVAALE1()),
		RVAALE1IS(AARCH64_TLBI_RVAALE1IS()),
		RVAALE1ISNXS(AARCH64_TLBI_RVAALE1ISNXS()),
		RVAALE1NXS(AARCH64_TLBI_RVAALE1NXS()),
		RVAALE1OS(AARCH64_TLBI_RVAALE1OS()),
		RVAALE1OSNXS(AARCH64_TLBI_RVAALE1OSNXS()),
		RVAE1(AARCH64_TLBI_RVAE1()),
		RVAE1IS(AARCH64_TLBI_RVAE1IS()),
		RVAE1ISNXS(AARCH64_TLBI_RVAE1ISNXS()),
		RVAE1NXS(AARCH64_TLBI_RVAE1NXS()),
		RVAE1OS(AARCH64_TLBI_RVAE1OS()),
		RVAE1OSNXS(AARCH64_TLBI_RVAE1OSNXS()),
		RVAE2(AARCH64_TLBI_RVAE2()),
		RVAE2IS(AARCH64_TLBI_RVAE2IS()),
		RVAE2ISNXS(AARCH64_TLBI_RVAE2ISNXS()),
		RVAE2NXS(AARCH64_TLBI_RVAE2NXS()),
		RVAE2OS(AARCH64_TLBI_RVAE2OS()),
		RVAE2OSNXS(AARCH64_TLBI_RVAE2OSNXS()),
		RVAE3(AARCH64_TLBI_RVAE3()),
		RVAE3IS(AARCH64_TLBI_RVAE3IS()),
		RVAE3ISNXS(AARCH64_TLBI_RVAE3ISNXS()),
		RVAE3NXS(AARCH64_TLBI_RVAE3NXS()),
		RVAE3OS(AARCH64_TLBI_RVAE3OS()),
		RVAE3OSNXS(AARCH64_TLBI_RVAE3OSNXS()),
		RVALE1(AARCH64_TLBI_RVALE1()),
		RVALE1IS(AARCH64_TLBI_RVALE1IS()),
		RVALE1ISNXS(AARCH64_TLBI_RVALE1ISNXS()),
		RVALE1NXS(AARCH64_TLBI_RVALE1NXS()),
		RVALE1OS(AARCH64_TLBI_RVALE1OS()),
		RVALE1OSNXS(AARCH64_TLBI_RVALE1OSNXS()),
		RVALE2(AARCH64_TLBI_RVALE2()),
		RVALE2IS(AARCH64_TLBI_RVALE2IS()),
		RVALE2ISNXS(AARCH64_TLBI_RVALE2ISNXS()),
		RVALE2NXS(AARCH64_TLBI_RVALE2NXS()),
		RVALE2OS(AARCH64_TLBI_RVALE2OS()),
		RVALE2OSNXS(AARCH64_TLBI_RVALE2OSNXS()),
		RVALE3(AARCH64_TLBI_RVALE3()),
		RVALE3IS(AARCH64_TLBI_RVALE3IS()),
		RVALE3ISNXS(AARCH64_TLBI_RVALE3ISNXS()),
		RVALE3NXS(AARCH64_TLBI_RVALE3NXS()),
		RVALE3OS(AARCH64_TLBI_RVALE3OS()),
		RVALE3OSNXS(AARCH64_TLBI_RVALE3OSNXS()),
		VAAE1(AARCH64_TLBI_VAAE1()),
		VAAE1IS(AARCH64_TLBI_VAAE1IS()),
		VAAE1ISNXS(AARCH64_TLBI_VAAE1ISNXS()),
		VAAE1NXS(AARCH64_TLBI_VAAE1NXS()),
		VAAE1OS(AARCH64_TLBI_VAAE1OS()),
		VAAE1OSNXS(AARCH64_TLBI_VAAE1OSNXS()),
		VAALE1(AARCH64_TLBI_VAALE1()),
		VAALE1IS(AARCH64_TLBI_VAALE1IS()),
		VAALE1ISNXS(AARCH64_TLBI_VAALE1ISNXS()),
		VAALE1NXS(AARCH64_TLBI_VAALE1NXS()),
		VAALE1OS(AARCH64_TLBI_VAALE1OS()),
		VAALE1OSNXS(AARCH64_TLBI_VAALE1OSNXS()),
		VAE1(AARCH64_TLBI_VAE1()),
		VAE1IS(AARCH64_TLBI_VAE1IS()),
		VAE1ISNXS(AARCH64_TLBI_VAE1ISNXS()),
		VAE1NXS(AARCH64_TLBI_VAE1NXS()),
		VAE1OS(AARCH64_TLBI_VAE1OS()),
		VAE1OSNXS(AARCH64_TLBI_VAE1OSNXS()),
		VAE2(AARCH64_TLBI_VAE2()),
		VAE2IS(AARCH64_TLBI_VAE2IS()),
		VAE2ISNXS(AARCH64_TLBI_VAE2ISNXS()),
		VAE2NXS(AARCH64_TLBI_VAE2NXS()),
		VAE2OS(AARCH64_TLBI_VAE2OS()),
		VAE2OSNXS(AARCH64_TLBI_VAE2OSNXS()),
		VAE3(AARCH64_TLBI_VAE3()),
		VAE3IS(AARCH64_TLBI_VAE3IS()),
		VAE3ISNXS(AARCH64_TLBI_VAE3ISNXS()),
		VAE3NXS(AARCH64_TLBI_VAE3NXS()),
		VAE3OS(AARCH64_TLBI_VAE3OS()),
		VAE3OSNXS(AARCH64_TLBI_VAE3OSNXS()),
		VALE1(AARCH64_TLBI_VALE1()),
		VALE1IS(AARCH64_TLBI_VALE1IS()),
		VALE1ISNXS(AARCH64_TLBI_VALE1ISNXS()),
		VALE1NXS(AARCH64_TLBI_VALE1NXS()),
		VALE1OS(AARCH64_TLBI_VALE1OS()),
		VALE1OSNXS(AARCH64_TLBI_VALE1OSNXS()),
		VALE2(AARCH64_TLBI_VALE2()),
		VALE2IS(AARCH64_TLBI_VALE2IS()),
		VALE2ISNXS(AARCH64_TLBI_VALE2ISNXS()),
		VALE2NXS(AARCH64_TLBI_VALE2NXS()),
		VALE2OS(AARCH64_TLBI_VALE2OS()),
		VALE2OSNXS(AARCH64_TLBI_VALE2OSNXS()),
		VALE3(AARCH64_TLBI_VALE3()),
		VALE3IS(AARCH64_TLBI_VALE3IS()),
		VALE3ISNXS(AARCH64_TLBI_VALE3ISNXS()),
		VALE3NXS(AARCH64_TLBI_VALE3NXS()),
		VALE3OS(AARCH64_TLBI_VALE3OS()),
		VALE3OSNXS(AARCH64_TLBI_VALE3OSNXS()),
		VMALLE1(AARCH64_TLBI_VMALLE1()),
		VMALLE1IS(AARCH64_TLBI_VMALLE1IS()),
		VMALLE1ISNXS(AARCH64_TLBI_VMALLE1ISNXS()),
		VMALLE1NXS(AARCH64_TLBI_VMALLE1NXS()),
		VMALLE1OS(AARCH64_TLBI_VMALLE1OS()),
		VMALLE1OSNXS(AARCH64_TLBI_VMALLE1OSNXS()),
		VMALLS12E1(AARCH64_TLBI_VMALLS12E1()),
		VMALLS12E1IS(AARCH64_TLBI_VMALLS12E1IS()),
		VMALLS12E1ISNXS(AARCH64_TLBI_VMALLS12E1ISNXS()),
		VMALLS12E1NXS(AARCH64_TLBI_VMALLS12E1NXS()),
		VMALLS12E1OS(AARCH64_TLBI_VMALLS12E1OS()),
		VMALLS12E1OSNXS(AARCH64_TLBI_VMALLS12E1OSNXS()),
		VMALLWS2E1(AARCH64_TLBI_VMALLWS2E1()),
		VMALLWS2E1IS(AARCH64_TLBI_VMALLWS2E1IS()),
		VMALLWS2E1ISNXS(AARCH64_TLBI_VMALLWS2E1ISNXS()),
		VMALLWS2E1NXS(AARCH64_TLBI_VMALLWS2E1NXS()),
		VMALLWS2E1OS(AARCH64_TLBI_VMALLWS2E1OS()),
		VMALLWS2E1OSNXS(AARCH64_TLBI_VMALLWS2E1OSNXS()),

		// clang-format on
		// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_TLBI> end
		ENDING(AARCH64_TLBI_ENDING());

		private final int value;

		private AArch64Tlbi(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Tlbi fromValue(int value) {
			for (AArch64Tlbi tlbi : AArch64Tlbi.values()) {
				if (tlbi.value == value) {
					return tlbi;
				}
			}
			throw new IllegalArgumentException("Invalid TLBI value: " + value);
		}
	}

	static class AArch64Operand {
		private final int vectorIndex;
		private final AArch64VectorLayout vas;
		private final AArch64Shift shift;
		private final AArch64Extender ext;
		private final AArch64OperandType type;
		private final boolean isVReg;
		private final AArch64Reg[] reg;
		private final long imm;
		private final AArch64ImmRange immRange;
		private final double fp;
		private final AArch64OpMem mem;
		private final AArch64OpSme sme;
		private final AArch64Pred pred;
		private final AArch64SysOp sys;
		private final int access;
		private final boolean isListMember;

		AArch64Operand(int vectorIndex, AArch64VectorLayout vas, AArch64Shift shift, AArch64Extender ext, AArch64OperandType type, boolean isVReg, AArch64Reg[] reg, long imm, AArch64ImmRange immRange, double fp, AArch64OpMem mem, AArch64OpSme sme, AArch64Pred pred, AArch64SysOp sys, int access, boolean isListMember) {
			this.vectorIndex = vectorIndex;
			this.vas = vas;
			this.shift = shift;
			this.ext = ext;
			this.type = type;
			this.isVReg = isVReg;
			this.reg = reg;
			this.imm = imm;
			this.immRange = immRange;
			this.fp = fp;
			this.mem = mem;
			this.sme = sme;
			this.pred = pred;
			this.sys = sys;
			this.access = access;
			this.isListMember = isListMember;
		}

		public int getVectorIndex() {
			return vectorIndex;
		}	

		public AArch64VectorLayout getVas() {
			return vas;
		}

		public AArch64Shift getShift() {
			return shift;
		}

		public AArch64Extender getExt() {
			return ext;
		}

		public AArch64OperandType getType() {
			return type;
		}

		public boolean isVReg() {
			return isVReg;
		}

		public AArch64Reg[] getReg() {
			return reg;
		}	

		public long getImm() {
			return imm;
		}

		public AArch64ImmRange getImmRange() {
			return immRange;
		}

		public double getFp() {
			return fp;
		}

		public AArch64OpMem getMem() {
			return mem;
		}

		public AArch64OpSme getSme() {
			return sme;
		}

		public AArch64Pred getPred() {
			return pred;
		}

		public AArch64SysOp getSys() {
			return sys;
		}

		public int getAccess() {
			return access;
		}

		public boolean isListMember() {
			return isListMember;
		}
	}

	public enum AArch64InsnGroup {
		INVALID(AARCH64_GRP_INVALID()), ///< = CS_GRP_INVALID

		// Generic groups
		// all jump instructions (conditional+direct+indirect jumps)
		JUMP(AARCH64_GRP_JUMP()), ///< = CS_GRP_JUMP
		CALL(AARCH64_GRP_CALL()),
		RET(AARCH64_GRP_RET()),
		INT(AARCH64_GRP_INT()),
		PRIVILEGE(AARCH64_GRP_PRIVILEGE()),   ///< = CS_GRP_PRIVILEGE
		BRANCH_RELATIVE(AARCH64_GRP_BRANCH_RELATIVE()), ///< = CS_GRP_BRANCH_RELATIVE
			// generated content <AArch64GenCSFeatureEnum.inc> begin
			// clang-format off

		HASV8_0A(AARCH64_FEATURE_HASV8_0A()),
		HASV8_1A(AARCH64_FEATURE_HASV8_1A()),
		HASV8_2A(AARCH64_FEATURE_HASV8_2A()),
		HASV8_3A(AARCH64_FEATURE_HASV8_3A()),
		HASV8_4A(AARCH64_FEATURE_HASV8_4A()),
		HASV8_5A(AARCH64_FEATURE_HASV8_5A()),
		HASV8_6A(AARCH64_FEATURE_HASV8_6A()),
		HASV8_7A(AARCH64_FEATURE_HASV8_7A()),
		HASV8_8A(AARCH64_FEATURE_HASV8_8A()),
		HASV8_9A(AARCH64_FEATURE_HASV8_9A()),
		HASV9_0A(AARCH64_FEATURE_HASV9_0A()),
		HASV9_1A(AARCH64_FEATURE_HASV9_1A()),
		HASV9_2A(AARCH64_FEATURE_HASV9_2A()),
		HASV9_3A(AARCH64_FEATURE_HASV9_3A()),
		HASV9_4A(AARCH64_FEATURE_HASV9_4A()),
		HASV8_0R(AARCH64_FEATURE_HASV8_0R()),
		HASEL2VMSA(AARCH64_FEATURE_HASEL2VMSA()),
		HASEL3(AARCH64_FEATURE_HASEL3()),
		HASVH(AARCH64_FEATURE_HASVH()),
		HASLOR(AARCH64_FEATURE_HASLOR()),
		HASPAUTH(AARCH64_FEATURE_HASPAUTH()),
		HASPAUTHLR(AARCH64_FEATURE_HASPAUTHLR()),
		HASJS(AARCH64_FEATURE_HASJS()),
		HASCCIDX(AARCH64_FEATURE_HASCCIDX()),
		HASCOMPLXNUM(AARCH64_FEATURE_HASCOMPLXNUM()),
		HASNV(AARCH64_FEATURE_HASNV()),
		HASMPAM(AARCH64_FEATURE_HASMPAM()),
		HASDIT(AARCH64_FEATURE_HASDIT()),
		HASTRACEV8_4(AARCH64_FEATURE_HASTRACEV8_4()),
		HASAM(AARCH64_FEATURE_HASAM()),
		HASSEL2(AARCH64_FEATURE_HASSEL2()),
		HASTLB_RMI(AARCH64_FEATURE_HASTLB_RMI()),
		HASFLAGM(AARCH64_FEATURE_HASFLAGM()),
		HASRCPC_IMMO(AARCH64_FEATURE_HASRCPC_IMMO()),
		HASFPARMV8(AARCH64_FEATURE_HASFPARMV8()),
		HASNEON(AARCH64_FEATURE_HASNEON()),
		HASSM4(AARCH64_FEATURE_HASSM4()),
		HASSHA3(AARCH64_FEATURE_HASSHA3()),
		HASSHA2(AARCH64_FEATURE_HASSHA2()),
		HASAES(AARCH64_FEATURE_HASAES()),
		HASDOTPROD(AARCH64_FEATURE_HASDOTPROD()),
		HASCRC(AARCH64_FEATURE_HASCRC()),
		HASCSSC(AARCH64_FEATURE_HASCSSC()),
		HASLSE(AARCH64_FEATURE_HASLSE()),
		HASRAS(AARCH64_FEATURE_HASRAS()),
		HASRDM(AARCH64_FEATURE_HASRDM()),
		HASFULLFP16(AARCH64_FEATURE_HASFULLFP16()),
		HASFP16FML(AARCH64_FEATURE_HASFP16FML()),
		HASSPE(AARCH64_FEATURE_HASSPE()),
		HASFUSEAES(AARCH64_FEATURE_HASFUSEAES()),
		HASSVE(AARCH64_FEATURE_HASSVE()),
		HASSVE2(AARCH64_FEATURE_HASSVE2()),
		HASSVE2P1(AARCH64_FEATURE_HASSVE2P1()),
		HASSVE2AES(AARCH64_FEATURE_HASSVE2AES()),
		HASSVE2SM4(AARCH64_FEATURE_HASSVE2SM4()),
		HASSVE2SHA3(AARCH64_FEATURE_HASSVE2SHA3()),
		HASSVE2BITPERM(AARCH64_FEATURE_HASSVE2BITPERM()),
		HASB16B16(AARCH64_FEATURE_HASB16B16()),
		HASSME(AARCH64_FEATURE_HASSME()),
		HASSMEF64F64(AARCH64_FEATURE_HASSMEF64F64()),
		HASSMEF16F16(AARCH64_FEATURE_HASSMEF16F16()),
		HASSMEFA64(AARCH64_FEATURE_HASSMEFA64()),
		HASSMEI16I64(AARCH64_FEATURE_HASSMEI16I64()),
		HASSME2(AARCH64_FEATURE_HASSME2()),
		HASSME2P1(AARCH64_FEATURE_HASSME2P1()),
		HASFPMR(AARCH64_FEATURE_HASFPMR()),
		HASFP8(AARCH64_FEATURE_HASFP8()),
		HASFAMINMAX(AARCH64_FEATURE_HASFAMINMAX()),
		HASFP8FMA(AARCH64_FEATURE_HASFP8FMA()),
		HASSSVE_FP8FMA(AARCH64_FEATURE_HASSSVE_FP8FMA()),
		HASFP8DOT2(AARCH64_FEATURE_HASFP8DOT2()),
		HASSSVE_FP8DOT2(AARCH64_FEATURE_HASSSVE_FP8DOT2()),
		HASFP8DOT4(AARCH64_FEATURE_HASFP8DOT4()),
		HASSSVE_FP8DOT4(AARCH64_FEATURE_HASSSVE_FP8DOT4()),
		HASLUT(AARCH64_FEATURE_HASLUT()),
		HASSME_LUTV2(AARCH64_FEATURE_HASSME_LUTV2()),
		HASSMEF8F16(AARCH64_FEATURE_HASSMEF8F16()),
		HASSMEF8F32(AARCH64_FEATURE_HASSMEF8F32()),
		HASSVEORSME(AARCH64_FEATURE_HASSVEORSME()),
		HASSVE2ORSME(AARCH64_FEATURE_HASSVE2ORSME()),
		HASSVE2ORSME2(AARCH64_FEATURE_HASSVE2ORSME2()),
		HASSVE2P1_OR_HASSME(AARCH64_FEATURE_HASSVE2P1_OR_HASSME()),
		HASSVE2P1_OR_HASSME2(AARCH64_FEATURE_HASSVE2P1_OR_HASSME2()),
		HASSVE2P1_OR_HASSME2P1(AARCH64_FEATURE_HASSVE2P1_OR_HASSME2P1()),
		HASNEONORSME(AARCH64_FEATURE_HASNEONORSME()),
		HASRCPC(AARCH64_FEATURE_HASRCPC()),
		HASALTNZCV(AARCH64_FEATURE_HASALTNZCV()),
		HASFRINT3264(AARCH64_FEATURE_HASFRINT3264()),
		HASSB(AARCH64_FEATURE_HASSB()),
		HASPREDRES(AARCH64_FEATURE_HASPREDRES()),
		HASCCDP(AARCH64_FEATURE_HASCCDP()),
		HASBTI(AARCH64_FEATURE_HASBTI()),
		HASMTE(AARCH64_FEATURE_HASMTE()),
		HASTME(AARCH64_FEATURE_HASTME()),
		HASETE(AARCH64_FEATURE_HASETE()),
		HASTRBE(AARCH64_FEATURE_HASTRBE()),
		HASBF16(AARCH64_FEATURE_HASBF16()),
		HASMATMULINT8(AARCH64_FEATURE_HASMATMULINT8()),
		HASMATMULFP32(AARCH64_FEATURE_HASMATMULFP32()),
		HASMATMULFP64(AARCH64_FEATURE_HASMATMULFP64()),
		HASXS(AARCH64_FEATURE_HASXS()),
		HASWFXT(AARCH64_FEATURE_HASWFXT()),
		HASLS64(AARCH64_FEATURE_HASLS64()),
		HASBRBE(AARCH64_FEATURE_HASBRBE()),
		HASSPE_EEF(AARCH64_FEATURE_HASSPE_EEF()),
		HASHBC(AARCH64_FEATURE_HASHBC()),
		HASMOPS(AARCH64_FEATURE_HASMOPS()),
		HASCLRBHB(AARCH64_FEATURE_HASCLRBHB()),
		HASSPECRES2(AARCH64_FEATURE_HASSPECRES2()),
		HASITE(AARCH64_FEATURE_HASITE()),
		HASTHE(AARCH64_FEATURE_HASTHE()),
		HASRCPC3(AARCH64_FEATURE_HASRCPC3()),
		HASLSE128(AARCH64_FEATURE_HASLSE128()),
		HASD128(AARCH64_FEATURE_HASD128()),
		HASCHK(AARCH64_FEATURE_HASCHK()),
		HASGCS(AARCH64_FEATURE_HASGCS()),
		HASCPA(AARCH64_FEATURE_HASCPA()),
		USENEGATIVEIMMEDIATES(AARCH64_FEATURE_USENEGATIVEIMMEDIATES()),
		HASCCPP(AARCH64_FEATURE_HASCCPP()),
		HASPAN(AARCH64_FEATURE_HASPAN()),
		HASPSUAO(AARCH64_FEATURE_HASPSUAO()),
		HASPAN_RWV(AARCH64_FEATURE_HASPAN_RWV()),
		HASCONTEXTIDREL2(AARCH64_FEATURE_HASCONTEXTIDREL2()),

		// clang-format on
		// generated content <AArch64GenCSFeatureEnum.inc> end

		ENDING(AARCH64_GRP_ENDING()); // <-- mark the end of the list of groups

		private final int value;

		private AArch64InsnGroup(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64InsnGroup fromValue(int value) {
			for (AArch64InsnGroup group : AArch64InsnGroup.values()) {
				if (group.value == value) {
					return group;
				}
			}
			throw new IllegalArgumentException("Invalid instruction group value: " + value);
		}
	}

	public enum AArch64Insn {
		INVALID(AARCH64_INS_INVALID()),
		ABS(AARCH64_INS_ABS()),
		ADCLB(AARCH64_INS_ADCLB()),
		ADCLT(AARCH64_INS_ADCLT()),
		ADCS(AARCH64_INS_ADCS()),
		ADC(AARCH64_INS_ADC()),
		ADDG(AARCH64_INS_ADDG()),
		ADDHA(AARCH64_INS_ADDHA()),
		ADDHNB(AARCH64_INS_ADDHNB()),
		ADDHNT(AARCH64_INS_ADDHNT()),
		ADDHN(AARCH64_INS_ADDHN()),
		ADDHN2(AARCH64_INS_ADDHN2()),
		ADDPL(AARCH64_INS_ADDPL()),
		ADDPT(AARCH64_INS_ADDPT()),
		ADDP(AARCH64_INS_ADDP()),
		ADDQV(AARCH64_INS_ADDQV()),
		ADDSPL(AARCH64_INS_ADDSPL()),
		ADDSVL(AARCH64_INS_ADDSVL()),
		ADDS(AARCH64_INS_ADDS()),
		ADDVA(AARCH64_INS_ADDVA()),
		ADDVL(AARCH64_INS_ADDVL()),
		ADDV(AARCH64_INS_ADDV()),
		ADD(AARCH64_INS_ADD()),
		ADR(AARCH64_INS_ADR()),
		ADRP(AARCH64_INS_ADRP()),
		AESD(AARCH64_INS_AESD()),
		AESE(AARCH64_INS_AESE()),
		AESIMC(AARCH64_INS_AESIMC()),
		AESMC(AARCH64_INS_AESMC()),
		ANDQV(AARCH64_INS_ANDQV()),
		ANDS(AARCH64_INS_ANDS()),
		ANDV(AARCH64_INS_ANDV()),
		AND(AARCH64_INS_AND()),
		ASRD(AARCH64_INS_ASRD()),
		ASRR(AARCH64_INS_ASRR()),
		ASR(AARCH64_INS_ASR()),
		AUTDA(AARCH64_INS_AUTDA()),
		AUTDB(AARCH64_INS_AUTDB()),
		AUTDZA(AARCH64_INS_AUTDZA()),
		AUTDZB(AARCH64_INS_AUTDZB()),
		AUTIA(AARCH64_INS_AUTIA()),
		HINT(AARCH64_INS_HINT()),
		AUTIA171615(AARCH64_INS_AUTIA171615()),
		AUTIASPPC(AARCH64_INS_AUTIASPPC()),
		AUTIB(AARCH64_INS_AUTIB()),
		AUTIB171615(AARCH64_INS_AUTIB171615()),
		AUTIBSPPC(AARCH64_INS_AUTIBSPPC()),
		AUTIZA(AARCH64_INS_AUTIZA()),
		AUTIZB(AARCH64_INS_AUTIZB()),
		AXFLAG(AARCH64_INS_AXFLAG()),
		B(AARCH64_INS_B()),
		BCAX(AARCH64_INS_BCAX()),
		BC(AARCH64_INS_BC()),
		BDEP(AARCH64_INS_BDEP()),
		BEXT(AARCH64_INS_BEXT()),
		BFDOT(AARCH64_INS_BFDOT()),
		BF1CVTL2(AARCH64_INS_BF1CVTL2()),
		BF1CVTLT(AARCH64_INS_BF1CVTLT()),
		BF1CVTL(AARCH64_INS_BF1CVTL()),
		BF1CVT(AARCH64_INS_BF1CVT()),
		BF2CVTL2(AARCH64_INS_BF2CVTL2()),
		BF2CVTLT(AARCH64_INS_BF2CVTLT()),
		BF2CVTL(AARCH64_INS_BF2CVTL()),
		BF2CVT(AARCH64_INS_BF2CVT()),
		BFADD(AARCH64_INS_BFADD()),
		BFCLAMP(AARCH64_INS_BFCLAMP()),
		BFCVT(AARCH64_INS_BFCVT()),
		BFCVTN(AARCH64_INS_BFCVTN()),
		BFCVTN2(AARCH64_INS_BFCVTN2()),
		BFCVTNT(AARCH64_INS_BFCVTNT()),
		BFMAXNM(AARCH64_INS_BFMAXNM()),
		BFMAX(AARCH64_INS_BFMAX()),
		BFMINNM(AARCH64_INS_BFMINNM()),
		BFMIN(AARCH64_INS_BFMIN()),
		BFMLALB(AARCH64_INS_BFMLALB()),
		BFMLALT(AARCH64_INS_BFMLALT()),
		BFMLAL(AARCH64_INS_BFMLAL()),
		BFMLA(AARCH64_INS_BFMLA()),
		BFMLSLB(AARCH64_INS_BFMLSLB()),
		BFMLSLT(AARCH64_INS_BFMLSLT()),
		BFMLSL(AARCH64_INS_BFMLSL()),
		BFMLS(AARCH64_INS_BFMLS()),
		BFMMLA(AARCH64_INS_BFMMLA()),
		BFMOPA(AARCH64_INS_BFMOPA()),
		BFMOPS(AARCH64_INS_BFMOPS()),
		BFMUL(AARCH64_INS_BFMUL()),
		BFM(AARCH64_INS_BFM()),
		BFSUB(AARCH64_INS_BFSUB()),
		BFVDOT(AARCH64_INS_BFVDOT()),
		BGRP(AARCH64_INS_BGRP()),
		BICS(AARCH64_INS_BICS()),
		BIC(AARCH64_INS_BIC()),
		BIF(AARCH64_INS_BIF()),
		BIT(AARCH64_INS_BIT()),
		BL(AARCH64_INS_BL()),
		BLR(AARCH64_INS_BLR()),
		BLRAA(AARCH64_INS_BLRAA()),
		BLRAAZ(AARCH64_INS_BLRAAZ()),
		BLRAB(AARCH64_INS_BLRAB()),
		BLRABZ(AARCH64_INS_BLRABZ()),
		BMOPA(AARCH64_INS_BMOPA()),
		BMOPS(AARCH64_INS_BMOPS()),
		BR(AARCH64_INS_BR()),
		BRAA(AARCH64_INS_BRAA()),
		BRAAZ(AARCH64_INS_BRAAZ()),
		BRAB(AARCH64_INS_BRAB()),
		BRABZ(AARCH64_INS_BRABZ()),
		BRB(AARCH64_INS_BRB()),
		BRK(AARCH64_INS_BRK()),
		BRKAS(AARCH64_INS_BRKAS()),
		BRKA(AARCH64_INS_BRKA()),
		BRKBS(AARCH64_INS_BRKBS()),
		BRKB(AARCH64_INS_BRKB()),
		BRKNS(AARCH64_INS_BRKNS()),
		BRKN(AARCH64_INS_BRKN()),
		BRKPAS(AARCH64_INS_BRKPAS()),
		BRKPA(AARCH64_INS_BRKPA()),
		BRKPBS(AARCH64_INS_BRKPBS()),
		BRKPB(AARCH64_INS_BRKPB()),
		BSL1N(AARCH64_INS_BSL1N()),
		BSL2N(AARCH64_INS_BSL2N()),
		BSL(AARCH64_INS_BSL()),
		CADD(AARCH64_INS_CADD()),
		CASAB(AARCH64_INS_CASAB()),
		CASAH(AARCH64_INS_CASAH()),
		CASALB(AARCH64_INS_CASALB()),
		CASALH(AARCH64_INS_CASALH()),
		CASAL(AARCH64_INS_CASAL()),
		CASA(AARCH64_INS_CASA()),
		CASB(AARCH64_INS_CASB()),
		CASH(AARCH64_INS_CASH()),
		CASLB(AARCH64_INS_CASLB()),
		CASLH(AARCH64_INS_CASLH()),
		CASL(AARCH64_INS_CASL()),
		CASPAL(AARCH64_INS_CASPAL()),
		CASPA(AARCH64_INS_CASPA()),
		CASPL(AARCH64_INS_CASPL()),
		CASP(AARCH64_INS_CASP()),
		CAS(AARCH64_INS_CAS()),
		CBNZ(AARCH64_INS_CBNZ()),
		CBZ(AARCH64_INS_CBZ()),
		CCMN(AARCH64_INS_CCMN()),
		CCMP(AARCH64_INS_CCMP()),
		CDOT(AARCH64_INS_CDOT()),
		CFINV(AARCH64_INS_CFINV()),
		CLASTA(AARCH64_INS_CLASTA()),
		CLASTB(AARCH64_INS_CLASTB()),
		CLREX(AARCH64_INS_CLREX()),
		CLS(AARCH64_INS_CLS()),
		CLZ(AARCH64_INS_CLZ()),
		CMEQ(AARCH64_INS_CMEQ()),
		CMGE(AARCH64_INS_CMGE()),
		CMGT(AARCH64_INS_CMGT()),
		CMHI(AARCH64_INS_CMHI()),
		CMHS(AARCH64_INS_CMHS()),
		CMLA(AARCH64_INS_CMLA()),
		CMLE(AARCH64_INS_CMLE()),
		CMLT(AARCH64_INS_CMLT()),
		CMPEQ(AARCH64_INS_CMPEQ()),
		CMPGE(AARCH64_INS_CMPGE()),
		CMPGT(AARCH64_INS_CMPGT()),
		CMPHI(AARCH64_INS_CMPHI()),
		CMPHS(AARCH64_INS_CMPHS()),
		CMPLE(AARCH64_INS_CMPLE()),
		CMPLO(AARCH64_INS_CMPLO()),
		CMPLS(AARCH64_INS_CMPLS()),
		CMPLT(AARCH64_INS_CMPLT()),
		CMPNE(AARCH64_INS_CMPNE()),
		CMTST(AARCH64_INS_CMTST()),
		CNOT(AARCH64_INS_CNOT()),
		CNTB(AARCH64_INS_CNTB()),
		CNTD(AARCH64_INS_CNTD()),
		CNTH(AARCH64_INS_CNTH()),
		CNTP(AARCH64_INS_CNTP()),
		CNTW(AARCH64_INS_CNTW()),
		CNT(AARCH64_INS_CNT()),
		COMPACT(AARCH64_INS_COMPACT()),
		CPYE(AARCH64_INS_CPYE()),
		CPYEN(AARCH64_INS_CPYEN()),
		CPYERN(AARCH64_INS_CPYERN()),
		CPYERT(AARCH64_INS_CPYERT()),
		CPYERTN(AARCH64_INS_CPYERTN()),
		CPYERTRN(AARCH64_INS_CPYERTRN()),
		CPYERTWN(AARCH64_INS_CPYERTWN()),
		CPYET(AARCH64_INS_CPYET()),
		CPYETN(AARCH64_INS_CPYETN()),
		CPYETRN(AARCH64_INS_CPYETRN()),
		CPYETWN(AARCH64_INS_CPYETWN()),
		CPYEWN(AARCH64_INS_CPYEWN()),
		CPYEWT(AARCH64_INS_CPYEWT()),
		CPYEWTN(AARCH64_INS_CPYEWTN()),
		CPYEWTRN(AARCH64_INS_CPYEWTRN()),
		CPYEWTWN(AARCH64_INS_CPYEWTWN()),
		CPYFE(AARCH64_INS_CPYFE()),
		CPYFEN(AARCH64_INS_CPYFEN()),
		CPYFERN(AARCH64_INS_CPYFERN()),
		CPYFERT(AARCH64_INS_CPYFERT()),
		CPYFERTN(AARCH64_INS_CPYFERTN()),
		CPYFERTRN(AARCH64_INS_CPYFERTRN()),
		CPYFERTWN(AARCH64_INS_CPYFERTWN()),
		CPYFET(AARCH64_INS_CPYFET()),
		CPYFETN(AARCH64_INS_CPYFETN()),
		CPYFETRN(AARCH64_INS_CPYFETRN()),
		CPYFETWN(AARCH64_INS_CPYFETWN()),
		CPYFEWN(AARCH64_INS_CPYFEWN()),
		CPYFEWT(AARCH64_INS_CPYFEWT()),
		CPYFEWTN(AARCH64_INS_CPYFEWTN()),
		CPYFEWTRN(AARCH64_INS_CPYFEWTRN()),
		CPYFEWTWN(AARCH64_INS_CPYFEWTWN()),
		CPYFM(AARCH64_INS_CPYFM()),
		CPYFMN(AARCH64_INS_CPYFMN()),
		CPYFMRN(AARCH64_INS_CPYFMRN()),
		CPYFMRT(AARCH64_INS_CPYFMRT()),
		CPYFMRTN(AARCH64_INS_CPYFMRTN()),
		CPYFMRTRN(AARCH64_INS_CPYFMRTRN()),
		CPYFMRTWN(AARCH64_INS_CPYFMRTWN()),
		CPYFMT(AARCH64_INS_CPYFMT()),
		CPYFMTN(AARCH64_INS_CPYFMTN()),
		CPYFMTRN(AARCH64_INS_CPYFMTRN()),
		CPYFMTWN(AARCH64_INS_CPYFMTWN()),
		CPYFMWN(AARCH64_INS_CPYFMWN()),
		CPYFMWT(AARCH64_INS_CPYFMWT()),
		CPYFMWTN(AARCH64_INS_CPYFMWTN()),
		CPYFMWTRN(AARCH64_INS_CPYFMWTRN()),
		CPYFMWTWN(AARCH64_INS_CPYFMWTWN()),
		CPYFP(AARCH64_INS_CPYFP()),
		CPYFPN(AARCH64_INS_CPYFPN()),
		CPYFPRN(AARCH64_INS_CPYFPRN()),
		CPYFPRT(AARCH64_INS_CPYFPRT()),
		CPYFPRTN(AARCH64_INS_CPYFPRTN()),
		CPYFPRTRN(AARCH64_INS_CPYFPRTRN()),
		CPYFPRTWN(AARCH64_INS_CPYFPRTWN()),
		CPYFPT(AARCH64_INS_CPYFPT()),
		CPYFPTN(AARCH64_INS_CPYFPTN()),
		CPYFPTRN(AARCH64_INS_CPYFPTRN()),
		CPYFPTWN(AARCH64_INS_CPYFPTWN()),
		CPYFPWN(AARCH64_INS_CPYFPWN()),
		CPYFPWT(AARCH64_INS_CPYFPWT()),
		CPYFPWTN(AARCH64_INS_CPYFPWTN()),
		CPYFPWTRN(AARCH64_INS_CPYFPWTRN()),
		CPYFPWTWN(AARCH64_INS_CPYFPWTWN()),
		CPYM(AARCH64_INS_CPYM()),
		CPYMN(AARCH64_INS_CPYMN()),
		CPYMRN(AARCH64_INS_CPYMRN()),
		CPYMRT(AARCH64_INS_CPYMRT()),
		CPYMRTN(AARCH64_INS_CPYMRTN()),
		CPYMRTRN(AARCH64_INS_CPYMRTRN()),
		CPYMRTWN(AARCH64_INS_CPYMRTWN()),
		CPYMT(AARCH64_INS_CPYMT()),
		CPYMTN(AARCH64_INS_CPYMTN()),
		CPYMTRN(AARCH64_INS_CPYMTRN()),
		CPYMTWN(AARCH64_INS_CPYMTWN()),
		CPYMWN(AARCH64_INS_CPYMWN()),
		CPYMWT(AARCH64_INS_CPYMWT()),
		CPYMWTN(AARCH64_INS_CPYMWTN()),
		CPYMWTRN(AARCH64_INS_CPYMWTRN()),
		CPYMWTWN(AARCH64_INS_CPYMWTWN()),
		CPYP(AARCH64_INS_CPYP()),
		CPYPN(AARCH64_INS_CPYPN()),
		CPYPRN(AARCH64_INS_CPYPRN()),
		CPYPRT(AARCH64_INS_CPYPRT()),
		CPYPRTN(AARCH64_INS_CPYPRTN()),
		CPYPRTRN(AARCH64_INS_CPYPRTRN()),
		CPYPRTWN(AARCH64_INS_CPYPRTWN()),
		CPYPT(AARCH64_INS_CPYPT()),
		CPYPTN(AARCH64_INS_CPYPTN()),
		CPYPTRN(AARCH64_INS_CPYPTRN()),
		CPYPTWN(AARCH64_INS_CPYPTWN()),
		CPYPWN(AARCH64_INS_CPYPWN()),
		CPYPWT(AARCH64_INS_CPYPWT()),
		CPYPWTN(AARCH64_INS_CPYPWTN()),
		CPYPWTRN(AARCH64_INS_CPYPWTRN()),
		CPYPWTWN(AARCH64_INS_CPYPWTWN()),
		CPY(AARCH64_INS_CPY()),
		CRC32B(AARCH64_INS_CRC32B()),
		CRC32CB(AARCH64_INS_CRC32CB()),
		CRC32CH(AARCH64_INS_CRC32CH()),
		CRC32CW(AARCH64_INS_CRC32CW()),
		CRC32CX(AARCH64_INS_CRC32CX()),
		CRC32H(AARCH64_INS_CRC32H()),
		CRC32W(AARCH64_INS_CRC32W()),
		CRC32X(AARCH64_INS_CRC32X()),
		CSEL(AARCH64_INS_CSEL()),
		CSINC(AARCH64_INS_CSINC()),
		CSINV(AARCH64_INS_CSINV()),
		CSNEG(AARCH64_INS_CSNEG()),
		CTERMEQ(AARCH64_INS_CTERMEQ()),
		CTERMNE(AARCH64_INS_CTERMNE()),
		CTZ(AARCH64_INS_CTZ()),
		DCPS1(AARCH64_INS_DCPS1()),
		DCPS2(AARCH64_INS_DCPS2()),
		DCPS3(AARCH64_INS_DCPS3()),
		DECB(AARCH64_INS_DECB()),
		DECD(AARCH64_INS_DECD()),
		DECH(AARCH64_INS_DECH()),
		DECP(AARCH64_INS_DECP()),
		DECW(AARCH64_INS_DECW()),
		DMB(AARCH64_INS_DMB()),
		DRPS(AARCH64_INS_DRPS()),
		DSB(AARCH64_INS_DSB()),
		DUPM(AARCH64_INS_DUPM()),
		DUPQ(AARCH64_INS_DUPQ()),
		DUP(AARCH64_INS_DUP()),
		MOV(AARCH64_INS_MOV()),
		EON(AARCH64_INS_EON()),
		EOR3(AARCH64_INS_EOR3()),
		EORBT(AARCH64_INS_EORBT()),
		EORQV(AARCH64_INS_EORQV()),
		EORS(AARCH64_INS_EORS()),
		EORTB(AARCH64_INS_EORTB()),
		EORV(AARCH64_INS_EORV()),
		EOR(AARCH64_INS_EOR()),
		ERET(AARCH64_INS_ERET()),
		ERETAA(AARCH64_INS_ERETAA()),
		ERETAB(AARCH64_INS_ERETAB()),
		EXTQ(AARCH64_INS_EXTQ()),
		MOVA(AARCH64_INS_MOVA()),
		EXTR(AARCH64_INS_EXTR()),
		EXT(AARCH64_INS_EXT()),
		F1CVTL2(AARCH64_INS_F1CVTL2()),
		F1CVTLT(AARCH64_INS_F1CVTLT()),
		F1CVTL(AARCH64_INS_F1CVTL()),
		F1CVT(AARCH64_INS_F1CVT()),
		F2CVTL2(AARCH64_INS_F2CVTL2()),
		F2CVTLT(AARCH64_INS_F2CVTLT()),
		F2CVTL(AARCH64_INS_F2CVTL()),
		F2CVT(AARCH64_INS_F2CVT()),
		FABD(AARCH64_INS_FABD()),
		FABS(AARCH64_INS_FABS()),
		FACGE(AARCH64_INS_FACGE()),
		FACGT(AARCH64_INS_FACGT()),
		FADDA(AARCH64_INS_FADDA()),
		FADD(AARCH64_INS_FADD()),
		FADDP(AARCH64_INS_FADDP()),
		FADDQV(AARCH64_INS_FADDQV()),
		FADDV(AARCH64_INS_FADDV()),
		FAMAX(AARCH64_INS_FAMAX()),
		FAMIN(AARCH64_INS_FAMIN()),
		FCADD(AARCH64_INS_FCADD()),
		FCCMP(AARCH64_INS_FCCMP()),
		FCCMPE(AARCH64_INS_FCCMPE()),
		FCLAMP(AARCH64_INS_FCLAMP()),
		FCMEQ(AARCH64_INS_FCMEQ()),
		FCMGE(AARCH64_INS_FCMGE()),
		FCMGT(AARCH64_INS_FCMGT()),
		FCMLA(AARCH64_INS_FCMLA()),
		FCMLE(AARCH64_INS_FCMLE()),
		FCMLT(AARCH64_INS_FCMLT()),
		FCMNE(AARCH64_INS_FCMNE()),
		FCMP(AARCH64_INS_FCMP()),
		FCMPE(AARCH64_INS_FCMPE()),
		FCMUO(AARCH64_INS_FCMUO()),
		FCPY(AARCH64_INS_FCPY()),
		FCSEL(AARCH64_INS_FCSEL()),
		FCVTAS(AARCH64_INS_FCVTAS()),
		FCVTAU(AARCH64_INS_FCVTAU()),
		FCVT(AARCH64_INS_FCVT()),
		FCVTLT(AARCH64_INS_FCVTLT()),
		FCVTL(AARCH64_INS_FCVTL()),
		FCVTL2(AARCH64_INS_FCVTL2()),
		FCVTMS(AARCH64_INS_FCVTMS()),
		FCVTMU(AARCH64_INS_FCVTMU()),
		FCVTNB(AARCH64_INS_FCVTNB()),
		FCVTNS(AARCH64_INS_FCVTNS()),
		FCVTNT(AARCH64_INS_FCVTNT()),
		FCVTNU(AARCH64_INS_FCVTNU()),
		FCVTN(AARCH64_INS_FCVTN()),
		FCVTN2(AARCH64_INS_FCVTN2()),
		FCVTPS(AARCH64_INS_FCVTPS()),
		FCVTPU(AARCH64_INS_FCVTPU()),
		FCVTXNT(AARCH64_INS_FCVTXNT()),
		FCVTXN(AARCH64_INS_FCVTXN()),
		FCVTXN2(AARCH64_INS_FCVTXN2()),
		FCVTX(AARCH64_INS_FCVTX()),
		FCVTZS(AARCH64_INS_FCVTZS()),
		FCVTZU(AARCH64_INS_FCVTZU()),
		FDIV(AARCH64_INS_FDIV()),
		FDIVR(AARCH64_INS_FDIVR()),
		FDOT(AARCH64_INS_FDOT()),
		FDUP(AARCH64_INS_FDUP()),
		FEXPA(AARCH64_INS_FEXPA()),
		FJCVTZS(AARCH64_INS_FJCVTZS()),
		FLOGB(AARCH64_INS_FLOGB()),
		FMADD(AARCH64_INS_FMADD()),
		FMAD(AARCH64_INS_FMAD()),
		FMAX(AARCH64_INS_FMAX()),
		FMAXNM(AARCH64_INS_FMAXNM()),
		FMAXNMP(AARCH64_INS_FMAXNMP()),
		FMAXNMQV(AARCH64_INS_FMAXNMQV()),
		FMAXNMV(AARCH64_INS_FMAXNMV()),
		FMAXP(AARCH64_INS_FMAXP()),
		FMAXQV(AARCH64_INS_FMAXQV()),
		FMAXV(AARCH64_INS_FMAXV()),
		FMIN(AARCH64_INS_FMIN()),
		FMINNM(AARCH64_INS_FMINNM()),
		FMINNMP(AARCH64_INS_FMINNMP()),
		FMINNMQV(AARCH64_INS_FMINNMQV()),
		FMINNMV(AARCH64_INS_FMINNMV()),
		FMINP(AARCH64_INS_FMINP()),
		FMINQV(AARCH64_INS_FMINQV()),
		FMINV(AARCH64_INS_FMINV()),
		FMLAL2(AARCH64_INS_FMLAL2()),
		FMLALB(AARCH64_INS_FMLALB()),
		FMLALLBB(AARCH64_INS_FMLALLBB()),
		FMLALLBT(AARCH64_INS_FMLALLBT()),
		FMLALLTB(AARCH64_INS_FMLALLTB()),
		FMLALLTT(AARCH64_INS_FMLALLTT()),
		FMLALL(AARCH64_INS_FMLALL()),
		FMLALT(AARCH64_INS_FMLALT()),
		FMLAL(AARCH64_INS_FMLAL()),
		FMLA(AARCH64_INS_FMLA()),
		FMLSL2(AARCH64_INS_FMLSL2()),
		FMLSLB(AARCH64_INS_FMLSLB()),
		FMLSLT(AARCH64_INS_FMLSLT()),
		FMLSL(AARCH64_INS_FMLSL()),
		FMLS(AARCH64_INS_FMLS()),
		FMMLA(AARCH64_INS_FMMLA()),
		FMOPA(AARCH64_INS_FMOPA()),
		FMOPS(AARCH64_INS_FMOPS()),
		FMOV(AARCH64_INS_FMOV()),
		FMSB(AARCH64_INS_FMSB()),
		FMSUB(AARCH64_INS_FMSUB()),
		FMUL(AARCH64_INS_FMUL()),
		FMULX(AARCH64_INS_FMULX()),
		FNEG(AARCH64_INS_FNEG()),
		FNMADD(AARCH64_INS_FNMADD()),
		FNMAD(AARCH64_INS_FNMAD()),
		FNMLA(AARCH64_INS_FNMLA()),
		FNMLS(AARCH64_INS_FNMLS()),
		FNMSB(AARCH64_INS_FNMSB()),
		FNMSUB(AARCH64_INS_FNMSUB()),
		FNMUL(AARCH64_INS_FNMUL()),
		FRECPE(AARCH64_INS_FRECPE()),
		FRECPS(AARCH64_INS_FRECPS()),
		FRECPX(AARCH64_INS_FRECPX()),
		FRINT32X(AARCH64_INS_FRINT32X()),
		FRINT32Z(AARCH64_INS_FRINT32Z()),
		FRINT64X(AARCH64_INS_FRINT64X()),
		FRINT64Z(AARCH64_INS_FRINT64Z()),
		FRINTA(AARCH64_INS_FRINTA()),
		FRINTI(AARCH64_INS_FRINTI()),
		FRINTM(AARCH64_INS_FRINTM()),
		FRINTN(AARCH64_INS_FRINTN()),
		FRINTP(AARCH64_INS_FRINTP()),
		FRINTX(AARCH64_INS_FRINTX()),
		FRINTZ(AARCH64_INS_FRINTZ()),
		FRSQRTE(AARCH64_INS_FRSQRTE()),
		FRSQRTS(AARCH64_INS_FRSQRTS()),
		FSCALE(AARCH64_INS_FSCALE()),
		FSQRT(AARCH64_INS_FSQRT()),
		FSUB(AARCH64_INS_FSUB()),
		FSUBR(AARCH64_INS_FSUBR()),
		FTMAD(AARCH64_INS_FTMAD()),
		FTSMUL(AARCH64_INS_FTSMUL()),
		FTSSEL(AARCH64_INS_FTSSEL()),
		FVDOTB(AARCH64_INS_FVDOTB()),
		FVDOTT(AARCH64_INS_FVDOTT()),
		FVDOT(AARCH64_INS_FVDOT()),
		GCSPOPCX(AARCH64_INS_GCSPOPCX()),
		GCSPOPM(AARCH64_INS_GCSPOPM()),
		GCSPOPX(AARCH64_INS_GCSPOPX()),
		GCSPUSHM(AARCH64_INS_GCSPUSHM()),
		GCSPUSHX(AARCH64_INS_GCSPUSHX()),
		GCSSS1(AARCH64_INS_GCSSS1()),
		GCSSS2(AARCH64_INS_GCSSS2()),
		GCSSTR(AARCH64_INS_GCSSTR()),
		GCSSTTR(AARCH64_INS_GCSSTTR()),
		LD1B(AARCH64_INS_LD1B()),
		LD1D(AARCH64_INS_LD1D()),
		LD1H(AARCH64_INS_LD1H()),
		LD1Q(AARCH64_INS_LD1Q()),
		LD1SB(AARCH64_INS_LD1SB()),
		LD1SH(AARCH64_INS_LD1SH()),
		LD1SW(AARCH64_INS_LD1SW()),
		LD1W(AARCH64_INS_LD1W()),
		LDFF1B(AARCH64_INS_LDFF1B()),
		LDFF1D(AARCH64_INS_LDFF1D()),
		LDFF1H(AARCH64_INS_LDFF1H()),
		LDFF1SB(AARCH64_INS_LDFF1SB()),
		LDFF1SH(AARCH64_INS_LDFF1SH()),
		LDFF1SW(AARCH64_INS_LDFF1SW()),
		LDFF1W(AARCH64_INS_LDFF1W()),
		GMI(AARCH64_INS_GMI()),
		HISTCNT(AARCH64_INS_HISTCNT()),
		HISTSEG(AARCH64_INS_HISTSEG()),
		HLT(AARCH64_INS_HLT()),
		HVC(AARCH64_INS_HVC()),
		INCB(AARCH64_INS_INCB()),
		INCD(AARCH64_INS_INCD()),
		INCH(AARCH64_INS_INCH()),
		INCP(AARCH64_INS_INCP()),
		INCW(AARCH64_INS_INCW()),
		INDEX(AARCH64_INS_INDEX()),
		INSR(AARCH64_INS_INSR()),
		INS(AARCH64_INS_INS()),
		IRG(AARCH64_INS_IRG()),
		ISB(AARCH64_INS_ISB()),
		LASTA(AARCH64_INS_LASTA()),
		LASTB(AARCH64_INS_LASTB()),
		LD1(AARCH64_INS_LD1()),
		LD1RB(AARCH64_INS_LD1RB()),
		LD1RD(AARCH64_INS_LD1RD()),
		LD1RH(AARCH64_INS_LD1RH()),
		LD1ROB(AARCH64_INS_LD1ROB()),
		LD1ROD(AARCH64_INS_LD1ROD()),
		LD1ROH(AARCH64_INS_LD1ROH()),
		LD1ROW(AARCH64_INS_LD1ROW()),
		LD1RQB(AARCH64_INS_LD1RQB()),
		LD1RQD(AARCH64_INS_LD1RQD()),
		LD1RQH(AARCH64_INS_LD1RQH()),
		LD1RQW(AARCH64_INS_LD1RQW()),
		LD1RSB(AARCH64_INS_LD1RSB()),
		LD1RSH(AARCH64_INS_LD1RSH()),
		LD1RSW(AARCH64_INS_LD1RSW()),
		LD1RW(AARCH64_INS_LD1RW()),
		LD1R(AARCH64_INS_LD1R()),
		LD2B(AARCH64_INS_LD2B()),
		LD2D(AARCH64_INS_LD2D()),
		LD2H(AARCH64_INS_LD2H()),
		LD2Q(AARCH64_INS_LD2Q()),
		LD2R(AARCH64_INS_LD2R()),
		LD2(AARCH64_INS_LD2()),
		LD2W(AARCH64_INS_LD2W()),
		LD3B(AARCH64_INS_LD3B()),
		LD3D(AARCH64_INS_LD3D()),
		LD3H(AARCH64_INS_LD3H()),
		LD3Q(AARCH64_INS_LD3Q()),
		LD3R(AARCH64_INS_LD3R()),
		LD3(AARCH64_INS_LD3()),
		LD3W(AARCH64_INS_LD3W()),
		LD4B(AARCH64_INS_LD4B()),
		LD4D(AARCH64_INS_LD4D()),
		LD4(AARCH64_INS_LD4()),
		LD4H(AARCH64_INS_LD4H()),
		LD4Q(AARCH64_INS_LD4Q()),
		LD4R(AARCH64_INS_LD4R()),
		LD4W(AARCH64_INS_LD4W()),
		LD64B(AARCH64_INS_LD64B()),
		LDADDAB(AARCH64_INS_LDADDAB()),
		LDADDAH(AARCH64_INS_LDADDAH()),
		LDADDALB(AARCH64_INS_LDADDALB()),
		LDADDALH(AARCH64_INS_LDADDALH()),
		LDADDAL(AARCH64_INS_LDADDAL()),
		LDADDA(AARCH64_INS_LDADDA()),
		LDADDB(AARCH64_INS_LDADDB()),
		LDADDH(AARCH64_INS_LDADDH()),
		LDADDLB(AARCH64_INS_LDADDLB()),
		LDADDLH(AARCH64_INS_LDADDLH()),
		LDADDL(AARCH64_INS_LDADDL()),
		LDADD(AARCH64_INS_LDADD()),
		LDAP1(AARCH64_INS_LDAP1()),
		LDAPRB(AARCH64_INS_LDAPRB()),
		LDAPRH(AARCH64_INS_LDAPRH()),
		LDAPR(AARCH64_INS_LDAPR()),
		LDAPURB(AARCH64_INS_LDAPURB()),
		LDAPURH(AARCH64_INS_LDAPURH()),
		LDAPURSB(AARCH64_INS_LDAPURSB()),
		LDAPURSH(AARCH64_INS_LDAPURSH()),
		LDAPURSW(AARCH64_INS_LDAPURSW()),
		LDAPUR(AARCH64_INS_LDAPUR()),
		LDARB(AARCH64_INS_LDARB()),
		LDARH(AARCH64_INS_LDARH()),
		LDAR(AARCH64_INS_LDAR()),
		LDAXP(AARCH64_INS_LDAXP()),
		LDAXRB(AARCH64_INS_LDAXRB()),
		LDAXRH(AARCH64_INS_LDAXRH()),
		LDAXR(AARCH64_INS_LDAXR()),
		LDCLRAB(AARCH64_INS_LDCLRAB()),
		LDCLRAH(AARCH64_INS_LDCLRAH()),
		LDCLRALB(AARCH64_INS_LDCLRALB()),
		LDCLRALH(AARCH64_INS_LDCLRALH()),
		LDCLRAL(AARCH64_INS_LDCLRAL()),
		LDCLRA(AARCH64_INS_LDCLRA()),
		LDCLRB(AARCH64_INS_LDCLRB()),
		LDCLRH(AARCH64_INS_LDCLRH()),
		LDCLRLB(AARCH64_INS_LDCLRLB()),
		LDCLRLH(AARCH64_INS_LDCLRLH()),
		LDCLRL(AARCH64_INS_LDCLRL()),
		LDCLRP(AARCH64_INS_LDCLRP()),
		LDCLRPA(AARCH64_INS_LDCLRPA()),
		LDCLRPAL(AARCH64_INS_LDCLRPAL()),
		LDCLRPL(AARCH64_INS_LDCLRPL()),
		LDCLR(AARCH64_INS_LDCLR()),
		LDEORAB(AARCH64_INS_LDEORAB()),
		LDEORAH(AARCH64_INS_LDEORAH()),
		LDEORALB(AARCH64_INS_LDEORALB()),
		LDEORALH(AARCH64_INS_LDEORALH()),
		LDEORAL(AARCH64_INS_LDEORAL()),
		LDEORA(AARCH64_INS_LDEORA()),
		LDEORB(AARCH64_INS_LDEORB()),
		LDEORH(AARCH64_INS_LDEORH()),
		LDEORLB(AARCH64_INS_LDEORLB()),
		LDEORLH(AARCH64_INS_LDEORLH()),
		LDEORL(AARCH64_INS_LDEORL()),
		LDEOR(AARCH64_INS_LDEOR()),
		LDG(AARCH64_INS_LDG()),
		LDGM(AARCH64_INS_LDGM()),
		LDIAPP(AARCH64_INS_LDIAPP()),
		LDLARB(AARCH64_INS_LDLARB()),
		LDLARH(AARCH64_INS_LDLARH()),
		LDLAR(AARCH64_INS_LDLAR()),
		LDNF1B(AARCH64_INS_LDNF1B()),
		LDNF1D(AARCH64_INS_LDNF1D()),
		LDNF1H(AARCH64_INS_LDNF1H()),
		LDNF1SB(AARCH64_INS_LDNF1SB()),
		LDNF1SH(AARCH64_INS_LDNF1SH()),
		LDNF1SW(AARCH64_INS_LDNF1SW()),
		LDNF1W(AARCH64_INS_LDNF1W()),
		LDNP(AARCH64_INS_LDNP()),
		LDNT1B(AARCH64_INS_LDNT1B()),
		LDNT1D(AARCH64_INS_LDNT1D()),
		LDNT1H(AARCH64_INS_LDNT1H()),
		LDNT1SB(AARCH64_INS_LDNT1SB()),
		LDNT1SH(AARCH64_INS_LDNT1SH()),
		LDNT1SW(AARCH64_INS_LDNT1SW()),
		LDNT1W(AARCH64_INS_LDNT1W()),
		LDP(AARCH64_INS_LDP()),
		LDPSW(AARCH64_INS_LDPSW()),
		LDRAA(AARCH64_INS_LDRAA()),
		LDRAB(AARCH64_INS_LDRAB()),
		LDRB(AARCH64_INS_LDRB()),
		LDR(AARCH64_INS_LDR()),
		LDRH(AARCH64_INS_LDRH()),
		LDRSB(AARCH64_INS_LDRSB()),
		LDRSH(AARCH64_INS_LDRSH()),
		LDRSW(AARCH64_INS_LDRSW()),
		LDSETAB(AARCH64_INS_LDSETAB()),
		LDSETAH(AARCH64_INS_LDSETAH()),
		LDSETALB(AARCH64_INS_LDSETALB()),
		LDSETALH(AARCH64_INS_LDSETALH()),
		LDSETAL(AARCH64_INS_LDSETAL()),
		LDSETA(AARCH64_INS_LDSETA()),
		LDSETB(AARCH64_INS_LDSETB()),
		LDSETH(AARCH64_INS_LDSETH()),
		LDSETLB(AARCH64_INS_LDSETLB()),
		LDSETLH(AARCH64_INS_LDSETLH()),
		LDSETL(AARCH64_INS_LDSETL()),
		LDSETP(AARCH64_INS_LDSETP()),
		LDSETPA(AARCH64_INS_LDSETPA()),
		LDSETPAL(AARCH64_INS_LDSETPAL()),
		LDSETPL(AARCH64_INS_LDSETPL()),
		LDSET(AARCH64_INS_LDSET()),
		LDSMAXAB(AARCH64_INS_LDSMAXAB()),
		LDSMAXAH(AARCH64_INS_LDSMAXAH()),
		LDSMAXALB(AARCH64_INS_LDSMAXALB()),
		LDSMAXALH(AARCH64_INS_LDSMAXALH()),
		LDSMAXAL(AARCH64_INS_LDSMAXAL()),
		LDSMAXA(AARCH64_INS_LDSMAXA()),
		LDSMAXB(AARCH64_INS_LDSMAXB()),
		LDSMAXH(AARCH64_INS_LDSMAXH()),
		LDSMAXLB(AARCH64_INS_LDSMAXLB()),
		LDSMAXLH(AARCH64_INS_LDSMAXLH()),
		LDSMAXL(AARCH64_INS_LDSMAXL()),
		LDSMAX(AARCH64_INS_LDSMAX()),
		LDSMINAB(AARCH64_INS_LDSMINAB()),
		LDSMINAH(AARCH64_INS_LDSMINAH()),
		LDSMINALB(AARCH64_INS_LDSMINALB()),
		LDSMINALH(AARCH64_INS_LDSMINALH()),
		LDSMINAL(AARCH64_INS_LDSMINAL()),
		LDSMINA(AARCH64_INS_LDSMINA()),
		LDSMINB(AARCH64_INS_LDSMINB()),
		LDSMINH(AARCH64_INS_LDSMINH()),
		LDSMINLB(AARCH64_INS_LDSMINLB()),
		LDSMINLH(AARCH64_INS_LDSMINLH()),
		LDSMINL(AARCH64_INS_LDSMINL()),
		LDSMIN(AARCH64_INS_LDSMIN()),
		LDTRB(AARCH64_INS_LDTRB()),
		LDTRH(AARCH64_INS_LDTRH()),
		LDTRSB(AARCH64_INS_LDTRSB()),
		LDTRSH(AARCH64_INS_LDTRSH()),
		LDTRSW(AARCH64_INS_LDTRSW()),
		LDTR(AARCH64_INS_LDTR()),
		LDUMAXAB(AARCH64_INS_LDUMAXAB()),
		LDUMAXAH(AARCH64_INS_LDUMAXAH()),
		LDUMAXALB(AARCH64_INS_LDUMAXALB()),
		LDUMAXALH(AARCH64_INS_LDUMAXALH()),
		LDUMAXAL(AARCH64_INS_LDUMAXAL()),
		LDUMAXA(AARCH64_INS_LDUMAXA()),
		LDUMAXB(AARCH64_INS_LDUMAXB()),
		LDUMAXH(AARCH64_INS_LDUMAXH()),
		LDUMAXLB(AARCH64_INS_LDUMAXLB()),
		LDUMAXLH(AARCH64_INS_LDUMAXLH()),
		LDUMAXL(AARCH64_INS_LDUMAXL()),
		LDUMAX(AARCH64_INS_LDUMAX()),
		LDUMINAB(AARCH64_INS_LDUMINAB()),
		LDUMINAH(AARCH64_INS_LDUMINAH()),
		LDUMINALB(AARCH64_INS_LDUMINALB()),
		LDUMINALH(AARCH64_INS_LDUMINALH()),
		LDUMINAL(AARCH64_INS_LDUMINAL()),
		LDUMINA(AARCH64_INS_LDUMINA()),
		LDUMINB(AARCH64_INS_LDUMINB()),
		LDUMINH(AARCH64_INS_LDUMINH()),
		LDUMINLB(AARCH64_INS_LDUMINLB()),
		LDUMINLH(AARCH64_INS_LDUMINLH()),
		LDUMINL(AARCH64_INS_LDUMINL()),
		LDUMIN(AARCH64_INS_LDUMIN()),
		LDURB(AARCH64_INS_LDURB()),
		LDUR(AARCH64_INS_LDUR()),
		LDURH(AARCH64_INS_LDURH()),
		LDURSB(AARCH64_INS_LDURSB()),
		LDURSH(AARCH64_INS_LDURSH()),
		LDURSW(AARCH64_INS_LDURSW()),
		LDXP(AARCH64_INS_LDXP()),
		LDXRB(AARCH64_INS_LDXRB()),
		LDXRH(AARCH64_INS_LDXRH()),
		LDXR(AARCH64_INS_LDXR()),
		LSLR(AARCH64_INS_LSLR()),
		LSL(AARCH64_INS_LSL()),
		LSRR(AARCH64_INS_LSRR()),
		LSR(AARCH64_INS_LSR()),
		LUTI2(AARCH64_INS_LUTI2()),
		LUTI4(AARCH64_INS_LUTI4()),
		MADDPT(AARCH64_INS_MADDPT()),
		MADD(AARCH64_INS_MADD()),
		MADPT(AARCH64_INS_MADPT()),
		MAD(AARCH64_INS_MAD()),
		MATCH(AARCH64_INS_MATCH()),
		MLAPT(AARCH64_INS_MLAPT()),
		MLA(AARCH64_INS_MLA()),
		MLS(AARCH64_INS_MLS()),
		SETGE(AARCH64_INS_SETGE()),
		SETGEN(AARCH64_INS_SETGEN()),
		SETGET(AARCH64_INS_SETGET()),
		SETGETN(AARCH64_INS_SETGETN()),
		MOVAZ(AARCH64_INS_MOVAZ()),
		MOVI(AARCH64_INS_MOVI()),
		MOVK(AARCH64_INS_MOVK()),
		MOVN(AARCH64_INS_MOVN()),
		MOVPRFX(AARCH64_INS_MOVPRFX()),
		MOVT(AARCH64_INS_MOVT()),
		MOVZ(AARCH64_INS_MOVZ()),
		MRRS(AARCH64_INS_MRRS()),
		MRS(AARCH64_INS_MRS()),
		MSB(AARCH64_INS_MSB()),
		MSR(AARCH64_INS_MSR()),
		MSRR(AARCH64_INS_MSRR()),
		MSUBPT(AARCH64_INS_MSUBPT()),
		MSUB(AARCH64_INS_MSUB()),
		MUL(AARCH64_INS_MUL()),
		MVNI(AARCH64_INS_MVNI()),
		NANDS(AARCH64_INS_NANDS()),
		NAND(AARCH64_INS_NAND()),
		NBSL(AARCH64_INS_NBSL()),
		NEG(AARCH64_INS_NEG()),
		NMATCH(AARCH64_INS_NMATCH()),
		NORS(AARCH64_INS_NORS()),
		NOR(AARCH64_INS_NOR()),
		NOT(AARCH64_INS_NOT()),
		ORNS(AARCH64_INS_ORNS()),
		ORN(AARCH64_INS_ORN()),
		ORQV(AARCH64_INS_ORQV()),
		ORRS(AARCH64_INS_ORRS()),
		ORR(AARCH64_INS_ORR()),
		ORV(AARCH64_INS_ORV()),
		PACDA(AARCH64_INS_PACDA()),
		PACDB(AARCH64_INS_PACDB()),
		PACDZA(AARCH64_INS_PACDZA()),
		PACDZB(AARCH64_INS_PACDZB()),
		PACGA(AARCH64_INS_PACGA()),
		PACIA(AARCH64_INS_PACIA()),
		PACIA171615(AARCH64_INS_PACIA171615()),
		PACIASPPC(AARCH64_INS_PACIASPPC()),
		PACIB(AARCH64_INS_PACIB()),
		PACIB171615(AARCH64_INS_PACIB171615()),
		PACIBSPPC(AARCH64_INS_PACIBSPPC()),
		PACIZA(AARCH64_INS_PACIZA()),
		PACIZB(AARCH64_INS_PACIZB()),
		PACNBIASPPC(AARCH64_INS_PACNBIASPPC()),
		PACNBIBSPPC(AARCH64_INS_PACNBIBSPPC()),
		PEXT(AARCH64_INS_PEXT()),
		PFALSE(AARCH64_INS_PFALSE()),
		PFIRST(AARCH64_INS_PFIRST()),
		PMOV(AARCH64_INS_PMOV()),
		PMULLB(AARCH64_INS_PMULLB()),
		PMULLT(AARCH64_INS_PMULLT()),
		PMULL2(AARCH64_INS_PMULL2()),
		PMULL(AARCH64_INS_PMULL()),
		PMUL(AARCH64_INS_PMUL()),
		PNEXT(AARCH64_INS_PNEXT()),
		PRFB(AARCH64_INS_PRFB()),
		PRFD(AARCH64_INS_PRFD()),
		PRFH(AARCH64_INS_PRFH()),
		PRFM(AARCH64_INS_PRFM()),
		PRFUM(AARCH64_INS_PRFUM()),
		PRFW(AARCH64_INS_PRFW()),
		PSEL(AARCH64_INS_PSEL()),
		PTEST(AARCH64_INS_PTEST()),
		PTRUES(AARCH64_INS_PTRUES()),
		PTRUE(AARCH64_INS_PTRUE()),
		PUNPKHI(AARCH64_INS_PUNPKHI()),
		PUNPKLO(AARCH64_INS_PUNPKLO()),
		RADDHNB(AARCH64_INS_RADDHNB()),
		RADDHNT(AARCH64_INS_RADDHNT()),
		RADDHN(AARCH64_INS_RADDHN()),
		RADDHN2(AARCH64_INS_RADDHN2()),
		RAX1(AARCH64_INS_RAX1()),
		RBIT(AARCH64_INS_RBIT()),
		RCWCAS(AARCH64_INS_RCWCAS()),
		RCWCASA(AARCH64_INS_RCWCASA()),
		RCWCASAL(AARCH64_INS_RCWCASAL()),
		RCWCASL(AARCH64_INS_RCWCASL()),
		RCWCASP(AARCH64_INS_RCWCASP()),
		RCWCASPA(AARCH64_INS_RCWCASPA()),
		RCWCASPAL(AARCH64_INS_RCWCASPAL()),
		RCWCASPL(AARCH64_INS_RCWCASPL()),
		RCWCLR(AARCH64_INS_RCWCLR()),
		RCWCLRA(AARCH64_INS_RCWCLRA()),
		RCWCLRAL(AARCH64_INS_RCWCLRAL()),
		RCWCLRL(AARCH64_INS_RCWCLRL()),
		RCWCLRP(AARCH64_INS_RCWCLRP()),
		RCWCLRPA(AARCH64_INS_RCWCLRPA()),
		RCWCLRPAL(AARCH64_INS_RCWCLRPAL()),
		RCWCLRPL(AARCH64_INS_RCWCLRPL()),
		RCWSCLR(AARCH64_INS_RCWSCLR()),
		RCWSCLRA(AARCH64_INS_RCWSCLRA()),
		RCWSCLRAL(AARCH64_INS_RCWSCLRAL()),
		RCWSCLRL(AARCH64_INS_RCWSCLRL()),
		RCWSCLRP(AARCH64_INS_RCWSCLRP()),
		RCWSCLRPA(AARCH64_INS_RCWSCLRPA()),
		RCWSCLRPAL(AARCH64_INS_RCWSCLRPAL()),
		RCWSCLRPL(AARCH64_INS_RCWSCLRPL()),
		RCWSCAS(AARCH64_INS_RCWSCAS()),
		RCWSCASA(AARCH64_INS_RCWSCASA()),
		RCWSCASAL(AARCH64_INS_RCWSCASAL()),
		RCWSCASL(AARCH64_INS_RCWSCASL()),
		RCWSCASP(AARCH64_INS_RCWSCASP()),
		RCWSCASPA(AARCH64_INS_RCWSCASPA()),
		RCWSCASPAL(AARCH64_INS_RCWSCASPAL()),
		RCWSCASPL(AARCH64_INS_RCWSCASPL()),
		RCWSET(AARCH64_INS_RCWSET()),
		RCWSETA(AARCH64_INS_RCWSETA()),
		RCWSETAL(AARCH64_INS_RCWSETAL()),
		RCWSETL(AARCH64_INS_RCWSETL()),
		RCWSETP(AARCH64_INS_RCWSETP()),
		RCWSETPA(AARCH64_INS_RCWSETPA()),
		RCWSETPAL(AARCH64_INS_RCWSETPAL()),
		RCWSETPL(AARCH64_INS_RCWSETPL()),
		RCWSSET(AARCH64_INS_RCWSSET()),
		RCWSSETA(AARCH64_INS_RCWSSETA()),
		RCWSSETAL(AARCH64_INS_RCWSSETAL()),
		RCWSSETL(AARCH64_INS_RCWSSETL()),
		RCWSSETP(AARCH64_INS_RCWSSETP()),
		RCWSSETPA(AARCH64_INS_RCWSSETPA()),
		RCWSSETPAL(AARCH64_INS_RCWSSETPAL()),
		RCWSSETPL(AARCH64_INS_RCWSSETPL()),
		RCWSWP(AARCH64_INS_RCWSWP()),
		RCWSWPA(AARCH64_INS_RCWSWPA()),
		RCWSWPAL(AARCH64_INS_RCWSWPAL()),
		RCWSWPL(AARCH64_INS_RCWSWPL()),
		RCWSWPP(AARCH64_INS_RCWSWPP()),
		RCWSWPPA(AARCH64_INS_RCWSWPPA()),
		RCWSWPPAL(AARCH64_INS_RCWSWPPAL()),
		RCWSWPPL(AARCH64_INS_RCWSWPPL()),
		RCWSSWP(AARCH64_INS_RCWSSWP()),
		RCWSSWPA(AARCH64_INS_RCWSSWPA()),
		RCWSSWPAL(AARCH64_INS_RCWSSWPAL()),
		RCWSSWPL(AARCH64_INS_RCWSSWPL()),
		RCWSSWPP(AARCH64_INS_RCWSSWPP()),
		RCWSSWPPA(AARCH64_INS_RCWSSWPPA()),
		RCWSSWPPAL(AARCH64_INS_RCWSSWPPAL()),
		RCWSSWPPL(AARCH64_INS_RCWSSWPPL()),
		RDFFRS(AARCH64_INS_RDFFRS()),
		RDFFR(AARCH64_INS_RDFFR()),
		RDSVL(AARCH64_INS_RDSVL()),
		RDVL(AARCH64_INS_RDVL()),
		RET(AARCH64_INS_RET()),
		RETAA(AARCH64_INS_RETAA()),
		RETAASPPC(AARCH64_INS_RETAASPPC()),
		RETAB(AARCH64_INS_RETAB()),
		RETABSPPC(AARCH64_INS_RETABSPPC()),
		REV16(AARCH64_INS_REV16()),
		REV32(AARCH64_INS_REV32()),
		REV64(AARCH64_INS_REV64()),
		REVB(AARCH64_INS_REVB()),
		REVD(AARCH64_INS_REVD()),
		REVH(AARCH64_INS_REVH()),
		REVW(AARCH64_INS_REVW()),
		REV(AARCH64_INS_REV()),
		RMIF(AARCH64_INS_RMIF()),
		ROR(AARCH64_INS_ROR()),
		RPRFM(AARCH64_INS_RPRFM()),
		RSHRNB(AARCH64_INS_RSHRNB()),
		RSHRNT(AARCH64_INS_RSHRNT()),
		RSHRN2(AARCH64_INS_RSHRN2()),
		RSHRN(AARCH64_INS_RSHRN()),
		RSUBHNB(AARCH64_INS_RSUBHNB()),
		RSUBHNT(AARCH64_INS_RSUBHNT()),
		RSUBHN(AARCH64_INS_RSUBHN()),
		RSUBHN2(AARCH64_INS_RSUBHN2()),
		SABALB(AARCH64_INS_SABALB()),
		SABALT(AARCH64_INS_SABALT()),
		SABAL2(AARCH64_INS_SABAL2()),
		SABAL(AARCH64_INS_SABAL()),
		SABA(AARCH64_INS_SABA()),
		SABDLB(AARCH64_INS_SABDLB()),
		SABDLT(AARCH64_INS_SABDLT()),
		SABDL2(AARCH64_INS_SABDL2()),
		SABDL(AARCH64_INS_SABDL()),
		SABD(AARCH64_INS_SABD()),
		SADALP(AARCH64_INS_SADALP()),
		SADDLBT(AARCH64_INS_SADDLBT()),
		SADDLB(AARCH64_INS_SADDLB()),
		SADDLP(AARCH64_INS_SADDLP()),
		SADDLT(AARCH64_INS_SADDLT()),
		SADDLV(AARCH64_INS_SADDLV()),
		SADDL2(AARCH64_INS_SADDL2()),
		SADDL(AARCH64_INS_SADDL()),
		SADDV(AARCH64_INS_SADDV()),
		SADDWB(AARCH64_INS_SADDWB()),
		SADDWT(AARCH64_INS_SADDWT()),
		SADDW2(AARCH64_INS_SADDW2()),
		SADDW(AARCH64_INS_SADDW()),
		SB(AARCH64_INS_SB()),
		SBCLB(AARCH64_INS_SBCLB()),
		SBCLT(AARCH64_INS_SBCLT()),
		SBCS(AARCH64_INS_SBCS()),
		SBC(AARCH64_INS_SBC()),
		SBFM(AARCH64_INS_SBFM()),
		SCLAMP(AARCH64_INS_SCLAMP()),
		SCVTF(AARCH64_INS_SCVTF()),
		SDIVR(AARCH64_INS_SDIVR()),
		SDIV(AARCH64_INS_SDIV()),
		SDOT(AARCH64_INS_SDOT()),
		SEL(AARCH64_INS_SEL()),
		SETE(AARCH64_INS_SETE()),
		SETEN(AARCH64_INS_SETEN()),
		SETET(AARCH64_INS_SETET()),
		SETETN(AARCH64_INS_SETETN()),
		SETF16(AARCH64_INS_SETF16()),
		SETF8(AARCH64_INS_SETF8()),
		SETFFR(AARCH64_INS_SETFFR()),
		SETGM(AARCH64_INS_SETGM()),
		SETGMN(AARCH64_INS_SETGMN()),
		SETGMT(AARCH64_INS_SETGMT()),
		SETGMTN(AARCH64_INS_SETGMTN()),
		SETGP(AARCH64_INS_SETGP()),
		SETGPN(AARCH64_INS_SETGPN()),
		SETGPT(AARCH64_INS_SETGPT()),
		SETGPTN(AARCH64_INS_SETGPTN()),
		SETM(AARCH64_INS_SETM()),
		SETMN(AARCH64_INS_SETMN()),
		SETMT(AARCH64_INS_SETMT()),
		SETMTN(AARCH64_INS_SETMTN()),
		SETP(AARCH64_INS_SETP()),
		SETPN(AARCH64_INS_SETPN()),
		SETPT(AARCH64_INS_SETPT()),
		SETPTN(AARCH64_INS_SETPTN()),
		SHA1C(AARCH64_INS_SHA1C()),
		SHA1H(AARCH64_INS_SHA1H()),
		SHA1M(AARCH64_INS_SHA1M()),
		SHA1P(AARCH64_INS_SHA1P()),
		SHA1SU0(AARCH64_INS_SHA1SU0()),
		SHA1SU1(AARCH64_INS_SHA1SU1()),
		SHA256H2(AARCH64_INS_SHA256H2()),
		SHA256H(AARCH64_INS_SHA256H()),
		SHA256SU0(AARCH64_INS_SHA256SU0()),
		SHA256SU1(AARCH64_INS_SHA256SU1()),
		SHA512H(AARCH64_INS_SHA512H()),
		SHA512H2(AARCH64_INS_SHA512H2()),
		SHA512SU0(AARCH64_INS_SHA512SU0()),
		SHA512SU1(AARCH64_INS_SHA512SU1()),
		SHADD(AARCH64_INS_SHADD()),
		SHLL2(AARCH64_INS_SHLL2()),
		SHLL(AARCH64_INS_SHLL()),
		SHL(AARCH64_INS_SHL()),
		SHRNB(AARCH64_INS_SHRNB()),
		SHRNT(AARCH64_INS_SHRNT()),
		SHRN2(AARCH64_INS_SHRN2()),
		SHRN(AARCH64_INS_SHRN()),
		SHSUBR(AARCH64_INS_SHSUBR()),
		SHSUB(AARCH64_INS_SHSUB()),
		SLI(AARCH64_INS_SLI()),
		SM3PARTW1(AARCH64_INS_SM3PARTW1()),
		SM3PARTW2(AARCH64_INS_SM3PARTW2()),
		SM3SS1(AARCH64_INS_SM3SS1()),
		SM3TT1A(AARCH64_INS_SM3TT1A()),
		SM3TT1B(AARCH64_INS_SM3TT1B()),
		SM3TT2A(AARCH64_INS_SM3TT2A()),
		SM3TT2B(AARCH64_INS_SM3TT2B()),
		SM4E(AARCH64_INS_SM4E()),
		SM4EKEY(AARCH64_INS_SM4EKEY()),
		SMADDL(AARCH64_INS_SMADDL()),
		SMAXP(AARCH64_INS_SMAXP()),
		SMAXQV(AARCH64_INS_SMAXQV()),
		SMAXV(AARCH64_INS_SMAXV()),
		SMAX(AARCH64_INS_SMAX()),
		SMC(AARCH64_INS_SMC()),
		SMINP(AARCH64_INS_SMINP()),
		SMINQV(AARCH64_INS_SMINQV()),
		SMINV(AARCH64_INS_SMINV()),
		SMIN(AARCH64_INS_SMIN()),
		SMLALB(AARCH64_INS_SMLALB()),
		SMLALL(AARCH64_INS_SMLALL()),
		SMLALT(AARCH64_INS_SMLALT()),
		SMLAL(AARCH64_INS_SMLAL()),
		SMLAL2(AARCH64_INS_SMLAL2()),
		SMLSLB(AARCH64_INS_SMLSLB()),
		SMLSLL(AARCH64_INS_SMLSLL()),
		SMLSLT(AARCH64_INS_SMLSLT()),
		SMLSL(AARCH64_INS_SMLSL()),
		SMLSL2(AARCH64_INS_SMLSL2()),
		SMMLA(AARCH64_INS_SMMLA()),
		SMOPA(AARCH64_INS_SMOPA()),
		SMOPS(AARCH64_INS_SMOPS()),
		SMOV(AARCH64_INS_SMOV()),
		SMSUBL(AARCH64_INS_SMSUBL()),
		SMULH(AARCH64_INS_SMULH()),
		SMULLB(AARCH64_INS_SMULLB()),
		SMULLT(AARCH64_INS_SMULLT()),
		SMULL2(AARCH64_INS_SMULL2()),
		SMULL(AARCH64_INS_SMULL()),
		SPLICE(AARCH64_INS_SPLICE()),
		SQABS(AARCH64_INS_SQABS()),
		SQADD(AARCH64_INS_SQADD()),
		SQCADD(AARCH64_INS_SQCADD()),
		SQCVTN(AARCH64_INS_SQCVTN()),
		SQCVTUN(AARCH64_INS_SQCVTUN()),
		SQCVTU(AARCH64_INS_SQCVTU()),
		SQCVT(AARCH64_INS_SQCVT()),
		SQDECB(AARCH64_INS_SQDECB()),
		SQDECD(AARCH64_INS_SQDECD()),
		SQDECH(AARCH64_INS_SQDECH()),
		SQDECP(AARCH64_INS_SQDECP()),
		SQDECW(AARCH64_INS_SQDECW()),
		SQDMLALBT(AARCH64_INS_SQDMLALBT()),
		SQDMLALB(AARCH64_INS_SQDMLALB()),
		SQDMLALT(AARCH64_INS_SQDMLALT()),
		SQDMLAL(AARCH64_INS_SQDMLAL()),
		SQDMLAL2(AARCH64_INS_SQDMLAL2()),
		SQDMLSLBT(AARCH64_INS_SQDMLSLBT()),
		SQDMLSLB(AARCH64_INS_SQDMLSLB()),
		SQDMLSLT(AARCH64_INS_SQDMLSLT()),
		SQDMLSL(AARCH64_INS_SQDMLSL()),
		SQDMLSL2(AARCH64_INS_SQDMLSL2()),
		SQDMULH(AARCH64_INS_SQDMULH()),
		SQDMULLB(AARCH64_INS_SQDMULLB()),
		SQDMULLT(AARCH64_INS_SQDMULLT()),
		SQDMULL(AARCH64_INS_SQDMULL()),
		SQDMULL2(AARCH64_INS_SQDMULL2()),
		SQINCB(AARCH64_INS_SQINCB()),
		SQINCD(AARCH64_INS_SQINCD()),
		SQINCH(AARCH64_INS_SQINCH()),
		SQINCP(AARCH64_INS_SQINCP()),
		SQINCW(AARCH64_INS_SQINCW()),
		SQNEG(AARCH64_INS_SQNEG()),
		SQRDCMLAH(AARCH64_INS_SQRDCMLAH()),
		SQRDMLAH(AARCH64_INS_SQRDMLAH()),
		SQRDMLSH(AARCH64_INS_SQRDMLSH()),
		SQRDMULH(AARCH64_INS_SQRDMULH()),
		SQRSHLR(AARCH64_INS_SQRSHLR()),
		SQRSHL(AARCH64_INS_SQRSHL()),
		SQRSHRNB(AARCH64_INS_SQRSHRNB()),
		SQRSHRNT(AARCH64_INS_SQRSHRNT()),
		SQRSHRN(AARCH64_INS_SQRSHRN()),
		SQRSHRN2(AARCH64_INS_SQRSHRN2()),
		SQRSHRUNB(AARCH64_INS_SQRSHRUNB()),
		SQRSHRUNT(AARCH64_INS_SQRSHRUNT()),
		SQRSHRUN(AARCH64_INS_SQRSHRUN()),
		SQRSHRUN2(AARCH64_INS_SQRSHRUN2()),
		SQRSHRU(AARCH64_INS_SQRSHRU()),
		SQRSHR(AARCH64_INS_SQRSHR()),
		SQSHLR(AARCH64_INS_SQSHLR()),
		SQSHLU(AARCH64_INS_SQSHLU()),
		SQSHL(AARCH64_INS_SQSHL()),
		SQSHRNB(AARCH64_INS_SQSHRNB()),
		SQSHRNT(AARCH64_INS_SQSHRNT()),
		SQSHRN(AARCH64_INS_SQSHRN()),
		SQSHRN2(AARCH64_INS_SQSHRN2()),
		SQSHRUNB(AARCH64_INS_SQSHRUNB()),
		SQSHRUNT(AARCH64_INS_SQSHRUNT()),
		SQSHRUN(AARCH64_INS_SQSHRUN()),
		SQSHRUN2(AARCH64_INS_SQSHRUN2()),
		SQSUBR(AARCH64_INS_SQSUBR()),
		SQSUB(AARCH64_INS_SQSUB()),
		SQXTNB(AARCH64_INS_SQXTNB()),
		SQXTNT(AARCH64_INS_SQXTNT()),
		SQXTN2(AARCH64_INS_SQXTN2()),
		SQXTN(AARCH64_INS_SQXTN()),
		SQXTUNB(AARCH64_INS_SQXTUNB()),
		SQXTUNT(AARCH64_INS_SQXTUNT()),
		SQXTUN2(AARCH64_INS_SQXTUN2()),
		SQXTUN(AARCH64_INS_SQXTUN()),
		SRHADD(AARCH64_INS_SRHADD()),
		SRI(AARCH64_INS_SRI()),
		SRSHLR(AARCH64_INS_SRSHLR()),
		SRSHL(AARCH64_INS_SRSHL()),
		SRSHR(AARCH64_INS_SRSHR()),
		SRSRA(AARCH64_INS_SRSRA()),
		SSHLLB(AARCH64_INS_SSHLLB()),
		SSHLLT(AARCH64_INS_SSHLLT()),
		SSHLL2(AARCH64_INS_SSHLL2()),
		SSHLL(AARCH64_INS_SSHLL()),
		SSHL(AARCH64_INS_SSHL()),
		SSHR(AARCH64_INS_SSHR()),
		SSRA(AARCH64_INS_SSRA()),
		ST1B(AARCH64_INS_ST1B()),
		ST1D(AARCH64_INS_ST1D()),
		ST1H(AARCH64_INS_ST1H()),
		ST1Q(AARCH64_INS_ST1Q()),
		ST1W(AARCH64_INS_ST1W()),
		SSUBLBT(AARCH64_INS_SSUBLBT()),
		SSUBLB(AARCH64_INS_SSUBLB()),
		SSUBLTB(AARCH64_INS_SSUBLTB()),
		SSUBLT(AARCH64_INS_SSUBLT()),
		SSUBL2(AARCH64_INS_SSUBL2()),
		SSUBL(AARCH64_INS_SSUBL()),
		SSUBWB(AARCH64_INS_SSUBWB()),
		SSUBWT(AARCH64_INS_SSUBWT()),
		SSUBW2(AARCH64_INS_SSUBW2()),
		SSUBW(AARCH64_INS_SSUBW()),
		ST1(AARCH64_INS_ST1()),
		ST2B(AARCH64_INS_ST2B()),
		ST2D(AARCH64_INS_ST2D()),
		ST2G(AARCH64_INS_ST2G()),
		ST2H(AARCH64_INS_ST2H()),
		ST2Q(AARCH64_INS_ST2Q()),
		ST2(AARCH64_INS_ST2()),
		ST2W(AARCH64_INS_ST2W()),
		ST3B(AARCH64_INS_ST3B()),
		ST3D(AARCH64_INS_ST3D()),
		ST3H(AARCH64_INS_ST3H()),
		ST3Q(AARCH64_INS_ST3Q()),
		ST3(AARCH64_INS_ST3()),
		ST3W(AARCH64_INS_ST3W()),
		ST4B(AARCH64_INS_ST4B()),
		ST4D(AARCH64_INS_ST4D()),
		ST4(AARCH64_INS_ST4()),
		ST4H(AARCH64_INS_ST4H()),
		ST4Q(AARCH64_INS_ST4Q()),
		ST4W(AARCH64_INS_ST4W()),
		ST64B(AARCH64_INS_ST64B()),
		ST64BV(AARCH64_INS_ST64BV()),
		ST64BV0(AARCH64_INS_ST64BV0()),
		STGM(AARCH64_INS_STGM()),
		STGP(AARCH64_INS_STGP()),
		STG(AARCH64_INS_STG()),
		STILP(AARCH64_INS_STILP()),
		STL1(AARCH64_INS_STL1()),
		STLLRB(AARCH64_INS_STLLRB()),
		STLLRH(AARCH64_INS_STLLRH()),
		STLLR(AARCH64_INS_STLLR()),
		STLRB(AARCH64_INS_STLRB()),
		STLRH(AARCH64_INS_STLRH()),
		STLR(AARCH64_INS_STLR()),
		STLURB(AARCH64_INS_STLURB()),
		STLURH(AARCH64_INS_STLURH()),
		STLUR(AARCH64_INS_STLUR()),
		STLXP(AARCH64_INS_STLXP()),
		STLXRB(AARCH64_INS_STLXRB()),
		STLXRH(AARCH64_INS_STLXRH()),
		STLXR(AARCH64_INS_STLXR()),
		STNP(AARCH64_INS_STNP()),
		STNT1B(AARCH64_INS_STNT1B()),
		STNT1D(AARCH64_INS_STNT1D()),
		STNT1H(AARCH64_INS_STNT1H()),
		STNT1W(AARCH64_INS_STNT1W()),
		STP(AARCH64_INS_STP()),
		STRB(AARCH64_INS_STRB()),
		STR(AARCH64_INS_STR()),
		STRH(AARCH64_INS_STRH()),
		STTRB(AARCH64_INS_STTRB()),
		STTRH(AARCH64_INS_STTRH()),
		STTR(AARCH64_INS_STTR()),
		STURB(AARCH64_INS_STURB()),
		STUR(AARCH64_INS_STUR()),
		STURH(AARCH64_INS_STURH()),
		STXP(AARCH64_INS_STXP()),
		STXRB(AARCH64_INS_STXRB()),
		STXRH(AARCH64_INS_STXRH()),
		STXR(AARCH64_INS_STXR()),
		STZ2G(AARCH64_INS_STZ2G()),
		STZGM(AARCH64_INS_STZGM()),
		STZG(AARCH64_INS_STZG()),
		SUBG(AARCH64_INS_SUBG()),
		SUBHNB(AARCH64_INS_SUBHNB()),
		SUBHNT(AARCH64_INS_SUBHNT()),
		SUBHN(AARCH64_INS_SUBHN()),
		SUBHN2(AARCH64_INS_SUBHN2()),
		SUBP(AARCH64_INS_SUBP()),
		SUBPS(AARCH64_INS_SUBPS()),
		SUBPT(AARCH64_INS_SUBPT()),
		SUBR(AARCH64_INS_SUBR()),
		SUBS(AARCH64_INS_SUBS()),
		SUB(AARCH64_INS_SUB()),
		SUDOT(AARCH64_INS_SUDOT()),
		SUMLALL(AARCH64_INS_SUMLALL()),
		SUMOPA(AARCH64_INS_SUMOPA()),
		SUMOPS(AARCH64_INS_SUMOPS()),
		SUNPKHI(AARCH64_INS_SUNPKHI()),
		SUNPKLO(AARCH64_INS_SUNPKLO()),
		SUNPK(AARCH64_INS_SUNPK()),
		SUQADD(AARCH64_INS_SUQADD()),
		SUVDOT(AARCH64_INS_SUVDOT()),
		SVC(AARCH64_INS_SVC()),
		SVDOT(AARCH64_INS_SVDOT()),
		SWPAB(AARCH64_INS_SWPAB()),
		SWPAH(AARCH64_INS_SWPAH()),
		SWPALB(AARCH64_INS_SWPALB()),
		SWPALH(AARCH64_INS_SWPALH()),
		SWPAL(AARCH64_INS_SWPAL()),
		SWPA(AARCH64_INS_SWPA()),
		SWPB(AARCH64_INS_SWPB()),
		SWPH(AARCH64_INS_SWPH()),
		SWPLB(AARCH64_INS_SWPLB()),
		SWPLH(AARCH64_INS_SWPLH()),
		SWPL(AARCH64_INS_SWPL()),
		SWPP(AARCH64_INS_SWPP()),
		SWPPA(AARCH64_INS_SWPPA()),
		SWPPAL(AARCH64_INS_SWPPAL()),
		SWPPL(AARCH64_INS_SWPPL()),
		SWP(AARCH64_INS_SWP()),
		SXTB(AARCH64_INS_SXTB()),
		SXTH(AARCH64_INS_SXTH()),
		SXTW(AARCH64_INS_SXTW()),
		SYSL(AARCH64_INS_SYSL()),
		SYSP(AARCH64_INS_SYSP()),
		SYS(AARCH64_INS_SYS()),
		TBLQ(AARCH64_INS_TBLQ()),
		TBL(AARCH64_INS_TBL()),
		TBNZ(AARCH64_INS_TBNZ()),
		TBXQ(AARCH64_INS_TBXQ()),
		TBX(AARCH64_INS_TBX()),
		TBZ(AARCH64_INS_TBZ()),
		TCANCEL(AARCH64_INS_TCANCEL()),
		TCOMMIT(AARCH64_INS_TCOMMIT()),
		TRCIT(AARCH64_INS_TRCIT()),
		TRN1(AARCH64_INS_TRN1()),
		TRN2(AARCH64_INS_TRN2()),
		TSB(AARCH64_INS_TSB()),
		TSTART(AARCH64_INS_TSTART()),
		TTEST(AARCH64_INS_TTEST()),
		UABALB(AARCH64_INS_UABALB()),
		UABALT(AARCH64_INS_UABALT()),
		UABAL2(AARCH64_INS_UABAL2()),
		UABAL(AARCH64_INS_UABAL()),
		UABA(AARCH64_INS_UABA()),
		UABDLB(AARCH64_INS_UABDLB()),
		UABDLT(AARCH64_INS_UABDLT()),
		UABDL2(AARCH64_INS_UABDL2()),
		UABDL(AARCH64_INS_UABDL()),
		UABD(AARCH64_INS_UABD()),
		UADALP(AARCH64_INS_UADALP()),
		UADDLB(AARCH64_INS_UADDLB()),
		UADDLP(AARCH64_INS_UADDLP()),
		UADDLT(AARCH64_INS_UADDLT()),
		UADDLV(AARCH64_INS_UADDLV()),
		UADDL2(AARCH64_INS_UADDL2()),
		UADDL(AARCH64_INS_UADDL()),
		UADDV(AARCH64_INS_UADDV()),
		UADDWB(AARCH64_INS_UADDWB()),
		UADDWT(AARCH64_INS_UADDWT()),
		UADDW2(AARCH64_INS_UADDW2()),
		UADDW(AARCH64_INS_UADDW()),
		UBFM(AARCH64_INS_UBFM()),
		UCLAMP(AARCH64_INS_UCLAMP()),
		UCVTF(AARCH64_INS_UCVTF()),
		UDF(AARCH64_INS_UDF()),
		UDIVR(AARCH64_INS_UDIVR()),
		UDIV(AARCH64_INS_UDIV()),
		UDOT(AARCH64_INS_UDOT()),
		UHADD(AARCH64_INS_UHADD()),
		UHSUBR(AARCH64_INS_UHSUBR()),
		UHSUB(AARCH64_INS_UHSUB()),
		UMADDL(AARCH64_INS_UMADDL()),
		UMAXP(AARCH64_INS_UMAXP()),
		UMAXQV(AARCH64_INS_UMAXQV()),
		UMAXV(AARCH64_INS_UMAXV()),
		UMAX(AARCH64_INS_UMAX()),
		UMINP(AARCH64_INS_UMINP()),
		UMINQV(AARCH64_INS_UMINQV()),
		UMINV(AARCH64_INS_UMINV()),
		UMIN(AARCH64_INS_UMIN()),
		UMLALB(AARCH64_INS_UMLALB()),
		UMLALL(AARCH64_INS_UMLALL()),
		UMLALT(AARCH64_INS_UMLALT()),
		UMLAL(AARCH64_INS_UMLAL()),
		UMLAL2(AARCH64_INS_UMLAL2()),
		UMLSLB(AARCH64_INS_UMLSLB()),
		UMLSLL(AARCH64_INS_UMLSLL()),
		UMLSLT(AARCH64_INS_UMLSLT()),
		UMLSL(AARCH64_INS_UMLSL()),
		UMLSL2(AARCH64_INS_UMLSL2()),
		UMMLA(AARCH64_INS_UMMLA()),
		UMOPA(AARCH64_INS_UMOPA()),
		UMOPS(AARCH64_INS_UMOPS()),
		UMOV(AARCH64_INS_UMOV()),
		UMSUBL(AARCH64_INS_UMSUBL()),
		UMULH(AARCH64_INS_UMULH()),
		UMULLB(AARCH64_INS_UMULLB()),
		UMULLT(AARCH64_INS_UMULLT()),
		UMULL2(AARCH64_INS_UMULL2()),
		UMULL(AARCH64_INS_UMULL()),
		UQADD(AARCH64_INS_UQADD()),
		UQCVTN(AARCH64_INS_UQCVTN()),
		UQCVT(AARCH64_INS_UQCVT()),
		UQDECB(AARCH64_INS_UQDECB()),
		UQDECD(AARCH64_INS_UQDECD()),
		UQDECH(AARCH64_INS_UQDECH()),
		UQDECP(AARCH64_INS_UQDECP()),
		UQDECW(AARCH64_INS_UQDECW()),
		UQINCB(AARCH64_INS_UQINCB()),
		UQINCD(AARCH64_INS_UQINCD()),
		UQINCH(AARCH64_INS_UQINCH()),
		UQINCP(AARCH64_INS_UQINCP()),
		UQINCW(AARCH64_INS_UQINCW()),
		UQRSHLR(AARCH64_INS_UQRSHLR()),
		UQRSHL(AARCH64_INS_UQRSHL()),
		UQRSHRNB(AARCH64_INS_UQRSHRNB()),
		UQRSHRNT(AARCH64_INS_UQRSHRNT()),
		UQRSHRN(AARCH64_INS_UQRSHRN()),
		UQRSHRN2(AARCH64_INS_UQRSHRN2()),
		UQRSHR(AARCH64_INS_UQRSHR()),
		UQSHLR(AARCH64_INS_UQSHLR()),
		UQSHL(AARCH64_INS_UQSHL()),
		UQSHRNB(AARCH64_INS_UQSHRNB()),
		UQSHRNT(AARCH64_INS_UQSHRNT()),
		UQSHRN(AARCH64_INS_UQSHRN()),
		UQSHRN2(AARCH64_INS_UQSHRN2()),
		UQSUBR(AARCH64_INS_UQSUBR()),
		UQSUB(AARCH64_INS_UQSUB()),
		UQXTNB(AARCH64_INS_UQXTNB()),
		UQXTNT(AARCH64_INS_UQXTNT()),
		UQXTN2(AARCH64_INS_UQXTN2()),
		UQXTN(AARCH64_INS_UQXTN()),
		URECPE(AARCH64_INS_URECPE()),
		URHADD(AARCH64_INS_URHADD()),
		URSHLR(AARCH64_INS_URSHLR()),
		URSHL(AARCH64_INS_URSHL()),
		URSHR(AARCH64_INS_URSHR()),
		URSQRTE(AARCH64_INS_URSQRTE()),
		URSRA(AARCH64_INS_URSRA()),
		USDOT(AARCH64_INS_USDOT()),
		USHLLB(AARCH64_INS_USHLLB()),
		USHLLT(AARCH64_INS_USHLLT()),
		USHLL2(AARCH64_INS_USHLL2()),
		USHLL(AARCH64_INS_USHLL()),
		USHL(AARCH64_INS_USHL()),
		USHR(AARCH64_INS_USHR()),
		USMLALL(AARCH64_INS_USMLALL()),
		USMMLA(AARCH64_INS_USMMLA()),
		USMOPA(AARCH64_INS_USMOPA()),
		USMOPS(AARCH64_INS_USMOPS()),
		USQADD(AARCH64_INS_USQADD()),
		USRA(AARCH64_INS_USRA()),
		USUBLB(AARCH64_INS_USUBLB()),
		USUBLT(AARCH64_INS_USUBLT()),
		USUBL2(AARCH64_INS_USUBL2()),
		USUBL(AARCH64_INS_USUBL()),
		USUBWB(AARCH64_INS_USUBWB()),
		USUBWT(AARCH64_INS_USUBWT()),
		USUBW2(AARCH64_INS_USUBW2()),
		USUBW(AARCH64_INS_USUBW()),
		USVDOT(AARCH64_INS_USVDOT()),
		UUNPKHI(AARCH64_INS_UUNPKHI()),
		UUNPKLO(AARCH64_INS_UUNPKLO()),
		UUNPK(AARCH64_INS_UUNPK()),
		UVDOT(AARCH64_INS_UVDOT()),
		UXTB(AARCH64_INS_UXTB()),
		UXTH(AARCH64_INS_UXTH()),
		UXTW(AARCH64_INS_UXTW()),
		UZP1(AARCH64_INS_UZP1()),
		UZP2(AARCH64_INS_UZP2()),
		UZPQ1(AARCH64_INS_UZPQ1()),
		UZPQ2(AARCH64_INS_UZPQ2()),
		UZP(AARCH64_INS_UZP()),
		WFET(AARCH64_INS_WFET()),
		WFIT(AARCH64_INS_WFIT()),
		WHILEGE(AARCH64_INS_WHILEGE()),
		WHILEGT(AARCH64_INS_WHILEGT()),
		WHILEHI(AARCH64_INS_WHILEHI()),
		WHILEHS(AARCH64_INS_WHILEHS()),
		WHILELE(AARCH64_INS_WHILELE()),
		WHILELO(AARCH64_INS_WHILELO()),
		WHILELS(AARCH64_INS_WHILELS()),
		WHILELT(AARCH64_INS_WHILELT()),
		WHILERW(AARCH64_INS_WHILERW()),
		WHILEWR(AARCH64_INS_WHILEWR()),
		WRFFR(AARCH64_INS_WRFFR()),
		XAFLAG(AARCH64_INS_XAFLAG()),
		XAR(AARCH64_INS_XAR()),
		XPACD(AARCH64_INS_XPACD()),
		XPACI(AARCH64_INS_XPACI()),
		XTN2(AARCH64_INS_XTN2()),
		XTN(AARCH64_INS_XTN()),
		ZERO(AARCH64_INS_ZERO()),
		ZIP1(AARCH64_INS_ZIP1()),
		ZIP2(AARCH64_INS_ZIP2()),
		ZIPQ1(AARCH64_INS_ZIPQ1()),
		ZIPQ2(AARCH64_INS_ZIPQ2()),
		ZIP(AARCH64_INS_ZIP()),

		// clang-format on
		// generated content <AArch64GenCSInsnEnum.inc> end

		ENDING(AARCH64_INS_ENDING()), // <-- mark the end of the list of insn

		ALIAS_BEGIN(AARCH64_INS_ALIAS_BEGIN()),
		// generated content <AArch64GenCSAliasEnum.inc> begin
		// clang-format off

		ALIAS_ADDPT(AARCH64_INS_ALIAS_ADDPT()), // Real instr.: AARCH64_ADDPT_shift
		ALIAS_GCSB(AARCH64_INS_ALIAS_GCSB()), // Real instr.: AARCH64_HINT
		ALIAS_GCSPOPM(AARCH64_INS_ALIAS_GCSPOPM()), // Real instr.: AARCH64_GCSPOPM
		ALIAS_LDAPUR(AARCH64_INS_ALIAS_LDAPUR()), // Real instr.: AARCH64_LDAPURbi
		ALIAS_STLLRB(AARCH64_INS_ALIAS_STLLRB()), // Real instr.: AARCH64_STLLRB
		ALIAS_STLLRH(AARCH64_INS_ALIAS_STLLRH()), // Real instr.: AARCH64_STLLRH
		ALIAS_STLLR(AARCH64_INS_ALIAS_STLLR()), // Real instr.: AARCH64_STLLRW
		ALIAS_STLRB(AARCH64_INS_ALIAS_STLRB()), // Real instr.: AARCH64_STLRB
		ALIAS_STLRH(AARCH64_INS_ALIAS_STLRH()), // Real instr.: AARCH64_STLRH
		ALIAS_STLR(AARCH64_INS_ALIAS_STLR()), // Real instr.: AARCH64_STLRW
		ALIAS_STLUR(AARCH64_INS_ALIAS_STLUR()), // Real instr.: AARCH64_STLURbi
		ALIAS_SUBPT(AARCH64_INS_ALIAS_SUBPT()), // Real instr.: AARCH64_SUBPT_shift
		ALIAS_LDRAA(AARCH64_INS_ALIAS_LDRAA()), // Real instr.: AARCH64_LDRAAindexed
		ALIAS_ADD(AARCH64_INS_ALIAS_ADD()), // Real instr.: AARCH64_ADDWrs
		ALIAS_CMN(AARCH64_INS_ALIAS_CMN()), // Real instr.: AARCH64_ADDSWri
		ALIAS_ADDS(AARCH64_INS_ALIAS_ADDS()), // Real instr.: AARCH64_ADDSWrs
		ALIAS_AND(AARCH64_INS_ALIAS_AND()), // Real instr.: AARCH64_ANDWrs
		ALIAS_ANDS(AARCH64_INS_ALIAS_ANDS()), // Real instr.: AARCH64_ANDSWrs
		ALIAS_LDR(AARCH64_INS_ALIAS_LDR()), // Real instr.: AARCH64_LDRXui
		ALIAS_STR(AARCH64_INS_ALIAS_STR()), // Real instr.: AARCH64_STRBui
		ALIAS_LDRB(AARCH64_INS_ALIAS_LDRB()), // Real instr.: AARCH64_LDRBBroX
		ALIAS_STRB(AARCH64_INS_ALIAS_STRB()), // Real instr.: AARCH64_STRBBroX
		ALIAS_LDRH(AARCH64_INS_ALIAS_LDRH()), // Real instr.: AARCH64_LDRHHroX
		ALIAS_STRH(AARCH64_INS_ALIAS_STRH()), // Real instr.: AARCH64_STRHHroX
		ALIAS_PRFM(AARCH64_INS_ALIAS_PRFM()), // Real instr.: AARCH64_PRFMroX
		ALIAS_LDAPURB(AARCH64_INS_ALIAS_LDAPURB()), // Real instr.: AARCH64_LDAPURBi
		ALIAS_STLURB(AARCH64_INS_ALIAS_STLURB()), // Real instr.: AARCH64_STLURBi
		ALIAS_LDUR(AARCH64_INS_ALIAS_LDUR()), // Real instr.: AARCH64_LDURXi
		ALIAS_STUR(AARCH64_INS_ALIAS_STUR()), // Real instr.: AARCH64_STURXi
		ALIAS_PRFUM(AARCH64_INS_ALIAS_PRFUM()), // Real instr.: AARCH64_PRFUMi
		ALIAS_LDTR(AARCH64_INS_ALIAS_LDTR()), // Real instr.: AARCH64_LDTRXi
		ALIAS_STTR(AARCH64_INS_ALIAS_STTR()), // Real instr.: AARCH64_STTRWi
		ALIAS_LDP(AARCH64_INS_ALIAS_LDP()), // Real instr.: AARCH64_LDPWi
		ALIAS_STGP(AARCH64_INS_ALIAS_STGP()), // Real instr.: AARCH64_STGPi
		ALIAS_LDNP(AARCH64_INS_ALIAS_LDNP()), // Real instr.: AARCH64_LDNPWi
		ALIAS_STNP(AARCH64_INS_ALIAS_STNP()), // Real instr.: AARCH64_STNPWi
		ALIAS_STG(AARCH64_INS_ALIAS_STG()), // Real instr.: AARCH64_STGi
		ALIAS_MOV(AARCH64_INS_ALIAS_MOV()), // Real instr.: AARCH64_UMOVvi32_idx0
		ALIAS_LD1(AARCH64_INS_ALIAS_LD1()), // Real instr.: AARCH64_LD1Onev16b_POST
		ALIAS_LD1R(AARCH64_INS_ALIAS_LD1R()), // Real instr.: AARCH64_LD1Rv8b_POST
		ALIAS_STADDLB(AARCH64_INS_ALIAS_STADDLB()), // Real instr.: AARCH64_LDADDLB
		ALIAS_STADDLH(AARCH64_INS_ALIAS_STADDLH()), // Real instr.: AARCH64_LDADDLH
		ALIAS_STADDL(AARCH64_INS_ALIAS_STADDL()), // Real instr.: AARCH64_LDADDLW
		ALIAS_STADDB(AARCH64_INS_ALIAS_STADDB()), // Real instr.: AARCH64_LDADDB
		ALIAS_STADDH(AARCH64_INS_ALIAS_STADDH()), // Real instr.: AARCH64_LDADDH
		ALIAS_STADD(AARCH64_INS_ALIAS_STADD()), // Real instr.: AARCH64_LDADDW
		ALIAS_PTRUE(AARCH64_INS_ALIAS_PTRUE()), // Real instr.: AARCH64_PTRUE_B
		ALIAS_PTRUES(AARCH64_INS_ALIAS_PTRUES()), // Real instr.: AARCH64_PTRUES_B
		ALIAS_CNTB(AARCH64_INS_ALIAS_CNTB()), // Real instr.: AARCH64_CNTB_XPiI
		ALIAS_SQINCH(AARCH64_INS_ALIAS_SQINCH()), // Real instr.: AARCH64_SQINCH_ZPiI
		ALIAS_INCB(AARCH64_INS_ALIAS_INCB()), // Real instr.: AARCH64_INCB_XPiI
		ALIAS_SQINCB(AARCH64_INS_ALIAS_SQINCB()), // Real instr.: AARCH64_SQINCB_XPiWdI
		ALIAS_UQINCB(AARCH64_INS_ALIAS_UQINCB()), // Real instr.: AARCH64_UQINCB_WPiI
		ALIAS_ORR(AARCH64_INS_ALIAS_ORR()), // Real instr.: AARCH64_ORR_ZI
		ALIAS_DUPM(AARCH64_INS_ALIAS_DUPM()), // Real instr.: AARCH64_DUPM_ZI
		ALIAS_FMOV(AARCH64_INS_ALIAS_FMOV()), // Real instr.: AARCH64_DUP_ZI_H
		ALIAS_EOR3(AARCH64_INS_ALIAS_EOR3()), // Real instr.: AARCH64_EOR3_ZZZZ
		ALIAS_ST1B(AARCH64_INS_ALIAS_ST1B()), // Real instr.: AARCH64_ST1B_IMM
		ALIAS_ST2B(AARCH64_INS_ALIAS_ST2B()), // Real instr.: AARCH64_ST2B_IMM
		ALIAS_ST2Q(AARCH64_INS_ALIAS_ST2Q()), // Real instr.: AARCH64_ST2Q_IMM
		ALIAS_STNT1B(AARCH64_INS_ALIAS_STNT1B()), // Real instr.: AARCH64_STNT1B_ZRI
		ALIAS_LD1B(AARCH64_INS_ALIAS_LD1B()), // Real instr.: AARCH64_LD1B_IMM
		ALIAS_LDNT1B(AARCH64_INS_ALIAS_LDNT1B()), // Real instr.: AARCH64_LDNT1B_ZRI
		ALIAS_LD1RQB(AARCH64_INS_ALIAS_LD1RQB()), // Real instr.: AARCH64_LD1RQ_B_IMM
		ALIAS_LD1RB(AARCH64_INS_ALIAS_LD1RB()), // Real instr.: AARCH64_LD1RB_IMM
		ALIAS_LDFF1B(AARCH64_INS_ALIAS_LDFF1B()), // Real instr.: AARCH64_LDFF1B_REAL
		ALIAS_LDNF1B(AARCH64_INS_ALIAS_LDNF1B()), // Real instr.: AARCH64_LDNF1B_IMM_REAL
		ALIAS_LD2B(AARCH64_INS_ALIAS_LD2B()), // Real instr.: AARCH64_LD2B_IMM
		ALIAS_LD1SB(AARCH64_INS_ALIAS_LD1SB()), // Real instr.: AARCH64_GLD1SB_S_IMM_REAL
		ALIAS_PRFB(AARCH64_INS_ALIAS_PRFB()), // Real instr.: AARCH64_PRFB_PRI
		ALIAS_LDNT1SB(AARCH64_INS_ALIAS_LDNT1SB()), // Real instr.: AARCH64_LDNT1SB_ZZR_S_REAL
		ALIAS_LD1ROB(AARCH64_INS_ALIAS_LD1ROB()), // Real instr.: AARCH64_LD1RO_B_IMM
		ALIAS_LD1Q(AARCH64_INS_ALIAS_LD1Q()), // Real instr.: AARCH64_GLD1Q
		ALIAS_ST1Q(AARCH64_INS_ALIAS_ST1Q()), // Real instr.: AARCH64_SST1Q
		ALIAS_LD1W(AARCH64_INS_ALIAS_LD1W()), // Real instr.: AARCH64_LD1W_Q_IMM
		ALIAS_PMOV(AARCH64_INS_ALIAS_PMOV()), // Real instr.: AARCH64_PMOV_PZI_B
		ALIAS_SMSTART(AARCH64_INS_ALIAS_SMSTART()), // Real instr.: AARCH64_MSRpstatesvcrImm1
		ALIAS_SMSTOP(AARCH64_INS_ALIAS_SMSTOP()), // Real instr.: AARCH64_MSRpstatesvcrImm1
		ALIAS_ZERO(AARCH64_INS_ALIAS_ZERO()), // Real instr.: AARCH64_ZERO_M
		ALIAS_MOVT(AARCH64_INS_ALIAS_MOVT()), // Real instr.: AARCH64_MOVT
		ALIAS_NOP(AARCH64_INS_ALIAS_NOP()), // Real instr.: AARCH64_HINT
		ALIAS_YIELD(AARCH64_INS_ALIAS_YIELD()), // Real instr.: AARCH64_HINT
		ALIAS_WFE(AARCH64_INS_ALIAS_WFE()), // Real instr.: AARCH64_HINT
		ALIAS_WFI(AARCH64_INS_ALIAS_WFI()), // Real instr.: AARCH64_HINT
		ALIAS_SEV(AARCH64_INS_ALIAS_SEV()), // Real instr.: AARCH64_HINT
		ALIAS_SEVL(AARCH64_INS_ALIAS_SEVL()), // Real instr.: AARCH64_HINT
		ALIAS_DGH(AARCH64_INS_ALIAS_DGH()), // Real instr.: AARCH64_HINT
		ALIAS_ESB(AARCH64_INS_ALIAS_ESB()), // Real instr.: AARCH64_HINT
		ALIAS_CSDB(AARCH64_INS_ALIAS_CSDB()), // Real instr.: AARCH64_HINT
		ALIAS_BTI(AARCH64_INS_ALIAS_BTI()), // Real instr.: AARCH64_HINT
		ALIAS_PSB(AARCH64_INS_ALIAS_PSB()), // Real instr.: AARCH64_HINT
		ALIAS_CHKFEAT(AARCH64_INS_ALIAS_CHKFEAT()), // Real instr.: AARCH64_CHKFEAT
		ALIAS_PACIAZ(AARCH64_INS_ALIAS_PACIAZ()), // Real instr.: AARCH64_PACIAZ
		ALIAS_PACIBZ(AARCH64_INS_ALIAS_PACIBZ()), // Real instr.: AARCH64_PACIBZ
		ALIAS_AUTIAZ(AARCH64_INS_ALIAS_AUTIAZ()), // Real instr.: AARCH64_AUTIAZ
		ALIAS_AUTIBZ(AARCH64_INS_ALIAS_AUTIBZ()), // Real instr.: AARCH64_AUTIBZ
		ALIAS_PACIASP(AARCH64_INS_ALIAS_PACIASP()), // Real instr.: AARCH64_PACIASP
		ALIAS_PACIBSP(AARCH64_INS_ALIAS_PACIBSP()), // Real instr.: AARCH64_PACIBSP
		ALIAS_AUTIASP(AARCH64_INS_ALIAS_AUTIASP()), // Real instr.: AARCH64_AUTIASP
		ALIAS_AUTIBSP(AARCH64_INS_ALIAS_AUTIBSP()), // Real instr.: AARCH64_AUTIBSP
		ALIAS_PACIA1716(AARCH64_INS_ALIAS_PACIA1716()), // Real instr.: AARCH64_PACIA1716
		ALIAS_PACIB1716(AARCH64_INS_ALIAS_PACIB1716()), // Real instr.: AARCH64_PACIB1716
		ALIAS_AUTIA1716(AARCH64_INS_ALIAS_AUTIA1716()), // Real instr.: AARCH64_AUTIA1716
		ALIAS_AUTIB1716(AARCH64_INS_ALIAS_AUTIB1716()), // Real instr.: AARCH64_AUTIB1716
		ALIAS_XPACLRI(AARCH64_INS_ALIAS_XPACLRI()), // Real instr.: AARCH64_XPACLRI
		ALIAS_LDRAB(AARCH64_INS_ALIAS_LDRAB()), // Real instr.: AARCH64_LDRABindexed
		ALIAS_PACM(AARCH64_INS_ALIAS_PACM()), // Real instr.: AARCH64_PACM
		ALIAS_CLREX(AARCH64_INS_ALIAS_CLREX()), // Real instr.: AARCH64_CLREX
		ALIAS_ISB(AARCH64_INS_ALIAS_ISB()), // Real instr.: AARCH64_ISB
		ALIAS_SSBB(AARCH64_INS_ALIAS_SSBB()), // Real instr.: AARCH64_DSB
		ALIAS_PSSBB(AARCH64_INS_ALIAS_PSSBB()), // Real instr.: AARCH64_DSB
		ALIAS_DFB(AARCH64_INS_ALIAS_DFB()), // Real instr.: AARCH64_DSB
		ALIAS_SYS(AARCH64_INS_ALIAS_SYS()), // Real instr.: AARCH64_SYSxt
		ALIAS_MOVN(AARCH64_INS_ALIAS_MOVN()), // Real instr.: AARCH64_MOVNWi
		ALIAS_MOVZ(AARCH64_INS_ALIAS_MOVZ()), // Real instr.: AARCH64_MOVZWi
		ALIAS_NGC(AARCH64_INS_ALIAS_NGC()), // Real instr.: AARCH64_SBCWr
		ALIAS_NGCS(AARCH64_INS_ALIAS_NGCS()), // Real instr.: AARCH64_SBCSWr
		ALIAS_SUB(AARCH64_INS_ALIAS_SUB()), // Real instr.: AARCH64_SUBWrs
		ALIAS_CMP(AARCH64_INS_ALIAS_CMP()), // Real instr.: AARCH64_SUBSWri
		ALIAS_SUBS(AARCH64_INS_ALIAS_SUBS()), // Real instr.: AARCH64_SUBSWrs
		ALIAS_NEG(AARCH64_INS_ALIAS_NEG()), // Real instr.: AARCH64_SUBWrs
		ALIAS_NEGS(AARCH64_INS_ALIAS_NEGS()), // Real instr.: AARCH64_SUBSWrs
		ALIAS_MUL(AARCH64_INS_ALIAS_MUL()), // Real instr.: AARCH64_MADDWrrr
		ALIAS_MNEG(AARCH64_INS_ALIAS_MNEG()), // Real instr.: AARCH64_MSUBWrrr
		ALIAS_SMULL(AARCH64_INS_ALIAS_SMULL()), // Real instr.: AARCH64_SMADDLrrr
		ALIAS_SMNEGL(AARCH64_INS_ALIAS_SMNEGL()), // Real instr.: AARCH64_SMSUBLrrr
		ALIAS_UMULL(AARCH64_INS_ALIAS_UMULL()), // Real instr.: AARCH64_UMADDLrrr
		ALIAS_UMNEGL(AARCH64_INS_ALIAS_UMNEGL()), // Real instr.: AARCH64_UMSUBLrrr
		ALIAS_STCLRLB(AARCH64_INS_ALIAS_STCLRLB()), // Real instr.: AARCH64_LDCLRLB
		ALIAS_STCLRLH(AARCH64_INS_ALIAS_STCLRLH()), // Real instr.: AARCH64_LDCLRLH
		ALIAS_STCLRL(AARCH64_INS_ALIAS_STCLRL()), // Real instr.: AARCH64_LDCLRLW
		ALIAS_STCLRB(AARCH64_INS_ALIAS_STCLRB()), // Real instr.: AARCH64_LDCLRB
		ALIAS_STCLRH(AARCH64_INS_ALIAS_STCLRH()), // Real instr.: AARCH64_LDCLRH
		ALIAS_STCLR(AARCH64_INS_ALIAS_STCLR()), // Real instr.: AARCH64_LDCLRW
		ALIAS_STEORLB(AARCH64_INS_ALIAS_STEORLB()), // Real instr.: AARCH64_LDEORLB
		ALIAS_STEORLH(AARCH64_INS_ALIAS_STEORLH()), // Real instr.: AARCH64_LDEORLH
		ALIAS_STEORL(AARCH64_INS_ALIAS_STEORL()), // Real instr.: AARCH64_LDEORLW
		ALIAS_STEORB(AARCH64_INS_ALIAS_STEORB()), // Real instr.: AARCH64_LDEORB
		ALIAS_STEORH(AARCH64_INS_ALIAS_STEORH()), // Real instr.: AARCH64_LDEORH
		ALIAS_STEOR(AARCH64_INS_ALIAS_STEOR()), // Real instr.: AARCH64_LDEORW
		ALIAS_STSETLB(AARCH64_INS_ALIAS_STSETLB()), // Real instr.: AARCH64_LDSETLB
		ALIAS_STSETLH(AARCH64_INS_ALIAS_STSETLH()), // Real instr.: AARCH64_LDSETLH
		ALIAS_STSETL(AARCH64_INS_ALIAS_STSETL()), // Real instr.: AARCH64_LDSETLW
		ALIAS_STSETB(AARCH64_INS_ALIAS_STSETB()), // Real instr.: AARCH64_LDSETB
		ALIAS_STSETH(AARCH64_INS_ALIAS_STSETH()), // Real instr.: AARCH64_LDSETH
		ALIAS_STSET(AARCH64_INS_ALIAS_STSET()), // Real instr.: AARCH64_LDSETW
		ALIAS_STSMAXLB(AARCH64_INS_ALIAS_STSMAXLB()), // Real instr.: AARCH64_LDSMAXLB
		ALIAS_STSMAXLH(AARCH64_INS_ALIAS_STSMAXLH()), // Real instr.: AARCH64_LDSMAXLH
		ALIAS_STSMAXL(AARCH64_INS_ALIAS_STSMAXL()), // Real instr.: AARCH64_LDSMAXLW
		ALIAS_STSMAXB(AARCH64_INS_ALIAS_STSMAXB()), // Real instr.: AARCH64_LDSMAXB
		ALIAS_STSMAXH(AARCH64_INS_ALIAS_STSMAXH()), // Real instr.: AARCH64_LDSMAXH
		ALIAS_STSMAX(AARCH64_INS_ALIAS_STSMAX()), // Real instr.: AARCH64_LDSMAXW
		ALIAS_STSMINLB(AARCH64_INS_ALIAS_STSMINLB()), // Real instr.: AARCH64_LDSMINLB
		ALIAS_STSMINLH(AARCH64_INS_ALIAS_STSMINLH()), // Real instr.: AARCH64_LDSMINLH
		ALIAS_STSMINL(AARCH64_INS_ALIAS_STSMINL()), // Real instr.: AARCH64_LDSMINLW
		ALIAS_STSMINB(AARCH64_INS_ALIAS_STSMINB()), // Real instr.: AARCH64_LDSMINB
		ALIAS_STSMINH(AARCH64_INS_ALIAS_STSMINH()), // Real instr.: AARCH64_LDSMINH
		ALIAS_STSMIN(AARCH64_INS_ALIAS_STSMIN()), // Real instr.: AARCH64_LDSMINW
		ALIAS_STUMAXLB(AARCH64_INS_ALIAS_STUMAXLB()), // Real instr.: AARCH64_LDUMAXLB
		ALIAS_STUMAXLH(AARCH64_INS_ALIAS_STUMAXLH()), // Real instr.: AARCH64_LDUMAXLH
		ALIAS_STUMAXL(AARCH64_INS_ALIAS_STUMAXL()), // Real instr.: AARCH64_LDUMAXLW
		ALIAS_STUMAXB(AARCH64_INS_ALIAS_STUMAXB()), // Real instr.: AARCH64_LDUMAXB
		ALIAS_STUMAXH(AARCH64_INS_ALIAS_STUMAXH()), // Real instr.: AARCH64_LDUMAXH
		ALIAS_STUMAX(AARCH64_INS_ALIAS_STUMAX()), // Real instr.: AARCH64_LDUMAXW
		ALIAS_STUMINLB(AARCH64_INS_ALIAS_STUMINLB()), // Real instr.: AARCH64_LDUMINLB
		ALIAS_STUMINLH(AARCH64_INS_ALIAS_STUMINLH()), // Real instr.: AARCH64_LDUMINLH
		ALIAS_STUMINL(AARCH64_INS_ALIAS_STUMINL()), // Real instr.: AARCH64_LDUMINLW
		ALIAS_STUMINB(AARCH64_INS_ALIAS_STUMINB()), // Real instr.: AARCH64_LDUMINB
		ALIAS_STUMINH(AARCH64_INS_ALIAS_STUMINH()), // Real instr.: AARCH64_LDUMINH
		ALIAS_STUMIN(AARCH64_INS_ALIAS_STUMIN()), // Real instr.: AARCH64_LDUMINW
		ALIAS_IRG(AARCH64_INS_ALIAS_IRG()), // Real instr.: AARCH64_IRG
		ALIAS_LDG(AARCH64_INS_ALIAS_LDG()), // Real instr.: AARCH64_LDG
		ALIAS_STZG(AARCH64_INS_ALIAS_STZG()), // Real instr.: AARCH64_STZGi
		ALIAS_ST2G(AARCH64_INS_ALIAS_ST2G()), // Real instr.: AARCH64_ST2Gi
		ALIAS_STZ2G(AARCH64_INS_ALIAS_STZ2G()), // Real instr.: AARCH64_STZ2Gi
		ALIAS_BICS(AARCH64_INS_ALIAS_BICS()), // Real instr.: AARCH64_BICSWrs
		ALIAS_BIC(AARCH64_INS_ALIAS_BIC()), // Real instr.: AARCH64_BICWrs
		ALIAS_EON(AARCH64_INS_ALIAS_EON()), // Real instr.: AARCH64_EONWrs
		ALIAS_EOR(AARCH64_INS_ALIAS_EOR()), // Real instr.: AARCH64_EORWrs
		ALIAS_ORN(AARCH64_INS_ALIAS_ORN()), // Real instr.: AARCH64_ORNWrs
		ALIAS_MVN(AARCH64_INS_ALIAS_MVN()), // Real instr.: AARCH64_ORNWrs
		ALIAS_TST(AARCH64_INS_ALIAS_TST()), // Real instr.: AARCH64_ANDSWri
		ALIAS_ROR(AARCH64_INS_ALIAS_ROR()), // Real instr.: AARCH64_EXTRWrri
		ALIAS_ASR(AARCH64_INS_ALIAS_ASR()), // Real instr.: AARCH64_SBFMWri
		ALIAS_SXTB(AARCH64_INS_ALIAS_SXTB()), // Real instr.: AARCH64_SBFMWri
		ALIAS_SXTH(AARCH64_INS_ALIAS_SXTH()), // Real instr.: AARCH64_SBFMWri
		ALIAS_SXTW(AARCH64_INS_ALIAS_SXTW()), // Real instr.: AARCH64_SBFMXri
		ALIAS_LSR(AARCH64_INS_ALIAS_LSR()), // Real instr.: AARCH64_UBFMWri
		ALIAS_UXTB(AARCH64_INS_ALIAS_UXTB()), // Real instr.: AARCH64_UBFMWri
		ALIAS_UXTH(AARCH64_INS_ALIAS_UXTH()), // Real instr.: AARCH64_UBFMWri
		ALIAS_UXTW(AARCH64_INS_ALIAS_UXTW()), // Real instr.: AARCH64_UBFMXri
		ALIAS_CSET(AARCH64_INS_ALIAS_CSET()), // Real instr.: AARCH64_CSINCWr
		ALIAS_CSETM(AARCH64_INS_ALIAS_CSETM()), // Real instr.: AARCH64_CSINVWr
		ALIAS_CINC(AARCH64_INS_ALIAS_CINC()), // Real instr.: AARCH64_CSINCWr
		ALIAS_CINV(AARCH64_INS_ALIAS_CINV()), // Real instr.: AARCH64_CSINVWr
		ALIAS_CNEG(AARCH64_INS_ALIAS_CNEG()), // Real instr.: AARCH64_CSNEGWr
		ALIAS_RET(AARCH64_INS_ALIAS_RET()), // Real instr.: AARCH64_RET
		ALIAS_DCPS1(AARCH64_INS_ALIAS_DCPS1()), // Real instr.: AARCH64_DCPS1
		ALIAS_DCPS2(AARCH64_INS_ALIAS_DCPS2()), // Real instr.: AARCH64_DCPS2
		ALIAS_DCPS3(AARCH64_INS_ALIAS_DCPS3()), // Real instr.: AARCH64_DCPS3
		ALIAS_LDPSW(AARCH64_INS_ALIAS_LDPSW()), // Real instr.: AARCH64_LDPSWi
		ALIAS_LDRSH(AARCH64_INS_ALIAS_LDRSH()), // Real instr.: AARCH64_LDRSHWroX
		ALIAS_LDRSB(AARCH64_INS_ALIAS_LDRSB()), // Real instr.: AARCH64_LDRSBWroX
		ALIAS_LDRSW(AARCH64_INS_ALIAS_LDRSW()), // Real instr.: AARCH64_LDRSWroX
		ALIAS_LDURH(AARCH64_INS_ALIAS_LDURH()), // Real instr.: AARCH64_LDURHHi
		ALIAS_LDURB(AARCH64_INS_ALIAS_LDURB()), // Real instr.: AARCH64_LDURBBi
		ALIAS_LDURSH(AARCH64_INS_ALIAS_LDURSH()), // Real instr.: AARCH64_LDURSHWi
		ALIAS_LDURSB(AARCH64_INS_ALIAS_LDURSB()), // Real instr.: AARCH64_LDURSBWi
		ALIAS_LDURSW(AARCH64_INS_ALIAS_LDURSW()), // Real instr.: AARCH64_LDURSWi
		ALIAS_LDTRH(AARCH64_INS_ALIAS_LDTRH()), // Real instr.: AARCH64_LDTRHi
		ALIAS_LDTRB(AARCH64_INS_ALIAS_LDTRB()), // Real instr.: AARCH64_LDTRBi
		ALIAS_LDTRSH(AARCH64_INS_ALIAS_LDTRSH()), // Real instr.: AARCH64_LDTRSHWi
		ALIAS_LDTRSB(AARCH64_INS_ALIAS_LDTRSB()), // Real instr.: AARCH64_LDTRSBWi
		ALIAS_LDTRSW(AARCH64_INS_ALIAS_LDTRSW()), // Real instr.: AARCH64_LDTRSWi
		ALIAS_STP(AARCH64_INS_ALIAS_STP()), // Real instr.: AARCH64_STPWi
		ALIAS_STURH(AARCH64_INS_ALIAS_STURH()), // Real instr.: AARCH64_STURHHi
		ALIAS_STURB(AARCH64_INS_ALIAS_STURB()), // Real instr.: AARCH64_STURBBi
		ALIAS_STLURH(AARCH64_INS_ALIAS_STLURH()), // Real instr.: AARCH64_STLURHi
		ALIAS_LDAPURSB(AARCH64_INS_ALIAS_LDAPURSB()), // Real instr.: AARCH64_LDAPURSBWi
		ALIAS_LDAPURH(AARCH64_INS_ALIAS_LDAPURH()), // Real instr.: AARCH64_LDAPURHi
		ALIAS_LDAPURSH(AARCH64_INS_ALIAS_LDAPURSH()), // Real instr.: AARCH64_LDAPURSHWi
		ALIAS_LDAPURSW(AARCH64_INS_ALIAS_LDAPURSW()), // Real instr.: AARCH64_LDAPURSWi
		ALIAS_STTRH(AARCH64_INS_ALIAS_STTRH()), // Real instr.: AARCH64_STTRHi
		ALIAS_STTRB(AARCH64_INS_ALIAS_STTRB()), // Real instr.: AARCH64_STTRBi
		ALIAS_BIC_4H(AARCH64_INS_ALIAS_BIC_4H()), // Real instr.: AARCH64_BICv4i16
		ALIAS_BIC_8H(AARCH64_INS_ALIAS_BIC_8H()), // Real instr.: AARCH64_BICv8i16
		ALIAS_BIC_2S(AARCH64_INS_ALIAS_BIC_2S()), // Real instr.: AARCH64_BICv2i32
		ALIAS_BIC_4S(AARCH64_INS_ALIAS_BIC_4S()), // Real instr.: AARCH64_BICv4i32
		ALIAS_ORR_4H(AARCH64_INS_ALIAS_ORR_4H()), // Real instr.: AARCH64_ORRv4i16
		ALIAS_ORR_8H(AARCH64_INS_ALIAS_ORR_8H()), // Real instr.: AARCH64_ORRv8i16
		ALIAS_ORR_2S(AARCH64_INS_ALIAS_ORR_2S()), // Real instr.: AARCH64_ORRv2i32
		ALIAS_ORR_4S(AARCH64_INS_ALIAS_ORR_4S()), // Real instr.: AARCH64_ORRv4i32
		ALIAS_SXTL_8H(AARCH64_INS_ALIAS_SXTL_8H()), // Real instr.: AARCH64_SSHLLv8i8_shift
		ALIAS_SXTL(AARCH64_INS_ALIAS_SXTL()), // Real instr.: AARCH64_SSHLLv8i8_shift
		ALIAS_SXTL_4S(AARCH64_INS_ALIAS_SXTL_4S()), // Real instr.: AARCH64_SSHLLv4i16_shift
		ALIAS_SXTL_2D(AARCH64_INS_ALIAS_SXTL_2D()), // Real instr.: AARCH64_SSHLLv2i32_shift
		ALIAS_SXTL2_8H(AARCH64_INS_ALIAS_SXTL2_8H()), // Real instr.: AARCH64_SSHLLv16i8_shift
		ALIAS_SXTL2(AARCH64_INS_ALIAS_SXTL2()), // Real instr.: AARCH64_SSHLLv16i8_shift
		ALIAS_SXTL2_4S(AARCH64_INS_ALIAS_SXTL2_4S()), // Real instr.: AARCH64_SSHLLv8i16_shift
		ALIAS_SXTL2_2D(AARCH64_INS_ALIAS_SXTL2_2D()), // Real instr.: AARCH64_SSHLLv4i32_shift
		ALIAS_UXTL_8H(AARCH64_INS_ALIAS_UXTL_8H()), // Real instr.: AARCH64_USHLLv8i8_shift
		ALIAS_UXTL(AARCH64_INS_ALIAS_UXTL()), // Real instr.: AARCH64_USHLLv8i8_shift
		ALIAS_UXTL_4S(AARCH64_INS_ALIAS_UXTL_4S()), // Real instr.: AARCH64_USHLLv4i16_shift
		ALIAS_UXTL_2D(AARCH64_INS_ALIAS_UXTL_2D()), // Real instr.: AARCH64_USHLLv2i32_shift
		ALIAS_UXTL2_8H(AARCH64_INS_ALIAS_UXTL2_8H()), // Real instr.: AARCH64_USHLLv16i8_shift
		ALIAS_UXTL2(AARCH64_INS_ALIAS_UXTL2()), // Real instr.: AARCH64_USHLLv16i8_shift
		ALIAS_UXTL2_4S(AARCH64_INS_ALIAS_UXTL2_4S()), // Real instr.: AARCH64_USHLLv8i16_shift
		ALIAS_UXTL2_2D(AARCH64_INS_ALIAS_UXTL2_2D()), // Real instr.: AARCH64_USHLLv4i32_shift
		ALIAS_LD2(AARCH64_INS_ALIAS_LD2()), // Real instr.: AARCH64_LD2Twov16b_POST
		ALIAS_LD3(AARCH64_INS_ALIAS_LD3()), // Real instr.: AARCH64_LD3Threev16b_POST
		ALIAS_LD4(AARCH64_INS_ALIAS_LD4()), // Real instr.: AARCH64_LD4Fourv16b_POST
		ALIAS_ST1(AARCH64_INS_ALIAS_ST1()), // Real instr.: AARCH64_ST1Onev16b_POST
		ALIAS_ST2(AARCH64_INS_ALIAS_ST2()), // Real instr.: AARCH64_ST2Twov16b_POST
		ALIAS_ST3(AARCH64_INS_ALIAS_ST3()), // Real instr.: AARCH64_ST3Threev16b_POST
		ALIAS_ST4(AARCH64_INS_ALIAS_ST4()), // Real instr.: AARCH64_ST4Fourv16b_POST
		ALIAS_LD2R(AARCH64_INS_ALIAS_LD2R()), // Real instr.: AARCH64_LD2Rv8b_POST
		ALIAS_LD3R(AARCH64_INS_ALIAS_LD3R()), // Real instr.: AARCH64_LD3Rv8b_POST
		ALIAS_LD4R(AARCH64_INS_ALIAS_LD4R()), // Real instr.: AARCH64_LD4Rv8b_POST
		ALIAS_CLRBHB(AARCH64_INS_ALIAS_CLRBHB()), // Real instr.: AARCH64_HINT
		ALIAS_STILP(AARCH64_INS_ALIAS_STILP()), // Real instr.: AARCH64_STILPW
		ALIAS_STL1(AARCH64_INS_ALIAS_STL1()), // Real instr.: AARCH64_STL1
		ALIAS_SYSP(AARCH64_INS_ALIAS_SYSP()), // Real instr.: AARCH64_SYSPxt_XZR
		ALIAS_LD1SW(AARCH64_INS_ALIAS_LD1SW()), // Real instr.: AARCH64_LD1SW_D_IMM
		ALIAS_LD1H(AARCH64_INS_ALIAS_LD1H()), // Real instr.: AARCH64_LD1H_IMM
		ALIAS_LD1SH(AARCH64_INS_ALIAS_LD1SH()), // Real instr.: AARCH64_LD1SH_D_IMM
		ALIAS_LD1D(AARCH64_INS_ALIAS_LD1D()), // Real instr.: AARCH64_LD1D_IMM
		ALIAS_LD1RSW(AARCH64_INS_ALIAS_LD1RSW()), // Real instr.: AARCH64_LD1RSW_IMM
		ALIAS_LD1RH(AARCH64_INS_ALIAS_LD1RH()), // Real instr.: AARCH64_LD1RH_IMM
		ALIAS_LD1RSH(AARCH64_INS_ALIAS_LD1RSH()), // Real instr.: AARCH64_LD1RSH_D_IMM
		ALIAS_LD1RW(AARCH64_INS_ALIAS_LD1RW()), // Real instr.: AARCH64_LD1RW_IMM
		ALIAS_LD1RSB(AARCH64_INS_ALIAS_LD1RSB()), // Real instr.: AARCH64_LD1RSB_D_IMM
		ALIAS_LD1RD(AARCH64_INS_ALIAS_LD1RD()), // Real instr.: AARCH64_LD1RD_IMM
		ALIAS_LD1RQH(AARCH64_INS_ALIAS_LD1RQH()), // Real instr.: AARCH64_LD1RQ_H_IMM
		ALIAS_LD1RQW(AARCH64_INS_ALIAS_LD1RQW()), // Real instr.: AARCH64_LD1RQ_W_IMM
		ALIAS_LD1RQD(AARCH64_INS_ALIAS_LD1RQD()), // Real instr.: AARCH64_LD1RQ_D_IMM
		ALIAS_LDNF1SW(AARCH64_INS_ALIAS_LDNF1SW()), // Real instr.: AARCH64_LDNF1SW_D_IMM_REAL
		ALIAS_LDNF1H(AARCH64_INS_ALIAS_LDNF1H()), // Real instr.: AARCH64_LDNF1H_IMM_REAL
		ALIAS_LDNF1SH(AARCH64_INS_ALIAS_LDNF1SH()), // Real instr.: AARCH64_LDNF1SH_D_IMM_REAL
		ALIAS_LDNF1W(AARCH64_INS_ALIAS_LDNF1W()), // Real instr.: AARCH64_LDNF1W_IMM_REAL
		ALIAS_LDNF1SB(AARCH64_INS_ALIAS_LDNF1SB()), // Real instr.: AARCH64_LDNF1SB_D_IMM_REAL
		ALIAS_LDNF1D(AARCH64_INS_ALIAS_LDNF1D()), // Real instr.: AARCH64_LDNF1D_IMM_REAL
		ALIAS_LDFF1SW(AARCH64_INS_ALIAS_LDFF1SW()), // Real instr.: AARCH64_LDFF1SW_D_REAL
		ALIAS_LDFF1H(AARCH64_INS_ALIAS_LDFF1H()), // Real instr.: AARCH64_LDFF1H_REAL
		ALIAS_LDFF1SH(AARCH64_INS_ALIAS_LDFF1SH()), // Real instr.: AARCH64_LDFF1SH_D_REAL
		ALIAS_LDFF1W(AARCH64_INS_ALIAS_LDFF1W()), // Real instr.: AARCH64_LDFF1W_REAL
		ALIAS_LDFF1SB(AARCH64_INS_ALIAS_LDFF1SB()), // Real instr.: AARCH64_LDFF1SB_D_REAL
		ALIAS_LDFF1D(AARCH64_INS_ALIAS_LDFF1D()), // Real instr.: AARCH64_LDFF1D_REAL
		ALIAS_LD3B(AARCH64_INS_ALIAS_LD3B()), // Real instr.: AARCH64_LD3B_IMM
		ALIAS_LD4B(AARCH64_INS_ALIAS_LD4B()), // Real instr.: AARCH64_LD4B_IMM
		ALIAS_LD2H(AARCH64_INS_ALIAS_LD2H()), // Real instr.: AARCH64_LD2H_IMM
		ALIAS_LD3H(AARCH64_INS_ALIAS_LD3H()), // Real instr.: AARCH64_LD3H_IMM
		ALIAS_LD4H(AARCH64_INS_ALIAS_LD4H()), // Real instr.: AARCH64_LD4H_IMM
		ALIAS_LD2W(AARCH64_INS_ALIAS_LD2W()), // Real instr.: AARCH64_LD2W_IMM
		ALIAS_LD3W(AARCH64_INS_ALIAS_LD3W()), // Real instr.: AARCH64_LD3W_IMM
		ALIAS_LD4W(AARCH64_INS_ALIAS_LD4W()), // Real instr.: AARCH64_LD4W_IMM
		ALIAS_LD2D(AARCH64_INS_ALIAS_LD2D()), // Real instr.: AARCH64_LD2D_IMM
		ALIAS_LD3D(AARCH64_INS_ALIAS_LD3D()), // Real instr.: AARCH64_LD3D_IMM
		ALIAS_LD4D(AARCH64_INS_ALIAS_LD4D()), // Real instr.: AARCH64_LD4D_IMM
		ALIAS_LD2Q(AARCH64_INS_ALIAS_LD2Q()), // Real instr.: AARCH64_LD2Q_IMM
		ALIAS_LD3Q(AARCH64_INS_ALIAS_LD3Q()), // Real instr.: AARCH64_LD3Q_IMM
		ALIAS_LD4Q(AARCH64_INS_ALIAS_LD4Q()), // Real instr.: AARCH64_LD4Q_IMM
		ALIAS_LDNT1H(AARCH64_INS_ALIAS_LDNT1H()), // Real instr.: AARCH64_LDNT1H_ZRI
		ALIAS_LDNT1W(AARCH64_INS_ALIAS_LDNT1W()), // Real instr.: AARCH64_LDNT1W_ZRI
		ALIAS_LDNT1D(AARCH64_INS_ALIAS_LDNT1D()), // Real instr.: AARCH64_LDNT1D_ZRI
		ALIAS_ST1H(AARCH64_INS_ALIAS_ST1H()), // Real instr.: AARCH64_ST1H_IMM
		ALIAS_ST1W(AARCH64_INS_ALIAS_ST1W()), // Real instr.: AARCH64_ST1W_IMM
		ALIAS_ST1D(AARCH64_INS_ALIAS_ST1D()), // Real instr.: AARCH64_ST1D_IMM
		ALIAS_ST3B(AARCH64_INS_ALIAS_ST3B()), // Real instr.: AARCH64_ST3B_IMM
		ALIAS_ST4B(AARCH64_INS_ALIAS_ST4B()), // Real instr.: AARCH64_ST4B_IMM
		ALIAS_ST2H(AARCH64_INS_ALIAS_ST2H()), // Real instr.: AARCH64_ST2H_IMM
		ALIAS_ST3H(AARCH64_INS_ALIAS_ST3H()), // Real instr.: AARCH64_ST3H_IMM
		ALIAS_ST4H(AARCH64_INS_ALIAS_ST4H()), // Real instr.: AARCH64_ST4H_IMM
		ALIAS_ST2W(AARCH64_INS_ALIAS_ST2W()), // Real instr.: AARCH64_ST2W_IMM
		ALIAS_ST3W(AARCH64_INS_ALIAS_ST3W()), // Real instr.: AARCH64_ST3W_IMM
		ALIAS_ST4W(AARCH64_INS_ALIAS_ST4W()), // Real instr.: AARCH64_ST4W_IMM
		ALIAS_ST2D(AARCH64_INS_ALIAS_ST2D()), // Real instr.: AARCH64_ST2D_IMM
		ALIAS_ST3D(AARCH64_INS_ALIAS_ST3D()), // Real instr.: AARCH64_ST3D_IMM
		ALIAS_ST4D(AARCH64_INS_ALIAS_ST4D()), // Real instr.: AARCH64_ST4D_IMM
		ALIAS_ST3Q(AARCH64_INS_ALIAS_ST3Q()), // Real instr.: AARCH64_ST3Q_IMM
		ALIAS_ST4Q(AARCH64_INS_ALIAS_ST4Q()), // Real instr.: AARCH64_ST4Q_IMM
		ALIAS_STNT1H(AARCH64_INS_ALIAS_STNT1H()), // Real instr.: AARCH64_STNT1H_ZRI
		ALIAS_STNT1W(AARCH64_INS_ALIAS_STNT1W()), // Real instr.: AARCH64_STNT1W_ZRI
		ALIAS_STNT1D(AARCH64_INS_ALIAS_STNT1D()), // Real instr.: AARCH64_STNT1D_ZRI
		ALIAS_PRFH(AARCH64_INS_ALIAS_PRFH()), // Real instr.: AARCH64_PRFH_PRI
		ALIAS_PRFW(AARCH64_INS_ALIAS_PRFW()), // Real instr.: AARCH64_PRFW_PRI
		ALIAS_PRFD(AARCH64_INS_ALIAS_PRFD()), // Real instr.: AARCH64_PRFD_PRI
		ALIAS_CNTH(AARCH64_INS_ALIAS_CNTH()), // Real instr.: AARCH64_CNTH_XPiI
		ALIAS_CNTW(AARCH64_INS_ALIAS_CNTW()), // Real instr.: AARCH64_CNTW_XPiI
		ALIAS_CNTD(AARCH64_INS_ALIAS_CNTD()), // Real instr.: AARCH64_CNTD_XPiI
		ALIAS_DECB(AARCH64_INS_ALIAS_DECB()), // Real instr.: AARCH64_DECB_XPiI
		ALIAS_INCH(AARCH64_INS_ALIAS_INCH()), // Real instr.: AARCH64_INCH_XPiI
		ALIAS_DECH(AARCH64_INS_ALIAS_DECH()), // Real instr.: AARCH64_DECH_XPiI
		ALIAS_INCW(AARCH64_INS_ALIAS_INCW()), // Real instr.: AARCH64_INCW_XPiI
		ALIAS_DECW(AARCH64_INS_ALIAS_DECW()), // Real instr.: AARCH64_DECW_XPiI
		ALIAS_INCD(AARCH64_INS_ALIAS_INCD()), // Real instr.: AARCH64_INCD_XPiI
		ALIAS_DECD(AARCH64_INS_ALIAS_DECD()), // Real instr.: AARCH64_DECD_XPiI
		ALIAS_SQDECB(AARCH64_INS_ALIAS_SQDECB()), // Real instr.: AARCH64_SQDECB_XPiWdI
		ALIAS_UQDECB(AARCH64_INS_ALIAS_UQDECB()), // Real instr.: AARCH64_UQDECB_WPiI
		ALIAS_UQINCH(AARCH64_INS_ALIAS_UQINCH()), // Real instr.: AARCH64_UQINCH_WPiI
		ALIAS_SQDECH(AARCH64_INS_ALIAS_SQDECH()), // Real instr.: AARCH64_SQDECH_XPiWdI
		ALIAS_UQDECH(AARCH64_INS_ALIAS_UQDECH()), // Real instr.: AARCH64_UQDECH_WPiI
		ALIAS_SQINCW(AARCH64_INS_ALIAS_SQINCW()), // Real instr.: AARCH64_SQINCW_XPiWdI
		ALIAS_UQINCW(AARCH64_INS_ALIAS_UQINCW()), // Real instr.: AARCH64_UQINCW_WPiI
		ALIAS_SQDECW(AARCH64_INS_ALIAS_SQDECW()), // Real instr.: AARCH64_SQDECW_XPiWdI
		ALIAS_UQDECW(AARCH64_INS_ALIAS_UQDECW()), // Real instr.: AARCH64_UQDECW_WPiI
		ALIAS_SQINCD(AARCH64_INS_ALIAS_SQINCD()), // Real instr.: AARCH64_SQINCD_XPiWdI
		ALIAS_UQINCD(AARCH64_INS_ALIAS_UQINCD()), // Real instr.: AARCH64_UQINCD_WPiI
		ALIAS_SQDECD(AARCH64_INS_ALIAS_SQDECD()), // Real instr.: AARCH64_SQDECD_XPiWdI
		ALIAS_UQDECD(AARCH64_INS_ALIAS_UQDECD()), // Real instr.: AARCH64_UQDECD_WPiI
		ALIAS_MOVS(AARCH64_INS_ALIAS_MOVS()), // Real instr.: AARCH64_ORRS_PPzPP
		ALIAS_NOT(AARCH64_INS_ALIAS_NOT()), // Real instr.: AARCH64_EOR_PPzPP
		ALIAS_NOTS(AARCH64_INS_ALIAS_NOTS()), // Real instr.: AARCH64_EORS_PPzPP
		ALIAS_LD1ROH(AARCH64_INS_ALIAS_LD1ROH()), // Real instr.: AARCH64_LD1RO_H_IMM
		ALIAS_LD1ROW(AARCH64_INS_ALIAS_LD1ROW()), // Real instr.: AARCH64_LD1RO_W_IMM
		ALIAS_LD1ROD(AARCH64_INS_ALIAS_LD1ROD()), // Real instr.: AARCH64_LD1RO_D_IMM
		ALIAS_BCAX(AARCH64_INS_ALIAS_BCAX()), // Real instr.: AARCH64_BCAX_ZZZZ
		ALIAS_BSL(AARCH64_INS_ALIAS_BSL()), // Real instr.: AARCH64_BSL_ZZZZ
		ALIAS_BSL1N(AARCH64_INS_ALIAS_BSL1N()), // Real instr.: AARCH64_BSL1N_ZZZZ
		ALIAS_BSL2N(AARCH64_INS_ALIAS_BSL2N()), // Real instr.: AARCH64_BSL2N_ZZZZ
		ALIAS_NBSL(AARCH64_INS_ALIAS_NBSL()), // Real instr.: AARCH64_NBSL_ZZZZ
		ALIAS_LDNT1SH(AARCH64_INS_ALIAS_LDNT1SH()), // Real instr.: AARCH64_LDNT1SH_ZZR_S_REAL
		ALIAS_LDNT1SW(AARCH64_INS_ALIAS_LDNT1SW()), // Real instr.: AARCH64_LDNT1SW_ZZR_D_REAL

		// clang-format on
		// generated content <AArch64GenCSAliasEnum.inc> end

		// Hardcoded in LLVM printer
		ALIAS_CFP(AARCH64_INS_ALIAS_CFP()),
		ALIAS_DVP(AARCH64_INS_ALIAS_DVP()),
		ALIAS_COSP(AARCH64_INS_ALIAS_COSP()),
		ALIAS_CPP(AARCH64_INS_ALIAS_CPP()),
		ALIAS_IC(AARCH64_INS_ALIAS_IC()),
		ALIAS_DC(AARCH64_INS_ALIAS_DC()),
		ALIAS_AT(AARCH64_INS_ALIAS_AT()),
		ALIAS_TLBI(AARCH64_INS_ALIAS_TLBI()),
		ALIAS_TLBIP(AARCH64_INS_ALIAS_TLBIP()),
		ALIAS_RPRFM(AARCH64_INS_ALIAS_RPRFM()),
		ALIAS_LSL(AARCH64_INS_ALIAS_LSL()),
		ALIAS_SBFX(AARCH64_INS_ALIAS_SBFX()),
		ALIAS_UBFX(AARCH64_INS_ALIAS_UBFX()),
		ALIAS_SBFIZ(AARCH64_INS_ALIAS_SBFIZ()),
		ALIAS_UBFIZ(AARCH64_INS_ALIAS_UBFIZ()),
		ALIAS_BFC(AARCH64_INS_ALIAS_BFC()),
		ALIAS_BFI(AARCH64_INS_ALIAS_BFI()),
		ALIAS_BFXIL(AARCH64_INS_ALIAS_BFXIL()),

		ALIAS_END(AARCH64_INS_ALIAS_END());

		private final int value;

		AArch64Insn(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}

		public static AArch64Insn[] fromValue(int value) {
			List<AArch64Insn> result = new ArrayList<>();
			boolean found = false;
			for (AArch64Insn insn : AArch64Insn.values()) {
				if (insn.getValue() == value) {
					result.add(insn);
					found = true;
				}
			}
			if (!found) {
				result.add(INVALID);
			}
			return result.toArray(new AArch64Insn[0]);
		}
	}
}
