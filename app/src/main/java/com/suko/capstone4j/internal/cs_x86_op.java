// Generated by jextract

package com.suko.capstone4j.internal;

import java.lang.invoke.*;
import java.lang.foreign.*;
import java.nio.ByteOrder;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

import static java.lang.foreign.ValueLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * {@snippet lang=c :
 * struct cs_x86_op {
 *     x86_op_type type;
 *     union {
 *         x86_reg reg;
 *         int64_t imm;
 *         x86_op_mem mem;
 *     };
 *     uint8_t size;
 *     uint8_t access;
 *     x86_avx_bcast avx_bcast;
 *     bool avx_zero_opmask;
 * }
 * }
 */
public class cs_x86_op {

    cs_x86_op() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_INT.withName("type"),
        MemoryLayout.paddingLayout(4),
        MemoryLayout.unionLayout(
            capstone_h.C_INT.withName("reg"),
            capstone_h.C_LONG_LONG.withName("imm"),
            x86_op_mem.layout().withName("mem")
        ).withName("$anon$280:2"),
        capstone_h.C_CHAR.withName("size"),
        capstone_h.C_CHAR.withName("access"),
        MemoryLayout.paddingLayout(2),
        capstone_h.C_INT.withName("avx_bcast"),
        capstone_h.C_BOOL.withName("avx_zero_opmask"),
        MemoryLayout.paddingLayout(7)
    ).withName("cs_x86_op");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfInt type$LAYOUT = (OfInt)$LAYOUT.select(groupElement("type"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * x86_op_type type
     * }
     */
    public static final OfInt type$layout() {
        return type$LAYOUT;
    }

    private static final long type$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * x86_op_type type
     * }
     */
    public static final long type$offset() {
        return type$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * x86_op_type type
     * }
     */
    public static int type(MemorySegment struct) {
        return struct.get(type$LAYOUT, type$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * x86_op_type type
     * }
     */
    public static void type(MemorySegment struct, int fieldValue) {
        struct.set(type$LAYOUT, type$OFFSET, fieldValue);
    }

    private static final OfInt reg$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$280:2"), groupElement("reg"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * x86_reg reg
     * }
     */
    public static final OfInt reg$layout() {
        return reg$LAYOUT;
    }

    private static final long reg$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * x86_reg reg
     * }
     */
    public static final long reg$offset() {
        return reg$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * x86_reg reg
     * }
     */
    public static int reg(MemorySegment struct) {
        return struct.get(reg$LAYOUT, reg$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * x86_reg reg
     * }
     */
    public static void reg(MemorySegment struct, int fieldValue) {
        struct.set(reg$LAYOUT, reg$OFFSET, fieldValue);
    }

    private static final OfLong imm$LAYOUT = (OfLong)$LAYOUT.select(groupElement("$anon$280:2"), groupElement("imm"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * int64_t imm
     * }
     */
    public static final OfLong imm$layout() {
        return imm$LAYOUT;
    }

    private static final long imm$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * int64_t imm
     * }
     */
    public static final long imm$offset() {
        return imm$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * int64_t imm
     * }
     */
    public static long imm(MemorySegment struct) {
        return struct.get(imm$LAYOUT, imm$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * int64_t imm
     * }
     */
    public static void imm(MemorySegment struct, long fieldValue) {
        struct.set(imm$LAYOUT, imm$OFFSET, fieldValue);
    }

    private static final GroupLayout mem$LAYOUT = (GroupLayout)$LAYOUT.select(groupElement("$anon$280:2"), groupElement("mem"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * x86_op_mem mem
     * }
     */
    public static final GroupLayout mem$layout() {
        return mem$LAYOUT;
    }

    private static final long mem$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * x86_op_mem mem
     * }
     */
    public static final long mem$offset() {
        return mem$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * x86_op_mem mem
     * }
     */
    public static MemorySegment mem(MemorySegment struct) {
        return struct.asSlice(mem$OFFSET, mem$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * x86_op_mem mem
     * }
     */
    public static void mem(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, mem$OFFSET, mem$LAYOUT.byteSize());
    }

    private static final OfByte size$LAYOUT = (OfByte)$LAYOUT.select(groupElement("size"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t size
     * }
     */
    public static final OfByte size$layout() {
        return size$LAYOUT;
    }

    private static final long size$OFFSET = 32;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t size
     * }
     */
    public static final long size$offset() {
        return size$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t size
     * }
     */
    public static byte size(MemorySegment struct) {
        return struct.get(size$LAYOUT, size$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t size
     * }
     */
    public static void size(MemorySegment struct, byte fieldValue) {
        struct.set(size$LAYOUT, size$OFFSET, fieldValue);
    }

    private static final OfByte access$LAYOUT = (OfByte)$LAYOUT.select(groupElement("access"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t access
     * }
     */
    public static final OfByte access$layout() {
        return access$LAYOUT;
    }

    private static final long access$OFFSET = 33;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t access
     * }
     */
    public static final long access$offset() {
        return access$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t access
     * }
     */
    public static byte access(MemorySegment struct) {
        return struct.get(access$LAYOUT, access$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t access
     * }
     */
    public static void access(MemorySegment struct, byte fieldValue) {
        struct.set(access$LAYOUT, access$OFFSET, fieldValue);
    }

    private static final OfInt avx_bcast$LAYOUT = (OfInt)$LAYOUT.select(groupElement("avx_bcast"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * x86_avx_bcast avx_bcast
     * }
     */
    public static final OfInt avx_bcast$layout() {
        return avx_bcast$LAYOUT;
    }

    private static final long avx_bcast$OFFSET = 36;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * x86_avx_bcast avx_bcast
     * }
     */
    public static final long avx_bcast$offset() {
        return avx_bcast$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * x86_avx_bcast avx_bcast
     * }
     */
    public static int avx_bcast(MemorySegment struct) {
        return struct.get(avx_bcast$LAYOUT, avx_bcast$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * x86_avx_bcast avx_bcast
     * }
     */
    public static void avx_bcast(MemorySegment struct, int fieldValue) {
        struct.set(avx_bcast$LAYOUT, avx_bcast$OFFSET, fieldValue);
    }

    private static final OfBoolean avx_zero_opmask$LAYOUT = (OfBoolean)$LAYOUT.select(groupElement("avx_zero_opmask"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * bool avx_zero_opmask
     * }
     */
    public static final OfBoolean avx_zero_opmask$layout() {
        return avx_zero_opmask$LAYOUT;
    }

    private static final long avx_zero_opmask$OFFSET = 40;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * bool avx_zero_opmask
     * }
     */
    public static final long avx_zero_opmask$offset() {
        return avx_zero_opmask$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * bool avx_zero_opmask
     * }
     */
    public static boolean avx_zero_opmask(MemorySegment struct) {
        return struct.get(avx_zero_opmask$LAYOUT, avx_zero_opmask$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * bool avx_zero_opmask
     * }
     */
    public static void avx_zero_opmask(MemorySegment struct, boolean fieldValue) {
        struct.set(avx_zero_opmask$LAYOUT, avx_zero_opmask$OFFSET, fieldValue);
    }

    /**
     * Obtains a slice of {@code arrayParam} which selects the array element at {@code index}.
     * The returned segment has address {@code arrayParam.address() + index * layout().byteSize()}
     */
    public static MemorySegment asSlice(MemorySegment array, long index) {
        return array.asSlice(layout().byteSize() * index);
    }

    /**
     * The size (in bytes) of this struct
     */
    public static long sizeof() { return layout().byteSize(); }

    /**
     * Allocate a segment of size {@code layout().byteSize()} using {@code allocator}
     */
    public static MemorySegment allocate(SegmentAllocator allocator) {
        return allocator.allocate(layout());
    }

    /**
     * Allocate an array of size {@code elementCount} using {@code allocator}.
     * The returned segment has size {@code elementCount * layout().byteSize()}.
     */
    public static MemorySegment allocateArray(long elementCount, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(elementCount, layout()));
    }

    /**
     * Reinterprets {@code addr} using target {@code arena} and {@code cleanupAction} (if any).
     * The returned segment has size {@code layout().byteSize()}
     */
    public static MemorySegment reinterpret(MemorySegment addr, Arena arena, Consumer<MemorySegment> cleanup) {
        return reinterpret(addr, 1, arena, cleanup);
    }

    /**
     * Reinterprets {@code addr} using target {@code arena} and {@code cleanupAction} (if any).
     * The returned segment has size {@code elementCount * layout().byteSize()}
     */
    public static MemorySegment reinterpret(MemorySegment addr, long elementCount, Arena arena, Consumer<MemorySegment> cleanup) {
        return addr.reinterpret(layout().byteSize() * elementCount, arena, cleanup);
    }
}

