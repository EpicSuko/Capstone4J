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
 * struct cs_aarch64 {
 *     AArch64CC_CondCode cc;
 *     bool update_flags;
 *     bool post_index;
 *     bool is_doing_sme;
 *     uint8_t op_count;
 *     cs_aarch64_op operands[16];
 * }
 * }
 */
public class cs_aarch64 {

    cs_aarch64() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_INT.withName("cc"),
        capstone_h.C_BOOL.withName("update_flags"),
        capstone_h.C_BOOL.withName("post_index"),
        capstone_h.C_BOOL.withName("is_doing_sme"),
        capstone_h.C_CHAR.withName("op_count"),
        MemoryLayout.sequenceLayout(16, cs_aarch64_op.layout()).withName("operands")
    ).withName("cs_aarch64");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfInt cc$LAYOUT = (OfInt)$LAYOUT.select(groupElement("cc"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * AArch64CC_CondCode cc
     * }
     */
    public static final OfInt cc$layout() {
        return cc$LAYOUT;
    }

    private static final long cc$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * AArch64CC_CondCode cc
     * }
     */
    public static final long cc$offset() {
        return cc$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * AArch64CC_CondCode cc
     * }
     */
    public static int cc(MemorySegment struct) {
        return struct.get(cc$LAYOUT, cc$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * AArch64CC_CondCode cc
     * }
     */
    public static void cc(MemorySegment struct, int fieldValue) {
        struct.set(cc$LAYOUT, cc$OFFSET, fieldValue);
    }

    private static final OfBoolean update_flags$LAYOUT = (OfBoolean)$LAYOUT.select(groupElement("update_flags"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * bool update_flags
     * }
     */
    public static final OfBoolean update_flags$layout() {
        return update_flags$LAYOUT;
    }

    private static final long update_flags$OFFSET = 4;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * bool update_flags
     * }
     */
    public static final long update_flags$offset() {
        return update_flags$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * bool update_flags
     * }
     */
    public static boolean update_flags(MemorySegment struct) {
        return struct.get(update_flags$LAYOUT, update_flags$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * bool update_flags
     * }
     */
    public static void update_flags(MemorySegment struct, boolean fieldValue) {
        struct.set(update_flags$LAYOUT, update_flags$OFFSET, fieldValue);
    }

    private static final OfBoolean post_index$LAYOUT = (OfBoolean)$LAYOUT.select(groupElement("post_index"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * bool post_index
     * }
     */
    public static final OfBoolean post_index$layout() {
        return post_index$LAYOUT;
    }

    private static final long post_index$OFFSET = 5;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * bool post_index
     * }
     */
    public static final long post_index$offset() {
        return post_index$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * bool post_index
     * }
     */
    public static boolean post_index(MemorySegment struct) {
        return struct.get(post_index$LAYOUT, post_index$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * bool post_index
     * }
     */
    public static void post_index(MemorySegment struct, boolean fieldValue) {
        struct.set(post_index$LAYOUT, post_index$OFFSET, fieldValue);
    }

    private static final OfBoolean is_doing_sme$LAYOUT = (OfBoolean)$LAYOUT.select(groupElement("is_doing_sme"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * bool is_doing_sme
     * }
     */
    public static final OfBoolean is_doing_sme$layout() {
        return is_doing_sme$LAYOUT;
    }

    private static final long is_doing_sme$OFFSET = 6;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * bool is_doing_sme
     * }
     */
    public static final long is_doing_sme$offset() {
        return is_doing_sme$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * bool is_doing_sme
     * }
     */
    public static boolean is_doing_sme(MemorySegment struct) {
        return struct.get(is_doing_sme$LAYOUT, is_doing_sme$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * bool is_doing_sme
     * }
     */
    public static void is_doing_sme(MemorySegment struct, boolean fieldValue) {
        struct.set(is_doing_sme$LAYOUT, is_doing_sme$OFFSET, fieldValue);
    }

    private static final OfByte op_count$LAYOUT = (OfByte)$LAYOUT.select(groupElement("op_count"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t op_count
     * }
     */
    public static final OfByte op_count$layout() {
        return op_count$LAYOUT;
    }

    private static final long op_count$OFFSET = 7;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t op_count
     * }
     */
    public static final long op_count$offset() {
        return op_count$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t op_count
     * }
     */
    public static byte op_count(MemorySegment struct) {
        return struct.get(op_count$LAYOUT, op_count$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t op_count
     * }
     */
    public static void op_count(MemorySegment struct, byte fieldValue) {
        struct.set(op_count$LAYOUT, op_count$OFFSET, fieldValue);
    }

    private static final SequenceLayout operands$LAYOUT = (SequenceLayout)$LAYOUT.select(groupElement("operands"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * cs_aarch64_op operands[16]
     * }
     */
    public static final SequenceLayout operands$layout() {
        return operands$LAYOUT;
    }

    private static final long operands$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * cs_aarch64_op operands[16]
     * }
     */
    public static final long operands$offset() {
        return operands$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * cs_aarch64_op operands[16]
     * }
     */
    public static MemorySegment operands(MemorySegment struct) {
        return struct.asSlice(operands$OFFSET, operands$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * cs_aarch64_op operands[16]
     * }
     */
    public static void operands(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, operands$OFFSET, operands$LAYOUT.byteSize());
    }

    private static long[] operands$DIMS = { 16 };

    /**
     * Dimensions for array field:
     * {@snippet lang=c :
     * cs_aarch64_op operands[16]
     * }
     */
    public static long[] operands$dimensions() {
        return operands$DIMS;
    }
    private static final MethodHandle operands$ELEM_HANDLE = operands$LAYOUT.sliceHandle(sequenceElement());

    /**
     * Indexed getter for field:
     * {@snippet lang=c :
     * cs_aarch64_op operands[16]
     * }
     */
    public static MemorySegment operands(MemorySegment struct, long index0) {
        try {
            return (MemorySegment)operands$ELEM_HANDLE.invokeExact(struct, 0L, index0);
        } catch (Throwable ex$) {
            throw new AssertionError("should not reach here", ex$);
        }
    }

    /**
     * Indexed setter for field:
     * {@snippet lang=c :
     * cs_aarch64_op operands[16]
     * }
     */
    public static void operands(MemorySegment struct, long index0, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, operands(struct, index0), 0L, cs_aarch64_op.layout().byteSize());
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

