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
 * struct cs_arm {
 *     bool usermode;
 *     int vector_size;
 *     arm_vectordata_type vector_data;
 *     arm_cpsmode_type cps_mode;
 *     arm_cpsflag_type cps_flag;
 *     ARMCC_CondCodes cc;
 *     ARMVCC_VPTCodes vcc;
 *     bool update_flags;
 *     bool post_index;
 *     arm_mem_bo_opt mem_barrier;
 *     uint8_t pred_mask;
 *     uint8_t op_count;
 *     cs_arm_op operands[36];
 * }
 * }
 */
public class cs_arm {

    cs_arm() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_BOOL.withName("usermode"),
        MemoryLayout.paddingLayout(3),
        capstone_h.C_INT.withName("vector_size"),
        capstone_h.C_INT.withName("vector_data"),
        capstone_h.C_INT.withName("cps_mode"),
        capstone_h.C_INT.withName("cps_flag"),
        capstone_h.C_INT.withName("cc"),
        capstone_h.C_INT.withName("vcc"),
        capstone_h.C_BOOL.withName("update_flags"),
        capstone_h.C_BOOL.withName("post_index"),
        MemoryLayout.paddingLayout(2),
        capstone_h.C_INT.withName("mem_barrier"),
        capstone_h.C_CHAR.withName("pred_mask"),
        capstone_h.C_CHAR.withName("op_count"),
        MemoryLayout.paddingLayout(2),
        MemoryLayout.sequenceLayout(36, cs_arm_op.layout()).withName("operands")
    ).withName("cs_arm");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfBoolean usermode$LAYOUT = (OfBoolean)$LAYOUT.select(groupElement("usermode"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * bool usermode
     * }
     */
    public static final OfBoolean usermode$layout() {
        return usermode$LAYOUT;
    }

    private static final long usermode$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * bool usermode
     * }
     */
    public static final long usermode$offset() {
        return usermode$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * bool usermode
     * }
     */
    public static boolean usermode(MemorySegment struct) {
        return struct.get(usermode$LAYOUT, usermode$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * bool usermode
     * }
     */
    public static void usermode(MemorySegment struct, boolean fieldValue) {
        struct.set(usermode$LAYOUT, usermode$OFFSET, fieldValue);
    }

    private static final OfInt vector_size$LAYOUT = (OfInt)$LAYOUT.select(groupElement("vector_size"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * int vector_size
     * }
     */
    public static final OfInt vector_size$layout() {
        return vector_size$LAYOUT;
    }

    private static final long vector_size$OFFSET = 4;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * int vector_size
     * }
     */
    public static final long vector_size$offset() {
        return vector_size$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * int vector_size
     * }
     */
    public static int vector_size(MemorySegment struct) {
        return struct.get(vector_size$LAYOUT, vector_size$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * int vector_size
     * }
     */
    public static void vector_size(MemorySegment struct, int fieldValue) {
        struct.set(vector_size$LAYOUT, vector_size$OFFSET, fieldValue);
    }

    private static final OfInt vector_data$LAYOUT = (OfInt)$LAYOUT.select(groupElement("vector_data"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * arm_vectordata_type vector_data
     * }
     */
    public static final OfInt vector_data$layout() {
        return vector_data$LAYOUT;
    }

    private static final long vector_data$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * arm_vectordata_type vector_data
     * }
     */
    public static final long vector_data$offset() {
        return vector_data$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * arm_vectordata_type vector_data
     * }
     */
    public static int vector_data(MemorySegment struct) {
        return struct.get(vector_data$LAYOUT, vector_data$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * arm_vectordata_type vector_data
     * }
     */
    public static void vector_data(MemorySegment struct, int fieldValue) {
        struct.set(vector_data$LAYOUT, vector_data$OFFSET, fieldValue);
    }

    private static final OfInt cps_mode$LAYOUT = (OfInt)$LAYOUT.select(groupElement("cps_mode"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * arm_cpsmode_type cps_mode
     * }
     */
    public static final OfInt cps_mode$layout() {
        return cps_mode$LAYOUT;
    }

    private static final long cps_mode$OFFSET = 12;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * arm_cpsmode_type cps_mode
     * }
     */
    public static final long cps_mode$offset() {
        return cps_mode$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * arm_cpsmode_type cps_mode
     * }
     */
    public static int cps_mode(MemorySegment struct) {
        return struct.get(cps_mode$LAYOUT, cps_mode$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * arm_cpsmode_type cps_mode
     * }
     */
    public static void cps_mode(MemorySegment struct, int fieldValue) {
        struct.set(cps_mode$LAYOUT, cps_mode$OFFSET, fieldValue);
    }

    private static final OfInt cps_flag$LAYOUT = (OfInt)$LAYOUT.select(groupElement("cps_flag"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * arm_cpsflag_type cps_flag
     * }
     */
    public static final OfInt cps_flag$layout() {
        return cps_flag$LAYOUT;
    }

    private static final long cps_flag$OFFSET = 16;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * arm_cpsflag_type cps_flag
     * }
     */
    public static final long cps_flag$offset() {
        return cps_flag$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * arm_cpsflag_type cps_flag
     * }
     */
    public static int cps_flag(MemorySegment struct) {
        return struct.get(cps_flag$LAYOUT, cps_flag$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * arm_cpsflag_type cps_flag
     * }
     */
    public static void cps_flag(MemorySegment struct, int fieldValue) {
        struct.set(cps_flag$LAYOUT, cps_flag$OFFSET, fieldValue);
    }

    private static final OfInt cc$LAYOUT = (OfInt)$LAYOUT.select(groupElement("cc"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * ARMCC_CondCodes cc
     * }
     */
    public static final OfInt cc$layout() {
        return cc$LAYOUT;
    }

    private static final long cc$OFFSET = 20;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * ARMCC_CondCodes cc
     * }
     */
    public static final long cc$offset() {
        return cc$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * ARMCC_CondCodes cc
     * }
     */
    public static int cc(MemorySegment struct) {
        return struct.get(cc$LAYOUT, cc$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * ARMCC_CondCodes cc
     * }
     */
    public static void cc(MemorySegment struct, int fieldValue) {
        struct.set(cc$LAYOUT, cc$OFFSET, fieldValue);
    }

    private static final OfInt vcc$LAYOUT = (OfInt)$LAYOUT.select(groupElement("vcc"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * ARMVCC_VPTCodes vcc
     * }
     */
    public static final OfInt vcc$layout() {
        return vcc$LAYOUT;
    }

    private static final long vcc$OFFSET = 24;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * ARMVCC_VPTCodes vcc
     * }
     */
    public static final long vcc$offset() {
        return vcc$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * ARMVCC_VPTCodes vcc
     * }
     */
    public static int vcc(MemorySegment struct) {
        return struct.get(vcc$LAYOUT, vcc$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * ARMVCC_VPTCodes vcc
     * }
     */
    public static void vcc(MemorySegment struct, int fieldValue) {
        struct.set(vcc$LAYOUT, vcc$OFFSET, fieldValue);
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

    private static final long update_flags$OFFSET = 28;

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

    private static final long post_index$OFFSET = 29;

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

    private static final OfInt mem_barrier$LAYOUT = (OfInt)$LAYOUT.select(groupElement("mem_barrier"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * arm_mem_bo_opt mem_barrier
     * }
     */
    public static final OfInt mem_barrier$layout() {
        return mem_barrier$LAYOUT;
    }

    private static final long mem_barrier$OFFSET = 32;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * arm_mem_bo_opt mem_barrier
     * }
     */
    public static final long mem_barrier$offset() {
        return mem_barrier$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * arm_mem_bo_opt mem_barrier
     * }
     */
    public static int mem_barrier(MemorySegment struct) {
        return struct.get(mem_barrier$LAYOUT, mem_barrier$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * arm_mem_bo_opt mem_barrier
     * }
     */
    public static void mem_barrier(MemorySegment struct, int fieldValue) {
        struct.set(mem_barrier$LAYOUT, mem_barrier$OFFSET, fieldValue);
    }

    private static final OfByte pred_mask$LAYOUT = (OfByte)$LAYOUT.select(groupElement("pred_mask"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t pred_mask
     * }
     */
    public static final OfByte pred_mask$layout() {
        return pred_mask$LAYOUT;
    }

    private static final long pred_mask$OFFSET = 36;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t pred_mask
     * }
     */
    public static final long pred_mask$offset() {
        return pred_mask$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t pred_mask
     * }
     */
    public static byte pred_mask(MemorySegment struct) {
        return struct.get(pred_mask$LAYOUT, pred_mask$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t pred_mask
     * }
     */
    public static void pred_mask(MemorySegment struct, byte fieldValue) {
        struct.set(pred_mask$LAYOUT, pred_mask$OFFSET, fieldValue);
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

    private static final long op_count$OFFSET = 37;

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
     * cs_arm_op operands[36]
     * }
     */
    public static final SequenceLayout operands$layout() {
        return operands$LAYOUT;
    }

    private static final long operands$OFFSET = 40;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * cs_arm_op operands[36]
     * }
     */
    public static final long operands$offset() {
        return operands$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * cs_arm_op operands[36]
     * }
     */
    public static MemorySegment operands(MemorySegment struct) {
        return struct.asSlice(operands$OFFSET, operands$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * cs_arm_op operands[36]
     * }
     */
    public static void operands(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, operands$OFFSET, operands$LAYOUT.byteSize());
    }

    private static long[] operands$DIMS = { 36 };

    /**
     * Dimensions for array field:
     * {@snippet lang=c :
     * cs_arm_op operands[36]
     * }
     */
    public static long[] operands$dimensions() {
        return operands$DIMS;
    }
    private static final MethodHandle operands$ELEM_HANDLE = operands$LAYOUT.sliceHandle(sequenceElement());

    /**
     * Indexed getter for field:
     * {@snippet lang=c :
     * cs_arm_op operands[36]
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
     * cs_arm_op operands[36]
     * }
     */
    public static void operands(MemorySegment struct, long index0, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, operands(struct, index0), 0L, cs_arm_op.layout().byteSize());
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

