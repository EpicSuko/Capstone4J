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
 * struct cs_ppc {
 *     ppc_bc bc;
 *     bool update_cr0;
 *     ppc_insn_form format;
 *     uint8_t op_count;
 *     cs_ppc_op operands[8];
 * }
 * }
 */
public class cs_ppc {

    cs_ppc() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        ppc_bc.layout().withName("bc"),
        capstone_h.C_BOOL.withName("update_cr0"),
        MemoryLayout.paddingLayout(3),
        capstone_h.C_INT.withName("format"),
        capstone_h.C_CHAR.withName("op_count"),
        MemoryLayout.paddingLayout(3),
        MemoryLayout.sequenceLayout(8, cs_ppc_op.layout()).withName("operands")
    ).withName("cs_ppc");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final GroupLayout bc$LAYOUT = (GroupLayout)$LAYOUT.select(groupElement("bc"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * ppc_bc bc
     * }
     */
    public static final GroupLayout bc$layout() {
        return bc$LAYOUT;
    }

    private static final long bc$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * ppc_bc bc
     * }
     */
    public static final long bc$offset() {
        return bc$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * ppc_bc bc
     * }
     */
    public static MemorySegment bc(MemorySegment struct) {
        return struct.asSlice(bc$OFFSET, bc$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * ppc_bc bc
     * }
     */
    public static void bc(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, bc$OFFSET, bc$LAYOUT.byteSize());
    }

    private static final OfBoolean update_cr0$LAYOUT = (OfBoolean)$LAYOUT.select(groupElement("update_cr0"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * bool update_cr0
     * }
     */
    public static final OfBoolean update_cr0$layout() {
        return update_cr0$LAYOUT;
    }

    private static final long update_cr0$OFFSET = 28;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * bool update_cr0
     * }
     */
    public static final long update_cr0$offset() {
        return update_cr0$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * bool update_cr0
     * }
     */
    public static boolean update_cr0(MemorySegment struct) {
        return struct.get(update_cr0$LAYOUT, update_cr0$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * bool update_cr0
     * }
     */
    public static void update_cr0(MemorySegment struct, boolean fieldValue) {
        struct.set(update_cr0$LAYOUT, update_cr0$OFFSET, fieldValue);
    }

    private static final OfInt format$LAYOUT = (OfInt)$LAYOUT.select(groupElement("format"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * ppc_insn_form format
     * }
     */
    public static final OfInt format$layout() {
        return format$LAYOUT;
    }

    private static final long format$OFFSET = 32;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * ppc_insn_form format
     * }
     */
    public static final long format$offset() {
        return format$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * ppc_insn_form format
     * }
     */
    public static int format(MemorySegment struct) {
        return struct.get(format$LAYOUT, format$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * ppc_insn_form format
     * }
     */
    public static void format(MemorySegment struct, int fieldValue) {
        struct.set(format$LAYOUT, format$OFFSET, fieldValue);
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

    private static final long op_count$OFFSET = 36;

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
     * cs_ppc_op operands[8]
     * }
     */
    public static final SequenceLayout operands$layout() {
        return operands$LAYOUT;
    }

    private static final long operands$OFFSET = 40;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * cs_ppc_op operands[8]
     * }
     */
    public static final long operands$offset() {
        return operands$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * cs_ppc_op operands[8]
     * }
     */
    public static MemorySegment operands(MemorySegment struct) {
        return struct.asSlice(operands$OFFSET, operands$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * cs_ppc_op operands[8]
     * }
     */
    public static void operands(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, operands$OFFSET, operands$LAYOUT.byteSize());
    }

    private static long[] operands$DIMS = { 8 };

    /**
     * Dimensions for array field:
     * {@snippet lang=c :
     * cs_ppc_op operands[8]
     * }
     */
    public static long[] operands$dimensions() {
        return operands$DIMS;
    }
    private static final MethodHandle operands$ELEM_HANDLE = operands$LAYOUT.sliceHandle(sequenceElement());

    /**
     * Indexed getter for field:
     * {@snippet lang=c :
     * cs_ppc_op operands[8]
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
     * cs_ppc_op operands[8]
     * }
     */
    public static void operands(MemorySegment struct, long index0, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, operands(struct, index0), 0L, cs_ppc_op.layout().byteSize());
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

