// Generated by jextract

package com.capstone4j.internal;

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
 * struct cs_sh {
 *     sh_insn insn;
 *     uint8_t size;
 *     uint8_t op_count;
 *     cs_sh_op operands[3];
 * }
 * }
 */
public class cs_sh {

    cs_sh() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_INT.withName("insn"),
        capstone_h.C_CHAR.withName("size"),
        capstone_h.C_CHAR.withName("op_count"),
        MemoryLayout.paddingLayout(2),
        MemoryLayout.sequenceLayout(3, cs_sh_op.layout()).withName("operands")
    ).withName("cs_sh");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfInt insn$LAYOUT = (OfInt)$LAYOUT.select(groupElement("insn"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * sh_insn insn
     * }
     */
    public static final OfInt insn$layout() {
        return insn$LAYOUT;
    }

    private static final long insn$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * sh_insn insn
     * }
     */
    public static final long insn$offset() {
        return insn$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * sh_insn insn
     * }
     */
    public static int insn(MemorySegment struct) {
        return struct.get(insn$LAYOUT, insn$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * sh_insn insn
     * }
     */
    public static void insn(MemorySegment struct, int fieldValue) {
        struct.set(insn$LAYOUT, insn$OFFSET, fieldValue);
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

    private static final long size$OFFSET = 4;

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

    private static final long op_count$OFFSET = 5;

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
     * cs_sh_op operands[3]
     * }
     */
    public static final SequenceLayout operands$layout() {
        return operands$LAYOUT;
    }

    private static final long operands$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * cs_sh_op operands[3]
     * }
     */
    public static final long operands$offset() {
        return operands$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * cs_sh_op operands[3]
     * }
     */
    public static MemorySegment operands(MemorySegment struct) {
        return struct.asSlice(operands$OFFSET, operands$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * cs_sh_op operands[3]
     * }
     */
    public static void operands(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, operands$OFFSET, operands$LAYOUT.byteSize());
    }

    private static long[] operands$DIMS = { 3 };

    /**
     * Dimensions for array field:
     * {@snippet lang=c :
     * cs_sh_op operands[3]
     * }
     */
    public static long[] operands$dimensions() {
        return operands$DIMS;
    }
    private static final MethodHandle operands$ELEM_HANDLE = operands$LAYOUT.sliceHandle(sequenceElement());

    /**
     * Indexed getter for field:
     * {@snippet lang=c :
     * cs_sh_op operands[3]
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
     * cs_sh_op operands[3]
     * }
     */
    public static void operands(MemorySegment struct, long index0, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, operands(struct, index0), 0L, cs_sh_op.layout().byteSize());
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

