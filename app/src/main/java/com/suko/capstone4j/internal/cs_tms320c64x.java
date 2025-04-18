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
 * struct cs_tms320c64x {
 *     uint8_t op_count;
 *     cs_tms320c64x_op operands[8];
 *     struct {
 *         unsigned int reg;
 *         unsigned int zero;
 *     } condition;
 *     struct {
 *         unsigned int unit;
 *         unsigned int side;
 *         unsigned int crosspath;
 *     } funit;
 *     unsigned int parallel;
 * }
 * }
 */
public class cs_tms320c64x {

    cs_tms320c64x() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_CHAR.withName("op_count"),
        MemoryLayout.paddingLayout(3),
        MemoryLayout.sequenceLayout(8, cs_tms320c64x_op.layout()).withName("operands"),
        cs_tms320c64x.condition.layout().withName("condition"),
        cs_tms320c64x.funit.layout().withName("funit"),
        capstone_h.C_INT.withName("parallel")
    ).withName("cs_tms320c64x");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
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

    private static final long op_count$OFFSET = 0;

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
     * cs_tms320c64x_op operands[8]
     * }
     */
    public static final SequenceLayout operands$layout() {
        return operands$LAYOUT;
    }

    private static final long operands$OFFSET = 4;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * cs_tms320c64x_op operands[8]
     * }
     */
    public static final long operands$offset() {
        return operands$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * cs_tms320c64x_op operands[8]
     * }
     */
    public static MemorySegment operands(MemorySegment struct) {
        return struct.asSlice(operands$OFFSET, operands$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * cs_tms320c64x_op operands[8]
     * }
     */
    public static void operands(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, operands$OFFSET, operands$LAYOUT.byteSize());
    }

    private static long[] operands$DIMS = { 8 };

    /**
     * Dimensions for array field:
     * {@snippet lang=c :
     * cs_tms320c64x_op operands[8]
     * }
     */
    public static long[] operands$dimensions() {
        return operands$DIMS;
    }
    private static final MethodHandle operands$ELEM_HANDLE = operands$LAYOUT.sliceHandle(sequenceElement());

    /**
     * Indexed getter for field:
     * {@snippet lang=c :
     * cs_tms320c64x_op operands[8]
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
     * cs_tms320c64x_op operands[8]
     * }
     */
    public static void operands(MemorySegment struct, long index0, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, operands(struct, index0), 0L, cs_tms320c64x_op.layout().byteSize());
    }

    /**
     * {@snippet lang=c :
     * struct {
     *     unsigned int reg;
     *     unsigned int zero;
     * }
     * }
     */
    public static class condition {

        condition() {
            // Should not be called directly
        }

        private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
            capstone_h.C_INT.withName("reg"),
            capstone_h.C_INT.withName("zero")
        ).withName("$anon$68:2");

        /**
         * The layout of this struct
         */
        public static final GroupLayout layout() {
            return $LAYOUT;
        }

        private static final OfInt reg$LAYOUT = (OfInt)$LAYOUT.select(groupElement("reg"));

        /**
         * Layout for field:
         * {@snippet lang=c :
         * unsigned int reg
         * }
         */
        public static final OfInt reg$layout() {
            return reg$LAYOUT;
        }

        private static final long reg$OFFSET = 0;

        /**
         * Offset for field:
         * {@snippet lang=c :
         * unsigned int reg
         * }
         */
        public static final long reg$offset() {
            return reg$OFFSET;
        }

        /**
         * Getter for field:
         * {@snippet lang=c :
         * unsigned int reg
         * }
         */
        public static int reg(MemorySegment struct) {
            return struct.get(reg$LAYOUT, reg$OFFSET);
        }

        /**
         * Setter for field:
         * {@snippet lang=c :
         * unsigned int reg
         * }
         */
        public static void reg(MemorySegment struct, int fieldValue) {
            struct.set(reg$LAYOUT, reg$OFFSET, fieldValue);
        }

        private static final OfInt zero$LAYOUT = (OfInt)$LAYOUT.select(groupElement("zero"));

        /**
         * Layout for field:
         * {@snippet lang=c :
         * unsigned int zero
         * }
         */
        public static final OfInt zero$layout() {
            return zero$LAYOUT;
        }

        private static final long zero$OFFSET = 4;

        /**
         * Offset for field:
         * {@snippet lang=c :
         * unsigned int zero
         * }
         */
        public static final long zero$offset() {
            return zero$OFFSET;
        }

        /**
         * Getter for field:
         * {@snippet lang=c :
         * unsigned int zero
         * }
         */
        public static int zero(MemorySegment struct) {
            return struct.get(zero$LAYOUT, zero$OFFSET);
        }

        /**
         * Setter for field:
         * {@snippet lang=c :
         * unsigned int zero
         * }
         */
        public static void zero(MemorySegment struct, int fieldValue) {
            struct.set(zero$LAYOUT, zero$OFFSET, fieldValue);
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

    private static final GroupLayout condition$LAYOUT = (GroupLayout)$LAYOUT.select(groupElement("condition"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct {
     *     unsigned int reg;
     *     unsigned int zero;
     * } condition
     * }
     */
    public static final GroupLayout condition$layout() {
        return condition$LAYOUT;
    }

    private static final long condition$OFFSET = 260;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct {
     *     unsigned int reg;
     *     unsigned int zero;
     * } condition
     * }
     */
    public static final long condition$offset() {
        return condition$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct {
     *     unsigned int reg;
     *     unsigned int zero;
     * } condition
     * }
     */
    public static MemorySegment condition(MemorySegment struct) {
        return struct.asSlice(condition$OFFSET, condition$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct {
     *     unsigned int reg;
     *     unsigned int zero;
     * } condition
     * }
     */
    public static void condition(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, condition$OFFSET, condition$LAYOUT.byteSize());
    }

    /**
     * {@snippet lang=c :
     * struct {
     *     unsigned int unit;
     *     unsigned int side;
     *     unsigned int crosspath;
     * }
     * }
     */
    public static class funit {

        funit() {
            // Should not be called directly
        }

        private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
            capstone_h.C_INT.withName("unit"),
            capstone_h.C_INT.withName("side"),
            capstone_h.C_INT.withName("crosspath")
        ).withName("$anon$72:2");

        /**
         * The layout of this struct
         */
        public static final GroupLayout layout() {
            return $LAYOUT;
        }

        private static final OfInt unit$LAYOUT = (OfInt)$LAYOUT.select(groupElement("unit"));

        /**
         * Layout for field:
         * {@snippet lang=c :
         * unsigned int unit
         * }
         */
        public static final OfInt unit$layout() {
            return unit$LAYOUT;
        }

        private static final long unit$OFFSET = 0;

        /**
         * Offset for field:
         * {@snippet lang=c :
         * unsigned int unit
         * }
         */
        public static final long unit$offset() {
            return unit$OFFSET;
        }

        /**
         * Getter for field:
         * {@snippet lang=c :
         * unsigned int unit
         * }
         */
        public static int unit(MemorySegment struct) {
            return struct.get(unit$LAYOUT, unit$OFFSET);
        }

        /**
         * Setter for field:
         * {@snippet lang=c :
         * unsigned int unit
         * }
         */
        public static void unit(MemorySegment struct, int fieldValue) {
            struct.set(unit$LAYOUT, unit$OFFSET, fieldValue);
        }

        private static final OfInt side$LAYOUT = (OfInt)$LAYOUT.select(groupElement("side"));

        /**
         * Layout for field:
         * {@snippet lang=c :
         * unsigned int side
         * }
         */
        public static final OfInt side$layout() {
            return side$LAYOUT;
        }

        private static final long side$OFFSET = 4;

        /**
         * Offset for field:
         * {@snippet lang=c :
         * unsigned int side
         * }
         */
        public static final long side$offset() {
            return side$OFFSET;
        }

        /**
         * Getter for field:
         * {@snippet lang=c :
         * unsigned int side
         * }
         */
        public static int side(MemorySegment struct) {
            return struct.get(side$LAYOUT, side$OFFSET);
        }

        /**
         * Setter for field:
         * {@snippet lang=c :
         * unsigned int side
         * }
         */
        public static void side(MemorySegment struct, int fieldValue) {
            struct.set(side$LAYOUT, side$OFFSET, fieldValue);
        }

        private static final OfInt crosspath$LAYOUT = (OfInt)$LAYOUT.select(groupElement("crosspath"));

        /**
         * Layout for field:
         * {@snippet lang=c :
         * unsigned int crosspath
         * }
         */
        public static final OfInt crosspath$layout() {
            return crosspath$LAYOUT;
        }

        private static final long crosspath$OFFSET = 8;

        /**
         * Offset for field:
         * {@snippet lang=c :
         * unsigned int crosspath
         * }
         */
        public static final long crosspath$offset() {
            return crosspath$OFFSET;
        }

        /**
         * Getter for field:
         * {@snippet lang=c :
         * unsigned int crosspath
         * }
         */
        public static int crosspath(MemorySegment struct) {
            return struct.get(crosspath$LAYOUT, crosspath$OFFSET);
        }

        /**
         * Setter for field:
         * {@snippet lang=c :
         * unsigned int crosspath
         * }
         */
        public static void crosspath(MemorySegment struct, int fieldValue) {
            struct.set(crosspath$LAYOUT, crosspath$OFFSET, fieldValue);
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

    private static final GroupLayout funit$LAYOUT = (GroupLayout)$LAYOUT.select(groupElement("funit"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct {
     *     unsigned int unit;
     *     unsigned int side;
     *     unsigned int crosspath;
     * } funit
     * }
     */
    public static final GroupLayout funit$layout() {
        return funit$LAYOUT;
    }

    private static final long funit$OFFSET = 268;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct {
     *     unsigned int unit;
     *     unsigned int side;
     *     unsigned int crosspath;
     * } funit
     * }
     */
    public static final long funit$offset() {
        return funit$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct {
     *     unsigned int unit;
     *     unsigned int side;
     *     unsigned int crosspath;
     * } funit
     * }
     */
    public static MemorySegment funit(MemorySegment struct) {
        return struct.asSlice(funit$OFFSET, funit$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct {
     *     unsigned int unit;
     *     unsigned int side;
     *     unsigned int crosspath;
     * } funit
     * }
     */
    public static void funit(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, funit$OFFSET, funit$LAYOUT.byteSize());
    }

    private static final OfInt parallel$LAYOUT = (OfInt)$LAYOUT.select(groupElement("parallel"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * unsigned int parallel
     * }
     */
    public static final OfInt parallel$layout() {
        return parallel$LAYOUT;
    }

    private static final long parallel$OFFSET = 280;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * unsigned int parallel
     * }
     */
    public static final long parallel$offset() {
        return parallel$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * unsigned int parallel
     * }
     */
    public static int parallel(MemorySegment struct) {
        return struct.get(parallel$LAYOUT, parallel$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * unsigned int parallel
     * }
     */
    public static void parallel(MemorySegment struct, int fieldValue) {
        struct.set(parallel$LAYOUT, parallel$OFFSET, fieldValue);
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

