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
 * struct m68k_op_mem {
 *     m68k_reg base_reg;
 *     m68k_reg index_reg;
 *     m68k_reg in_base_reg;
 *     uint32_t in_disp;
 *     uint32_t out_disp;
 *     int16_t disp;
 *     uint8_t scale;
 *     uint8_t bitfield;
 *     uint8_t width;
 *     uint8_t offset;
 *     uint8_t index_size;
 * }
 * }
 */
public class m68k_op_mem {

    m68k_op_mem() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_INT.withName("base_reg"),
        capstone_h.C_INT.withName("index_reg"),
        capstone_h.C_INT.withName("in_base_reg"),
        capstone_h.C_INT.withName("in_disp"),
        capstone_h.C_INT.withName("out_disp"),
        capstone_h.C_SHORT.withName("disp"),
        capstone_h.C_CHAR.withName("scale"),
        capstone_h.C_CHAR.withName("bitfield"),
        capstone_h.C_CHAR.withName("width"),
        capstone_h.C_CHAR.withName("offset"),
        capstone_h.C_CHAR.withName("index_size"),
        MemoryLayout.paddingLayout(1)
    ).withName("m68k_op_mem");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfInt base_reg$LAYOUT = (OfInt)$LAYOUT.select(groupElement("base_reg"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * m68k_reg base_reg
     * }
     */
    public static final OfInt base_reg$layout() {
        return base_reg$LAYOUT;
    }

    private static final long base_reg$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * m68k_reg base_reg
     * }
     */
    public static final long base_reg$offset() {
        return base_reg$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * m68k_reg base_reg
     * }
     */
    public static int base_reg(MemorySegment struct) {
        return struct.get(base_reg$LAYOUT, base_reg$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * m68k_reg base_reg
     * }
     */
    public static void base_reg(MemorySegment struct, int fieldValue) {
        struct.set(base_reg$LAYOUT, base_reg$OFFSET, fieldValue);
    }

    private static final OfInt index_reg$LAYOUT = (OfInt)$LAYOUT.select(groupElement("index_reg"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * m68k_reg index_reg
     * }
     */
    public static final OfInt index_reg$layout() {
        return index_reg$LAYOUT;
    }

    private static final long index_reg$OFFSET = 4;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * m68k_reg index_reg
     * }
     */
    public static final long index_reg$offset() {
        return index_reg$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * m68k_reg index_reg
     * }
     */
    public static int index_reg(MemorySegment struct) {
        return struct.get(index_reg$LAYOUT, index_reg$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * m68k_reg index_reg
     * }
     */
    public static void index_reg(MemorySegment struct, int fieldValue) {
        struct.set(index_reg$LAYOUT, index_reg$OFFSET, fieldValue);
    }

    private static final OfInt in_base_reg$LAYOUT = (OfInt)$LAYOUT.select(groupElement("in_base_reg"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * m68k_reg in_base_reg
     * }
     */
    public static final OfInt in_base_reg$layout() {
        return in_base_reg$LAYOUT;
    }

    private static final long in_base_reg$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * m68k_reg in_base_reg
     * }
     */
    public static final long in_base_reg$offset() {
        return in_base_reg$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * m68k_reg in_base_reg
     * }
     */
    public static int in_base_reg(MemorySegment struct) {
        return struct.get(in_base_reg$LAYOUT, in_base_reg$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * m68k_reg in_base_reg
     * }
     */
    public static void in_base_reg(MemorySegment struct, int fieldValue) {
        struct.set(in_base_reg$LAYOUT, in_base_reg$OFFSET, fieldValue);
    }

    private static final OfInt in_disp$LAYOUT = (OfInt)$LAYOUT.select(groupElement("in_disp"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint32_t in_disp
     * }
     */
    public static final OfInt in_disp$layout() {
        return in_disp$LAYOUT;
    }

    private static final long in_disp$OFFSET = 12;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint32_t in_disp
     * }
     */
    public static final long in_disp$offset() {
        return in_disp$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint32_t in_disp
     * }
     */
    public static int in_disp(MemorySegment struct) {
        return struct.get(in_disp$LAYOUT, in_disp$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint32_t in_disp
     * }
     */
    public static void in_disp(MemorySegment struct, int fieldValue) {
        struct.set(in_disp$LAYOUT, in_disp$OFFSET, fieldValue);
    }

    private static final OfInt out_disp$LAYOUT = (OfInt)$LAYOUT.select(groupElement("out_disp"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint32_t out_disp
     * }
     */
    public static final OfInt out_disp$layout() {
        return out_disp$LAYOUT;
    }

    private static final long out_disp$OFFSET = 16;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint32_t out_disp
     * }
     */
    public static final long out_disp$offset() {
        return out_disp$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint32_t out_disp
     * }
     */
    public static int out_disp(MemorySegment struct) {
        return struct.get(out_disp$LAYOUT, out_disp$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint32_t out_disp
     * }
     */
    public static void out_disp(MemorySegment struct, int fieldValue) {
        struct.set(out_disp$LAYOUT, out_disp$OFFSET, fieldValue);
    }

    private static final OfShort disp$LAYOUT = (OfShort)$LAYOUT.select(groupElement("disp"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * int16_t disp
     * }
     */
    public static final OfShort disp$layout() {
        return disp$LAYOUT;
    }

    private static final long disp$OFFSET = 20;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * int16_t disp
     * }
     */
    public static final long disp$offset() {
        return disp$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * int16_t disp
     * }
     */
    public static short disp(MemorySegment struct) {
        return struct.get(disp$LAYOUT, disp$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * int16_t disp
     * }
     */
    public static void disp(MemorySegment struct, short fieldValue) {
        struct.set(disp$LAYOUT, disp$OFFSET, fieldValue);
    }

    private static final OfByte scale$LAYOUT = (OfByte)$LAYOUT.select(groupElement("scale"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t scale
     * }
     */
    public static final OfByte scale$layout() {
        return scale$LAYOUT;
    }

    private static final long scale$OFFSET = 22;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t scale
     * }
     */
    public static final long scale$offset() {
        return scale$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t scale
     * }
     */
    public static byte scale(MemorySegment struct) {
        return struct.get(scale$LAYOUT, scale$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t scale
     * }
     */
    public static void scale(MemorySegment struct, byte fieldValue) {
        struct.set(scale$LAYOUT, scale$OFFSET, fieldValue);
    }

    private static final OfByte bitfield$LAYOUT = (OfByte)$LAYOUT.select(groupElement("bitfield"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t bitfield
     * }
     */
    public static final OfByte bitfield$layout() {
        return bitfield$LAYOUT;
    }

    private static final long bitfield$OFFSET = 23;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t bitfield
     * }
     */
    public static final long bitfield$offset() {
        return bitfield$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t bitfield
     * }
     */
    public static byte bitfield(MemorySegment struct) {
        return struct.get(bitfield$LAYOUT, bitfield$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t bitfield
     * }
     */
    public static void bitfield(MemorySegment struct, byte fieldValue) {
        struct.set(bitfield$LAYOUT, bitfield$OFFSET, fieldValue);
    }

    private static final OfByte width$LAYOUT = (OfByte)$LAYOUT.select(groupElement("width"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t width
     * }
     */
    public static final OfByte width$layout() {
        return width$LAYOUT;
    }

    private static final long width$OFFSET = 24;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t width
     * }
     */
    public static final long width$offset() {
        return width$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t width
     * }
     */
    public static byte width(MemorySegment struct) {
        return struct.get(width$LAYOUT, width$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t width
     * }
     */
    public static void width(MemorySegment struct, byte fieldValue) {
        struct.set(width$LAYOUT, width$OFFSET, fieldValue);
    }

    private static final OfByte offset$LAYOUT = (OfByte)$LAYOUT.select(groupElement("offset"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t offset
     * }
     */
    public static final OfByte offset$layout() {
        return offset$LAYOUT;
    }

    private static final long offset$OFFSET = 25;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t offset
     * }
     */
    public static final long offset$offset() {
        return offset$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t offset
     * }
     */
    public static byte offset(MemorySegment struct) {
        return struct.get(offset$LAYOUT, offset$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t offset
     * }
     */
    public static void offset(MemorySegment struct, byte fieldValue) {
        struct.set(offset$LAYOUT, offset$OFFSET, fieldValue);
    }

    private static final OfByte index_size$LAYOUT = (OfByte)$LAYOUT.select(groupElement("index_size"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t index_size
     * }
     */
    public static final OfByte index_size$layout() {
        return index_size$LAYOUT;
    }

    private static final long index_size$OFFSET = 26;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t index_size
     * }
     */
    public static final long index_size$offset() {
        return index_size$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t index_size
     * }
     */
    public static byte index_size(MemorySegment struct) {
        return struct.get(index_size$LAYOUT, index_size$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t index_size
     * }
     */
    public static void index_size(MemorySegment struct, byte fieldValue) {
        struct.set(index_size$LAYOUT, index_size$OFFSET, fieldValue);
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

