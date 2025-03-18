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
 * struct cs_arc_op {
 *     arc_op_type type;
 *     union {
 *         unsigned int reg;
 *         int64_t imm;
 *     };
 *     enum cs_ac_type access;
 * }
 * }
 */
public class cs_arc_op {

    cs_arc_op() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_INT.withName("type"),
        MemoryLayout.paddingLayout(4),
        MemoryLayout.unionLayout(
            capstone_h.C_INT.withName("reg"),
            capstone_h.C_LONG_LONG.withName("imm")
        ).withName("$anon$25:2"),
        capstone_h.C_INT.withName("access"),
        MemoryLayout.paddingLayout(4)
    ).withName("cs_arc_op");

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
     * arc_op_type type
     * }
     */
    public static final OfInt type$layout() {
        return type$LAYOUT;
    }

    private static final long type$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * arc_op_type type
     * }
     */
    public static final long type$offset() {
        return type$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * arc_op_type type
     * }
     */
    public static int type(MemorySegment struct) {
        return struct.get(type$LAYOUT, type$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * arc_op_type type
     * }
     */
    public static void type(MemorySegment struct, int fieldValue) {
        struct.set(type$LAYOUT, type$OFFSET, fieldValue);
    }

    private static final OfInt reg$LAYOUT = (OfInt)$LAYOUT.select(groupElement("$anon$25:2"), groupElement("reg"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * unsigned int reg
     * }
     */
    public static final OfInt reg$layout() {
        return reg$LAYOUT;
    }

    private static final long reg$OFFSET = 8;

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

    private static final OfLong imm$LAYOUT = (OfLong)$LAYOUT.select(groupElement("$anon$25:2"), groupElement("imm"));

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

    private static final OfInt access$LAYOUT = (OfInt)$LAYOUT.select(groupElement("access"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * enum cs_ac_type access
     * }
     */
    public static final OfInt access$layout() {
        return access$LAYOUT;
    }

    private static final long access$OFFSET = 16;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * enum cs_ac_type access
     * }
     */
    public static final long access$offset() {
        return access$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * enum cs_ac_type access
     * }
     */
    public static int access(MemorySegment struct) {
        return struct.get(access$LAYOUT, access$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * enum cs_ac_type access
     * }
     */
    public static void access(MemorySegment struct, int fieldValue) {
        struct.set(access$LAYOUT, access$OFFSET, fieldValue);
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

