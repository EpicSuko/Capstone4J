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
 * struct mips_op_mem {
 *     mips_reg base;
 *     int64_t disp;
 * }
 * }
 */
public class mips_op_mem {

    mips_op_mem() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_INT.withName("base"),
        MemoryLayout.paddingLayout(4),
        capstone_h.C_LONG_LONG.withName("disp")
    ).withName("mips_op_mem");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfInt base$LAYOUT = (OfInt)$LAYOUT.select(groupElement("base"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * mips_reg base
     * }
     */
    public static final OfInt base$layout() {
        return base$LAYOUT;
    }

    private static final long base$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * mips_reg base
     * }
     */
    public static final long base$offset() {
        return base$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * mips_reg base
     * }
     */
    public static int base(MemorySegment struct) {
        return struct.get(base$LAYOUT, base$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * mips_reg base
     * }
     */
    public static void base(MemorySegment struct, int fieldValue) {
        struct.set(base$LAYOUT, base$OFFSET, fieldValue);
    }

    private static final OfLong disp$LAYOUT = (OfLong)$LAYOUT.select(groupElement("disp"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * int64_t disp
     * }
     */
    public static final OfLong disp$layout() {
        return disp$LAYOUT;
    }

    private static final long disp$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * int64_t disp
     * }
     */
    public static final long disp$offset() {
        return disp$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * int64_t disp
     * }
     */
    public static long disp(MemorySegment struct) {
        return struct.get(disp$LAYOUT, disp$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * int64_t disp
     * }
     */
    public static void disp(MemorySegment struct, long fieldValue) {
        struct.set(disp$LAYOUT, disp$OFFSET, fieldValue);
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

