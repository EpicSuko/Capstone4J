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
 * struct m68k_op_br_disp {
 *     int32_t disp;
 *     uint8_t disp_size;
 * }
 * }
 */
public class m68k_op_br_disp {

    m68k_op_br_disp() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        capstone_h.C_INT.withName("disp"),
        capstone_h.C_CHAR.withName("disp_size"),
        MemoryLayout.paddingLayout(3)
    ).withName("m68k_op_br_disp");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfInt disp$LAYOUT = (OfInt)$LAYOUT.select(groupElement("disp"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * int32_t disp
     * }
     */
    public static final OfInt disp$layout() {
        return disp$LAYOUT;
    }

    private static final long disp$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * int32_t disp
     * }
     */
    public static final long disp$offset() {
        return disp$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * int32_t disp
     * }
     */
    public static int disp(MemorySegment struct) {
        return struct.get(disp$LAYOUT, disp$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * int32_t disp
     * }
     */
    public static void disp(MemorySegment struct, int fieldValue) {
        struct.set(disp$LAYOUT, disp$OFFSET, fieldValue);
    }

    private static final OfByte disp_size$LAYOUT = (OfByte)$LAYOUT.select(groupElement("disp_size"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * uint8_t disp_size
     * }
     */
    public static final OfByte disp_size$layout() {
        return disp_size$LAYOUT;
    }

    private static final long disp_size$OFFSET = 4;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * uint8_t disp_size
     * }
     */
    public static final long disp_size$offset() {
        return disp_size$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * uint8_t disp_size
     * }
     */
    public static byte disp_size(MemorySegment struct) {
        return struct.get(disp_size$LAYOUT, disp_size$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * uint8_t disp_size
     * }
     */
    public static void disp_size(MemorySegment struct, byte fieldValue) {
        struct.set(disp_size$LAYOUT, disp_size$OFFSET, fieldValue);
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

